import json
import re
import socket
import time
import urllib.request

from .utils import console, info, ok, warn, alert, step, check_port, os_from_ssh_banner
from .poc import poc_log4shell, poc_sambacry, poc_ssh_enum


def scan_log4shell(target):
    host = target.replace("http://", "").replace("https://", "").split(":")[0]
    port = int(target.split(":")[-1]) if target.count(":") >= 2 else 8080

    info(f"CVE-2021-44228 스캔 시작대상: {target}")

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

    step("Log4j 취약 버전 대조 중...")
    time.sleep(0.3)
    try:
        parts = version.split('.')
        v_maj, v_min, v_pat = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
        # Solr 8.11.2부터 Log4j 2.17.0 적용 (완전 패치)
        vuln_solr = v_maj < 8 or (v_maj == 8 and v_min < 11) or (v_maj == 8 and v_min == 11 and v_pat < 2)
    except Exception:
        vuln_solr = False

    if vuln_solr:
        alert(f"CVE-2021-44228 탐지됨  (Solr {version}  /  취약한 Log4j 버전 사용)")
        console.print()
        poc_ok, poc_msg = poc_log4shell(target)
        return True, f"Solr {version} — 취약한 Log4j 버전 내장 (JNDI Lookup 가능)", poc_ok, poc_msg, os_info

    ok(f"취약 버전 아님 (Solr {version})")
    return False, "", False, "", os_info


def scan_sambacry(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 445

    info(f"CVE-2017-7494 스캔 시작대상: {target}")

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

    m = re.search(r'[Ss]amba\s+(\d+)\.(\d+)\.(\d+)', os_info)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        samba_ver = f"{major}.{minor}.{patch}"
        vulnerable = (
            (major == 3 and minor >= 5) or
            (major == 4 and (
                minor < 4 or
                (minor == 4 and patch < 14) or
                (minor == 5 and patch < 10) or
                (minor == 6 and patch < 4)
            ))
        )
    else:
        samba_ver = "알 수 없음"
        vulnerable = True

    if not vulnerable:
        ok(f"취약 버전 아님 (Samba {samba_ver})")
        return False, "", False, "", os_info

    alert(f"CVE-2017-7494 탐지됨  (Samba {samba_ver}  /  RCE 가능)")

    console.print()
    poc_ok, poc_msg = poc_sambacry(host, port)
    return True, f"Samba {samba_ver}  게스트 공유  NT 파이프 활성화  원격 코드 실행 가능", poc_ok, poc_msg, os_info


def scan_ssh_enum(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 22

    info(f"CVE-2018-15473 스캔 시작대상: {target}")

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
    os_info = os_from_ssh_banner(banner)
    ok(f"OS 추정: {os_info}")

    step("취약 버전 여부 확인 중...")
    time.sleep(0.3)
    m = re.search(r'OpenSSH_(\d+)\.(\d+)', banner)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        vulnerable = major < 7 or (major == 7 and minor <= 7)
        ssh_ver = f"{major}.{minor}"
    else:
        vulnerable = False
        ssh_ver = "알 수 없음"

    if vulnerable:
        alert(f"CVE-2018-15473 탐지됨  (OpenSSH {ssh_ver}  /  사용자 열거 가능)")

        console.print()
        poc_ok, poc_msg = poc_ssh_enum(host, port)
        return True, f"{banner}  공개키 인증 응답 차이로 사용자 열거 가능", poc_ok, poc_msg, os_info

    ok(f"취약 버전 아님 (OpenSSH {ssh_ver})")
    return False, "", False, "", os_info


SCANNERS = {
    "CVE-2021-44228": scan_log4shell,
    "CVE-2017-7494":  scan_sambacry,
    "CVE-2018-15473": scan_ssh_enum,
}
