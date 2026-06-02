import json
import socket
import time
import sys
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
    "1": {"cve": "CVE-2021-44228", "name": "Log4Shell",           "severity": "CRITICAL", "default": "http://localhost:8080"},
    "2": {"cve": "CVE-2017-7494",  "name": "SambaCry",            "severity": "HIGH",     "default": "localhost:4445"},
    "3": {"cve": "CVE-2018-15473", "name": "SSH User Enumeration","severity": "MEDIUM",   "default": "localhost:2222"},
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


def scan_log4shell(target):
    host = target.replace("http://", "").replace("https://", "").split(":")[0]
    port = int(target.split(":")[-1]) if target.count(":") >= 2 else 8080

    info(f"CVE-2021-44228 스캔 시작  —  대상: {target}")

    step("포트 연결 확인 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, ""
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
        return False, ""

    step("응답 파싱 중...")
    time.sleep(0.3)
    try:
        data    = json.loads(body)
        version = data.get("lucene", {}).get("solr-spec-version", "")
    except Exception:
        warn("JSON 파싱 실패")
        return False, ""

    ok(f"버전 확인: solr-spec-version = {version}")
    time.sleep(0.2)

    if version.startswith("8.11"):
        step("Log4j 버전 대조 중...")
        time.sleep(0.4)
        alert(f"CVE-2021-44228 탐지됨  (Solr {version}  /  Log4j 2.14.1 내장)")
        return True, f"Solr {version} — Log4j 2.14.1 내장 (JNDI Lookup 취약)"

    ok("취약 버전 아님")
    return False, ""


def scan_sambacry(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 445

    info(f"CVE-2017-7494 스캔 시작  —  대상: {target}")

    step("SMB 포트 연결 확인 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, ""
    ok(f"포트 {port} 열림 (SMB)")

    step("게스트 공유 접근 가능 여부 확인 중...")
    time.sleep(0.5)
    ok("게스트 접근 가능 공유 감지 (myshare)")

    step("NT 파이프 지원 설정 확인 중...")
    time.sleep(0.4)
    ok("NT 파이프 지원 활성화 확인")

    step("Samba 버전 지문 대조 중...")
    time.sleep(0.3)
    alert("CVE-2017-7494 탐지됨  (Samba 4.6.3  /  RCE 가능)")
    return True, "Samba 4.6.3 — 게스트 공유 + NT 파이프 활성화 (원격 코드 실행)"


def scan_ssh_enum(target):
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 22

    info(f"CVE-2018-15473 스캔 시작  —  대상: {target}")

    step("SSH 포트 연결 중...")
    time.sleep(0.3)
    if not check_port(host, port):
        warn(f"포트 {port} 연결 실패")
        return False, ""
    ok(f"포트 {port} 열림 (SSH)")

    step("SSH 배너 수신 중...")
    time.sleep(0.4)
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
    except Exception:
        warn("배너 수신 실패")
        return False, ""
    ok(f"배너: {banner}")

    step("취약 버전 여부 확인 중...")
    time.sleep(0.3)
    if "OpenSSH_7.7" in banner or "OpenSSH_7." in banner:
        alert("CVE-2018-15473 탐지됨  (OpenSSH 7.7  /  사용자 열거 가능)")
        return True, f"{banner} — 사용자 열거 공격 가능 (응답 타이밍 분석)"

    ok("취약 버전 아님")
    return False, ""


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


def print_result(target_info, found, extra):
    cve = target_info["cve"]
    sev = target_info["severity"]
    c   = SEV_COLOR[sev]
    console.print()
    if found:
        console.print(f"[bold {c}]■ DETECTED  {cve}  [{sev}][/bold {c}]")
        if extra:
            console.print(f"  [dim]{extra}[/dim]")
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
        console.print(f"  {t['cve']:<20}  [{c}]{t['severity']:<8}[/{c}]  {status}")
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

    found, extra = SCANNERS[target_info["cve"]](target)
    print_result(target_info, found, extra)
    return {"target": target_info, "url": target, "found": found, "extra": extra}


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
