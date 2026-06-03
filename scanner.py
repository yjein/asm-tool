import json
import sys
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.table import Table
from rich import box

from scanners.utils import console, info, warn
from scanners.config import TARGETS, REMEDIATION, SEV_COLOR
from scanners.detect import SCANNERS
from scanners.portscan import run_port_scan
from scanners.nmap_scan import run_nmap_scan

BASE_DIR    = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "scan_results"


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


def save_report(results, port_scan=None, nmap_scan=None):
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
    if port_scan:
        data["port_scan"] = port_scan
    if nmap_scan:
        data["nmap_scan"] = nmap_scan
    path = RESULTS_DIR / "report.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_scan(target_info, host="localhost"):
    default = target_info["default"].replace("localhost", host)
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

    val  = input("  대상 IP / 도메인 (엔터 = localhost): ").strip()
    host = val or "localhost"
    console.print()

    port_result = run_port_scan(host)
    nmap_result = run_nmap_scan(host)

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
            results.append(run_scan(t, host))

        print_summary(results)
        save_report(results, port_result, nmap_result)

        import report_html
        html_path = report_html.generate()
        info(f"HTML 보고서: {html_path}")

        again = input("\n  계속 스캔하시겠습니까? (y/n) > ").strip().lower()
        if again != "y":
            break
    console.print()


if __name__ == "__main__":
    main()
