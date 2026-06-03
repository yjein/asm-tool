import re
import subprocess
import sys
from pathlib import Path

from rich.table import Table
from rich import box

from .utils import console, info, warn, step

_NMAP_CANDIDATES = (
    ["nmap"],
    ["C:\\Program Files (x86)\\Nmap\\nmap.exe"],
    ["C:\\Program Files\\Nmap\\nmap.exe"],
)

def _nmap_cmd():
    for cmd in _NMAP_CANDIDATES:
        try:
            subprocess.run(cmd + ["--version"], capture_output=True, timeout=5)
            return cmd
        except Exception:
            continue
    return None

NMAP_TARGETS = [
    {"name": "OpenSSH (CVE-2018-15473)",   "port": "2222"},
    {"name": "Log4Shell (CVE-2021-44228)",  "port": "8080"},
    {"name": "SambaCry (CVE-2017-7494)",    "port": "4445"},
]

NMAP_CVE_INFO = {
    "2222": {"cve": "CVE-2018-15473", "vuln": "SSH User Enumeration", "severity": "MEDIUM"},
    "8080": {"cve": "CVE-2021-44228", "vuln": "Log4Shell RCE",        "severity": "CRITICAL"},
    "4445": {"cve": "CVE-2017-7494",  "vuln": "SambaCry RCE",         "severity": "CRITICAL"},
}

SEV_COLOR = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def _run_nmap(host, port):
    cmd = _nmap_cmd()
    if not cmd:
        return ""
    try:
        result = subprocess.run(
            cmd + ["-sV", "-p", port, host],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def _parse_nmap(output, port):
    m = re.search(rf"{port}/tcp\s+(\w+)\s+(\S+)\s*(.*)", output)
    if m:
        return m.group(1), m.group(2), m.group(3).strip() or "Unknown"
    return "closed", "Unknown", "Unknown"


def run_nmap_scan(host):
    if not _nmap_cmd():
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
        output           = _run_nmap(host, port)
        state, service, version = _parse_nmap(output, port)
        cve_data         = NMAP_CVE_INFO.get(port, {})
        sev              = cve_data.get("severity", "")
        c                = SEV_COLOR.get(sev, "white")
        if state == "open":
            t.add_row(port, service, version, cve_data.get("cve", "—"), f"[{c}]{sev}[/{c}]")
        results.append({
            "port": port, "service": service, "version": version,
            "state": state, "cve": cve_data.get("cve", ""), "severity": sev,
        })

    console.print(t)
    console.print()
    return results
