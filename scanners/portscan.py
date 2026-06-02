import platform
import re
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.table import Table
from rich import box

from .utils import console, info, ok, step, check_port

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

SEV_COLOR = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def _ttl_os(host):
    # localhost는 IPv4로 명시해 IPv6 fallback 방지
    target = "127.0.0.1" if host in ("localhost", "::1") else host
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-4", target]
        else:
            cmd = ["ping", "-c", "1", target]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        out = result.stdout.decode('utf-8', errors='ignore')
        if not out:
            out = result.stdout.decode('cp949', errors='ignore')
        m = re.search(r"TTL[=\s](\d+)", out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:  return f"Linux / macOS (TTL {ttl})"
            if ttl <= 128: return f"Windows (TTL {ttl})"
            return f"Network Device (TTL {ttl})"
    except Exception:
        pass
    return "확인 불가"


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

    def _scan_port(args):
        port, pinfo = args
        if not check_port(host, port, timeout=0.5):
            return None
        banner = _grab_banner(host, port)
        return {"port": port, "service": pinfo["service"], "risk": pinfo["risk"], "banner": banner}

    open_ports = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_scan_port, (p, i)): p for p, i in COMMON_PORTS.items()}
        results_map = {}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results_map[r["port"]] = r

    for port in sorted(results_map):
        r = results_map[port]
        c = SEV_COLOR.get(r["risk"], "white")
        t.add_row(str(r["port"]), r["service"], f"[{c}]{r['risk']}[/{c}]", r["banner"])
        open_ports.append(r)

    console.print(t)
    console.print(f"  열린 포트: {len(open_ports)}개")
    console.print()

    return {"target": host, "os_ttl": os_ttl, "open_ports": open_ports}
