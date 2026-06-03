import socket
from rich.console import Console

console = Console(highlight=False)

_log_callback = None

def set_log_callback(cb):
    global _log_callback
    _log_callback = cb

def _emit(level, msg):
    if _log_callback:
        _log_callback(level, msg)

def info(msg):
    _emit("info", msg)
    if not _log_callback: console.print(f"[cyan][*][/cyan] {msg}")

def ok(msg):
    _emit("ok", msg)
    if not _log_callback: console.print(f"[green][+][/green] {msg}")

def warn(msg):
    _emit("warn", msg)
    if not _log_callback: console.print(f"[yellow][-][/yellow] {msg}")

def alert(msg):
    _emit("alert", msg)
    if not _log_callback: console.print(f"[bold red][!][/bold red] {msg}")

def step(msg):
    _emit("step", msg)
    if not _log_callback: console.print(f"    [dim]->[/dim] {msg}")


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def os_from_ssh_banner(banner):
    b = banner.lower()
    if "ubuntu" in b:  return "Linux (Ubuntu)"
    if "debian" in b:  return "Linux (Debian)"
    if "centos" in b:  return "Linux (CentOS)"
    if "alpine" in b:  return "Linux (Alpine)"
    if "freebsd" in b: return "FreeBSD"
    if "windows" in b: return "Windows"
    return "Linux"


def free_port():
    for p in [1389, 4444, 9999, 8765]:
        try:
            with socket.socket() as s:
                s.bind(('', p))
                return p
        except OSError:
            continue
    return None
