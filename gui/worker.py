import ipaddress
import json
import subprocess
import traceback
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal

BASE_DIR       = Path(__file__).parent.parent
TOOLS_DIR      = BASE_DIR / "nuclei_bin"
NUCLEI_BIN     = TOOLS_DIR / "nuclei.exe"
SUBFINDER_BIN  = TOOLS_DIR / "subfinder.exe"
NAABU_BIN      = TOOLS_DIR / "naabu.exe"
TEMPLATES      = BASE_DIR / "custom_templates"
NUCLEI_OUT     = BASE_DIR / "nuclei_result.json"
SUBDOMAINS_OUT = BASE_DIR / "subdomains.txt"
PORTS_OUT      = BASE_DIR / "ports.txt"

# portscan.py의 COMMON_PORTS와 동일한 서비스 매핑 (naabu 결과 보강용)
PORT_META = {
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


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class ScanWorker(QThread):
    log_signal              = pyqtSignal(str, str)   # (level, message)
    phase_signal            = pyqtSignal(str, str)   # (phase_id, status)
    cve_result_signal       = pyqtSignal(dict)
    port_result_signal      = pyqtSignal(dict)
    nmap_result_signal      = pyqtSignal(object)
    nuclei_result_signal    = pyqtSignal(list)
    subfinder_result_signal = pyqtSignal(list)       # 발견된 서브도메인 목록
    progress_signal         = pyqtSignal(int)
    error_signal            = pyqtSignal(str)
    finished_signal         = pyqtSignal()

    def __init__(self, host, selected_cves, do_port_scan, do_nmap,
                 do_nuclei=True, do_subfinder=True):
        super().__init__()
        self.host          = host
        self.selected_cves = selected_cves
        self.do_port_scan  = do_port_scan
        self.do_nmap       = do_nmap
        self.do_nuclei     = do_nuclei and NUCLEI_BIN.exists()
        # 도메인 입력일 때만 subfinder 실행
        self.do_subfinder  = do_subfinder and SUBFINDER_BIN.exists() and not _is_ip(host)
        self.do_naabu      = NAABU_BIN.exists()
        self._cancel       = False

    def cancel(self):
        self._cancel = True

    # ── Subfinder ────────────────────────────────────────────────────────────

    def _run_subfinder(self) -> list:
        self.log_signal.emit('info', f'[Subfinder] 서브도메인 탐색 시작: {self.host}')
        SUBDOMAINS_OUT.unlink(missing_ok=True)
        try:
            result = subprocess.run(
                [str(SUBFINDER_BIN), "-d", self.host, "-silent", "-o", str(SUBDOMAINS_OUT)],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120,
            )
        except subprocess.TimeoutExpired:
            self.log_signal.emit('warn', '[Subfinder] 타임아웃')
            return [self.host]
        except Exception as e:
            self.log_signal.emit('warn', f'[Subfinder] 실행 실패: {e}')
            return [self.host]

        hosts = []
        if SUBDOMAINS_OUT.exists() and SUBDOMAINS_OUT.stat().st_size > 0:
            hosts = [l.strip() for l in SUBDOMAINS_OUT.read_text().splitlines() if l.strip()]

        if hosts:
            self.log_signal.emit('info', f'[Subfinder] {len(hosts)}개 서브도메인 발견')
        else:
            self.log_signal.emit('info', f'[Subfinder] 서브도메인 없음 — {self.host} 직접 사용')
            hosts = [self.host]

        self.subfinder_result_signal.emit(hosts)
        return hosts

    # ── Naabu ─────────────────────────────────────────────────────────────────

    def _run_naabu(self, hosts: list) -> dict:
        self.log_signal.emit('info', f'[Naabu] 포트 스캔 시작 ({len(hosts)}개 호스트)')
        PORTS_OUT.unlink(missing_ok=True)

        cmd = [str(NAABU_BIN), "-json", "-silent", "-o", str(PORTS_OUT)]
        for h in hosts:
            cmd += ["-host", h]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
        except subprocess.TimeoutExpired:
            self.log_signal.emit('warn', '[Naabu] 타임아웃')
            return {"target": self.host, "os_ttl": "", "open_ports": []}
        except Exception as e:
            self.log_signal.emit('warn', f'[Naabu] 실행 실패: {e}')
            return {"target": self.host, "os_ttl": "", "open_ports": []}

        if result.returncode not in (0, 1):
            self.log_signal.emit('warn', f'[Naabu] 비정상 종료 (code={result.returncode})')

        open_ports = []
        if PORTS_OUT.exists() and PORTS_OUT.stat().st_size > 0:
            for line in PORTS_OUT.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    open_ports.append({
                        "port":     int(entry.get("port", 0)),
                        "protocol": entry.get("protocol", "tcp"),
                    })
                except (json.JSONDecodeError, ValueError):
                    pass

        open_ports.sort(key=lambda x: x["port"])
        self.log_signal.emit('info', f'[Naabu] {len(open_ports)}개 포트 발견')
        return {"target": self.host, "open_ports": open_ports}

    # ── Nuclei ────────────────────────────────────────────────────────────────

    def _nuclei_run(self, cmd, label):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        except subprocess.TimeoutExpired:
            self.log_signal.emit('warn', f'[Nuclei/{label}] 타임아웃 (120s 초과)')
            return
        except Exception as e:
            self.log_signal.emit('warn', f'[Nuclei/{label}] 실행 실패: {e}')
            return

        rc = result.returncode
        if rc not in (0, 1):
            self.log_signal.emit('warn', f'[Nuclei/{label}] 비정상 종료 (code={rc}): {result.stderr.strip()[:300]}')
        else:
            self.log_signal.emit('info', f'[Nuclei/{label}] 완료 (code={rc})')

    def _run_nuclei(self):
        self.log_signal.emit('info', 'Nuclei 스캔 시작')

        # 각 실행마다 별도 파일 → 마지막에 합산 (같은 파일 쓰면 두 번째가 덮어씀)
        out_http = BASE_DIR / "nuclei_http.json"
        out_tcp  = BASE_DIR / "nuclei_tcp.json"
        for f in (out_http, out_tcp):
            f.unlink(missing_ok=True)

        self._nuclei_run([
            str(NUCLEI_BIN), "-u", "http://127.0.0.1:8080",
            "-t", str(TEMPLATES / "CVE-2021-44228.yaml"),
            "-jsonl", "-o", str(out_http), "-silent", "-timeout", "30", "-duc",
        ], "HTTP")

        self._nuclei_run([
            str(NUCLEI_BIN),
            "-u", "127.0.0.1:4445", "-u", "127.0.0.1:2222",
            "-t", str(TEMPLATES / "CVE-2017-7494.yaml"),
            "-t", str(TEMPLATES / "CVE-2018-15473.yaml"),
            "-no-httpx",
            "-jsonl", "-o", str(out_tcp), "-silent", "-timeout", "30", "-duc",
        ], "TCP")

        # 두 파일 합산
        combined = ""
        for f in (out_http, out_tcp):
            if f.exists() and f.stat().st_size > 0:
                combined += f.read_text(encoding='utf-8', errors='replace')
        NUCLEI_OUT.write_text(combined, encoding='utf-8')

        findings = []
        file_size = NUCLEI_OUT.stat().st_size if NUCLEI_OUT.exists() else 0
        self.log_signal.emit('info', f'[Nuclei] 결과 파일 크기: {file_size}바이트')

        if file_size > 0:
            for i, line in enumerate(NUCLEI_OUT.read_text(encoding='utf-8').splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self.log_signal.emit('warn', f'[Nuclei] {i}번째 줄 JSON 파싱 실패: {e}')
        else:
            self.log_signal.emit('info', '[Nuclei] 결과 파일 없음 또는 0바이트 — 탐지된 항목 없음')

        if findings:
            for item in findings:
                cve_id     = item.get('template-id', 'unknown')
                matched_at = item.get('matched-at', '')
                severity   = item.get('info', {}).get('severity', '')
                self.log_signal.emit('alert', f'[Nuclei] {cve_id} 탐지됨  →  {matched_at}  ({severity})')
        else:
            self.log_signal.emit('info', '[Nuclei] 파싱된 탐지 결과 없음')

        return findings

    # ── 메인 실행 흐름 ─────────────────────────────────────────────────────────

    def run(self):
        from scanners import utils
        from scanners.config import TARGETS, REMEDIATION
        from scanners.detect import SCANNERS

        utils.set_log_callback(lambda lvl, msg: self.log_signal.emit(lvl, msg))

        total = (int(self.do_subfinder) + int(self.do_naabu or self.do_port_scan) +
                 int(self.do_nmap) + len(self.selected_cves) + int(self.do_nuclei))
        done = 0

        try:
            # ── 1. Subfinder (도메인일 때만) ──────────────────────────────
            hosts = [self.host]
            if self.do_subfinder and not self._cancel:
                self.phase_signal.emit('subfinder', 'running')
                hosts = self._run_subfinder()
                self.phase_signal.emit('subfinder', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            # ── 2. Naabu 포트 스캔 ────────────────────────────────────────
            if not self._cancel:
                self.phase_signal.emit('naabu', 'running')
                if self.do_naabu:
                    port_result = self._run_naabu(hosts)
                else:
                    from scanners.portscan import run_port_scan
                    port_result = run_port_scan(self.host)
                self.port_result_signal.emit(port_result)
                self.phase_signal.emit('naabu', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            # ── 3. Nmap 서비스 탐지 ───────────────────────────────────────
            if self.do_nmap and not self._cancel:
                self.phase_signal.emit('nmap', 'running')
                from scanners.nmap_scan import run_nmap_scan
                self.nmap_result_signal.emit(run_nmap_scan(self.host))
                self.phase_signal.emit('nmap', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            # ── 4. Python CVE 스캐너 ─────────────────────────────────────
            for key in self.selected_cves:
                if self._cancel:
                    break
                tgt    = TARGETS[key]
                cve_id = tgt['cve']
                self.phase_signal.emit(cve_id, 'running')

                found, extra, poc_ok, poc_msg, os_info = SCANNERS[cve_id](tgt['default'])
                self.cve_result_signal.emit({
                    'cve':         cve_id,
                    'name':        tgt['name'],
                    'severity':    tgt['severity'],
                    'url':         tgt['default'],
                    'found':       found,
                    'extra':       extra,
                    'poc_success': poc_ok,
                    'poc_msg':     poc_msg,
                    'os_info':     os_info,
                    'remediation': REMEDIATION.get(cve_id, []),
                })
                self.phase_signal.emit(cve_id, 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            # ── 5. Nuclei YAML 스캔 ───────────────────────────────────────
            if self.do_nuclei and not self._cancel:
                self.phase_signal.emit('nuclei', 'running')
                findings = self._run_nuclei()
                self.nuclei_result_signal.emit(findings)
                self.phase_signal.emit('nuclei', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

        except Exception:
            self.error_signal.emit(traceback.format_exc())
        finally:
            utils.set_log_callback(None)
            self.progress_signal.emit(100)
            self.finished_signal.emit()
