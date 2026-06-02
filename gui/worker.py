import traceback
from PyQt5.QtCore import QThread, pyqtSignal


class ScanWorker(QThread):
    log_signal        = pyqtSignal(str, str)   # (level, message)
    phase_signal      = pyqtSignal(str, str)   # (phase_id, status: running|done|skip)
    cve_result_signal = pyqtSignal(dict)
    port_result_signal = pyqtSignal(dict)
    nmap_result_signal = pyqtSignal(object)
    progress_signal   = pyqtSignal(int)        # 0~100
    error_signal      = pyqtSignal(str)
    finished_signal   = pyqtSignal()

    def __init__(self, host, selected_cves, do_port_scan, do_nmap):
        super().__init__()
        self.host          = host
        self.selected_cves = selected_cves   # list of "1","2","3"
        self.do_port_scan  = do_port_scan
        self.do_nmap       = do_nmap
        self._cancel       = False

    def cancel(self):
        self._cancel = True

    def run(self):
        from scanners import utils
        from scanners.config import TARGETS, REMEDIATION
        from scanners.detect import SCANNERS

        utils.set_log_callback(lambda lvl, msg: self.log_signal.emit(lvl, msg))

        total  = int(self.do_port_scan) + int(self.do_nmap) + len(self.selected_cves)
        done   = 0

        try:
            if self.do_port_scan and not self._cancel:
                self.phase_signal.emit('port_scan', 'running')
                from scanners.portscan import run_port_scan
                self.port_result_signal.emit(run_port_scan(self.host))
                self.phase_signal.emit('port_scan', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            if self.do_nmap and not self._cancel:
                self.phase_signal.emit('nmap', 'running')
                from scanners.nmap_scan import run_nmap_scan
                self.nmap_result_signal.emit(run_nmap_scan(self.host))
                self.phase_signal.emit('nmap', 'done')
                done += 1
                self.progress_signal.emit(int(done / total * 100))

            for key in self.selected_cves:
                if self._cancel:
                    break
                tgt    = TARGETS[key]
                cve_id = tgt['cve']
                self.phase_signal.emit(cve_id, 'running')

                default = tgt['default']
                found, extra, poc_ok, poc_msg, os_info = SCANNERS[cve_id](default)

                self.cve_result_signal.emit({
                    'cve':         cve_id,
                    'name':        tgt['name'],
                    'severity':    tgt['severity'],
                    'url':         default,
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

        except Exception:
            self.error_signal.emit(traceback.format_exc())
        finally:
            utils.set_log_callback(None)
            self.progress_signal.emit(100)
            self.finished_signal.emit()
