from PyQt5.QtWidgets import QMainWindow, QStackedWidget
from PyQt5.QtCore import Qt
from gui.style import DARK
from gui.screens.start import StartScreen
from gui.screens.scanning import ScanningScreen
from gui.screens.report import ReportScreen
from gui.worker import ScanWorker

SCREEN_START   = 0
SCREEN_SCAN    = 1
SCREEN_REPORT  = 2


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ASM Scanner")
        self.resize(900, 700)
        self.setStyleSheet(DARK)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.start_screen   = StartScreen()
        self.scan_screen    = ScanningScreen()
        self.report_screen  = ReportScreen()

        self.stack.addWidget(self.start_screen)
        self.stack.addWidget(self.scan_screen)
        self.stack.addWidget(self.report_screen)

        self._worker = None
        self._connect_signals()

    def _connect_signals(self):
        self.start_screen.scan_requested.connect(self._start_scan)
        self.scan_screen.cancel_requested.connect(self._cancel_scan)
        self.report_screen.new_scan_requested.connect(self._go_start)

    def _start_scan(self, host, selected_cves, do_port, do_nmap):
        self.report_screen.reset()

        phases = []
        if do_port: phases.append('port_scan')
        if do_nmap: phases.append('nmap')
        phases += [{'1':'CVE-2021-44228','2':'CVE-2017-7494','3':'CVE-2018-15473'}[k]
                   for k in selected_cves]

        self.scan_screen.setup(host, phases)
        self.stack.setCurrentIndex(SCREEN_SCAN)

        self._worker = ScanWorker(host, selected_cves, do_port, do_nmap)
        self._worker.log_signal.connect(self.scan_screen.append_log)
        self._worker.phase_signal.connect(self.scan_screen.set_phase)
        self._worker.progress_signal.connect(self.scan_screen.set_progress)
        self._worker.cve_result_signal.connect(self.report_screen.add_cve_result)
        self._worker.port_result_signal.connect(self.report_screen.set_port_result)
        self._worker.nmap_result_signal.connect(self.report_screen.set_nmap_result)
        self._worker.finished_signal.connect(lambda: self._on_finished(host))
        self._worker.error_signal.connect(
            lambda e: self.scan_screen.append_log('alert', f'오류: {e[:120]}')
        )
        self._worker.start()

    def _on_finished(self, host):
        self.report_screen.render(host)
        self.stack.setCurrentIndex(SCREEN_REPORT)

    def _cancel_scan(self):
        if self._worker:
            self._worker.cancel()

    def _go_start(self):
        self.stack.setCurrentIndex(SCREEN_START)
