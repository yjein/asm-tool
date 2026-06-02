from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QProgressBar, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QPixmap
from gui.widgets.log_viewer import LogViewer
from gui.icons import icon_check, icon_loader, icon_minus
from gui.style import AURORA

PHASE_LABELS = {
    'port_scan':       '포트 스캔',
    'nmap':            'Nmap',
    'CVE-2021-44228':  'Log4Shell',
    'CVE-2017-7494':   'SambaCry',
    'CVE-2018-15473':  'SSH Enum',
}


class PhaseIndicator(QWidget):
    def __init__(self, phase_id: str, label: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignCenter)

        self.icon_lbl = QLabel()
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        self.icon_lbl.setFixedSize(20, 20)
        self.icon_lbl.setPixmap(icon_minus(16))

        name_lbl = QLabel(label)
        name_lbl.setAlignment(Qt.AlignCenter)
        name_lbl.setStyleSheet("font-size:13px; font-weight:500; color:#6b7280;")

        layout.addWidget(self.icon_lbl, 0, Qt.AlignCenter)
        layout.addWidget(name_lbl, 0, Qt.AlignCenter)

    def set_status(self, status: str):
        if status == 'done':      self.icon_lbl.setPixmap(icon_check(16))
        elif status == 'running': self.icon_lbl.setPixmap(icon_loader(16))
        else:                     self.icon_lbl.setPixmap(icon_minus(16))


class ScanningScreen(QWidget):
    cancel_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phases: dict = {}
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        aurora_bar = QFrame()
        aurora_bar.setFixedHeight(4)
        aurora_bar.setStyleSheet(f"background: {AURORA}; border:none;")
        root.addWidget(aurora_bar)

        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(56, 40, 56, 40)
        lay.setSpacing(20)

        self.title_lbl = QLabel("스캔 중")
        self.title_lbl.setStyleSheet(
            "font-size:24px; font-weight:700; color:#111827;"
        )

        self.target_lbl = QLabel()
        self.target_lbl.setStyleSheet(
            "font-size:15px; font-weight:600; color:#111827;"
        )

        lay.addWidget(self.title_lbl)
        lay.addWidget(self.target_lbl)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        lay.addWidget(self.progress)

        phase_frame = QFrame()
        phase_frame.setStyleSheet("""
            QFrame {
                background: #ffffff;
                border: none;
                border-radius: 10px;
            }
        """)
        phase_layout = QHBoxLayout(phase_frame)
        phase_layout.setContentsMargins(24, 16, 24, 16)
        phase_layout.setSpacing(0)

        for ph in ['port_scan', 'nmap', 'CVE-2021-44228', 'CVE-2017-7494', 'CVE-2018-15473']:
            ind = PhaseIndicator(ph, PHASE_LABELS.get(ph, ph))
            self._phases[ph] = ind
            phase_layout.addWidget(ind, 1)

        lay.addWidget(phase_frame)

        log_lbl = QLabel("실시간 로그")
        log_lbl.setStyleSheet("font-size:13px; font-weight:700; color:#374151;")
        lay.addWidget(log_lbl)

        self.log_viewer = LogViewer()
        lay.addWidget(self.log_viewer, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("중단")
        cancel_btn.setObjectName("cancel")
        cancel_btn.setFixedWidth(90)
        cancel_btn.clicked.connect(self.cancel_requested.emit)
        btn_row.addWidget(cancel_btn)
        lay.addLayout(btn_row)

        root.addWidget(body)

    def setup(self, host: str, phases: list):
        self.target_lbl.setText(host)
        self.progress.setValue(0)
        self.log_viewer.clear_log()
        for ph, ind in self._phases.items():
            ind.set_status('pending' if ph in phases else 'skip')

    def set_phase(self, phase_id: str, status: str):
        if phase_id in self._phases:
            self._phases[phase_id].set_status(status)

    def set_progress(self, val: int):
        anim = QPropertyAnimation(self.progress, b"value")
        anim.setDuration(400)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.setStartValue(self.progress.value())
        anim.setEndValue(val)
        anim.start()
        self._anim = anim  # GC 방지

    def append_log(self, level: str, msg: str):
        self.log_viewer.append_log(level, msg)
