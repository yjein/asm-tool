import socket
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QCheckBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from scanners.config import TARGETS
from gui.style import AURORA


class StartScreen(QWidget):
    scan_requested = pyqtSignal(str, list, bool, bool)

    def __init__(self, parent=None):
        super().__init__(parent)
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
        lay.setContentsMargins(56, 44, 56, 44)
        lay.setSpacing(26)

        # ── 타이틀 ──────────────────────────────────────
        title = QLabel("ASM Scanner")
        title.setStyleSheet("font-size:28px; font-weight:700; color:#111827; letter-spacing:-0.5px;")
        sub = QLabel("Attack Surface Management")
        sub.setStyleSheet("font-size:15px; font-weight:400; color:#6b7280;")
        lay.addWidget(title)
        lay.addWidget(sub)

        lay.addWidget(self._divider())

        # ── 대상 입력 ──────────────────────────────────────
        lay.addWidget(self._section("대상"))
        target_row = QHBoxLayout()
        target_row.setSpacing(10)
        self.host_input = QLineEdit("localhost")
        self.host_input.setPlaceholderText("IP 또는 도메인")
        self.host_input.setFixedHeight(44)
        self.host_input.setStyleSheet(
            "font-size:16px; color:#111827; background:#ffffff;"
            "border:1.5px solid #e2e4ed; border-radius:8px; padding:0 14px;"
        )
        validate_btn = QPushButton("연결 확인")
        validate_btn.setObjectName("secondary")
        validate_btn.setFixedSize(100, 44)
        validate_btn.clicked.connect(self._validate)
        self.validate_lbl = QLabel()
        self.validate_lbl.setStyleSheet("font-size:14px; color:#9ca3af;")
        target_row.addWidget(self.host_input)
        target_row.addWidget(validate_btn)
        target_row.addWidget(self.validate_lbl)
        lay.addLayout(target_row)

        # ── 스캔 옵션 ──────────────────────────────────────
        lay.addWidget(self._section("스캔 옵션"))
        opts = QHBoxLayout()
        opts.setSpacing(24)
        self.chk_port = self._chk("포트 스캔  +  OS 추정")
        self.chk_nmap = self._chk("Nmap 서비스 탐지")
        self.chk_port.setChecked(True)
        self.chk_nmap.setChecked(True)
        opts.addWidget(self.chk_port)
        opts.addWidget(self.chk_nmap)
        opts.addStretch()
        lay.addLayout(opts)

        # ── CVE 선택 ──────────────────────────────────────
        lay.addWidget(self._section("CVE 선택"))
        self.cve_checks = {}
        for key, tgt in TARGETS.items():
            row = QHBoxLayout()
            row.setSpacing(14)
            chk = QCheckBox()
            chk.setChecked(True)
            chk.setFixedSize(20, 20)
            self.cve_checks[key] = chk

            cve_lbl = QLabel(tgt['cve'])
            cve_lbl.setStyleSheet(
                "font-size:15px; font-weight:700; color:#111827; min-width:170px;"
                "font-family:'Consolas','D2Coding',monospace;"
            )
            name_lbl = QLabel(tgt['name'])
            name_lbl.setStyleSheet("font-size:14px; font-weight:500; color:#374151;")

            row.addWidget(chk)
            row.addWidget(cve_lbl)
            row.addWidget(name_lbl)
            row.addStretch()
            lay.addLayout(row)

        lay.addStretch()

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.start_btn = QPushButton("스캔 시작")
        self.start_btn.setFixedSize(160, 46)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #818cf8, stop:1 #3b82f6);
                color:#ffffff; border:none; border-radius:8px;
                font-size:15px; font-weight:600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #9ba4fb, stop:1 #60a5fa);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #6366f1, stop:1 #2563eb);
            }
        """)
        self.start_btn.clicked.connect(self._on_start)
        btn_row.addWidget(self.start_btn)
        lay.addLayout(btn_row)

        root.addWidget(body)

    def _section(self, text):
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size:13px; font-weight:700; color:#374151;")
        return lbl

    def _divider(self):
        f = QFrame()
        f.setFrameShape(QFrame.HLine)
        f.setStyleSheet("background:#e5e7ef; border:none;")
        f.setFixedHeight(1)
        return f

    def _chk(self, text):
        c = QCheckBox(text)
        c.setStyleSheet("font-size:15px; font-weight:600; color:#111827; spacing:10px;")
        return c

    def _validate(self):
        host = self.host_input.text().strip()
        for port in [8080, 2222, 4445, 22, 80]:
            try:
                socket.create_connection((host, port), timeout=2).close()
                self.validate_lbl.setText(f"연결됨  (:{port})")
                self.validate_lbl.setStyleSheet("font-size:14px; color:#16a34a; font-weight:500;")
                return
            except Exception:
                continue
        self.validate_lbl.setText("응답 없음")
        self.validate_lbl.setStyleSheet("font-size:14px; color:#d97706;")

    def _on_start(self):
        host     = self.host_input.text().strip() or "localhost"
        selected = [k for k, c in self.cve_checks.items() if c.isChecked()]
        if not selected:
            return
        self.scan_requested.emit(host, selected, self.chk_port.isChecked(), self.chk_nmap.isChecked())
