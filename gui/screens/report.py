from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal
from gui.widgets.cve_card import CveResultCard
from gui.widgets.port_table import PortTable, NmapTable
from gui.widgets.circle_stat import CircleStat
from gui.style import AURORA


def _table_box(table_widget) -> QFrame:
    box = QFrame()
    box.setStyleSheet("""
        QFrame {
            background: #ffffff;
            border-radius: 8px;
        }
    """)
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.addWidget(table_widget)
    return box


class ReportScreen(QWidget):
    new_scan_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cve_results = []
        self._port_result = None
        self._nmap_result = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        aurora_bar = QFrame()
        aurora_bar.setFixedHeight(4)
        aurora_bar.setStyleSheet(f"background: {AURORA}; border:none;")
        root.addWidget(aurora_bar)

        header = QFrame()
        header.setStyleSheet("background:#ffffff; border-bottom:1px solid #e5e7ef;")
        header.setFixedHeight(58)
        h = QHBoxLayout(header)
        h.setContentsMargins(56, 0, 56, 0)

        self.header_title = QLabel("진단 결과")
        self.header_title.setStyleSheet("font-size:16px; font-weight:700; color:#1e293b;")
        self.header_meta = QLabel()
        self.header_meta.setStyleSheet("font-size:13px; color:#64748b;")
        export_btn = QPushButton("HTML 저장")
        export_btn.setObjectName("export")
        export_btn.setFixedWidth(100)
        export_btn.clicked.connect(self._export)

        h.addWidget(self.header_title)
        h.addSpacing(12)
        h.addWidget(self.header_meta)
        h.addStretch()
        h.addWidget(export_btn)
        root.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border:none; background:#f7f8fc;")
        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(56, 36, 56, 56)
        self.body_layout.setSpacing(24)
        scroll.setWidget(self.body)
        root.addWidget(scroll, 1)

    def add_cve_result(self, r):   self._cve_results.append(r)
    def set_port_result(self, r):  self._port_result = r
    def set_nmap_result(self, r):  self._nmap_result = r

    def render(self, host: str):
        self._clear_body()
        now = datetime.now().strftime("%Y-%m-%d  %H:%M")
        self.header_meta.setText(f"{host}  ·  {now}")

        total    = len(self._cve_results)
        detected = sum(1 for r in self._cve_results if r['found'])
        verified = sum(1 for r in self._cve_results if r.get('poc_success'))
        safe     = total - detected

        # ── 원형 통계 ──────────────────────────────────────
        stat_row = QHBoxLayout()
        stat_row.setSpacing(0)
        stat_row.addStretch()

        # CVE 탐지: 빨강(탐지됨) / 초록(안전) 분할
        stat_row.addWidget(CircleStat(
            str(total), "CVE 탐지",
            highlighted=detected, total=total,
            color_hi="#ef4444", color_lo="#10b981",
        ))
        stat_row.addSpacing(52)

        # 취약점 검증: 인디고(검증됨) / 회색(미검증) 분할
        stat_row.addWidget(CircleStat(
            str(verified), "취약점 검증",
            highlighted=verified, total=total,
            color_hi="#6366f1", color_lo="#e2e8f0",
        ))

        if self._port_result:
            cnt = len(self._port_result.get('open_ports', []))
            stat_row.addSpacing(52)
            stat_row.addWidget(CircleStat(
                str(cnt), "열린 포트",
                highlighted=0, total=1,
                neutral=True,
            ))

        stat_row.addStretch()
        self.body_layout.addLayout(stat_row)

        # OS 추정
        if self._port_result and self._port_result.get('os_ttl'):
            os_lbl = QLabel(f"OS  {self._port_result['os_ttl']}")
            os_lbl.setStyleSheet("font-size:13px; color:#64748b;")
            os_lbl.setAlignment(Qt.AlignCenter)
            self.body_layout.addWidget(os_lbl)

        # ── CVE 탐지 결과 ──────────────────────────────────────
        self.body_layout.addWidget(self._section("CVE 탐지 결과"))
        for r in self._cve_results:
            self.body_layout.addWidget(CveResultCard(r))

        # ── 포트 스캔 (원형 통계 바로 아래) ──────────────────────────────────────
        if self._port_result and self._port_result.get('open_ports'):
            ports = self._port_result['open_ports']
            self.body_layout.addWidget(self._section(f"포트 스캔  ({len(ports)}개 열림)"))
            tbl = PortTable()
            tbl.load(ports)
            tbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            tbl.setFixedHeight(48 + 40 * len(ports))
            self.body_layout.addWidget(_table_box(tbl))

        # ── Nmap ──────────────────────────────────────
        if self._nmap_result:
            open_r = [r for r in self._nmap_result if r.get('state') == 'open']
            if open_r:
                self.body_layout.addWidget(self._section(f"Nmap 서비스 탐지  ({len(open_r)}개)"))
                tbl = NmapTable()
                tbl.load(self._nmap_result)
                tbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                tbl.setFixedHeight(48 + 40 * len(open_r))
                self.body_layout.addWidget(_table_box(tbl))

        self.body_layout.addStretch()
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        new_btn = QPushButton("새 스캔")
        new_btn.setObjectName("secondary")
        new_btn.setFixedSize(120, 42)
        new_btn.clicked.connect(self.new_scan_requested.emit)
        btn_row.addWidget(new_btn)
        self.body_layout.addLayout(btn_row)

    def _section(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size:15px; font-weight:700; color:#1e293b;")
        return lbl

    def _clear_body(self):
        while self.body_layout.count():
            item = self.body_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def reset(self):
        self._cve_results = []
        self._port_result = None
        self._nmap_result = None

    def _export(self):
        try:
            import report_html, subprocess
            path = report_html.generate()
            subprocess.Popen(f'explorer "{path}"', shell=True)
        except Exception as e:
            print(f"HTML 저장 실패: {e}")
