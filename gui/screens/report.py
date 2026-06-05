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

SEV_COLORS = {
    'CRITICAL': '#ef4444', 'HIGH': '#f97316',
    'MEDIUM':   '#eab308', 'LOW':  '#22c55e', 'INFO': '#64748b',
}

TOOL_COLORS = {
    'subfinder': '#8b5cf6',
    'naabu':     '#3b82f6',
    'nmap':      '#06b6d4',
    'python':    '#6366f1',
    'nuclei':    '#ef4444',
}


def _table_box(table_widget) -> QFrame:
    box = QFrame()
    box.setStyleSheet("QFrame { background:#ffffff; border-radius:8px; }")
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.addWidget(table_widget)
    return box


def _tool_header(name: str, subtitle: str = "", color: str = "#6366f1") -> QWidget:
    w   = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(10)

    badge = QLabel(name)
    badge.setStyleSheet(
        f"font-size:12px; font-weight:700; color:#ffffff;"
        f"background:{color}; border-radius:5px; padding:3px 10px;"
    )
    badge.setFixedHeight(24)

    if subtitle:
        sub = QLabel(subtitle)
        sub.setStyleSheet("font-size:13px; color:#64748b; font-weight:500;")
        lay.addWidget(badge)
        lay.addWidget(sub)
    else:
        lay.addWidget(badge)

    lay.addStretch()
    return w


class ReportScreen(QWidget):
    new_scan_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cve_results       = []
        self._port_result       = None
        self._nmap_result       = None
        self._nuclei_results    = []
        self._subfinder_results = []
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
        self.body_layout.setContentsMargins(56, 36, 56, 36)
        self.body_layout.setSpacing(20)
        scroll.setWidget(self.body)
        root.addWidget(scroll, 1)

    # ── 데이터 수신 ───────────────────────────────────────────────────────────

    def add_cve_result(self, r):          self._cve_results.append(r)
    def set_port_result(self, r):         self._port_result = r
    def set_nmap_result(self, r):         self._nmap_result = r
    def set_nuclei_result(self, r):       self._nuclei_results = r
    def set_subfinder_result(self, r):    self._subfinder_results = r

    # ── 렌더링 ────────────────────────────────────────────────────────────────

    def render(self, host: str):
        self._clear_body()
        now = datetime.now().strftime("%Y-%m-%d  %H:%M")
        self.header_meta.setText(f"{host}  ·  {now}")

        # ── 요약 통계 (원형) ────────────────────────────────────────────────
        self._render_summary()

        # ── 도구별 섹션 (자산 식별 → 취약 버전 탐지 → 취약점 검증) ────────
        self._render_subfinder()
        self._render_naabu()
        self._render_nmap()
        self._render_nuclei()
        self._render_python_scanner()

        self.body_layout.addStretch()
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        new_btn = QPushButton("새 스캔")
        new_btn.setObjectName("secondary")
        new_btn.setFixedSize(120, 42)
        new_btn.clicked.connect(self.new_scan_requested.emit)
        btn_row.addWidget(new_btn)
        self.body_layout.addLayout(btn_row)

    # ── 섹션별 렌더러 ─────────────────────────────────────────────────────────

    def _render_summary(self):
        total    = len(self._cve_results)
        detected = sum(1 for r in self._cve_results if r['found'])
        verified = sum(1 for r in self._cve_results if r.get('poc_success'))
        n_ports  = len(self._port_result.get('open_ports', [])) if self._port_result else 0
        n_nuclei = len(self._nuclei_results)

        stat_row = QHBoxLayout()
        stat_row.setSpacing(0)
        stat_row.addStretch()
        stat_row.addWidget(CircleStat(
            str(n_ports), "공격 표면 (포트)",
            highlighted=0, total=1, neutral=True,
        ))
        stat_row.addSpacing(40)
        stat_row.addWidget(CircleStat(
            str(n_nuclei), "취약 버전 탐지",
            highlighted=n_nuclei, total=max(n_nuclei, 1),
            color_hi="#ef4444", color_lo="#e2e8f0",
        ))
        stat_row.addSpacing(40)
        stat_row.addWidget(CircleStat(
            str(verified), "취약점 검증 (PoC)",
            highlighted=verified, total=max(total, 1),
            color_hi="#6366f1", color_lo="#e2e8f0",
        ))
        stat_row.addStretch()
        self.body_layout.addLayout(stat_row)

    def _render_subfinder(self):
        if not self._subfinder_results:
            return
        hosts = self._subfinder_results
        self.body_layout.addWidget(_tool_header(
            "Subfinder", f"서브도메인 {len(hosts)}개 발견", TOOL_COLORS['subfinder']
        ))
        card = QFrame()
        card.setStyleSheet("QFrame { background:#ffffff; border-radius:8px; }")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(20, 14, 20, 14)
        lay.setSpacing(6)
        for h in hosts:
            lbl = QLabel(h)
            lbl.setStyleSheet(
                "font-size:13px; color:#374151; font-family:'Consolas','D2Coding',monospace;"
            )
            lay.addWidget(lbl)
        self.body_layout.addWidget(card)

    def _render_naabu(self):
        if not self._port_result:
            return
        ports = self._port_result.get('open_ports', [])
        self.body_layout.addWidget(_tool_header(
            "Naabu", f"열린 포트 {len(ports)}개", TOOL_COLORS['naabu']
        ))
        if not ports:
            self.body_layout.addWidget(self._empty("열린 포트 없음"))
            return

        from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        tbl = QTableWidget()
        tbl.setColumnCount(2)
        tbl.setHorizontalHeaderLabels(["포트", "프로토콜"])
        tbl.horizontalHeader().resizeSection(0, 100)
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        tbl.setRowCount(len(ports))
        for i, p in enumerate(ports):
            tbl.setItem(i, 0, QTableWidgetItem(str(p.get("port", ""))))
            tbl.setItem(i, 1, QTableWidgetItem(p.get("protocol", "tcp").upper()))
        tbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        tbl.setFixedHeight(48 + 36 * len(ports))
        self.body_layout.addWidget(_table_box(tbl))

    def _render_nmap(self):
        if not self._nmap_result:
            return
        open_r   = [r for r in self._nmap_result if r.get('state') == 'open']
        vuln_r   = [r for r in open_r if r.get('version_vuln')]
        subtitle = f"서비스 탐지 {len(open_r)}개"
        if vuln_r:
            subtitle += f"  /  버전 기반 CVE {len(vuln_r)}건"
        self.body_layout.addWidget(_tool_header("Nmap", subtitle, TOOL_COLORS['nmap']))

        if open_r:
            tbl = NmapTable()
            tbl.load(self._nmap_result)
            tbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            tbl.setFixedHeight(48 + 40 * len(open_r))
            self.body_layout.addWidget(_table_box(tbl))

            # 버전으로 확인된 CVE 별도 카드
            for r in vuln_r:
                card = QFrame()
                card.setStyleSheet("QFrame { background:#fff7ed; border-radius:8px; }")
                cl = QHBoxLayout(card)
                cl.setContentsMargins(20, 12, 20, 12)
                cl.setSpacing(16)

                cve_lbl = QLabel(r.get('cve', ''))
                cve_lbl.setStyleSheet(
                    "font-size:13px; font-weight:700; color:#ffffff;"
                    f"background:{SEV_COLORS.get(r.get('severity',''), '#64748b')};"
                    "border-radius:4px; padding:2px 8px;"
                )
                ver_lbl = QLabel(f"버전  {r.get('version', '')}  →  {r.get('service', '')}:{r.get('port', '')}")
                ver_lbl.setStyleSheet(
                    "font-size:13px; color:#374151; font-family:'Consolas','D2Coding',monospace;"
                )
                cl.addWidget(cve_lbl)
                cl.addWidget(ver_lbl, 1)
                self.body_layout.addWidget(card)
        else:
            self.body_layout.addWidget(self._empty("탐지된 서비스 없음"))

    def _render_python_scanner(self):
        if not self._cve_results:
            return
        verified = sum(1 for r in self._cve_results if r.get('poc_success'))
        self.body_layout.addWidget(_tool_header(
            "취약점 검증 (PoC)", f"{verified}/{len(self._cve_results)}개 검증됨", TOOL_COLORS['python']
        ))
        for r in self._cve_results:
            self.body_layout.addWidget(CveResultCard(r))

    def _render_nuclei(self):
        if not self._nuclei_results:
            return
        self.body_layout.addWidget(_tool_header(
            "Nuclei", f"취약 버전 탐지 {len(self._nuclei_results)}건", TOOL_COLORS['nuclei']
        ))

        for item in self._nuclei_results:
            info        = item.get('info', {})
            cve_id      = item.get('template-id', 'unknown')
            name        = info.get('name', cve_id)
            severity    = info.get('severity', '').upper()
            matched_at  = item.get('matched-at', '')
            description = info.get('description', '').strip()
            references  = info.get('reference', [])
            proto_type  = item.get('type', '').upper()
            timestamp   = item.get('timestamp', '')[:19].replace('T', '  ') if item.get('timestamp') else ''
            matcher     = item.get('matcher-name', '')
            extracted   = item.get('extracted-results', [])
            curl_cmd    = item.get('curl-command', '')
            request     = item.get('request', '')
            response    = item.get('response', '')

            color = SEV_COLORS.get(severity, '#64748b')

            card = QFrame()
            card.setStyleSheet("QFrame { background:#ffffff; border-radius:10px; }")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(24, 18, 24, 18)
            cl.setSpacing(10)

            # 헤더
            hdr = QHBoxLayout()
            sev_lbl = QLabel(severity or 'N/A')
            sev_lbl.setFixedWidth(76)
            sev_lbl.setAlignment(Qt.AlignCenter)
            sev_lbl.setStyleSheet(
                f"font-size:12px; font-weight:700; color:#ffffff;"
                f"background:{color}; border-radius:4px; padding:2px 6px;"
            )
            name_lbl = QLabel(f"<b>{cve_id}</b>  {name}")
            name_lbl.setStyleSheet("font-size:14px; color:#111827;")
            proto_lbl = QLabel(proto_type)
            proto_lbl.setStyleSheet("font-size:11px; color:#6b7280; font-weight:600;")
            ts_lbl = QLabel(timestamp)
            ts_lbl.setStyleSheet("font-size:12px; color:#9ca3af;")
            hdr.addWidget(sev_lbl)
            hdr.addSpacing(10)
            hdr.addWidget(name_lbl, 1)
            hdr.addWidget(proto_lbl)
            hdr.addSpacing(12)
            hdr.addWidget(ts_lbl)
            cl.addLayout(hdr)

            def _mono(text, label=""):
                w = QLabel(f"<b>{label}</b>  {text}" if label else text)
                w.setStyleSheet(
                    "font-size:12px; color:#374151; font-family:'Consolas','D2Coding',monospace;"
                )
                w.setWordWrap(True)
                return w

            def _dim(text):
                w = QLabel(text)
                w.setStyleSheet("font-size:12px; color:#6b7280;")
                w.setWordWrap(True)
                return w

            cl.addWidget(_mono(matched_at, "탐지 위치"))

            if description:
                cl.addWidget(_dim(description))
            if references:
                refs = "  |  ".join(references) if isinstance(references, list) else str(references)
                cl.addWidget(_mono(refs, "참조"))
            if matcher:
                cl.addWidget(_mono(matcher, "매처"))
            if extracted:
                cl.addWidget(_mono(", ".join(extracted), "추출값"))
            if curl_cmd:
                cl.addWidget(_mono(curl_cmd, "curl"))

            for lbl_txt, raw in [("요청", request), ("응답", response)]:
                if raw:
                    lines   = raw.strip().splitlines()
                    preview = "\n".join(lines[:10]) + ("\n…" if len(lines) > 10 else "")
                    w = QLabel(f"<b>{lbl_txt}</b>\n{preview}")
                    w.setStyleSheet(
                        "font-size:11px; color:#374151; font-family:'Consolas','D2Coding',monospace;"
                        "background:#f3f4f6; border-radius:6px; padding:8px;"
                    )
                    w.setWordWrap(True)
                    cl.addWidget(w)

            self.body_layout.addWidget(card)

    # ── 유틸 ──────────────────────────────────────────────────────────────────

    def _empty(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "font-size:13px; color:#9ca3af; background:#ffffff;"
            "border-radius:8px; padding:16px 20px;"
        )
        return lbl

    def _clear_body(self):
        while self.body_layout.count():
            item = self.body_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def reset(self):
        self._cve_results       = []
        self._port_result       = None
        self._nmap_result       = None
        self._nuclei_results    = []
        self._subfinder_results = []

    def _export(self):
        try:
            import report_html, subprocess
            path = report_html.generate()
            subprocess.Popen(f'explorer "{path}"', shell=True)
        except Exception as e:
            print(f"HTML 저장 실패: {e}")
