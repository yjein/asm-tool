from PyQt5.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget
)
from PyQt5.QtCore import Qt
from gui.style import SEV_COLORS
from gui.widgets.severity_badge import SeverityBadge
from scanners.config import CVE_DESCRIPTIONS



class CveResultCard(QFrame):
    def __init__(self, result: dict, parent=None):
        super().__init__(parent)
        cve         = result['cve']
        name        = result['name']
        severity    = result['severity']
        found       = result['found']
        extra       = result.get('extra', '')
        poc_ok      = result.get('poc_success', False)
        poc_msg     = result.get('poc_msg', '')
        os_info     = result.get('os_info', '')
        remediation = result.get('remediation', [])

        self.setStyleSheet("QFrame { background: #ffffff; border: none; border-radius: 8px; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(10)

        # ── 헤더 (CVE ID + 이름 + 배지 + 상태) ──────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(10)

        cve_lbl = QLabel(cve)
        cve_lbl.setStyleSheet(
            "font-size:15px; font-weight:700; color:#1e293b;"
            "font-family:'Consolas','D2Coding',monospace;"
        )
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet("font-size:14px; font-weight:500; color:#475569;")

        badge = SeverityBadge(severity)
        dot_color = "#ef4444" if found else "#16a34a"
        status_lbl = QLabel("탐지됨" if found else "안전")
        status_lbl.setStyleSheet(f"color:{dot_color}; font-size:14px; font-weight:600;")

        header.addWidget(cve_lbl)
        header.addSpacing(8)
        header.addWidget(name_lbl)
        header.addSpacing(6)
        header.addWidget(badge)
        header.addStretch()
        header.addWidget(status_lbl)
        root.addLayout(header)

        # ── CVE 설명 (CVE 넘버 바로 아래) ──────────────────────────────────────
        desc = CVE_DESCRIPTIONS.get(cve, "")
        if desc:
            desc_lbl = QLabel(desc)
            desc_lbl.setStyleSheet("font-size:13px; font-weight:400; color:#475569;")
            desc_lbl.setWordWrap(True)
            root.addWidget(desc_lbl)

        # ── 구분선 ──────────────────────────────────────
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background:#f1f5f9; border:none; max-height:1px;")
        line.setFixedHeight(1)
        root.addWidget(line)

        # ── 상세 행 ──────────────────────────────────────
        def row(label, value, val_color="#1e293b"):
            h = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(150)
            lbl.setStyleSheet("color:#64748b; font-size:13px; font-weight:500;")
            val = QLabel(value or "없음")
            val.setStyleSheet(f"color:{val_color}; font-size:14px; font-weight:500;")
            val.setWordWrap(True)
            h.addWidget(lbl)
            h.addWidget(val, 1)
            return h

        p1_text = extra if extra else ("위험 버전 감지됨" if found else "위험 요소 없음")
        root.addLayout(row("버전 탐지", p1_text, "#ef4444" if found else "#16a34a"))

        poc_text = poc_msg if poc_msg else "추가 확인 필요"
        root.addLayout(row("취약점 검증", poc_text, "#6366f1" if poc_ok else "#94a3b8"))

        if os_info:
            root.addLayout(row("OS 추정", os_info, "#475569"))

        # ── 조치 방법 ──────────────────────────────────────
        if found and remediation:
            toggle_btn = QPushButton("조치 방법 보기")
            toggle_btn.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    color: #6366f1;
                    border: none;
                    text-align: left;
                    font-size: 14px;
                    font-weight: 500;
                    padding: 4px 0;
                }
                QPushButton:hover { color: #4f46e5; }
            """)

            rem_widget = QWidget()
            rem_widget.setStyleSheet("background:#f5f3ff; border-radius:6px;")
            rem_layout = QVBoxLayout(rem_widget)
            rem_layout.setContentsMargins(14, 10, 14, 10)
            rem_layout.setSpacing(6)
            for item in remediation:
                lbl = QLabel(item)
                lbl.setStyleSheet("color:#334155; font-size:13px; background:transparent;")
                lbl.setWordWrap(True)
                rem_layout.addWidget(lbl)
            rem_widget.setVisible(False)

            def toggle():
                vis = not rem_widget.isVisible()
                rem_widget.setVisible(vis)
                toggle_btn.setText("조치 방법 접기" if vis else "조치 방법 보기")

            toggle_btn.clicked.connect(toggle)
            root.addWidget(toggle_btn)
            root.addWidget(rem_widget)
