from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt
from gui.style import SEV_COLORS


class SeverityBadge(QLabel):
    def __init__(self, severity: str, parent=None):
        super().__init__(severity, parent)
        fg, bg = SEV_COLORS.get(severity, ("#6b7280", "#f3f4f6"))
        self.setStyleSheet(f"""
            QLabel {{
                color: {fg};
                background: {bg};
                border-radius: 5px;
                padding: 3px 10px;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.04em;
            }}
        """)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(24)
