from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtGui import QTextCursor, QFont

LEVEL_STYLE = {
    'info':  ("#6366f1", ""),
    'ok':    ("#16a34a", "font-weight:600;"),
    'warn':  ("#d97706", ""),
    'alert': ("#dc2626", "font-weight:600;"),
    'step':  ("#6b7280", ""),
}


class LogViewer(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 12))
        self.setStyleSheet("""
            QTextEdit {
                background: #ffffff;
                border: 1px solid #e5e7ef;
                border-radius: 10px;
                padding: 14px 16px;
                color: #1f2937;
            }
            QScrollBar:vertical { background: transparent; width: 6px; }
            QScrollBar::handle:vertical { background: #d1d5db; border-radius: 3px; }
        """)

    def append_log(self, level: str, msg: str):
        color, weight = LEVEL_STYLE.get(level, ("#374151", ""))
        html = (
            f'<span style="color:{color};{weight}'
            f'font-family:Consolas;font-size:13px;">'
            f'{msg}</span><br>'
        )
        self.moveCursor(QTextCursor.End)
        self.insertHtml(html)
        self.moveCursor(QTextCursor.End)

    def clear_log(self):
        self.clear()
