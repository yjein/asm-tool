AURORA = "qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #c77dff, stop:0.35 #818cf8, stop:0.7 #06b6d4, stop:1 #2dd4bf)"

DARK = """
QWidget {
    background-color: #f7f8fc;
    color: #1e293b;
    font-size: 15px;
}
QLabel { background: transparent; color: #1e293b; }

QLineEdit {
    background: #ffffff;
    border: 1.5px solid #e2e4ed;
    border-radius: 8px;
    padding: 10px 14px;
    color: #1e293b;
    font-size: 14px;
    selection-background-color: #818cf8;
}
QLineEdit:focus { border: 1.5px solid #818cf8; }
QLineEdit:hover { border-color: #c4b5fd; }

QPushButton {
    background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #c77dff, stop:0.35 #818cf8, stop:0.7 #06b6d4, stop:1 #2dd4bf);
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 22px;
    font-size: 14px;
    font-weight: 500;
}
QPushButton:hover {
    background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #d4a0ff, stop:0.35 #9ba4fb, stop:0.7 #22c8e8, stop:1 #3de8d0);
}
QPushButton:pressed {
    background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #a855f7, stop:0.35 #6366f1, stop:0.7 #0891b2, stop:1 #0d9488);
}
QPushButton:disabled { background: #e5e7ef; color: #9ca3af; }

QPushButton#secondary {
    background: #ffffff;
    color: #6366f1;
    border: 1.5px solid #c4b5fd;
}
QPushButton#secondary:hover { background: #faf5ff; border-color: #818cf8; }

QPushButton#cancel {
    background: #ffffff;
    color: #6b7280;
    border: 1.5px solid #e5e7eb;
    font-size: 14px;
}
QPushButton#cancel:hover { background: #f9fafb; color: #374151; }

QPushButton#export {
    background: #10b981;
    color: #fff;
    font-size: 14px;
}
QPushButton#export:hover { background: #059669; }

QCheckBox {
    spacing: 8px;
    color: #374151;
    font-size: 14px;
}
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1.5px solid #d1d5db;
    border-radius: 4px;
    background: #ffffff;
}
QCheckBox::indicator:checked {
    background-color: #6366f1;
    border-color: #6366f1;
    image: url(assets/icons/check_white.svg);
}
QCheckBox::indicator:hover { border-color: #818cf8; }

QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: transparent; width: 6px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #d1d5db; border-radius: 3px; min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #9ca3af; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QTableWidget {
    background: #ffffff;
    border: 1px solid #e5e7ef;
    border-radius: 10px;
    gridline-color: #f3f4f8;
    outline: 0;
    font-size: 13px;
}
QTableWidget::item {
    padding: 11px 14px;
    color: #1f2937;
    border: none;
    font-size: 14px;
}
QTableWidget::item:selected { background: #ede9fe; color: #1e293b; }
QTableWidget::item:hover    { background: #f5f3ff; }

QHeaderView::section {
    background: #f9fafb;
    color: #6b7280;
    border: none;
    border-bottom: 1px solid #e5e7ef;
    padding: 9px 14px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

QProgressBar {
    background: #e5e7ef;
    border: none;
    border-radius: 3px;
    height: 4px;
}
QProgressBar::chunk {
    background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #c77dff, stop:0.35 #818cf8, stop:0.7 #06b6d4, stop:1 #2dd4bf);
    border-radius: 3px;
}
"""

SEV_COLORS = {
    "CRITICAL": ("#dc2626", "#fef2f2"),
    "HIGH":     ("#ea580c", "#fff7ed"),
    "MEDIUM":   ("#d97706", "#fffbeb"),
    "LOW":      ("#16a34a", "#f0fdf4"),
}

LOG_COLORS = {
    "info":  "#6366f1",
    "ok":    "#10b981",
    "warn":  "#f59e0b",
    "alert": "#ef4444",
    "step":  "#9ca3af",
}
