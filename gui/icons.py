from pathlib import Path
from PyQt5.QtGui import QPixmap, QColor, QPainter
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtCore import Qt

ICONS_DIR = Path(__file__).parent.parent / "assets" / "icons"


def load_icon(name: str, color: str = "#94a3b8", size: int = 16) -> QPixmap:
    path = str(ICONS_DIR / f"{name}.svg")
    renderer = QSvgRenderer(path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return pixmap


# 상태별 아이콘 프리셋
def icon_check(size=16):     return load_icon("check_circle",   "#10b981", size)
def icon_x(size=16):         return load_icon("x_circle",       "#ef4444", size)
def icon_loader(size=16):    return load_icon("loader",          "#6366f1", size)
def icon_minus(size=16):     return load_icon("minus_circle",   "#6b7280", size)
def icon_shield(size=16):    return load_icon("shield",          "#94a3b8", size)
def icon_alert(size=16):     return load_icon("shield_alert",   "#ef4444", size)
def icon_activity(size=16):  return load_icon("activity",        "#6366f1", size)
def icon_terminal(size=16):  return load_icon("terminal",        "#94a3b8", size)
def icon_network(size=16):   return load_icon("network",         "#94a3b8", size)
def icon_scan(size=16):      return load_icon("scan",            "#94a3b8", size)
def icon_warn(size=16):      return load_icon("alert_triangle",  "#f59e0b", size)
