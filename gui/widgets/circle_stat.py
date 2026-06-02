from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QPainter, QPen, QColor, QFont


class DonutRing(QWidget):
    """분할 도넛 링: highlighted 비율만큼 color_hi, 나머지 color_lo"""

    def __init__(self, value: str, highlighted: int, total: int,
                 color_hi: str, color_lo: str, neutral: bool = False, parent=None):
        super().__init__(parent)
        self.value = value
        self.highlighted = max(0, min(highlighted, total))
        self.total = max(1, total)
        self.color_hi = QColor(color_hi)
        self.color_lo = QColor(color_lo)
        self.neutral = neutral
        self.setFixedSize(76, 76)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        margin = 6
        rect = QRect(margin, margin, self.width() - margin * 2, self.height() - margin * 2)
        pen_width = 7

        if self.neutral:
            pen = QPen(QColor("#d1d5db"), pen_width)
            pen.setCapStyle(Qt.FlatCap)
            p.setPen(pen)
            p.drawArc(rect, 0, 360 * 16)
        else:
            ratio = self.highlighted / self.total
            hi_span  = int(ratio * 360 * 16)
            lo_span  = 360 * 16 - hi_span
            start    = 90 * 16  # 12시 방향 시작

            # 비강조 부분 (초록 또는 회색)
            if lo_span > 0:
                pen = QPen(self.color_lo, pen_width)
                pen.setCapStyle(Qt.FlatCap)
                p.setPen(pen)
                p.drawArc(rect, start - hi_span, -lo_span)

            # 강조 부분 (빨강)
            if hi_span > 0:
                pen = QPen(self.color_hi, pen_width)
                pen.setCapStyle(Qt.FlatCap)
                p.setPen(pen)
                p.drawArc(rect, start, -hi_span)

        # 중앙 숫자
        p.setPen(QColor("#1e293b"))
        f = QFont("Pretendard", 18)
        f.setWeight(QFont.Bold)
        p.setFont(f)
        p.drawText(rect, Qt.AlignCenter, self.value)
        p.end()


class CircleStat(QWidget):
    def __init__(self, value: str, label: str,
                 highlighted: int = 0, total: int = 0,
                 color_hi: str = "#ef4444", color_lo: str = "#10b981",
                 neutral: bool = False,
                 parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        lay.setAlignment(Qt.AlignCenter)

        ring = DonutRing(value, highlighted, total, color_hi, color_lo, neutral)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("font-size:13px; font-weight:500; color:#475569;")

        lay.addWidget(ring, 0, Qt.AlignCenter)
        lay.addWidget(lbl, 0, Qt.AlignCenter)
