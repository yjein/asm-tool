import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont, QFontDatabase
from gui.app import MainWindow

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FONTS_DIR = Path(__file__).parent / "assets" / "fonts"


def load_fonts():
    for weight in ["Regular", "Medium", "SemiBold", "Bold"]:
        QFontDatabase.addApplicationFont(str(FONTS_DIR / f"Pretendard-{weight}.otf"))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("ASM Scanner")

    load_fonts()

    # 폰트 로드 후 적용 — pt 단위로 DPI 대응
    font = QFont("Pretendard", 11)   # 11pt ≈ 14~15px at 96DPI, 더 크게 보임
    font.setWeight(QFont.Normal)
    font.setStyleStrategy(QFont.PreferAntialias | QFont.PreferQuality)
    app.setFont(font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
