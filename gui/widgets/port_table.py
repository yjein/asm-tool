from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from gui.style import SEV_COLORS

RISK_COL = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a"}


class PortTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["포트", "서비스", "위험도", "배너"])
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.horizontalHeader().resizeSection(0, 70)
        self.horizontalHeader().resizeSection(1, 110)
        self.horizontalHeader().resizeSection(2, 90)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.verticalHeader().setVisible(False)

    def load(self, open_ports: list):
        self.setRowCount(len(open_ports))
        for i, p in enumerate(open_ports):
            risk  = p.get('risk', '')
            color = RISK_COL.get(risk, "#e2e8f0")
            items = [
                str(p.get('port', '')),
                p.get('service', ''),
                risk,
                p.get('banner', '—'),
            ]
            for j, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if j == 2:
                    item.setForeground(QColor(color))
                self.setItem(i, j, item)
        self.resizeRowsToContents()


class NmapTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["포트", "서비스", "버전", "CVE", "심각도"])
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().resizeSection(0, 60)
        self.horizontalHeader().resizeSection(1, 100)
        self.horizontalHeader().resizeSection(3, 150)
        self.horizontalHeader().resizeSection(4, 90)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.verticalHeader().setVisible(False)

    def load(self, results: list):
        rows = [r for r in results if r.get('state') == 'open']
        self.setRowCount(len(rows))
        for i, r in enumerate(rows):
            sev   = r.get('severity', '')
            color = RISK_COL.get(sev, "#e2e8f0")
            items = [
                r.get('port', ''),
                r.get('service', ''),
                r.get('version', ''),
                r.get('cve', '—'),
                sev,
            ]
            for j, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if j == 4:
                    item.setForeground(QColor(color))
                self.setItem(i, j, item)
        self.resizeRowsToContents()
