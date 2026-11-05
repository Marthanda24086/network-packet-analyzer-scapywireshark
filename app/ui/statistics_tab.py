"""
Statistics Tab Widget for NetScope.
Renders metric summaries, protocol breakdown tables, top talkers, and port distribution.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import Qt
from typing import List, Dict, Any

from app.analysis.packet_models import PacketRecord
from app.analysis.statistics import StatisticsEngine


class StatisticsTabWidget(QWidget):
    """Widget displaying detailed tabular statistical breakdowns."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        grid = QGridLayout()

        # Box 1: Protocol Distribution
        box_proto = QGroupBox("Protocol Distribution")
        lay_proto = QVBoxLayout(box_proto)
        self.tbl_proto = QTableWidget(0, 3)
        self.tbl_proto.setHorizontalHeaderLabels(["Protocol", "Packet Count", "% Total"])
        self.tbl_proto.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay_proto.addWidget(self.tbl_proto)
        grid.addWidget(box_proto, 0, 0)

        # Box 2: Transport Protocol Split
        box_trans = QGroupBox("Transport Protocol Summary")
        lay_trans = QVBoxLayout(box_trans)
        self.tbl_trans = QTableWidget(0, 2)
        self.tbl_trans.setHorizontalHeaderLabels(["Category", "Packet Count"])
        self.tbl_trans.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay_trans.addWidget(self.tbl_trans)
        grid.addWidget(box_trans, 0, 1)

        # Box 3: Top Source IP Endpoints
        box_src = QGroupBox("Top Source IP Endpoints")
        lay_src = QVBoxLayout(box_src)
        self.tbl_src = QTableWidget(0, 2)
        self.tbl_src.setHorizontalHeaderLabels(["Source IP Address", "Packet Count"])
        self.tbl_src.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay_src.addWidget(self.tbl_src)
        grid.addWidget(box_src, 1, 0)

        # Box 4: Top Destination IP Endpoints
        box_dst = QGroupBox("Top Destination IP Endpoints")
        lay_dst = QVBoxLayout(box_dst)
        self.tbl_dst = QTableWidget(0, 2)
        self.tbl_dst.setHorizontalHeaderLabels(["Destination IP Address", "Packet Count"])
        self.tbl_dst.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay_dst.addWidget(self.tbl_dst)
        grid.addWidget(box_dst, 1, 1)

        layout.addLayout(grid)

    def update_statistics(self, records: List[PacketRecord]):
        """Recalculates metrics and populates tables from records dataset."""
        stats = StatisticsEngine.calculate_summary(records)
        total_pkts = stats["total_packets"]

        # Populate Protocol Table
        self.tbl_proto.setRowCount(0)
        for proto, count in stats["protocol_counts"].items():
            row = self.tbl_proto.rowCount()
            self.tbl_proto.insertRow(row)
            pct = round((count / total_pkts) * 100, 1) if total_pkts > 0 else 0.0
            self.tbl_proto.setItem(row, 0, QTableWidgetItem(proto))
            self.tbl_proto.setItem(row, 1, QTableWidgetItem(str(count)))
            self.tbl_proto.setItem(row, 2, QTableWidgetItem(f"{pct}%"))

        # Populate Transport Table
        self.tbl_trans.setRowCount(0)
        for category, count in stats["transport_split"].items():
            row = self.tbl_trans.rowCount()
            self.tbl_trans.insertRow(row)
            self.tbl_trans.setItem(row, 0, QTableWidgetItem(category))
            self.tbl_trans.setItem(row, 1, QTableWidgetItem(str(count)))

        # Populate Top Source IPs
        self.tbl_src.setRowCount(0)
        for ip, count in stats["top_sources"]:
            row = self.tbl_src.rowCount()
            self.tbl_src.insertRow(row)
            self.tbl_src.setItem(row, 0, QTableWidgetItem(ip))
            self.tbl_src.setItem(row, 1, QTableWidgetItem(str(count)))

        # Populate Top Destination IPs
        self.tbl_dst.setRowCount(0)
        for ip, count in stats["top_destinations"]:
            row = self.tbl_dst.rowCount()
            self.tbl_dst.insertRow(row)
            self.tbl_dst.setItem(row, 0, QTableWidgetItem(ip))
            self.tbl_dst.setItem(row, 1, QTableWidgetItem(str(count)))
