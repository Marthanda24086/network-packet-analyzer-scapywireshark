"""
Live Capture Tab and Packet Table View for NetScope.
Displays live incoming packet records, supports real-time filtering,
auto-scrolling, and row selection.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox, QHeaderView,
    QAbstractItemView
)
from PySide6.QtCore import Qt, Signal
from typing import List, Optional

from app.analysis.packet_models import PacketRecord
from app.analysis.filters import FilterEngine


class CaptureTabWidget(QWidget):
    """Tab widget displaying live packet summary table and display filters."""

    packet_selected = Signal(object)  # Emits PacketRecord when user selects a row

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_records: List[PacketRecord] = []
        self._displayed_records: List[PacketRecord] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Filter Controls Bar
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("Protocol:"))
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP", "TLS", "ARP", "DHCP", "IPv4", "IPv6"])
        filter_layout.addWidget(self.combo_proto)

        filter_layout.addWidget(QLabel("IP Addr:"))
        self.txt_ip = QLineEdit()
        self.txt_ip.setPlaceholderText("e.g. 192.168.1.1")
        self.txt_ip.setMaximumWidth(140)
        filter_layout.addWidget(self.txt_ip)

        filter_layout.addWidget(QLabel("Port:"))
        self.txt_port = QLineEdit()
        self.txt_port.setPlaceholderText("e.g. 80, 443")
        self.txt_port.setMaximumWidth(80)
        filter_layout.addWidget(self.txt_port)

        filter_layout.addWidget(QLabel("Search:"))
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter info or fields...")
        filter_layout.addWidget(self.txt_search)

        btn_apply = QPushButton("Apply Filter")
        btn_apply.clicked.connect(self.apply_filter)
        filter_layout.addWidget(btn_apply)

        btn_reset = QPushButton("Reset")
        btn_reset.clicked.connect(self.reset_filter)
        filter_layout.addWidget(btn_reset)

        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        filter_layout.addWidget(self.chk_autoscroll)

        layout.addLayout(filter_layout)

        # Packet Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "No.", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)

        self.table.itemSelectionChanged.connect(self._on_row_selected)
        layout.addWidget(self.table)

        # Signal connections for live filter auto-update
        self.combo_proto.currentTextChanged.connect(self.apply_filter)
        self.txt_ip.textChanged.connect(self.apply_filter)
        self.txt_port.textChanged.connect(self.apply_filter)
        self.txt_search.textChanged.connect(self.apply_filter)

    def add_packet(self, record: PacketRecord):
        """Appends a newly captured packet to internal model and updates table if matches filter."""
        self._all_records.append(record)

        if self._matches_current_filter(record):
            self._displayed_records.append(record)
            self._append_row_to_table(record)

            if self.chk_autoscroll.isChecked():
                self.table.scrollToBottom()

    def set_records(self, records: List[PacketRecord]):
        """Sets dataset (e.g. from loaded PCAP) and refreshes table."""
        self._all_records = list(records)
        self.apply_filter()

    def clear(self):
        """Clears all records and empties table."""
        self._all_records.clear()
        self._displayed_records.clear()
        self.table.setRowCount(0)

    def apply_filter(self):
        """Evaluates current filter fields and rebuilds visible table rows."""
        proto = self.combo_proto.currentText()
        ip_str = self.txt_ip.text().strip()

        port_val = None
        if self.txt_port.text().strip().isdigit():
            port_val = int(self.txt_port.text().strip())

        search_str = self.txt_search.text().strip()

        self._displayed_records = FilterEngine.filter_packets(
            self._all_records,
            protocol=proto,
            ip_addr=ip_str,
            port=port_val,
            search_text=search_str
        )

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in self._displayed_records:
            self._append_row_to_table(rec)
        self.table.setSortingEnabled(True)

    def reset_filter(self):
        """Resets filter inputs."""
        self.combo_proto.setCurrentIndex(0)
        self.txt_ip.clear()
        self.txt_port.clear()
        self.txt_search.clear()
        self.apply_filter()

    def _matches_current_filter(self, record: PacketRecord) -> bool:
        """Helper checking if a single record passes current active filter."""
        res = FilterEngine.filter_packets(
            [record],
            protocol=self.combo_proto.currentText(),
            ip_addr=self.txt_ip.text().strip(),
            port=int(self.txt_port.text().strip()) if self.txt_port.text().strip().isdigit() else None,
            search_text=self.txt_search.text().strip()
        )
        return len(res) > 0

    def _append_row_to_table(self, record: PacketRecord):
        """Adds a row item into QTableWidget."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        item_num = QTableWidgetItem()
        item_num.setData(Qt.DisplayRole, record.packet_num)
        self.table.setItem(row, 0, item_num)

        self.table.setItem(row, 1, QTableWidgetItem(record.formatted_time))
        self.table.setItem(row, 2, QTableWidgetItem(record.src_ip))
        self.table.setItem(row, 3, QTableWidgetItem(record.dst_ip))

        proto_item = QTableWidgetItem(record.protocol)
        proto_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 4, proto_item)

        item_len = QTableWidgetItem()
        item_len.setData(Qt.DisplayRole, record.length)
        self.table.setItem(row, 5, item_len)

        self.table.setItem(row, 6, QTableWidgetItem(record.info))

    def _on_row_selected(self):
        """Dispatches selected record when user clicks table row."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            self.packet_selected.emit(None)
            return

        row_idx = selected_rows[0].row()
        item_num = self.table.item(row_idx, 0)
        if not item_num:
            return

        pkt_num = item_num.data(Qt.DisplayRole)
        # Find matching record by packet_num
        record = next((r for r in self._all_records if r.packet_num == pkt_num), None)
        self.packet_selected.emit(record)
