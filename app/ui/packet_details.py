"""
Packet Details and Hex Viewer Widget for NetScope.
Displays structured tree decomposition of packet protocol layers, field values,
and Wireshark-style 16-byte hex dump.
"""

import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from typing import Optional

from app.analysis.packet_models import PacketRecord
from app.utils.helpers import format_hex_dump


class PacketDetailsWidget(QWidget):
    """Widget rendering Protocol Tree View, Field Details Table, and Hex Dump."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Vertical)

        # Top Section: Protocol Tree View
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Protocol Structure", "Field Value / Summary"])
        self.tree_widget.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree_widget.header().setSectionResizeMode(1, QHeaderView.Stretch)

        # Bottom Section: Hex View
        hex_container = QWidget()
        hex_layout = QVBoxLayout(hex_container)
        hex_layout.setContentsMargins(0, 0, 0, 0)

        hex_label = QLabel("Raw Packet Hexadecimal Payload View")
        hex_label.setStyleSheet("font-weight: bold; color: #38bdf8;")

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        # Fixed monospace font for hex dump alignment
        font_family = "Courier New" if sys.platform.startswith("win") else "Monospace"
        hex_font = QFont(font_family, 10)
        hex_font.setStyleHint(QFont.Monospace)
        self.hex_view.setFont(hex_font)

        hex_layout.addWidget(hex_label)
        hex_layout.addWidget(self.hex_view)

        splitter.addWidget(self.tree_widget)
        splitter.addWidget(hex_container)
        splitter.setSizes([350, 200])

        layout.addWidget(splitter)

    def display_packet(self, record: Optional[PacketRecord]):
        """Populates protocol tree and hex view for selected packet."""
        self.tree_widget.clear()
        self.hex_view.clear()

        if not record:
            self.hex_view.setText("Select a packet from table to inspect protocol details.")
            return

        # Build Root Tree Item
        root_item = QTreeWidgetItem(self.tree_widget, [
            f"Frame #{record.packet_num}",
            f"{record.length} bytes on wire, captured at {record.formatted_time}"
        ])

        # Iterate through protocol layers
        for layer in record.layers:
            layer_item = QTreeWidgetItem(root_item, [layer.name, f"{len(layer.fields)} fields decoded"])
            for fld in layer.fields:
                field_item = QTreeWidgetItem(layer_item, [fld.name, str(fld.value)])
                if fld.description:
                    field_item.setToolTip(1, fld.description)

        self.tree_widget.expandAll()

        # Format Hex View
        hex_dump_str = format_hex_dump(record.raw_hex)
        self.hex_view.setText(hex_dump_str)
