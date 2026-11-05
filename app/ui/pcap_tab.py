"""
PCAP Analysis & Exporter Tab Widget for NetScope.
Provides PCAP loading, saving, Wireshark launcher integration, and multi-format report exports.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QPushButton,
    QFileDialog, QMessageBox, QComboBox
)
from PySide6.QtCore import Qt, Signal
import os
from typing import List, Optional

from scapy.all import Packet
from app.analysis.packet_models import PacketRecord
from app.pcap.pcap_manager import PcapManager
from app.pcap.exporters import Exporter
from app.utils.helpers import find_wireshark_path, open_pcap_in_wireshark


class PcapTabWidget(QWidget):
    """Tab widget managing PCAP file IO and Wireshark launch operations."""

    pcap_loaded = Signal(list, list)  # Emits (packet_records, raw_scapy_packets)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_records: List[PacketRecord] = []
        self._current_raw_packets: List[Packet] = []
        self._current_file_path: Optional[str] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        # Section 1: PCAP File Operations
        box_pcap = QGroupBox("PCAP File Operations")
        lay_pcap = QVBoxLayout(box_pcap)

        btn_layout = QHBoxLayout()
        btn_open = QPushButton("Open PCAP / PCAPNG File")
        btn_open.clicked.connect(self._on_open_pcap)
        btn_layout.addWidget(btn_open)

        btn_save = QPushButton("Save Active Capture to PCAP")
        btn_save.clicked.connect(self._on_save_pcap)
        btn_layout.addWidget(btn_save)

        lay_pcap.addLayout(btn_layout)

        self.lbl_file_info = QLabel("No PCAP file currently loaded.")
        self.lbl_file_info.setStyleSheet("color: #94a3b8; font-style: italic; margin-top: 8px;")
        lay_pcap.addWidget(self.lbl_file_info)

        layout.addWidget(box_pcap)

        # Section 2: Wireshark Interoperability
        box_ws = QGroupBox("Wireshark Integration")
        lay_ws = QVBoxLayout(box_ws)

        ws_bin = find_wireshark_path()
        status_text = f"Wireshark Executable: {ws_bin}" if ws_bin else "Wireshark Status: Not found in standard system PATH."
        lbl_ws_status = QLabel(status_text)
        lbl_ws_status.setStyleSheet("color: #38bdf8;" if ws_bin else "color: #f43f5e;")
        lay_ws.addWidget(lbl_ws_status)

        btn_launch_ws = QPushButton("Open Current Capture in Wireshark")
        btn_launch_ws.clicked.connect(self._on_launch_wireshark)
        lay_ws.addWidget(btn_launch_ws)

        layout.addWidget(box_ws)

        # Section 3: Export Analysis Reports
        box_exp = QGroupBox("Export Analysis & Reports")
        lay_exp = QVBoxLayout(box_exp)

        exp_layout = QHBoxLayout()
        exp_layout.addWidget(QLabel("Export Format:"))
        self.combo_format = QComboBox()
        self.combo_format.addItems(["CSV Table (.csv)", "JSON Data (.json)", "Markdown Report (.md)", "HTML Summary (.html)"])
        exp_layout.addWidget(self.combo_format)

        btn_export = QPushButton("Export Analysis Report")
        btn_export.clicked.connect(self._on_export_report)
        exp_layout.addWidget(btn_export)

        lay_exp.addLayout(exp_layout)
        layout.addWidget(box_exp)

        layout.addStretch()

    def set_dataset(self, records: List[PacketRecord], raw_packets: List[Packet]):
        """Sets dataset references from main window."""
        self._current_records = list(records)
        self._current_raw_packets = list(raw_packets)
        self.lbl_file_info.setText(f"Active Capture Dataset: {len(records)} packets loaded.")

    def _on_open_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if not file_path:
            return

        records, raw_pkts, err = PcapManager.load_pcap(file_path)
        if err:
            QMessageBox.critical(self, "PCAP Read Error", err)
            return

        self._current_file_path = file_path
        self._current_records = records
        self._current_raw_packets = raw_pkts

        file_name = os.path.basename(file_path)
        size_kb = round(os.path.getsize(file_path) / 1024, 1)
        self.lbl_file_info.setText(f"Loaded: {file_name} ({size_kb} KB, {len(records)} packets)")

        self.pcap_loaded.emit(records, raw_pkts)

    def _on_save_pcap(self):
        if not self._current_raw_packets:
            QMessageBox.warning(self, "Save PCAP", "No captured packets available to save.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture to PCAP", "capture.pcap", "PCAP Files (*.pcap)"
        )
        if not file_path:
            return

        ok, err = PcapManager.save_pcap(file_path, self._current_raw_packets)
        if ok:
            self._current_file_path = file_path
            QMessageBox.information(self, "Save Successful", f"Saved {len(self._current_raw_packets)} packets to:\n{file_path}")
        else:
            QMessageBox.critical(self, "Save Error", err or "Unknown error saving PCAP.")

    def _on_launch_wireshark(self):
        if not self._current_file_path:
            # Offer to save temp PCAP first
            if not self._current_raw_packets:
                QMessageBox.warning(self, "Wireshark", "No packet data available. Capture packets or open a PCAP first.")
                return

            temp_path = os.path.abspath("temp_capture.pcap")
            ok, err = PcapManager.save_pcap(temp_path, self._current_raw_packets)
            if not ok:
                QMessageBox.critical(self, "Wireshark Error", f"Failed to prepare temp PCAP: {err}")
                return
            self._current_file_path = temp_path

        ok, msg = open_pcap_in_wireshark(self._current_file_path)
        if not ok:
            QMessageBox.warning(self, "Wireshark Integration", msg)
        else:
            QMessageBox.information(self, "Wireshark Integration", msg)

    def _on_export_report(self):
        if not self._current_records:
            QMessageBox.warning(self, "Export Report", "No packet dataset available to export.")
            return

        fmt = self.combo_format.currentText()
        if "CSV" in fmt:
            default_name, filter_str = "export_packets.csv", "CSV Files (*.csv)"
        elif "JSON" in fmt:
            default_name, filter_str = "export_packets.json", "JSON Files (*.json)"
        elif "Markdown" in fmt:
            default_name, filter_str = "export_report.md", "Markdown Files (*.md)"
        else:
            default_name, filter_str = "export_report.html", "HTML Files (*.html)"

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", default_name, filter_str)
        if not file_path:
            return

        if "CSV" in fmt:
            ok, err = Exporter.export_csv(file_path, self._current_records)
        elif "JSON" in fmt:
            ok, err = Exporter.export_json(file_path, self._current_records)
        elif "Markdown" in fmt:
            ok, err = Exporter.export_markdown_report(file_path, self._current_records, capture_source=self._current_file_path or "Live Capture")
        else:
            ok, err = Exporter.export_html_report(file_path, self._current_records, capture_source=self._current_file_path or "Live Capture")

        if ok:
            QMessageBox.information(self, "Export Successful", f"Successfully exported analysis report to:\n{file_path}")
        else:
            QMessageBox.critical(self, "Export Error", f"Failed to export report: {err}")
