"""
Main Window GUI for NetScope.
Assembles branding cards, capture toolbar, control sidebar, and tabbed analytics interfaces.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QGroupBox, QLabel, QComboBox, QLineEdit, QSpinBox, QPushButton,
    QStatusBar, QMessageBox, QFrame
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QIcon, QFont
from typing import List, Optional

from scapy.all import Packet
from app.analysis.packet_models import PacketRecord
from app.analysis.statistics import StatisticsEngine
from app.capture.interfaces import InterfaceManager, NetworkInterface
from app.capture.capture_manager import CaptureManager
from app.workers.capture_worker import CaptureWorker
from app.utils.helpers import is_admin, find_wireshark_path, open_pcap_in_wireshark
from app.ui.styles import DARK_THEME_QSS

from app.ui.capture_tab import CaptureTabWidget
from app.ui.packet_details import PacketDetailsWidget
from app.ui.statistics_tab import StatisticsTabWidget
from app.ui.visualization_tab import VisualizationTabWidget
from app.ui.pcap_tab import PcapTabWidget


class MainWindow(QMainWindow):
    """Master Application Window for NetScope."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope — Packet Sniffing & Protocol Analysis Tool")
        self.resize(1300, 850)

        # Internal Data Collections
        self._master_records: List[PacketRecord] = []
        self._master_raw_packets: List[Packet] = []
        self._capture_manager = CaptureManager(self)
        self._capture_manager.packet_captured.connect(self._on_packet_captured)
        self._capture_manager.capture_finished.connect(self._on_capture_finished)
        self._capture_manager.capture_error.connect(self._on_capture_error)

        self.setStyleSheet(DARK_THEME_QSS)
        self._init_ui()
        self._load_interfaces()

    def _init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        master_layout = QVBoxLayout(main_widget)
        master_layout.setContentsMargins(12, 12, 12, 12)
        master_layout.setSpacing(10)

        # ---------------- 1. Top Header Branding & Metric Cards ----------------
        header_layout = QHBoxLayout()

        # Branding Title
        title_box = QVBoxLayout()
        lbl_title = QLabel("NetScope — Packet Sniffing & Protocol Analysis Tool")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #38bdf8;")
        lbl_sub = QLabel("Wireshark + Scapy Based Network Traffic Analyzer")
        lbl_sub.setStyleSheet("font-size: 12px; color: #94a3b8;")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_layout.addLayout(title_box)

        header_layout.addStretch()

        # Top Metric Cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        self.card_pkts = self._create_metric_card("Packets", "0")
        self.card_bytes = self._create_metric_card("Total Bytes", "0 B")
        self.card_protos = self._create_metric_card("Protocols", "0")
        self.card_srcs = self._create_metric_card("Unique Src", "0")
        self.card_dsts = self._create_metric_card("Unique Dst", "0")

        cards_layout.addWidget(self.card_pkts["widget"])
        cards_layout.addWidget(self.card_bytes["widget"])
        cards_layout.addWidget(self.card_protos["widget"])
        cards_layout.addWidget(self.card_srcs["widget"])
        cards_layout.addWidget(self.card_dsts["widget"])

        header_layout.addLayout(cards_layout)
        master_layout.addLayout(header_layout)

        # Divider Line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #334155;")
        master_layout.addWidget(line)

        # ---------------- 2. Main Body Splitter ----------------
        body_splitter = QSplitter(Qt.Horizontal)

        # --- Left Control Sidebar ---
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 8, 0)
        sidebar.setMaximumWidth(280)

        # Group 1: Interface Selection
        box_iface = QGroupBox("Network Interface")
        lay_iface = QVBoxLayout(box_iface)

        self.combo_iface = QComboBox()
        lay_iface.addWidget(self.combo_iface)

        self.lbl_iface_info = QLabel("Status: Ready")
        self.lbl_iface_info.setWordWrap(True)
        self.lbl_iface_info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay_iface.addWidget(self.lbl_iface_info)

        sidebar_layout.addWidget(box_iface)

        # Group 2: Capture Controls
        box_ctrl = QGroupBox("Capture Parameters")
        lay_ctrl = QVBoxLayout(box_ctrl)

        lay_ctrl.addWidget(QLabel("BPF Capture Filter:"))
        self.txt_bpf = QLineEdit()
        self.txt_bpf.setPlaceholderText("e.g. tcp port 80 or ip")
        lay_ctrl.addWidget(self.txt_bpf)

        lay_ctrl.addWidget(QLabel("Max Packet Limit (0 = ∞):"))
        self.spin_count = QSpinBox()
        self.spin_count.setRange(0, 100000)
        self.spin_count.setValue(0)
        lay_ctrl.addWidget(self.spin_count)

        lay_ctrl.addWidget(QLabel("Max Duration (sec, 0 = ∞):"))
        self.spin_duration = QSpinBox()
        self.spin_duration.setRange(0, 86400)
        self.spin_duration.setValue(0)
        lay_ctrl.addWidget(self.spin_duration)

        self.btn_start = QPushButton("▶ Start Capture")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.clicked.connect(self._start_capture)
        lay_ctrl.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■ Stop Capture")
        self.btn_stop.setObjectName("btnStop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_capture)
        lay_ctrl.addWidget(self.btn_stop)

        self.btn_clear = QPushButton("🗑 Clear Dataset")
        self.btn_clear.clicked.connect(self._clear_dataset)
        lay_ctrl.addWidget(self.btn_clear)

        sidebar_layout.addWidget(box_ctrl)

        # Group 3: Environment Status
        box_env = QGroupBox("Privilege Status")
        lay_env = QVBoxLayout(box_env)
        admin_str = "Administrator (Live Capture OK)" if is_admin() else "Standard User (Demo / Offline OK)"
        lbl_admin = QLabel(admin_str)
        lbl_admin.setWordWrap(True)
        lbl_admin.setStyleSheet("color: #22c55e;" if is_admin() else "color: #fbbf24;")
        lay_env.addWidget(lbl_admin)
        sidebar_layout.addWidget(box_env)

        sidebar_layout.addStretch()
        body_splitter.addWidget(sidebar)

        # --- Right Main Tabs ---
        self.tabs = QTabWidget()

        self.tab_capture = CaptureTabWidget()
        self.tab_details = PacketDetailsWidget()
        self.tab_stats = StatisticsTabWidget()
        self.tab_vis = VisualizationTabWidget()
        self.tab_pcap = PcapTabWidget()

        self.tabs.addTab(self.tab_capture, "📡 Live Capture")
        self.tabs.addTab(self.tab_details, "🔍 Packet Details")
        self.tabs.addTab(self.tab_stats, "📊 Statistics")
        self.tabs.addTab(self.tab_vis, "📈 Visual Analytics")
        self.tabs.addTab(self.tab_pcap, "💾 PCAP Tools & Export")

        # Connect Row Selection Signal from Packet Table to Details Tree
        self.tab_capture.packet_selected.connect(self.tab_details.display_packet)
        # Connect PCAP Loaded Signal to Main Window
        self.tab_pcap.pcap_loaded.connect(self._on_pcap_loaded)

        body_splitter.addWidget(self.tabs)
        body_splitter.setSizes([260, 1040])
        master_layout.addWidget(body_splitter)

        # ---------------- 3. Status Bar ----------------
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("NetScope Ready. Select network interface or DEMO_MODE to start.")

    def _create_metric_card(self, title: str, default_val: str) -> dict:
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 6px 12px;
                min-width: 90px;
            }
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: bold;")
        lbl_v = QLabel(default_val)
        lbl_v.setStyleSheet("font-size: 16px; color: #38bdf8; font-weight: bold;")

        lay.addWidget(lbl_t, alignment=Qt.AlignCenter)
        lay.addWidget(lbl_v, alignment=Qt.AlignCenter)

        return {"widget": card, "val_lbl": lbl_v}

    def _load_interfaces(self):
        self._interfaces = InterfaceManager.get_interfaces()
        self.combo_iface.clear()

        for iface in self._interfaces:
            display_str = f"{iface.name} - {iface.description[:25]}"
            self.combo_iface.addItem(display_str, userData=iface)

        self.combo_iface.currentIndexChanged.connect(self._on_iface_changed)
        self._on_iface_changed(0)

    def _on_iface_changed(self, index: int):
        iface: NetworkInterface = self.combo_iface.itemData(index)
        if iface:
            self.lbl_iface_info.setText(f"IP: {iface.ip}\nMAC: {iface.mac}\nStatus: {iface.status}")

    @Slot()
    def _start_capture(self):
        iface: NetworkInterface = self.combo_iface.currentData()
        if not iface:
            return

        bpf_str = self.txt_bpf.text().strip()
        count_limit = self.spin_count.value()
        duration_limit = self.spin_duration.value()

        # Disable UI controls during capture
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.combo_iface.setEnabled(False)

        # Clear existing table if starting fresh
        self._clear_dataset()

        self.status_bar.showMessage(f"Capturing traffic on {iface.name}...")
        started = self._capture_manager.start_capture(
            interface=iface.name,
            bpf_filter=bpf_str,
            count_limit=count_limit,
            duration_limit=duration_limit
        )
        if not started:
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.combo_iface.setEnabled(True)

    @Slot()
    def _stop_capture(self):
        if self._capture_manager.is_capturing:
            self.status_bar.showMessage("Stopping capture stream...")
            self._capture_manager.stop_capture()

    @Slot(object, object)
    def _on_packet_captured(self, record: PacketRecord, raw_packet: Packet):
        self._master_records.append(record)
        self._master_raw_packets.append(raw_packet)

        # Update Live Table
        self.tab_capture.add_packet(record)

        # Periodically refresh top cards & analytics (every 5 packets)
        if len(self._master_records) % 5 == 0 or len(self._master_records) == 1:
            self._update_analytics()

    @Slot(int)
    def _on_capture_finished(self, total_count: int):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.combo_iface.setEnabled(True)

        self.status_bar.showMessage(f"Capture finished. Total packets: {total_count}")
        self._update_analytics()

    @Slot(str)
    def _on_capture_error(self, err_msg: str):
        self._stop_capture()
        QMessageBox.critical(self, "Capture Error", err_msg)
        self.status_bar.showMessage("Capture stopped due to error.")

    @Slot(list, list)
    def _on_pcap_loaded(self, records: List[PacketRecord], raw_packets: List[Packet]):
        self._clear_dataset()
        self._master_records = list(records)
        self._master_raw_packets = list(raw_packets)

        self.tab_capture.set_records(self._master_records)
        self._update_analytics()
        self.tabs.setCurrentIndex(0)  # Switch to table tab
        self.status_bar.showMessage(f"Successfully loaded PCAP dataset: {len(records)} packets.")

    def _clear_dataset(self):
        self._master_records.clear()
        self._master_raw_packets.clear()
        self.tab_capture.clear()
        self.tab_details.display_packet(None)
        self._update_analytics()
        self.status_bar.showMessage("Dataset cleared.")

    def _update_analytics(self):
        """Refreshes metric cards, statistics tables, visual charts, and PCAP tab dataset."""
        stats = StatisticsEngine.calculate_summary(self._master_records)

        self.card_pkts["val_lbl"].setText(str(stats["total_packets"]))

        # Format Bytes
        tb = stats["total_bytes"]
        if tb > 1024 * 1024:
            tb_str = f"{round(tb / (1024*1024), 2)} MB"
        elif tb > 1024:
            tb_str = f"{round(tb / 1024, 1)} KB"
        else:
            tb_str = f"{tb} B"
        self.card_bytes["val_lbl"].setText(tb_str)

        self.card_protos["val_lbl"].setText(str(len(stats["protocol_counts"])))
        self.card_srcs["val_lbl"].setText(str(stats["unique_sources"]))
        self.card_dsts["val_lbl"].setText(str(stats["unique_destinations"]))

        # Refresh Tabs
        self.tab_stats.update_statistics(self._master_records)
        self.tab_vis.update_charts(self._master_records)
        self.tab_pcap.set_dataset(self._master_records, self._master_raw_packets)
