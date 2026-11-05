"""
Automated Screenshot Generator for NetScope.
Renders high-resolution PNG captures of the actual PySide6 UI with loaded sample data.
"""

import sys
import os

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer

# Ensure offscreen rendering if headless
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from app.ui.main_window import MainWindow
from app.pcap.pcap_manager import PcapManager


def generate_screenshots():
    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.resize(1300, 850)

    # Load sample PCAP
    pcap_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data", "sample_traffic.pcap")
    records, raw_pkts, err = PcapManager.load_pcap(pcap_path)
    if records:
        window._on_pcap_loaded(records, raw_pkts)

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "screenshots")
    os.makedirs(output_dir, exist_ok=True)

    window.show()
    app.processEvents()

    # 1. Capture Live/Table Tab
    window.tabs.setCurrentIndex(0)
    app.processEvents()
    pix1 = window.grab()
    pix1.save(os.path.join(output_dir, "01_live_capture_table.png"))
    print("Saved 01_live_capture_table.png")

    # 2. Select Packet and Capture Details Tab
    window.tab_capture.table.selectRow(3)  # Select TCP 3-way handshake packet
    app.processEvents()
    window.tabs.setCurrentIndex(1)
    app.processEvents()
    pix2 = window.grab()
    pix2.save(os.path.join(output_dir, "02_packet_details_tree_hex.png"))
    print("Saved 02_packet_details_tree_hex.png")

    # 3. Capture Statistics Tab
    window.tabs.setCurrentIndex(2)
    app.processEvents()
    pix3 = window.grab()
    pix3.save(os.path.join(output_dir, "03_statistics_dashboard.png"))
    print("Saved 03_statistics_dashboard.png")

    # 4. Capture Visual Analytics Tab
    window.tabs.setCurrentIndex(3)
    app.processEvents()
    pix4 = window.grab()
    pix4.save(os.path.join(output_dir, "04_visual_analytics_charts.png"))
    print("Saved 04_visual_analytics_charts.png")

    # 5. Capture PCAP & Export Tab
    window.tabs.setCurrentIndex(4)
    app.processEvents()
    pix5 = window.grab()
    pix5.save(os.path.join(output_dir, "05_pcap_exporter.png"))
    print("Saved 05_pcap_exporter.png")

    print(f"Successfully generated all 5 real UI screenshots in {output_dir}")


if __name__ == "__main__":
    generate_screenshots()
