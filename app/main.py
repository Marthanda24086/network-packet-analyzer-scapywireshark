"""
NetScope Main Application Entrypoint.
Initializes logging, PySide6 QApplication, and renders the MainWindow interface.
"""

import sys
import os
import argparse
import logging
from PySide6.QtWidgets import QApplication

from app.utils.logging_config import setup_logging
from app.ui.main_window import MainWindow

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="NetScope - Packet Sniffing & Protocol Analysis Tool")
    parser.add_argument("--demo", action="store_true", help="Launch directly in Demo Mode")
    parser.add_argument("--pcap", type=str, help="Preload a PCAP file upon startup")
    args = parser.parse_args()

    setup_logging()
    logger.info("Initializing NetScope Application...")

    app = QApplication(sys.argv)
    app.setApplicationName("NetScope")
    app.setOrganizationName("NetScope Team")

    window = MainWindow()

    if args.pcap and os.path.exists(args.pcap):
        from app.pcap.pcap_manager import PcapManager
        recs, raw_pkts, err = PcapManager.load_pcap(args.pcap)
        if not err:
            window._on_pcap_loaded(recs, raw_pkts)

    elif args.demo:
        window.combo_iface.setCurrentIndex(0)
        window._start_capture()

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
