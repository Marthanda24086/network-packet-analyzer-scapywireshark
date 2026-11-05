"""
PCAP File Manager for NetScope.
Handles loading, parsing, and saving PCAP and PCAPNG file formats using Scapy.
"""

import os
import logging
from typing import List, Tuple, Optional
from scapy.all import rdpcap, wrpcap, Packet

from app.analysis.packet_analyzer import PacketAnalyzer
from app.analysis.packet_models import PacketRecord

logger = logging.getLogger(__name__)


class PcapManager:
    """Manages loading and exporting PCAP files."""

    @staticmethod
    def load_pcap(file_path: str) -> Tuple[List[PacketRecord], List[Packet], Optional[str]]:
        """
        Loads and parses a PCAP or PCAPNG file.

        Returns:
            (packet_records, raw_packets, error_message)
        """
        if not os.path.exists(file_path):
            return [], [], f"File not found: {file_path}"

        if not os.path.isfile(file_path):
            return [], [], f"Path is not a regular file: {file_path}"

        if os.path.getsize(file_path) == 0:
            return [], [], "PCAP file is empty (0 bytes)."

        try:
            raw_packets = rdpcap(file_path)
            analyzer = PacketAnalyzer()
            records: List[PacketRecord] = []

            for idx, pkt in enumerate(raw_packets, start=1):
                rec = analyzer.parse_packet(pkt, packet_num=idx, interface_name=os.path.basename(file_path))
                if rec:
                    records.append(rec)

            logger.info(f"Successfully loaded {len(records)} packets from {file_path}")
            return records, list(raw_packets), None

        except PermissionError:
            return [], [], f"Permission denied reading file: {file_path}"
        except Exception as e:
            logger.error(f"Failed to read PCAP file {file_path}: {e}", exc_info=True)
            return [], [], f"Corrupted or unsupported PCAP format: {str(e)}"

    @staticmethod
    def save_pcap(file_path: str, raw_packets: List[Packet]) -> Tuple[bool, Optional[str]]:
        """
        Saves raw Scapy packet frames to a PCAP file.

        Returns:
            (success, error_message)
        """
        if not raw_packets:
            return False, "No packets available to save."

        try:
            dir_name = os.path.dirname(file_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)

            wrpcap(file_path, raw_packets)
            logger.info(f"Saved {len(raw_packets)} packets to {file_path}")
            return True, None

        except PermissionError:
            return False, f"Permission denied writing to: {file_path}"
        except Exception as e:
            logger.error(f"Failed to save PCAP to {file_path}: {e}", exc_info=True)
            return False, f"Error saving PCAP file: {str(e)}"
