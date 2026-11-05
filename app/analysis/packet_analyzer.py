"""
Packet Analyzer engine for NetScope.
Transforms raw Scapy packets into normalized PacketRecord objects with error isolation.
"""

import datetime
import logging
import time
from typing import Optional, List
from scapy.all import Packet

from app.analysis.packet_models import PacketRecord
from app.analysis.protocol_decoder import ProtocolDecoder

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """High-level analyzer for normalizing Scapy frames."""

    def __init__(self):
        self._packet_count = 0

    def reset_counter(self):
        """Reset internal packet sequence number counter."""
        self._packet_count = 0

    def parse_packet(self, packet: Packet, packet_num: Optional[int] = None, interface_name: str = "", is_synthetic: bool = False) -> Optional[PacketRecord]:
        """
        Defensively parses a Scapy packet frame into a PacketRecord.

        Args:
            packet: Raw Scapy packet instance
            packet_num: Optional explicit packet sequence index
            interface_name: Name of network interface
            is_synthetic: Flag indicating synthetic demo data

        Returns:
            PacketRecord instance or None if parsing fails completely
        """
        if packet is None:
            return None

        if packet_num is None:
            self._packet_count += 1
            idx = self._packet_count
        else:
            idx = packet_num

        try:
            # Extract timestamp
            ts = float(getattr(packet, 'time', time.time()))
            formatted_time = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]

            # Length of raw packet
            try:
                pkt_len = len(packet)
            except Exception:
                pkt_len = 0

            # Decode layers using ProtocolDecoder
            (
                layers,
                top_protocol,
                transport_proto,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                ttl,
                payload_len,
                info_summary
            ) = ProtocolDecoder.decode_packet_layers(packet)

            # Raw hex representation of whole packet
            try:
                raw_hex = bytes(packet).hex()
            except Exception:
                raw_hex = ""

            record = PacketRecord(
                packet_num=idx,
                timestamp=ts,
                formatted_time=formatted_time,
                length=pkt_len,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=top_protocol,
                transport_protocol=transport_proto,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags="",  # populates in info or layers
                ttl=ttl,
                payload_len=payload_len,
                info=info_summary or f"{top_protocol} Packet",
                layers=layers,
                raw_hex=raw_hex,
                is_synthetic=is_synthetic,
                interface=interface_name
            )

            return record

        except Exception as e:
            logger.error(f"Error parsing packet #{idx}: {e}", exc_info=True)
            # Return fallback record instead of crashing app
            ts = time.time()
            return PacketRecord(
                packet_num=idx,
                timestamp=ts,
                formatted_time=datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3],
                length=0,
                protocol="Unknown (Malformed)",
                info=f"Malformed packet parse error: {str(e)}"
            )
