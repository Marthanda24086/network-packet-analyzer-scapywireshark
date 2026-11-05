"""
Statistics Engine for NetScope.
Aggregates network metrics, protocol distributions, top talkers, port usage, and timeline series.
"""

from collections import Counter
from typing import List, Dict, Any, Tuple
from app.analysis.packet_models import PacketRecord


class StatisticsEngine:
    """Calculates statistical metrics from a list of PacketRecord instances."""

    @staticmethod
    def calculate_summary(records: List[PacketRecord]) -> Dict[str, Any]:
        """
        Computes comprehensive summary metrics for dashboard display.

        Returns:
            Dict containing metric card values and breakdown dictionaries.
        """
        if not records:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_size": 0,
                "min_packet_size": 0,
                "max_packet_size": 0,
                "unique_sources": 0,
                "unique_destinations": 0,
                "protocol_counts": {},
                "top_sources": [],
                "top_destinations": [],
                "top_ports": [],
                "transport_split": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0},
                "timeline_series": ([], [])
            }

        total_packets = len(records)
        total_bytes = sum(r.length for r in records)
        sizes = [r.length for r in records]
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        avg_size = round(total_bytes / total_packets, 1) if total_packets > 0 else 0

        # Protocols
        proto_counter = Counter(r.protocol for r in records)

        # Endpoints
        src_counter = Counter(r.src_ip for r in records if r.src_ip != "N/A")
        dst_counter = Counter(r.dst_ip for r in records if r.dst_ip != "N/A")

        # Ports
        ports = []
        for r in records:
            if r.src_port:
                ports.append(r.src_port)
            if r.dst_port:
                ports.append(r.dst_port)
        port_counter = Counter(ports)

        # Transport split
        transport_split = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
        for r in records:
            p = r.protocol.upper()
            tp = r.transport_protocol.upper()
            if "TCP" in p or tp == "TCP":
                transport_split["TCP"] += 1
            elif "UDP" in p or tp == "UDP":
                transport_split["UDP"] += 1
            elif "ICMP" in p:
                transport_split["ICMP"] += 1
            elif "ARP" in p:
                transport_split["ARP"] += 1
            else:
                transport_split["Other"] += 1

        # Timeline series: bucket packets by 1-second intervals relative to start
        min_time = min(r.timestamp for r in records)
        timeline_buckets: Dict[int, int] = {}
        for r in records:
            sec_offset = int(r.timestamp - min_time)
            timeline_buckets[sec_offset] = timeline_buckets.get(sec_offset, 0) + 1

        sorted_sec = sorted(timeline_buckets.keys())
        timeline_x = sorted_sec
        timeline_y = [timeline_buckets[s] for s in sorted_sec]

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_size,
            "min_packet_size": min_size,
            "max_packet_size": max_size,
            "unique_sources": len(src_counter),
            "unique_destinations": len(dst_counter),
            "protocol_counts": dict(proto_counter),
            "top_sources": src_counter.most_common(5),
            "top_destinations": dst_counter.most_common(5),
            "top_ports": port_counter.most_common(5),
            "transport_split": transport_split,
            "timeline_series": (timeline_x, timeline_y)
        }
