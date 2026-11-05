"""
Filtering engine for NetScope.
Provides fast in-memory display filtering across protocol, address, port, and text queries,
and validates BPF capture filters.
"""

from typing import List, Optional
from app.analysis.packet_models import PacketRecord


class FilterEngine:
    """Evaluates packet records against user-specified filtering parameters."""

    @staticmethod
    def filter_packets(
        records: List[PacketRecord],
        protocol: Optional[str] = None,
        ip_addr: Optional[str] = None,
        port: Optional[int] = None,
        search_text: Optional[str] = None
    ) -> List[PacketRecord]:
        """
        Filters a list of PacketRecord objects in memory.

        Args:
            records: Master list of PacketRecord items
            protocol: Target protocol string (e.g. 'TCP', 'UDP', 'DNS', 'HTTP')
            ip_addr: Target IP address (matches either src or dst IP)
            port: Target port number (matches either src or dst port)
            search_text: Text snippet to search in info summary, IP, MAC, or layers

        Returns:
            Filtered list of PacketRecord items matching ALL criteria
        """
        filtered = records

        # Filter by Protocol
        if protocol and protocol.strip() and protocol.strip().upper() != "ALL":
            proto_upper = protocol.strip().upper()
            filtered = [
                r for r in filtered
                if r.protocol.upper() == proto_upper or r.transport_protocol.upper() == proto_upper
            ]

        # Filter by IP Address
        if ip_addr and ip_addr.strip():
            ip_str = ip_addr.strip().lower()
            filtered = [
                r for r in filtered
                if ip_str in r.src_ip.lower() or ip_str in r.dst_ip.lower()
            ]

        # Filter by Port
        if port is not None and port > 0:
            filtered = [
                r for r in filtered
                if r.src_port == port or r.dst_port == port
            ]

        # Filter by Search Text
        if search_text and search_text.strip():
            query = search_text.strip().lower()
            res = []
            for r in filtered:
                if (
                    query in r.info.lower() or
                    query in r.src_ip.lower() or
                    query in r.dst_ip.lower() or
                    query in r.src_mac.lower() or
                    query in r.dst_mac.lower() or
                    query in r.protocol.lower()
                ):
                    res.append(r)
                else:
                    # Search inside layer fields
                    found_in_layers = False
                    for layer in r.layers:
                        if query in layer.name.lower():
                            found_in_layers = True
                            break
                        for fld in layer.fields:
                            if query in fld.name.lower() or query in str(fld.value).lower():
                                found_in_layers = True
                                break
                        if found_in_layers:
                            break
                    if found_in_layers:
                        res.append(r)
            filtered = res

        return filtered

    @staticmethod
    def validate_bpf_filter(bpf_string: str) -> bool:
        """
        Basic syntax sanity check for BPF capture filters.

        Returns True if plausible, False if invalid format.
        """
        if not bpf_string or not bpf_string.strip():
            return True

        # Common BPF keywords
        allowed_keywords = {
            "ip", "ip6", "arp", "tcp", "udp", "icmp", "port", "src", "dst",
            "host", "net", "and", "or", "not", "proto", "less", "greater"
        }

        tokens = bpf_string.strip().lower().split()
        for token in tokens:
            # Check if numeric, IPv4/v6 like, or keyword
            if token.isdigit():
                continue
            if any(c in token for c in ('.', ':', '/')):
                continue
            if token not in allowed_keywords and not token.isalnum():
                return False

        return True
