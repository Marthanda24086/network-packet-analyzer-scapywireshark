"""
Packet data structures and models for NetScope.
Defines normalized, structured packet records extracted from raw Scapy frames.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Any, Dict


class ProtocolType(str, Enum):
    ETH = "Ethernet"
    ARP = "ARP"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    DHCP = "DHCP"
    UNKNOWN = "Unknown"


@dataclass
class FieldDetail:
    """Represents a single field inside a protocol layer."""
    name: str
    value: Any
    description: str = ""


@dataclass
class LayerDetail:
    """Represents a protocol layer (e.g. Ethernet, IPv4, TCP)."""
    name: str
    fields: List[FieldDetail] = field(default_factory=list)
    raw_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fields": [{"name": f.name, "value": str(f.value), "description": f.description} for f in self.fields]
        }


@dataclass
class PacketRecord:
    """
    Normalized immutable-style dataclass for displaying packets across GUI,
    statistics engine, and exported reports.
    """
    packet_num: int
    timestamp: float
    formatted_time: str
    length: int
    src_mac: str = "N/A"
    dst_mac: str = "N/A"
    src_ip: str = "N/A"
    dst_ip: str = "N/A"
    protocol: str = "Unknown"
    transport_protocol: str = "N/A"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""
    ttl: Optional[int] = None
    payload_len: int = 0
    info: str = ""
    layers: List[LayerDetail] = field(default_factory=list)
    raw_hex: str = ""
    is_synthetic: bool = False
    interface: str = ""

    def get_layer(self, layer_name: str) -> Optional[LayerDetail]:
        for layer in self.layers:
            if layer.name.lower() == layer_name.lower():
                return layer
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_num": self.packet_num,
            "timestamp": self.timestamp,
            "formatted_time": self.formatted_time,
            "length": self.length,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "transport_protocol": self.transport_protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl,
            "payload_len": self.payload_len,
            "info": self.info,
            "is_synthetic": self.is_synthetic,
            "interface": self.interface,
            "layers": [layer.to_dict() for layer in self.layers]
        }
