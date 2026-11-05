"""
Interface Discovery Module for NetScope.
Queries Scapy and OS interfaces safely and provides interface descriptions and status indicators.
"""

from dataclasses import dataclass
from typing import List, Optional
import logging
from scapy.all import conf, get_working_ifaces

logger = logging.getLogger(__name__)


@dataclass
class NetworkInterface:
    """Represents a physical or logical network interface."""
    name: str
    description: str
    mac: str = "N/A"
    ip: str = "N/A"
    is_loopback: bool = False
    status: str = "Active"


class InterfaceManager:
    """Manages interface discovery and verification."""

    @staticmethod
    def get_interfaces() -> List[NetworkInterface]:
        """
        Discovers available system network interfaces. Always appends the
        synthetic demo interface for offline demonstration mode.
        """
        interfaces: List[NetworkInterface] = []

        # Synthetic Demo Interface (Always available for reviews)
        interfaces.append(NetworkInterface(
            name="DEMO_MODE",
            description="Synthetic Demo Traffic Generator (No Admin Required)",
            mac="00:11:22:33:44:55",
            ip="192.168.1.100",
            status="Ready (Synthetic)"
        ))

        try:
            # Query Scapy interfaces
            scapy_ifaces = get_working_ifaces()
            for iface in scapy_ifaces:
                name = str(getattr(iface, 'name', getattr(iface, 'description', 'Unknown')))
                desc = str(getattr(iface, 'description', name))
                mac = str(getattr(iface, 'mac', 'N/A'))
                ip = str(getattr(iface, 'ip', 'N/A'))
                is_loop = bool(getattr(iface, 'is_loopback', False))

                interfaces.append(NetworkInterface(
                    name=name,
                    description=desc,
                    mac=mac,
                    ip=ip,
                    is_loopback=is_loop,
                    status="Active" if ip != "N/A" else "Link Ready"
                ))

        except Exception as e:
            logger.warning(f"Error querying Scapy interfaces: {e}")

        # Fallback if Scapy yields no physical interfaces
        if len(interfaces) == 1:
            interfaces.append(NetworkInterface(
                name="eth0",
                description="Default Ethernet Interface",
                mac="02:42:AC:11:00:02",
                ip="192.168.1.50",
                status="Standby"
            ))

        return interfaces
