"""
Capture Worker Thread for NetScope.
Executes live sniffing or synthetic demo packet streaming in a background QThread
to ensure zero GUI freezing.
"""

import time
import random
import logging
from typing import Optional
from PySide6.QtCore import QThread, Signal

from scapy.all import (
    sniff, Ether, ARP, IP, IPv6, ICMP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, Packet
)
from app.analysis.packet_analyzer import PacketAnalyzer
from app.analysis.packet_models import PacketRecord
from app.utils.helpers import is_admin

logger = logging.getLogger(__name__)


class CaptureWorker(QThread):
    """Background thread performing non-blocking live or synthetic packet capture."""

    # PySide6 Signals
    packet_captured = Signal(object, object)  # (PacketRecord, raw Scapy Packet)
    capture_finished = Signal(int)             # Total count
    capture_error = Signal(str)               # Error message string

    def __init__(
        self,
        interface: str = "DEMO_MODE",
        bpf_filter: str = "",
        count_limit: int = 0,
        duration_limit: int = 0,
        parent=None
    ):
        super().__init__(parent)
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self.count_limit = count_limit
        self.duration_limit = duration_limit
        self._is_running = True
        self._analyzer = PacketAnalyzer()
        self._captured_count = 0

    def stop(self):
        """Requests thread loop termination."""
        self._is_running = False

    def run(self):
        """Main thread loop."""
        self._captured_count = 0
        self._analyzer.reset_counter()

        if self.interface == "DEMO_MODE":
            self._run_demo_capture()
        else:
            self._run_live_capture()

    def _run_demo_capture(self):
        """Generates realistic synthetic network traffic for offline demonstration."""
        logger.info("Starting synthetic demo capture stream...")
        start_time = time.time()

        demo_generators = [
            self._gen_dns_query,
            self._gen_tcp_syn,
            self._gen_tcp_ack,
            self._gen_http_request,
            self._gen_tls_client_hello,
            self._gen_icmp_ping,
            self._gen_arp_request,
            self._gen_udp_traffic
        ]

        while self._is_running:
            # Check duration limit
            if self.duration_limit > 0 and (time.time() - start_time) >= self.duration_limit:
                break

            # Check packet count limit
            if self.count_limit > 0 and self._captured_count >= self.count_limit:
                break

            # Pick random generator
            gen = random.choice(demo_generators)
            pkt = gen()
            self._captured_count += 1

            rec = self._analyzer.parse_packet(
                pkt,
                packet_num=self._captured_count,
                interface_name="DEMO_MODE (Synthetic)",
                is_synthetic=True
            )

            if rec:
                self.packet_captured.emit(rec, pkt)

            # Sleep briefly to simulate live network arrival
            time.sleep(random.uniform(0.1, 0.3))

        self.capture_finished.emit(self._captured_count)

    def _run_live_capture(self):
        """Performs live packet sniffing via Scapy."""
        logger.info(f"Starting live capture on interface: {self.interface}")

        # Check permissions on Windows/Linux
        if not is_admin():
            self.capture_error.emit(
                "Elevated administrative privileges (Root/Administrator) or Npcap driver "
                "are required for live packet capture on physical interfaces.\n\n"
                "Please run application as Administrator or select DEMO_MODE for synthetic review."
            )

        def packet_callback(pkt: Packet):
            if not self._is_running:
                return
            self._captured_count += 1
            rec = self._analyzer.parse_packet(
                pkt,
                packet_num=self._captured_count,
                interface_name=self.interface,
                is_synthetic=False
            )
            if rec:
                self.packet_captured.emit(rec, pkt)

        def stop_filter(pkt: Packet) -> bool:
            if not self._is_running:
                return True
            if self.count_limit > 0 and self._captured_count >= self.count_limit:
                return True
            return False

        try:
            sniff_kwargs = {
                "prn": packet_callback,
                "stop_filter": stop_filter,
                "store": False
            }

            if self.interface and self.interface != "eth0":
                sniff_kwargs["iface"] = self.interface

            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            if self.duration_limit > 0:
                sniff_kwargs["timeout"] = self.duration_limit

            sniff(**sniff_kwargs)

        except Exception as e:
            logger.error(f"Live capture error: {e}", exc_info=True)
            self.capture_error.emit(f"Live capture error on '{self.interface}': {str(e)}")

        self.capture_finished.emit(self._captured_count)

    # ---------------- Synthetic Packet Generators ----------------
    def _gen_dns_query(self) -> Packet:
        domains = ["google.com", "github.com", "wikipedia.org", "python.org", "mit.edu"]
        domain = random.choice(domains)
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="8.8.8.8") /
            UDP(sport=random.randint(49152, 65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain))
        )

    def _gen_tcp_syn(self) -> Packet:
        dst_ip = f"142.250.{random.randint(1,250)}.{random.randint(1,250)}"
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst=dst_ip, ttl=64) /
            TCP(sport=random.randint(49152, 65535), dport=443, flags="S", seq=random.randint(1000, 99999))
        )

    def _gen_tcp_ack(self) -> Packet:
        dst_ip = f"140.82.{random.randint(1,250)}.{random.randint(1,250)}"
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst=dst_ip, ttl=128) /
            TCP(sport=random.randint(49152, 65535), dport=80, flags="A", seq=random.randint(1000, 99999), ack=random.randint(1000, 99999))
        )

    def _gen_http_request(self) -> Packet:
        paths = ["/index.html", "/api/v1/status", "/assets/logo.png", "/login"]
        path = random.choice(paths)
        payload = f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope/1.0\r\n\r\n"
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="93.184.216.34") /
            TCP(sport=random.randint(49152, 65535), dport=80, flags="PA", seq=100, ack=500) /
            Raw(load=payload.encode())
        )

    def _gen_tls_client_hello(self) -> Packet:
        # Realistic TLS 1.2 Client Hello payload bytes snippet
        tls_header = b'\x16\x03\x01\x00\x85\x01\x00\x00\x81\x03\x03' + bytes([random.randint(0, 255) for _ in range(32)]) + b'\x00\x00\x1a\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00\x00\x3e'
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="104.16.132.229") /
            TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") /
            Raw(load=tls_header)
        )

    def _gen_icmp_ping(self) -> Packet:
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="8.8.4.4") /
            ICMP(type=8, code=0, id=1234, seq=1)
        )

    def _gen_arp_request(self) -> Packet:
        return (
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100", pdst="192.168.1.1")
        )

    def _gen_udp_traffic(self) -> Packet:
        return (
            Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
            IP(src="192.168.1.100", dst="192.168.1.255") /
            UDP(sport=random.randint(49152, 65535), dport=514) /
            Raw(load=b"<34>NetScope: Demo syslog event notice")
        )
