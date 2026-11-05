"""
Unit test suite for NetScope protocol decoders and packet analyzer.
"""

import pytest
from scapy.all import Ether, ARP, IP, IPv6, ICMP, TCP, UDP, DNS, DNSQR, Raw
from app.analysis.packet_analyzer import PacketAnalyzer
from app.analysis.protocol_decoder import ProtocolDecoder
from app.analysis.packet_models import ProtocolType


@pytest.fixture
def analyzer():
    return PacketAnalyzer()


def test_eth_ipv4_tcp_parsing(analyzer):
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
        IP(src="192.168.1.10", dst="93.184.216.34", ttl=64) /
        TCP(sport=50123, dport=80, flags="S", seq=1000)
    )
    rec = analyzer.parse_packet(pkt, packet_num=1)

    assert rec is not None
    assert rec.packet_num == 1
    assert rec.src_mac == "00:11:22:33:44:55"
    assert rec.dst_mac == "00:aa:bb:cc:dd:ee"
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "93.184.216.34"
    assert rec.src_port == 50123
    assert rec.dst_port == 80
    assert rec.protocol == ProtocolType.TCP.value
    assert rec.ttl == 64


def test_arp_parsing(analyzer):
    pkt = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.10", pdst="192.168.1.1")
    rec = analyzer.parse_packet(pkt, packet_num=2)

    assert rec is not None
    assert rec.protocol == ProtocolType.ARP.value
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "192.168.1.1"
    assert "Who has" in rec.info


def test_icmp_parsing(analyzer):
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8, code=0)
    rec = analyzer.parse_packet(pkt, packet_num=3)

    assert rec is not None
    assert rec.protocol == ProtocolType.ICMP.value
    assert "Echo Request" in rec.info


def test_dns_parsing(analyzer):
    pkt = (
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") /
        UDP(sport=54321, dport=53) /
        DNS(id=0x1234, qr=0, qd=DNSQR(qname="example.com"))
    )
    rec = analyzer.parse_packet(pkt, packet_num=4)

    assert rec is not None
    assert rec.protocol == ProtocolType.DNS.value
    assert "example.com" in rec.info


def test_ipv6_udp_parsing(analyzer):
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=128) / UDP(sport=6000, dport=6001)
    rec = analyzer.parse_packet(pkt, packet_num=5)

    assert rec is not None
    assert rec.protocol == ProtocolType.UDP.value
    assert rec.src_ip == "2001:db8::1"
    assert rec.dst_ip == "2001:db8::2"
    assert rec.ttl == 128


def test_http_plaintext_parsing(analyzer):
    payload = b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
        IP(src="192.168.1.10", dst="93.184.216.34") /
        TCP(sport=50123, dport=80, flags="PA", seq=1000, ack=2000) /
        Raw(load=payload)
    )
    rec = analyzer.parse_packet(pkt, packet_num=6)
    assert rec is not None
    assert rec.protocol == ProtocolType.HTTP.value
    assert "GET /api/v1/status" in rec.info


def test_tls_handshake_metadata_parsing(analyzer):
    # TLS 1.2 Client Hello snippet
    tls_payload = b'\x16\x03\x01\x00\x10\x01\x00\x00\x0c\x03\x03' + b'\x00' * 16
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") /
        IP(src="192.168.1.10", dst="104.16.132.229") /
        TCP(sport=51234, dport=443, flags="PA") /
        Raw(load=tls_payload)
    )
    rec = analyzer.parse_packet(pkt, packet_num=7)
    assert rec is not None
    assert rec.protocol == ProtocolType.TLS.value
    assert "TLS/HTTPS" in rec.info
    # Verify no fake decryption is claimed
    tls_layer = rec.get_layer("TLS / HTTPS")
    assert tls_layer is not None
    assert any("Not Decrypted" in str(f.value) for f in tls_layer.fields)


def test_empty_packet_handling(analyzer):
    from scapy.all import Packet
    pkt = Packet()
    rec = analyzer.parse_packet(pkt, packet_num=8)
    assert rec is not None
    assert rec.packet_num == 8
    assert rec.protocol in (ProtocolType.UNKNOWN.value, "Unknown")


def test_missing_ip_layer(analyzer):
    # Pure Ethernet frame carrying raw binary payload
    pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / Raw(load=b"Non-IP Ethernet payload")
    rec = analyzer.parse_packet(pkt, packet_num=9)
    assert rec is not None
    assert rec.protocol == ProtocolType.ETH.value
    assert rec.src_ip == "N/A"
    assert rec.dst_ip == "N/A"


def test_missing_transport_layer(analyzer):
    # IPv4 packet carrying IGMP or arbitrary raw payload without TCP/UDP
    pkt = Ether() / IP(src="192.168.1.10", dst="224.0.0.1", proto=2) / Raw(load=b"IGMP Data")
    rec = analyzer.parse_packet(pkt, packet_num=10)
    assert rec is not None
    assert rec.protocol == ProtocolType.IPV4.value
    assert rec.transport_protocol == "N/A"
    assert rec.src_port is None
    assert rec.dst_port is None


def test_unsupported_protocol(analyzer):
    # IPv4 packet with unhandled protocol number (e.g. 253 - experimental)
    pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1", proto=253)
    rec = analyzer.parse_packet(pkt, packet_num=11)
    assert rec is not None
    assert rec.protocol == ProtocolType.IPV4.value
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "10.0.0.1"


def test_malformed_packet_handling(analyzer):
    # None or empty object should handle gracefully
    rec = analyzer.parse_packet(None)
    assert rec is None
