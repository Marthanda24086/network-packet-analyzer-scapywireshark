"""
Sample PCAP Generator Script for NetScope.
Creates a multi-protocol sample PCAP file in sample_data/sample_traffic.pcap
for testing, offline demonstrations, and academic review.
"""

import os
import random
from scapy.all import (
    wrpcap, Ether, ARP, IP, IPv6, ICMP, TCP, UDP, DNS, DNSQR, Raw
)


def generate_sample_pcap():
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, "sample_traffic.pcap")

    packets = []

    # 1. ARP Request & Reply
    packets.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.10", pdst="192.168.1.1"))
    packets.append(Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / ARP(op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.1", hwdst="00:11:22:33:44:55", pdst="192.168.1.10"))

    # 2. ICMP Echo Request & Reply
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) / ICMP(type=8, code=0, id=101, seq=1))
    packets.append(Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="8.8.8.8", dst="192.168.1.10", ttl=56) / ICMP(type=0, code=0, id=101, seq=1))

    # 3. DNS Query & Response
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53531, dport=53) / DNS(id=0x1234, qr=0, qd=DNSQR(qname="google.com")))

    # 4. TCP 3-Way Handshake
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="142.250.190.46") / TCP(sport=49152, dport=443, flags="S", seq=1000))
    packets.append(Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="142.250.190.46", dst="192.168.1.10") / TCP(sport=443, dport=49152, flags="SA", seq=5000, ack=1001))
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="142.250.190.46") / TCP(sport=49152, dport=443, flags="A", seq=1001, ack=5001))

    # 5. HTTP GET Request
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope/1.0\r\n\r\n"
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50123, dport=80, flags="PA", seq=2000, ack=6000) / Raw(load=http_payload))

    # 6. TLS Client Hello
    tls_payload = b'\x16\x03\x01\x00\x85\x01\x00\x00\x81\x03\x03' + bytes([0xAA]*32) + b'\x00\x00\x1a\xc0\x2b\xc0\x2f\x00\x9c\x01\x00\x00\x3e'
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.10", dst="104.16.132.229") / TCP(sport=51234, dport=443, flags="PA", seq=3000, ack=7000) / Raw(load=tls_payload))

    # 7. IPv6 Packet
    packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=6000, dport=6001) / Raw(load=b"IPv6 Test Payload"))

    wrpcap(file_path, packets)
    print(f"Generated {len(packets)} synthetic packets into {file_path}")


if __name__ == "__main__":
    generate_sample_pcap()
