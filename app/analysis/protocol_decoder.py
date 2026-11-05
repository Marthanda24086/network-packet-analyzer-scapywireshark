"""
Protocol Decoder Engine for NetScope.
Inspects Scapy packet structures safely and extracts layer details, field values,
and readable descriptions for networking protocols.
"""

import datetime
from typing import List, Tuple, Optional
from scapy.all import (
    Ether, ARP, IP, IPv6, ICMP, TCP, UDP, DNS, DNSQR, DNSRR, DHCP, Raw
)
from app.analysis.packet_models import LayerDetail, FieldDetail, ProtocolType


class ProtocolDecoder:
    """Decodes packet layers and generates detailed field breakdowns."""

    TCP_FLAGS_MAP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }

    DNS_TYPES = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
    }

    @staticmethod
    def decode_packet_layers(packet) -> Tuple[List[LayerDetail], str, str, Optional[int], Optional[int], str, str, str, str, Optional[int], int, str]:
        """
        Main entry point for parsing a raw Scapy packet into a structured record.

        Returns:
            (layers, top_protocol, transport_proto, src_port, dst_port, src_mac, dst_mac, src_ip, dst_ip, ttl, payload_len, info_summary)
        """
        layers: List[LayerDetail] = []
        top_protocol = ProtocolType.UNKNOWN.value
        transport_proto = "N/A"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        src_mac = "N/A"
        dst_mac = "N/A"
        src_ip = "N/A"
        dst_ip = "N/A"
        ttl: Optional[int] = None
        payload_len = 0
        info_summary = ""
        tcp_flags = ""

        # Layer 2: Ethernet
        if packet.haslayer(Ether):
            eth = packet[Ether]
            try:
                src_mac = str(eth.src) if eth.src else "N/A"
            except Exception:
                src_mac = "N/A"

            try:
                dst_mac = str(eth.dst) if eth.dst else "N/A"
            except Exception:
                dst_mac = "N/A"

            eth_type = getattr(eth, 'type', 0x0800) or 0x0800
            eth_fields = [
                FieldDetail("Destination MAC", dst_mac),
                FieldDetail("Source MAC", src_mac),
                FieldDetail("EtherType", f"0x{eth_type:04x}")
            ]
            try:
                raw_eth = bytes(eth).hex()
            except Exception:
                raw_eth = ""
            layers.append(LayerDetail("Ethernet II", eth_fields, raw_hex=raw_eth))
            top_protocol = ProtocolType.ETH.value

        # ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            top_protocol = ProtocolType.ARP.value
            src_mac = str(getattr(arp, 'hwsrc', src_mac))
            dst_mac = str(getattr(arp, 'hwdst', dst_mac))
            src_ip = str(getattr(arp, 'psrc', 'N/A'))
            dst_ip = str(getattr(arp, 'pdst', 'N/A'))
            op_val = getattr(arp, 'op', 1) or 1

            op_desc = "Request (Who has?)" if op_val == 1 else ("Reply (Is at)" if op_val == 2 else f"Opcode {op_val}")
            arp_fields = [
                FieldDetail("Hardware Type", getattr(arp, 'hwtype', 1)),
                FieldDetail("Protocol Type", f"0x{getattr(arp, 'ptype', 0x0800):04x}"),
                FieldDetail("Operation", f"{op_val} ({op_desc})"),
                FieldDetail("Sender MAC", src_mac),
                FieldDetail("Sender IP", src_ip),
                FieldDetail("Target MAC", dst_mac),
                FieldDetail("Target IP", dst_ip),
            ]
            try:
                raw_arp = bytes(arp).hex()
            except Exception:
                raw_arp = ""
            layers.append(LayerDetail("ARP", arp_fields, raw_hex=raw_arp))
            info_summary = f"ARP {op_desc} {src_ip} -> {dst_ip}"

        # Layer 3: IPv4
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = str(getattr(ip, 'src', 'N/A'))
            dst_ip = str(getattr(ip, 'dst', 'N/A'))
            ttl = int(getattr(ip, 'ttl', 64) or 64)
            top_protocol = ProtocolType.IPV4.value

            version_val = getattr(ip, 'version', 4) or 4
            ihl_val = getattr(ip, 'ihl', 5) or 5
            tos_val = getattr(ip, 'tos', 0) or 0
            len_val = getattr(ip, 'len', 0) or 0
            id_val = getattr(ip, 'id', 0) or 0
            frag_val = getattr(ip, 'frag', 0) or 0
            proto_val = getattr(ip, 'proto', 6) or 6
            chksum_val = getattr(ip, 'chksum', None)

            ip_fields = [
                FieldDetail("Version", version_val),
                FieldDetail("Header Length (IHL)", f"{ihl_val * 4} bytes ({ihl_val})"),
                FieldDetail("Type of Service (TOS)", f"0x{tos_val:02x}"),
                FieldDetail("Total Length", f"{len_val} bytes"),
                FieldDetail("Identification", f"0x{id_val:04x} ({id_val})"),
                FieldDetail("Flags", str(getattr(ip, 'flags', ''))),
                FieldDetail("Fragment Offset", frag_val),
                FieldDetail("Time to Live (TTL)", ttl),
                FieldDetail("Protocol", f"{proto_val}"),
                FieldDetail("Header Checksum", f"0x{chksum_val:04x}" if chksum_val is not None else "None"),
                FieldDetail("Source IP", src_ip),
                FieldDetail("Destination IP", dst_ip),
            ]
            try:
                raw_ip = bytes(ip).hex()
            except Exception:
                raw_ip = ""
            layers.append(LayerDetail("IPv4", ip_fields, raw_hex=raw_ip))
            info_summary = f"IPv4 {src_ip} -> {dst_ip}"

        # Layer 3: IPv6
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            src_ip = str(getattr(ip6, 'src', 'N/A'))
            dst_ip = str(getattr(ip6, 'dst', 'N/A'))
            ttl = int(getattr(ip6, 'hlim', 64))
            top_protocol = ProtocolType.IPV6.value

            ip6_fields = [
                FieldDetail("Version", ip6.version),
                FieldDetail("Traffic Class", getattr(ip6, 'tc', 0)),
                FieldDetail("Flow Label", getattr(ip6, 'fl', 0)),
                FieldDetail("Payload Length", getattr(ip6, 'plen', 0)),
                FieldDetail("Next Header", getattr(ip6, 'nh', 0)),
                FieldDetail("Hop Limit (TTL)", ip6.hlim),
                FieldDetail("Source IPv6", src_ip),
                FieldDetail("Destination IPv6", dst_ip),
            ]
            layers.append(LayerDetail("IPv6", ip6_fields, raw_hex=bytes(ip6).hex()))
            info_summary = f"IPv6 {src_ip} -> {dst_ip}"

        # Layer 4: ICMP
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            top_protocol = ProtocolType.ICMP.value
            type_val = getattr(icmp, 'type', 8) or 0
            code_val = getattr(icmp, 'code', 0) or 0
            chksum_val = getattr(icmp, 'chksum', None)

            type_desc = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request", 11: "Time Exceeded"}.get(type_val, f"Type {type_val}")
            icmp_fields = [
                FieldDetail("Type", f"{type_val} ({type_desc})"),
                FieldDetail("Code", code_val),
                FieldDetail("Checksum", f"0x{chksum_val:04x}" if chksum_val is not None else "None"),
            ]
            try:
                raw_icmp = bytes(icmp).hex()
            except Exception:
                raw_icmp = ""
            layers.append(LayerDetail("ICMP", icmp_fields, raw_hex=raw_icmp))
            info_summary = f"ICMP {type_desc} ({src_ip} -> {dst_ip})"

        # Layer 4: TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            transport_proto = "TCP"
            src_port = int(getattr(tcp, 'sport', 0) or 0)
            dst_port = int(getattr(tcp, 'dport', 0) or 0)

            # Build human readable flags string
            raw_flags = str(getattr(tcp, 'flags', ''))
            flag_names = [ProtocolDecoder.TCP_FLAGS_MAP.get(c, c) for c in raw_flags]
            tcp_flags = f"[{','.join(flag_names)}]" if flag_names else "[]"

            try:
                payload_data = bytes(tcp.payload)
                payload_len = len(payload_data)
            except Exception:
                payload_data = b""
                payload_len = 0

            if top_protocol in (ProtocolType.IPV4.value, ProtocolType.IPV6.value, ProtocolType.ETH.value):
                top_protocol = ProtocolType.TCP.value

            dataofs_val = getattr(tcp, 'dataofs', 5) or 5
            seq_val = getattr(tcp, 'seq', 0) or 0
            ack_val = getattr(tcp, 'ack', 0) or 0
            window_val = getattr(tcp, 'window', 0) or 0
            chksum_val = getattr(tcp, 'chksum', None)
            urgptr_val = getattr(tcp, 'urgptr', 0) or 0
            flags_int = int(tcp.flags) if hasattr(tcp, 'flags') and tcp.flags is not None else 0

            tcp_fields = [
                FieldDetail("Source Port", src_port),
                FieldDetail("Destination Port", dst_port),
                FieldDetail("Sequence Number", seq_val),
                FieldDetail("Acknowledgment Number", ack_val),
                FieldDetail("Header Length", f"{dataofs_val * 4} bytes"),
                FieldDetail("Flags", f"0x{flags_int:02x} {tcp_flags}"),
                FieldDetail("Window Size", window_val),
                FieldDetail("Checksum", f"0x{chksum_val:04x}" if chksum_val is not None else "None"),
                FieldDetail("Urgent Pointer", urgptr_val),
                FieldDetail("Payload Length", f"{payload_len} bytes")
            ]
            try:
                raw_tcp = bytes(tcp).hex()
            except Exception:
                raw_tcp = ""
            layers.append(LayerDetail("TCP", tcp_fields, raw_hex=raw_tcp))
            info_summary = f"{src_port} -> {dst_port} {tcp_flags} Seq={seq_val} Ack={ack_val} Win={window_val} Len={payload_len}"

        # Layer 4: UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            transport_proto = "UDP"
            src_port = int(getattr(udp, 'sport', 0) or 0)
            dst_port = int(getattr(udp, 'dport', 0) or 0)
            try:
                payload_data = bytes(udp.payload)
                payload_len = len(payload_data)
            except Exception:
                payload_data = b""
                payload_len = 0

            udp_len = getattr(udp, 'len', 8) or 8
            chksum_val = getattr(udp, 'chksum', None)

            if top_protocol in (ProtocolType.IPV4.value, ProtocolType.IPV6.value, ProtocolType.ETH.value):
                top_protocol = ProtocolType.UDP.value

            udp_fields = [
                FieldDetail("Source Port", src_port),
                FieldDetail("Destination Port", dst_port),
                FieldDetail("Length", udp_len),
                FieldDetail("Checksum", f"0x{chksum_val:04x}" if chksum_val is not None else "None"),
                FieldDetail("Payload Length", f"{payload_len} bytes")
            ]
            try:
                raw_udp = bytes(udp).hex()
            except Exception:
                raw_udp = ""
            layers.append(LayerDetail("UDP", udp_fields, raw_hex=raw_udp))
            info_summary = f"{src_port} -> {dst_port} Len={udp_len}"

        # Application Layer: DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            top_protocol = ProtocolType.DNS.value
            qr_val = getattr(dns, 'qr', 0) or 0
            qr_type = "Response" if qr_val == 1 else "Query"

            qname = "N/A"
            qtype_str = "A"
            qdcount_val = getattr(dns, 'qdcount', 0) or 0
            ancount_val = getattr(dns, 'ancount', 0) or 0
            nscount_val = getattr(dns, 'nscount', 0) or 0
            arcount_val = getattr(dns, 'arcount', 0) or 0
            dns_id = getattr(dns, 'id', 0) or 0

            if qdcount_val > 0 or hasattr(dns, 'qd'):
                try:
                    q = None
                    if packet.haslayer(DNSQR):
                        q = packet[DNSQR]
                    elif hasattr(dns, 'qd') and dns.qd:
                        q = dns.qd

                    if q:
                        qname = q.qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(q.qname, bytes) else str(q.qname).rstrip('.')
                        qtype_str = ProtocolDecoder.DNS_TYPES.get(getattr(q, 'qtype', 1), f"Type {getattr(q, 'qtype', 1)}")
                except Exception:
                    pass

            dns_fields = [
                FieldDetail("Transaction ID", f"0x{dns_id:04x}"),
                FieldDetail("Message Type", f"{qr_val} ({qr_type})"),
                FieldDetail("Opcode", getattr(dns, 'opcode', 0)),
                FieldDetail("Truncated", bool(getattr(dns, 'tc', 0))),
                FieldDetail("Recursion Desired", bool(getattr(dns, 'rd', 0))),
                FieldDetail("Recursion Available", bool(getattr(dns, 'ra', 0))),
                FieldDetail("Questions Count", qdcount_val),
                FieldDetail("Answer RRs", ancount_val),
                FieldDetail("Authority RRs", nscount_val),
                FieldDetail("Additional RRs", arcount_val),
                FieldDetail("Query Name", qname),
                FieldDetail("Query Type", qtype_str)
            ]
            try:
                raw_dns = bytes(dns).hex()
            except Exception:
                raw_dns = ""
            layers.append(LayerDetail("DNS", dns_fields, raw_hex=raw_dns))
            info_summary = f"DNS Standard {qr_type} 0x{dns_id:04x} {qtype_str} {qname}"

        # Application Layer: DHCP
        elif packet.haslayer(DHCP):
            dhcp = packet[DHCP]
            top_protocol = ProtocolType.DHCP.value
            msg_type = "DHCP Message"
            options_list = []
            try:
                for opt in dhcp.options:
                    if isinstance(opt, tuple):
                        options_list.append(f"{opt[0]}: {opt[1]}")
                        if opt[0] == 'message-type':
                            msg_type = f"DHCP Message Type {opt[1]}"
            except Exception:
                pass

            dhcp_fields = [
                FieldDetail("Options", ", ".join(options_list) if options_list else "None")
            ]
            layers.append(LayerDetail("DHCP", dhcp_fields, raw_hex=bytes(dhcp).hex()))
            info_summary = f"DHCP ({msg_type})"

        # Application Layer: HTTP / TLS Detection
        if transport_proto == "TCP":
            payload = bytes(packet[TCP].payload)
            if payload:
                # Check HTTP plaintext
                if payload.startswith((b'GET ', b'POST ', b'HTTP/', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ')):
                    top_protocol = ProtocolType.HTTP.value
                    try:
                        lines = payload.decode('utf-8', errors='ignore').split('\r\n')
                        first_line = lines[0] if lines else "HTTP Traffic"
                        http_fields = [
                            FieldDetail("First Line", first_line),
                            FieldDetail("Raw Payload Snippet", payload[:200].decode('utf-8', errors='ignore'))
                        ]
                        layers.append(LayerDetail("HTTP", http_fields, raw_hex=payload[:64].hex()))
                        info_summary = f"HTTP {first_line}"
                    except Exception:
                        pass
                # Check TLS handshake record (0x16 = Handshake, 0x14 = ChangeCipherSpec, 0x17 = Application Data)
                elif payload[0] in (0x16, 0x14, 0x17, 0x15) and len(payload) >= 5 and payload[1] == 0x03:
                    top_protocol = ProtocolType.TLS.value
                    record_types = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}
                    rec_type_str = record_types.get(payload[0], f"0x{payload[0]:02x}")
                    version_str = {0x01: "TLS 1.0", 0x02: "TLS 1.1", 0x03: "TLS 1.2 / 1.3"}.get(payload[2], "TLS")

                    handshake_type = ""
                    if payload[0] == 0x16 and len(payload) >= 6:
                        ht = payload[5]
                        handshake_types = {1: "Client Hello", 2: "Server Hello", 11: "Certificate", 16: "Client Key Exchange"}
                        handshake_type = f" ({handshake_types.get(ht, f'Type {ht}')})"

                    tls_fields = [
                        FieldDetail("Record Type", f"{rec_type_str} (0x{payload[0]:02x})"),
                        FieldDetail("Version", version_str),
                        FieldDetail("Length", int.from_bytes(payload[3:5], byteorder='big')),
                        FieldDetail("Encrypted Payload Status", "Encrypted TLS Content (Payload Not Decrypted)")
                    ]
                    layers.append(LayerDetail("TLS / HTTPS", tls_fields, raw_hex=payload[:64].hex()))
                    info_summary = f"TLS/HTTPS {version_str} {rec_type_str}{handshake_type}"

        # Raw fallback if present
        if packet.haslayer(Raw) and not any(l.name in ("HTTP", "TLS / HTTPS") for l in layers):
            raw_bytes = bytes(packet[Raw])
            layers.append(LayerDetail(
                "Raw Data",
                [FieldDetail("Length", f"{len(raw_bytes)} bytes")],
                raw_hex=raw_bytes[:64].hex()
            ))

        return layers, top_protocol, transport_proto, src_port, dst_port, src_mac, dst_mac, src_ip, dst_ip, ttl, payload_len, info_summary
