# NetScope — Packet Sniffing and Protocol Analysis Tool
## Academic Project Report

**Degree**: Bachelor of Technology (B.Tech) in Computer Science & Engineering  
**Project Title**: NetScope — Packet Sniffing and Protocol Analysis Tool using Wireshark and Scapy  

---

## Executive Summary

Network traffic analysis and packet sniffing form the operational foundation of modern network engineering, protocol diagnostics, and cybersecurity inspection. This project presents **NetScope**, a modular, high-performance desktop application built using Python 3.10+, PySide6, Scapy, and Matplotlib. NetScope combines programmable packet parsing, display filtering, multi-protocol layer dissection, statistical aggregation, visual analytics, and PCAP file management into a cohesive, professional interface.

---

## Chapter 1: Introduction

Packet sniffing is the technique of intercepting and logging network traffic passing over a digital network. As network data travels across physical mediums, it is formatted into protocol-specific frames and packets governed by standard protocol stacks such as the OSI model and TCP/IP suite.

NetScope was developed to bridge the gap between heavy, low-level packet capture utilities and high-level educational visualization requirements. By leveraging **Scapy** as a programmable networking framework and **Wireshark** as an optional validation reference, NetScope offers both live physical packet capture and a safe synthetic demonstration mode suitable for academic reviews.

---

## Chapter 2: Problem Statement and Objectives

### 2.1 Problem Statement
Standard network analyzers such as Wireshark offer deep protocol dissection but present steep learning curves and lack customizable programmatic analytical pipelines. Conversely, raw Python scripts using socket or Scapy lack responsive graphical user interfaces and visualization dashboards necessary for presenting real-time statistics during diagnostic evaluations.

### 2.2 Project Objectives
1. **Automated Interface Discovery**: Detect system network interfaces with friendly descriptions and administrative privilege checks.
2. **Defensive Multi-Layer Dissection**: Safely parse Ethernet II, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP, TLS metadata, and DHCP layers.
3. **In-Memory Display & BPF Filtering**: Implement real-time display filtering across protocol types, IP addresses, transport ports, and text queries.
4. **Visual Analytics & Dashboard**: Compute metric summaries and render interactive Matplotlib charts.
5. **PCAP Interoperability & Export**: Support PCAP loading, saving, multi-format exports (CSV, JSON, Markdown, HTML), and optional Wireshark launcher integration.
6. **Synthetic Demo Mode**: Guarantee 100% testability and demonstration capability without requiring elevated administrative privileges.

---

## Chapter 3: Literature & Background Review

Network protocol dissection builds upon standard networking RFCs published by the Internet Engineering Task Force (IETF):
- **RFC 791**: Internet Protocol (IPv4) Specification.
- **RFC 793**: Transmission Control Protocol (TCP) Specification.
- **RFC 768**: User Datagram Protocol (UDP) Specification.
- **RFC 826**: An Ethernet Address Resolution Protocol (ARP).
- **RFC 1035**: Domain Names — Implementation and Specification (DNS).
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3.

### Existing Systems
- **Wireshark**: Industry standard packet analyzer written in C/C++ using Qt. High performance, extensive dissector library.
- **TShark**: Command-line variant of Wireshark.
- **Scapy**: Interactive packet manipulation library written in Python by Philippe Biondi. Highly programmable for packet creation, sniffing, and crafting.

---

## Chapter 4: System Requirements

### 4.1 Software Requirements
- **Operating System**: Microsoft Windows 10/11, Linux (Ubuntu/Debian), or macOS.
- **Python Runtime**: Python 3.10+ (tested on Python 3.14).
- **Libraries**: `scapy>=2.5.0`, `PySide6>=6.5.0`, `matplotlib>=3.7.0`, `pytest>=7.3.0`.
- **Optional**: Wireshark / TShark installation, Npcap driver (Windows).

### 4.2 Hardware Requirements
- **Processor**: Dual-Core Intel/AMD Processor (2.0 GHz or higher).
- **RAM**: 4 GB minimum (8 GB recommended).
- **Disk Space**: 200 MB free space.

---

## Chapter 5: System Architecture and Design

NetScope uses a clean 3-tier architecture:
1. **Presentation Layer (`app/ui`)**: PySide6 dark-themed GUI containing metric cards, packet table, tree view, hex viewer, statistics tab, and visualization tab.
2. **Concurrency Layer (`app/workers`)**: `CaptureWorker` (`QThread`) managing asynchronous packet streaming.
3. **Engine Layer (`app/analysis`)**: `PacketAnalyzer`, `ProtocolDecoder`, `FilterEngine`, `StatisticsEngine`.

---

## Chapter 6: Implementation

### 6.1 Protocol Dissection Engine
The `ProtocolDecoder` class evaluates packet layers defensively:
```python
if packet.haslayer(IP):
    ip = packet[IP]
    src_ip = str(getattr(ip, 'src', 'N/A'))
    dst_ip = str(getattr(ip, 'dst', 'N/A'))
    ttl = int(getattr(ip, 'ttl', 64) or 64)
```

### 6.2 Synthetic Demo Mode
To ensure the application can be demonstrated in any environment without Npcap or root rights, `CaptureWorker` generates synthetic Scapy packets (DNS queries, TCP handshakes, HTTP GET requests, TLS Client Hello frames, ICMP pings, ARP requests).

---

## Chapter 7: Testing and Results

The project includes an automated test suite executed via `pytest`.

### Test Summary Results
- **Total Tests**: 14
- **Passed**: 14 (100% pass rate)
- **Execution Time**: 0.43 seconds

| Test File | Category | Status |
| :--- | :--- | :--- |
| `tests/unit/test_analyzer.py` | Packet Parsing & Layer Dissection | PASSED |
| `tests/unit/test_filters.py` | Display & BPF Filtering | PASSED |
| `tests/unit/test_statistics.py` | Metrics Aggregation | PASSED |
| `tests/integration/test_pcap_workflow.py` | PCAP Load/Save & Multi-Format Exports | PASSED |

---

## Chapter 8: Limitations

1. **Encrypted Payload Decryption**: In compliance with ethical cybersecurity principles, encrypted TLS/HTTPS application payloads are not decrypted. Only handshake metadata is extracted.
2. **Elevated Privileges for Live Physical Sniffing**: Live physical packet capture on Windows requires Npcap driver and Administrator rights. (Mitigated by synthetic Demo Mode).

---

## Chapter 9: Future Scope

1. **Advanced Flow Reassembly**: TCP stream reassembly for multi-packet HTTP payload reconstruction.
2. **GeoIP Endpoint Mapping**: Integration with MaxMind GeoIP database to map IP addresses onto geographical maps.
3. **Deep Packet Inspection (DPI) Signatures**: Signature matching for detecting known network protocol anomalies.

---

## Chapter 10: Conclusion

NetScope successfully fulfills all academic project requirements for a robust, runnable, and visually polished packet-sniffing and protocol-analysis application. By combining Scapy's programmable networking backend with PySide6's responsive GUI framework, NetScope provides an ideal balance of technical rigor, architectural clarity, and demonstrability.

---

## References

1. Biondi, P. (2024). *Scapy Documentation*. https://scapy.readthedocs.io/
2. Wireshark Foundation. (2024). *Wireshark User’s Guide*. https://www.wireshark.org/docs/wsug_html_chunked/
3. Qt Company. (2024). *PySide6 / Qt for Python Documentation*. https://doc.qt.io/qtforpython-6/
4. Postel, J. (1981). *Transmission Control Protocol*. RFC 793, IETF.
5. Postel, J. (1981). *Internet Protocol*. RFC 791, IETF.
