# NetScope — Viva Voce Preparation Guide

This document contains 30 likely viva questions and technical answers for defending the **NetScope** project in front of college project review faculty.

---

### Q1: What is packet sniffing?
**Answer**: Packet sniffing is the technique of capturing raw digital data frames as they travel across a network interface. A packet sniffer places the network interface (or socket layer) into a mode where it intercepts headers and payload data for inspection and analysis.

### Q2: What is protocol analysis?
**Answer**: Protocol analysis is the process of inspecting captured packet frames layer by layer according to network protocol standards (OSI/TCP-IP models). It extracts header fields (such as IP addresses, transport ports, sequence numbers, and DNS queries) to understand network behavior, diagnose issues, or detect anomalies.

### Q3: What is a PCAP file?
**Answer**: PCAP (Packet Capture) is a standard API and binary file format used for recording captured network traffic data. It stores packet timestamps, capture lengths, original frame lengths, and raw packet byte arrays.

### Q4: What is the difference between PCAP and PCAPNG?
**Answer**: PCAP is the legacy fixed format containing a global header followed by packet records. PCAPNG (PCAP Next Generation) is a extensible block-based format supporting multiple network interfaces per file, interface statistics, embedded comments, and enhanced name resolution blocks.

### Q5: Why did you choose Scapy for this project?
**Answer**: Scapy is a powerful, programmable Python networking library capable of dissecting, forging, sniffing, and reading packet frames across dozens of protocols. It allows us to build a custom analytical pipeline, parse protocol headers into Python data structures, and automate metrics calculation.

### Q6: Why did you include Wireshark integration?
**Answer**: Wireshark is the industry-standard visual packet analysis tool. In NetScope, Wireshark serves as an independent external validation reference. NetScope handles automated analysis, filtering, statistics, and reports, while providing a one-click launcher to open saved PCAPs in Wireshark for professional visual verification.

### Q7: What complementary roles do Wireshark and Scapy play in your project?
**Answer**: **Scapy** provides the programmable Python engine for capture, parsing, filtering, and metric calculation. **Wireshark** provides an established, independent visual inspection tool for validating packet records.

### Q8: What happens at the network interface when a packet is captured?
**Answer**: The physical Network Interface Card (NIC) receives hardware signals, performs CRC checks, strips the preamble, and delivers the Layer 2 Ethernet frame to the OS driver. If promiscuous mode is enabled (or socket sniffing is active), the kernel copies the raw frame to the capture socket buffer without dropping packets meant for other MAC addresses.

### Q9: Explain the Ethernet II frame structure.
**Answer**: An Ethernet II frame consists of:
1. Destination MAC Address (6 bytes)
2. Source MAC Address (6 bytes)
3. EtherType (2 bytes, e.g., `0x0800` for IPv4, `0x0806` for ARP, `0x86DD` for IPv6)
4. Payload (46–1500 bytes)
5. Frame Check Sequence / CRC (4 bytes).

### Q10: Explain the IPv4 header fields.
**Answer**: Key fields in an IPv4 header include:
- Version (4 bits) & IHL (Header Length, 4 bits)
- Type of Service / DSCP (1 byte)
- Total Length (2 bytes)
- Identification (2 bytes), Flags (3 bits), Fragment Offset (13 bits)
- Time to Live / TTL (1 byte, hop counter)
- Protocol (1 byte, e.g., 6 = TCP, 17 = UDP, 1 = ICMP)
- Header Checksum (2 bytes)
- Source IP (4 bytes) and Destination IP (4 bytes).

### Q11: What is the difference between TCP and UDP?
**Answer**: 
- **TCP (Transmission Control Protocol)**: Connection-oriented, reliable, stream-based protocol providing 3-way handshake connection setup, sequence/acknowledgment numbers, retransmission, and flow control.
- **UDP (User Datagram Protocol)**: Connectionless, lightweight, datagram-based protocol with minimal overhead and no guaranteed delivery or sequencing.

### Q12: What are TCP flags? Explain SYN, ACK, FIN, and RST.
**Answer**: TCP flags are control bits in the TCP header:
- **SYN (Synchronize)**: Initiates a connection and synchronizes sequence numbers.
- **ACK (Acknowledgment)**: Confirms receipt of packets.
- **FIN (Finish)**: Requests graceful connection termination.
- **RST (Reset)**: Aborts an invalid or refused connection immediately.

### Q13: Explain the TCP Three-Way Handshake.
**Answer**:
1. **Client -> Server (SYN)**: Client sends SYN packet with an Initial Sequence Number ($Seq = X$).
2. **Server -> Client (SYN-ACK)**: Server acknowledges with $Ack = X + 1$ and sends its own SYN with $Seq = Y$.
3. **Client -> Server (ACK)**: Client responds with $Ack = Y + 1$, establishing the active TCP connection.

### Q14: What is ARP and how does it work?
**Answer**: Address Resolution Protocol (ARP) maps a known Layer 3 IP address to an unknown Layer 2 MAC address on a local Ethernet segment. A host broadcasts an "ARP Request" (`Who has 192.168.1.1?`), and the target host responds with a unicast "ARP Reply" (`192.168.1.1 is at 00:aa:bb:cc:dd:ee`).

### Q15: What is DNS?
**Answer**: Domain Name System (DNS) is an application layer protocol running over UDP/TCP port 53 that translates human-readable domain names (e.g., `google.com`) into numerical IP addresses (e.g., `142.250.190.46`).

### Q16: What is ICMP?
**Answer**: Internet Control Message Protocol (ICMP) is an IP-layer supporting protocol used for network diagnostics and error reporting. Common types include Type 8 (Echo Request / Ping) and Type 0 (Echo Reply).

### Q17: What is promiscuous mode?
**Answer**: Promiscuous mode is a NIC configuration that causes the network controller to pass all received frame traffic to the operating system CPU, rather than filtering out frames not addressed to the host's MAC address.

### Q18: What is a BPF (Berkeley Packet Filter)?
**Answer**: BPF is an efficient kernel-level packet filtering mechanism. A BPF expression (e.g., `tcp port 80`) is compiled into a bytecode kernel filter that discards unwanted packets before copying them to user-space memory, reducing overhead.

### Q19: What is the difference between Capture Filters and Display Filters?
**Answer**: 
- **Capture Filter (BPF)**: Applied at kernel level *during* capture to select which packets to record. Packets dropped by BPF are never stored.
- **Display Filter**: Applied in memory *after* packets are captured. It hides non-matching packets from the GUI view without discarding them from the dataset.

### Q20: How does NetScope dissect packet layers safely?
**Answer**: NetScope uses `ProtocolDecoder` and `PacketAnalyzer`. It wraps field accessors in `getattr()` and `try/except` blocks, assigning safe fallback default values if optional fields or layer headers are missing or malformed.

### Q21: How does NetScope prevent GUI freezing during packet capture?
**Answer**: NetScope offloads packet capture and synthetic generation to a dedicated background thread subclassing `PySide6.QtCore.QThread` (`CaptureWorker`). Thread-safe Qt signals (`packet_captured`, `capture_finished`) pass structured records to the main GUI thread.

### Q22: Why can HTTPS/TLS application payloads not be read directly in packet sniffers?
**Answer**: HTTPS uses TLS (Transport Layer Security) encryption. Before application data is sent, the client and server negotiate cryptographic keys using asymmetric public-key cryptography. Raw packet sniffers intercept encrypted ciphertext, which cannot be decrypted without the session symmetric keys or private key. NetScope truthfully displays TLS record type and handshake metadata without claiming fake decryption.

### Q23: What is Demo Mode in NetScope and why was it implemented?
**Answer**: Demo Mode streams realistic synthetic Scapy packets (DNS, TCP handshakes, HTTP GET, TLS Client Hello, ICMP, ARP) in memory without accessing physical hardware interfaces. It guarantees that the application can be fully demonstrated during a college project review even on computers without Npcap or Administrator privileges.

### Q24: What is the difference between source port and destination port?
**Answer**: 
- **Source Port**: Ephemeral port number (e.g., 49152–65535) dynamically chosen by the client OS to identify the local application socket.
- **Destination Port**: Well-known service port (e.g., 80 for HTTP, 443 for HTTPS, 53 for DNS) identifying the target server service.

### Q25: What is TTL (Time to Live)?
**Answer**: TTL is an 8-bit field in the IPv4 header that specifies the maximum number of router hops a packet can traverse before being discarded. Each router decrements TTL by 1, preventing routing loops from clogging the internet indefinitely.

### Q26: How are packet sizes and bandwidth metrics computed in NetScope?
**Answer**: `StatisticsEngine` iterates through the dataset of `PacketRecord` instances, summing the raw frame byte lengths (`len(packet)`), calculating average byte sizes, minimum/maximum packet lengths, and grouping packet counts into 1-second time bins for timeline plotting.

### Q27: What export formats does NetScope support?
**Answer**: NetScope supports exporting packet records to **CSV** (table summary), **JSON** (structured deep records), **Markdown** (academic report summary), and **HTML** (styled visual summary report).

### Q28: How does NetScope handle malformed or corrupted packets?
**Answer**: If a packet frame fails to parse during layer dissection, `PacketAnalyzer` catches the exception, logs the error details, and constructs a fallback `PacketRecord` with protocol `"Unknown (Malformed)"` and info summary describing the parse error, ensuring the application never crashes.

### Q29: What are the legal and ethical considerations of packet sniffing?
**Answer**: Packet sniffing can intercept private communications. Unauthorized sniffing on networks without permission violates wiretapping laws and institutional security policies. NetScope must only be used on authorized networks, local loopbacks, or synthetic demo datasets for diagnostic, educational, and research purposes.

### Q30: What future enhancements could be added to NetScope?
**Answer**: Future scope includes TCP stream reassembly for full HTTP body reconstruction, GeoIP mapping for endpoint IP geographic visualization, and signature-based anomaly detection rules.
