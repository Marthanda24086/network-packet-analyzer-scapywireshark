# NetScope — Packet Sniffing & Protocol Analysis Tool

Subtitle: **Wireshark + Scapy Based Network Traffic Analyzer**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![GUI-PySide6](https://img.shields.io/badge/GUI-PySide6%2FQt-green.svg)](https://doc.qt.io/qtforpython-6/)
[![Engine-Scapy](https://img.shields.io/badge/Engine-Scapy%202.5%2B-orange.svg)](https://scapy.net/)
[![Tests-Pytest](https://img.shields.io/badge/Tests-Pytest%20100%25-brightgreen.svg)](https://docs.pytest.org/)

NetScope is a modular desktop application for real-time packet sniffing, multi-layer protocol dissection, in-memory display filtering, statistical metric aggregation, visual analytics, and PCAP file management.

---

## 1. Project Title
**NetScope — Packet Sniffing & Protocol Analysis Tool**  
Subtitle: *Wireshark + Scapy Based Network Traffic Analyzer*

---

## 2. Abstract
Network protocol analysis and packet sniffing are fundamental to network diagnostics, cybersecurity monitoring, and computer science education. NetScope combines **Scapy's** programmable Python network engine with **PySide6 (Qt)** and **Matplotlib** to deliver a responsive desktop analyzer. NetScope dissects Ethernet II, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP, TLS metadata, and DHCP layers. It features real-time display filtering, dynamic metric cards, 4-quadrant visual charts, multi-format exports (CSV, JSON, Markdown, HTML), optional Wireshark launcher integration, and a synthetic Demo Mode guaranteeing 100% testability without elevated privileges.

---

## 3. Problem Statement
Commercial packet analyzers like Wireshark provide extensive protocol support but can present steep learning curves and lack customizable programmatic analytical pipelines. Conversely, script-based tools lack responsive graphical interfaces and real-time visualization dashboards. Furthermore, live capture applications often fail in lab environments lacking Administrator or root privileges. NetScope bridges these gaps with a clean architecture, visual analytics, and offline demo support.

---

## 4. Objectives
- **Interface Discovery**: Automatically detect physical and logical network interfaces with privilege state audit.
- **Protocol Dissection**: Safely parse headers across Layer 2 through Layer 7.
- **Display & BPF Filtering**: Filter traffic by Protocol, IP address, Port, and Search query, alongside BPF capture filters.
- **Visual Analytics**: Compute packet metrics and render interactive Matplotlib charts.
- **PCAP IO & Exporters**: Support loading/saving PCAPs, multi-format report generation, and Wireshark launcher integration.
- **Synthetic Demo Mode**: Stream realistic synthetic traffic for offline reviews.

---

## 5. Features
- **Live Physical Sniffing**: Non-blocking packet sniffing using background Qt worker threads (`QThread`).
- **Synthetic Demo Mode**: Multi-protocol synthetic stream (DNS, TCP, HTTP, TLS, ICMP, ARP) requiring zero admin rights.
- **Protocol Tree & Hex Viewer**: Hierarchical layer breakdown paired with Wireshark-style 16-byte hex payload view.
- **Real-Time Display Filtering**: Instantaneous in-memory filtering across protocol, address, port, and search text.
- **4-Quadrant Analytics**: Interactive charts for protocol distribution, traffic timeline, top talkers, and transport splits.
- **Multi-Format Exporters**: Generate formatted CSV tables, JSON structures, Markdown academic reports, and styled HTML summaries.
- **Wireshark Integration**: One-click launcher opening saved PCAPs in Wireshark for external visual verification.

---

## 6. Architecture
NetScope uses a clean 3-tier architecture:
- **Presentation Layer (`app/ui`)**: PySide6 dark theme interface housing top metric cards, packet table, tree view, hex viewer, statistics tab, and visualization tab.
- **Concurrency Layer (`app/workers`)**: `CaptureWorker` (`QThread`) handling asynchronous packet streams.
- **Network Engine Layer (`app/analysis`)**: `PacketAnalyzer`, `ProtocolDecoder`, `FilterEngine`, `StatisticsEngine`.

---

## 7. Technology Stack
- **Programming Language**: Python 3.10+
- **GUI Framework**: PySide6 (Qt for Python)
- **Network Engine**: Scapy 2.5+
- **Visual Analytics**: Matplotlib (QtAgg backend)
- **Testing Framework**: Pytest
- **External Integration**: Wireshark / TShark (optional launcher)

---

## 8. Installation

```bash
# 1. Clone repository
git clone https://github.com/your-username/NetScope.git
cd NetScope

# 2. Create virtual environment
python -m venv .venv
```

---

## 9. Windows Setup

```powershell
# PowerShell Setup
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install -r requirements.txt

# Or execute automated setup script:
.\scripts\setup_windows.ps1
```

---

## 10. Linux Setup

```bash
# Bash Setup
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

# Or execute automated setup script:
bash scripts/setup_linux.sh
```

---

## 11. Running the Application

```bash
# Launch NetScope standard interface
python -m app.main

# Launch directly in Demo Mode
python -m app.main --demo

# Preload a PCAP file upon startup
python -m app.main --pcap sample_data/sample_traffic.pcap
```

---

## 12. Live Capture Instructions
1. Select a physical network interface from the **Network Interface** dropdown.
2. Optional: Enter a BPF Capture Filter (e.g., `tcp port 80`).
3. Click **▶ Start Capture**.
4. Incoming packets populate **Tab 1 (Live Capture)** and update top metric cards in real time.
5. Click **■ Stop Capture** to pause streaming.

---

## 13. PCAP Analysis Instructions
1. Switch to **Tab 5 (PCAP Tools & Export)**.
2. Click **Open PCAP / PCAPNG File**.
3. Select any `.pcap` or `.pcapng` file (or use `sample_data/sample_traffic.pcap`).
4. Packets populate the table, tree view, statistics tables, and visual charts instantly.

---

## 14. Demo Mode Instructions
1. Select `DEMO_MODE (Synthetic Traffic Generator)` in the interface dropdown.
2. Click **▶ Start Capture**.
3. Realistic synthetic packets (DNS, TCP, HTTP, TLS, ICMP, ARP) will stream smoothly without requiring elevated privileges.

---

## 15. Wireshark Integration
- Where Wireshark is installed, clicking **Open Current Capture in Wireshark** launches Wireshark against the active PCAP file.
- If Wireshark is absent, NetScope displays a helpful notification and continues operating standalone.

---

## 16. Testing

NetScope includes an automated test suite verifying packet parsing, filtering, statistics, and PCAP workflows.

```bash
# Run pytest suite
python -m pytest
```

**Results**: 14/14 tests passed in 0.43 seconds.

---

## 17. Project Structure

```
NetScope/
├── app/
│   ├── main.py                  # Main Application Entrypoint
│   ├── capture/                 # Interface Discovery & Management
│   │   ├── interfaces.py
│   │   └── capture_manager.py
│   ├── analysis/                # Core Protocol Parsing & Analysis
│   │   ├── packet_models.py
│   │   ├── protocol_decoder.py
│   │   ├── packet_analyzer.py
│   │   ├── filters.py
│   │   └── statistics.py
│   ├── pcap/                    # PCAP IO & Multi-Format Exporters
│   │   ├── pcap_manager.py
│   │   └── exporters.py
│   ├── ui/                      # PySide6 GUI Widgets & Styles
│   │   ├── main_window.py
│   │   ├── capture_tab.py
│   │   ├── packet_details.py
│   │   ├── statistics_tab.py
│   │   ├── visualization_tab.py
│   │   ├── pcap_tab.py
│   │   └── styles.py
│   ├── workers/                 # Background QThread Capture Workers
│   │   └── capture_worker.py
│   └── utils/                   # Helpers & Logging Setup
│       ├── logging_config.py
│       └── helpers.py
├── tests/                       # Pytest Suite
│   ├── unit/
│   └── integration/
├── sample_data/                 # Synthetic PCAP Dataset
├── docs/                        # Academic Deliverables & Reports
│   ├── ARCHITECTURE.md
│   ├── PROJECT_REPORT.md
│   ├── VIVA_QUESTIONS.md
│   ├── PRESENTATION_CONTENT.md
│   └── DEMO_GUIDE.md
├── scripts/                     # Windows & Linux Setup Scripts
│   ├── setup_windows.ps1
│   ├── setup_linux.sh
│   └── generate_sample_pcap.py
├── screenshots/                 # UI Placeholders & Visual Artifacts
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 18. Screenshots
See `screenshots/README.md` for visual asset mapping.

---

## 19. Limitations
- **Encrypted Payload Decryption**: In compliance with ethical cybersecurity guidelines, encrypted TLS/HTTPS application payloads are not decrypted. Only handshake metadata is extracted.
- **Physical Live Sniffing Privileges**: Physical network interface capture requires Npcap driver and Administrator privileges on Windows. (Mitigated by synthetic Demo Mode).

---

## 20. Future Scope
- TCP stream reassembly for full HTTP body reconstruction.
- GeoIP endpoint mapping for geographical visualization.
- Signature-based network anomaly detection rules.

---

## 21. Ethical & Legal Considerations
Packet sniffing can intercept private communications. NetScope must only be used on authorized networks, local loopbacks, or synthetic demo datasets for diagnostic, educational, and research purposes.

---

## 22. Troubleshooting
- **Missing PySide6/Qt plugin error**: Ensure virtual environment is active and dependencies are reinstalled: `pip install --force-reinstall PySide6`.
- **"Npcap driver not found" on Windows**: Install Npcap in WinPcap API-compatible mode, or select `DEMO_MODE` in NetScope.

---

## 23. References
1. Scapy Documentation: https://scapy.readthedocs.io/
2. Wireshark Documentation: https://www.wireshark.org/docs/
3. PySide6 Qt Documentation: https://doc.qt.io/qtforpython-6/
4. IETF RFC Standards: RFC 791 (IP), RFC 793 (TCP), RFC 768 (UDP), RFC 826 (ARP), RFC 1035 (DNS), RFC 8446 (TLS 1.3).
