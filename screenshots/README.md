# NetScope UI Screenshots & Visual Artifacts Directory

This directory contains real, high-resolution PNG captures rendered directly from the running PySide6 application with sample traffic loaded.

## Screenshot Index

1. **`01_live_capture_table.png`**  
   *Main Packet Summary Table*: Displays live packet stream with packet number, timestamp, source IP, destination IP, protocol badges, length, and human-readable info summary. Also shows the top metric cards (Packets, Total Bytes, Protocols, Unique Sources, Unique Destinations) and the network interface capture controls.

2. **`02_packet_details_tree_hex.png`**  
   *Packet Details & Hex Viewer*: Shows the hierarchical protocol decomposition tree view (Frame -> Ethernet II -> IPv4 -> TCP) with individual field values and descriptions, alongside the Wireshark-style 16-byte aligned hexadecimal and ASCII payload dump.

3. **`03_statistics_dashboard.png`**  
   *Statistics Tab*: Renders four structured breakdown tables: Protocol Distribution (% of total), Transport Protocol Split, Top Source IP Endpoints, and Top Destination IP Endpoints.

4. **`04_visual_analytics_charts.png`**  
   *Visual Analytics Tab*: Embedded Matplotlib charts in a 4-quadrant layout:
   - Protocol Breakdown (Pie Chart)
   - Packets per Second Timeline (Line Chart with area fill)
   - Top Source IP Endpoints (Horizontal Bar Chart)
   - Transport Protocol Split (Bar Chart)

5. **`05_pcap_exporter.png`**  
   *PCAP Analysis & Export Tab*: Shows PCAP/PCAPNG file operations, Wireshark status and launcher integration, and multi-format report exporter options (CSV, JSON, Markdown, HTML).

To regenerate these screenshots at any time:
```powershell
python scripts/generate_screenshots.py
```
