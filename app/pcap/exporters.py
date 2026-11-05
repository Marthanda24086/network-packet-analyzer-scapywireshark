"""
Exporter module for NetScope.
Generates CSV, JSON, Markdown, and HTML reports from captured packet data.
"""

import csv
import json
import os
import datetime
from typing import List, Dict, Any, Tuple, Optional
from app.analysis.packet_models import PacketRecord
from app.analysis.statistics import StatisticsEngine


class Exporter:
    """Handles formatted report exports across multiple formats."""

    @staticmethod
    def export_csv(file_path: str, records: List[PacketRecord]) -> Tuple[bool, Optional[str]]:
        """Exports summary table of packet records to CSV format."""
        try:
            fieldnames = [
                "No.", "Timestamp", "Source MAC", "Destination MAC",
                "Source IP", "Destination IP", "Protocol", "Transport Protocol",
                "Source Port", "Destination Port", "Length", "Info"
            ]
            with open(file_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(fieldnames)
                for r in records:
                    writer.writerow([
                        r.packet_num,
                        r.formatted_time,
                        r.src_mac,
                        r.dst_mac,
                        r.src_ip,
                        r.dst_ip,
                        r.protocol,
                        r.transport_protocol,
                        r.src_port or "",
                        r.dst_port or "",
                        r.length,
                        r.info
                    ])
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_json(file_path: str, records: List[PacketRecord]) -> Tuple[bool, Optional[str]]:
        """Exports detailed structured packet records to JSON format."""
        try:
            data = {
                "generated_at": datetime.datetime.now().isoformat(),
                "total_packets": len(records),
                "packets": [r.to_dict() for r in records]
            }
            with open(file_path, mode='w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_markdown_report(file_path: str, records: List[PacketRecord], capture_source: str = "Live Capture") -> Tuple[bool, Optional[str]]:
        """Generates a comprehensive Markdown analysis report."""
        try:
            stats = StatisticsEngine.calculate_summary(records)
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            top_src_str = "\n".join([f"- **{ip}**: {count} packets" for ip, count in stats["top_sources"]]) or "None"
            top_dst_str = "\n".join([f"- **{ip}**: {count} packets" for ip, count in stats["top_destinations"]]) or "None"
            proto_str = "\n".join([f"- **{proto}**: {count}" for proto, count in stats["protocol_counts"].items()]) or "None"

            content = f"""# NetScope Traffic Analysis Report

**Analysis Timestamp**: {now_str}  
**Capture Source**: {capture_source}  

---

## 1. Executive Summary

| Metric | Value |
| :--- | :--- |
| **Total Packets Captured** | {stats['total_packets']} |
| **Total Bytes Transferred** | {stats['total_bytes']:,} bytes |
| **Average Packet Size** | {stats['avg_packet_size']} bytes |
| **Min / Max Packet Size** | {stats['min_packet_size']} / {stats['max_packet_size']} bytes |
| **Unique Source IPs** | {stats['unique_sources']} |
| **Unique Destination IPs** | {stats['unique_destinations']} |

---

## 2. Protocol Breakdown

{proto_str}

---

## 3. Top Endpoint Analysis

### Top Source Addresses
{top_src_str}

### Top Destination Addresses
{top_dst_str}

---

## 4. Ethical & Compliance Notice
This capture analysis was conducted using **NetScope** strictly for authorized network monitoring, diagnostic, and educational evaluation purposes. Payload data is inspected in compliance with ethical privacy guidelines.
"""
            with open(file_path, mode='w', encoding='utf-8') as f:
                f.write(content)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_html_report(file_path: str, records: List[PacketRecord], capture_source: str = "Live Capture") -> Tuple[bool, Optional[str]]:
        """Generates a styled, interactive-like static HTML report."""
        try:
            stats = StatisticsEngine.calculate_summary(records)
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            rows_html = ""
            for r in records[:100]:  # Limit top 100 for fast HTML render
                rows_html += f"""
                <tr>
                    <td>{r.packet_num}</td>
                    <td>{r.formatted_time}</td>
                    <td>{r.src_ip}</td>
                    <td>{r.dst_ip}</td>
                    <td><span class="badge">{r.protocol}</span></td>
                    <td>{r.length}</td>
                    <td>{r.info}</td>
                </tr>
                """

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetScope Traffic Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .header {{ background: #1e293b; padding: 20px; border-radius: 8px; border-left: 5px solid #3b82f6; margin-bottom: 24px; }}
        h1 {{ margin: 0 0 10px 0; font-size: 24px; color: #60a5fa; }}
        .cards {{ display: flex; gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #1e293b; padding: 16px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #334155; }}
        .card .val {{ font-size: 28px; font-weight: bold; color: #38bdf8; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
        .badge {{ background: #1d4ed8; color: #eff6ff; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NetScope Protocol Analysis Summary Report</h1>
        <p><strong>Source:</strong> {capture_source} | <strong>Generated:</strong> {now_str}</p>
    </div>

    <div class="cards">
        <div class="card">
            <div>Total Packets</div>
            <div class="val">{stats['total_packets']}</div>
        </div>
        <div class="card">
            <div>Total Bytes</div>
            <div class="val">{stats['total_bytes']:,}</div>
        </div>
        <div class="card">
            <div>Avg Packet Size</div>
            <div class="val">{stats['avg_packet_size']} B</div>
        </div>
        <div class="card">
            <div>Unique Endpoints</div>
            <div class="val">{stats['unique_sources'] + stats['unique_destinations']}</div>
        </div>
    </div>

    <h2>Captured Packets Preview (Top 100)</h2>
    <table>
        <thead>
            <tr>
                <th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>
"""
            with open(file_path, mode='w', encoding='utf-8') as f:
                f.write(html_content)
            return True, None
        except Exception as e:
            return False, str(e)
