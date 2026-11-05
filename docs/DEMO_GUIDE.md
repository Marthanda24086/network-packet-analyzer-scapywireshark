# NetScope — 5-Minute Viva Demonstration Guide

This guide details the step-by-step sequence for presenting **NetScope** to college project evaluators in approximately 5 minutes.

---

## Pre-Demo Checklist (30 seconds before review)
1. Open PowerShell / Command Prompt in project root (`d:\CN_CBP`).
2. Verify virtual environment exists (`.venv`).
3. Have sample PCAP ready in `sample_data/sample_traffic.pcap`.

---

## 5-Minute Demonstration Sequence

### Step 1: Launch Application (30 seconds)
Launch NetScope using the synthetic demo flag or standard launcher:
```powershell
.\.venv\Scripts\python.exe -m app.main
```
Point out:
- Dark monitoring theme aesthetic and application header.
- Dynamic metric summary cards at the top (Packets, Bytes, Protocols, Unique Src, Unique Dst).
- Interface dropdown showing system adapters and `DEMO_MODE`.
- Privilege status indicator ("Standard User" or "Administrator").

---

### Step 2: Start Synthetic Demo Stream (1 minute)
1. Ensure Interface dropdown is set to `DEMO_MODE (Synthetic Traffic Generator)`.
2. Click **▶ Start Capture**.
3. Observe live packets populating the table in **Tab 1 (Live Capture)**:
   - Packet sequence numbers, formatted timestamps, source/destination IPs, protocol badges, lengths, and human-readable summaries.
   - Metric cards at top updating dynamically in real time.
4. Click **■ Stop Capture** after 20–30 packets arrive.

---

### Step 3: Demonstrate Protocol Layer Dissection & Hex View (1 minute)
1. In **Tab 1 (Live Capture)**, click a **DNS** or **TCP** or **HTTP** packet row.
2. Switch to **Tab 2 (Packet Details)**.
3. Show the **Protocol Tree View**:
   - Expand `Frame #X` -> `Ethernet II` -> `IPv4` -> `TCP/UDP` -> `Application Layer`.
   - Point out decoded field names, values, and tooltips.
4. Show the **Hexadecimal View**:
   - Point out the 16-byte formatted Wireshark-style hex dump aligned with ASCII representation.

---

### Step 4: Apply Display Filters (45 seconds)
1. Switch back to **Tab 1 (Live Capture)**.
2. In the Protocol filter dropdown, select **TCP**. Click **Apply Filter**.
   - Show that table updates to display only TCP frames.
3. In the Search field, type `google.com` or an IP address. Click **Apply Filter**.
4. Click **Reset** to restore full table.

---

### Step 5: Show Statistics & Visual Analytics (45 seconds)
1. Click **Tab 3 (Statistics)**:
   - Point out Protocol Distribution table, Transport Protocol Split, Top Source IP Endpoints, and Top Destination IP Endpoints.
2. Click **Tab 4 (Visual Analytics)**:
   - Show the 4 Matplotlib charts (Protocol Pie Chart, Packets Timeline, Top Sources Bar Chart, Transport Split Bar Chart).

---

### Step 6: Load PCAP & Export Reports (1 minute)
1. Click **Tab 5 (PCAP Tools & Export)**.
2. Click **Open PCAP / PCAPNG File**.
3. Select `sample_data/sample_traffic.pcap`.
4. Point out file metadata card (`sample_traffic.pcap`, packet count, file size).
5. Demonstrate report export:
   - Select **HTML Summary (.html)** or **Markdown Report (.md)** in the dropdown.
   - Click **Export Analysis Report** and save to `export_report.html`.
6. (Optional if Wireshark installed): Click **Open Current Capture in Wireshark** to demonstrate external validation.

---

## Backup Pathways

### Scenario A: Live Physical Capture Fails / Npcap Missing
- **Action**: Use `DEMO_MODE` or load `sample_data/sample_traffic.pcap`. Explain that NetScope incorporates an autonomous synthetic stream specifically designed to ensure 100% demonstrability offline.

### Scenario B: Wireshark Binary Not Installed
- **Action**: Click **Open Current Capture in Wireshark**. When the informative warning dialog appears ("Wireshark Executable Not Found"), explain that NetScope operates cleanly as a standalone viewer and does not hard-depend on external binaries.
