"""
Helper functions for NetScope application environment, Wireshark integration,
and formatting utilities.
"""

import os
import ctypes
import platform
import subprocess
from typing import Optional, List


def is_admin() -> bool:
    """Checks whether current process has administrative/root privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def find_wireshark_path() -> Optional[str]:
    """Finds Wireshark executable binary path on current system."""
    system = platform.system()

    if system == "Windows":
        possible_paths = [
            r"C:\Program Files\Wireshark\Wireshark.exe",
            r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\Wireshark.exe")
        ]
        for p in possible_paths:
            if os.path.exists(p):
                return p
    else: # Linux / macOS
        for binary in ["wireshark", "tshark"]:
            try:
                res = subprocess.run(["which", binary], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
            except Exception:
                pass

    return None


def open_pcap_in_wireshark(pcap_path: str) -> Tuple[bool, str]:
    """Launches Wireshark executable against specified PCAP file."""
    ws_bin = find_wireshark_path()
    if not ws_bin:
        return False, "Wireshark executable was not found on this system. Please install Wireshark."

    if not os.path.exists(pcap_path):
        return False, f"PCAP file does not exist: {pcap_path}"

    try:
        subprocess.Popen([ws_bin, pcap_path])
        return True, f"Launched Wireshark with {pcap_path}"
    except Exception as e:
        return False, f"Failed to launch Wireshark: {str(e)}"


def format_hex_dump(raw_hex: str) -> str:
    """Formats raw hex string into traditional Wireshark-style hex dump view."""
    if not raw_hex:
        return "No binary payload"

    try:
        raw_bytes = bytes.fromhex(raw_hex)
    except Exception:
        return raw_hex

    lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<48}  |{ascii_part}|")

    return '\n'.join(lines)
