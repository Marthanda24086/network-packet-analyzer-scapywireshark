#!/usr/bin/env bash
# NetScope Automated Linux Setup Script
# Run from repository root: bash scripts/setup_linux.sh

set -e

echo "========================================================="
echo " NetScope - Packet Sniffing & Protocol Analysis Tool"
echo " Linux Environment Setup"
echo "========================================================="

if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed."
    exit 1
fi

echo "[+] Python version: $(python3 --version)"

if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "[+] Installing dependencies..."
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

echo "[+] Generating sample PCAP dataset..."
./.venv/bin/python scripts/generate_sample_pcap.py

echo "[+] Running test suite..."
./.venv/bin/python -m pytest

echo "========================================================="
echo " Setup Complete! Launch with:"
echo "   ./.venv/bin/python -m app.main"
echo "========================================================="
