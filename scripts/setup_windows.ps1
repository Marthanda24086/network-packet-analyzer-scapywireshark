# NetScope Automated Windows Environment Setup Script
# Run from repository root in PowerShell: .\scripts\setup_windows.ps1

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " NetScope - Packet Sniffing & Protocol Analysis Tool" -ForegroundColor Cyan
Write-Host " Windows Environment Setup & Dependency Verification" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# 1. Check Python version
try {
    $pythonVer = & python --version 2>&1
    Write-Host "[+] Python Detected: $pythonVer" -ForegroundColor Green
} catch {
    Write-Host "[!] Error: Python 3.10+ is required but python command was not found." -ForegroundColor Red
    Exit 1
}

# 2. Check Virtual Environment
if (-Not (Test-Path ".venv")) {
    Write-Host "[+] Creating Virtual Environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
} else {
    Write-Host "[+] Virtual Environment (.venv) already exists." -ForegroundColor Green
}

# 3. Upgrade Pip & Install Dependencies
Write-Host "[+] Installing project dependencies from requirements.txt..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\pip.exe install -r requirements.txt

# 4. Generate Sample PCAP Data
Write-Host "[+] Generating synthetic sample PCAP dataset..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe scripts/generate_sample_pcap.py

# 5. Run Pytest Suite
Write-Host "[+] Running pytest test suite..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pytest

# 6. Check Wireshark / Npcap Environment Status
Write-Host "`n---------------- Environment Audit ----------------" -ForegroundColor Cyan
$wsFound = Test-Path "C:\Program Files\Wireshark\Wireshark.exe"
if ($wsFound) {
    Write-Host "[+] Wireshark Installation: FOUND (Wireshark GUI integration available)" -ForegroundColor Green
} else {
    Write-Host "[!] Wireshark Installation: NOT FOUND (Application will operate cleanly with built-in viewer)" -ForegroundColor Yellow
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[+] Privileges: ADMINISTRATOR (Live physical interface capture enabled)" -ForegroundColor Green
} else {
    Write-Host "[!] Privileges: STANDARD USER (Use DEMO_MODE or load PCAP files for project review)" -ForegroundColor Yellow
}

Write-Host "`n=========================================================" -ForegroundColor Cyan
Write-Host " Setup Complete! To launch NetScope run:" -ForegroundColor Green
Write-Host "   .\.venv\Scripts\python.exe -m app.main" -ForegroundColor White
Write-Host "   .\.venv\Scripts\python.exe -m app.main --demo" -ForegroundColor White
Write-Host "=========================================================" -ForegroundColor Cyan
