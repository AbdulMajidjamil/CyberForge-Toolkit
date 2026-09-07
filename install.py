#!/usr/bin/env python3
"""
CyberForge Toolkit - one-time installer
Targets: Kali Linux / Ubuntu / Debian-based distributions
"""

import subprocess
import sys

PACKAGES = [
    "python3",
    "python3-pip",
    "nmap",
    "dnsutils",
    "whois",
    "curl",
    "dirb",
]

def run_cmd(cmd):
    subprocess.run(cmd, check=False)

def main():
    print("[*] CyberForge Toolkit installer")
    print("[*] Updating package lists...")
    run_cmd(["sudo", "apt", "update"])

    print("[*] Installing packages...")
    run_cmd(["sudo", "apt", "install", "-y", *PACKAGES])

    print("[*] Installing Python module: requests")
    run_cmd([sys.executable, "-m", "pip", "install",
             "--break-system-packages", "requests"])

    print("[+] Done! Run: sudo python3 cyberforge.py")
    print("[i] Note: nmap SYN scan (-sS) requires root/sudo.")

if __name__ == "__main__":
    main()