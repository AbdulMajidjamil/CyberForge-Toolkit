# 🔥 CyberForge Toolkit

> An advanced, all-in-one cybersecurity reconnaissance & analysis toolkit built with Python.

**CyberForge Toolkit** is a beginner-friendly Python CLI that bundles phishing URL analysis, network reconnaissance, DNS analysis, OSINT gathering, vulnerability scanning basics, and password auditing into a single interface — now upgraded to PRO level with 17+ tools, colored output, JSON report export, and robust error handling.

---

## ⚠️ Disclaimer

This project is intended for **educational purposes and authorized security testing only**. Do not scan or investigate systems, networks, or websites without explicit permission. Unauthorized port scanning, reconnaissance, or information gathering may violate laws, policies, or terms of service. The author is **not responsible** for misuse of this software.

---

## 🚀 Features

| # | Tool | Description |
|---|------|-------------|
| 1 | **Phishing URL Detection** | Heuristic risk scoring (length, dots, IP, `@`, suspicious words, shorteners, free TLDs) |
| 2 | **Port Scanner** | Nmap TCP SYN scan with service detection (`-sS -sV`) |
| 3 | **IP Finder** | DNS lookup via `dig +short` |
| 4 | **Website Info** | WHOIS registration details |
| 5 | **DNS Records** | A, AAAA, MX, NS, TXT, CNAME, SOA via `dig` |
| 6 | **Password Analyzer** | Length, character classes, entropy estimate → STRONGEST → VERY WEAK |
| 7 | **HTTP Headers** | `curl -I` + security header audit (HSTS, CSP, XFO, etc.) |
| 8 | **Subdomain Enumeration** | crt.sh certificate transparency logs |
| 9 | **Geolocation Lookup** | IP → country, city, ISP via ip-api.com |
| 10 | **CMS & Tech Fingerprinting** | Detect WordPress, React, Cloudflare, nginx, etc. |
| 11 | **Directory Brute Force** | Wordlist-based path discovery |
| 12 | **Hash Identifier & Cracker** | MD5/SHA1/SHA256/SHA512 detection + dictionary attack |
| 13 | **SQLi / XSS Parameter Scanner** | Basic injection testing on URL parameters |
| 14 | **Email Harvester** | OSINT email discovery for a domain |
| 15 | **Banner Grabbing** | Service banner extraction |
| 16 | **Google Dork Helper** | Ready-made dork templates |
| 17 | **CVE Lookup** | NVD API search with CVSS scores |
| 18 | **JSON Report Export** | Save any result to `reports/` |

---

## 🛠️ Technologies Used

- Python 3
- Subprocess
- Regular Expressions (`re`)
- Nmap
- DNS / `dig` (dnsutils)
- WHOIS
- cURL
- `requests` (HTTP/API)
- Linux Terminal

## 📁 Project Structure

```
cyberforge-toolkit/
│
├── cyberforge.py       # Main application (all 17 tools + CLI)
├── install.py          # One-time dependency installer
├── README.md           # Documentation
├── LICENSE             # MIT License
└── .gitignore
```

---

## 💻 Requirements

Designed for **Kali Linux / Ubuntu / Debian-based distributions**.

Required software (auto-installed by `install.py`):

| Package | Purpose |
|---------|---------|
| `python3` | Runtime |
| `nmap` | Port scanning |
| `dnsutils` | `dig` DNS queries |
| `whois` | Domain registration info |
| `curl` | HTTP requests / headers |
| `dirb` | Wordlists for brute forcing |
| `python3-requests` | HTTP APIs (crt.sh, ip-api, NVD) |

---

## ⚙️ Installation

```bash
git clone https://github.com/AbdulMajidjamil/cyberforge-toolkit.git
cd cyberforge-toolkit
python3 install.py
```

Or install manually:

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap dnsutils whois curl dirb
pip3 install requests
```

---

## ▶️ Usage

```bash
sudo python3 cyberforge.py     # sudo needed for nmap SYN scan
```

You will see the main menu:

```
╔══════════════════════════════════════════════╗
║         C Y B E R F O R G E  T O O L K I T    ║
║              Version 1.1.0                    ║
║   [!] Authorized security testing only.      ║
╚══════════════════════════════════════════════╝
```

Then enter the number of the tool you want:

```
ENTER: 1

Enter URL: https://example.com/login

========== PHISHING URL RESULT ==========
 Suspicion Level : NOT SUSPICIOUS
 Risk Score      : 0
=========================================
```

### Example: DNS Records
```
ENTER: 5

Enter domain: example.com

A:
93.184.216.34

MX:
0 .  (null MX)
```

### Example: HTTP Headers + Security Audit
```
ENTER: 7

Enter URL: https://example.com

HTTP/2 200
server: nginx
...

Security Header Audit:
   [-] Strict-Transport-Security
   [-] Content-Security-Policy
   [+]
```

### Export Report
Run any tool, then:

```
ENTER: 18
[+] Report saved: reports/manual_20260907_123456.json
```

---

## 🔧 How It Works

The toolkit uses Python's `subprocess` module to drive battle-tested Linux networking tools:

```python
subprocess.run(["nmap", "-sS", "-sV", "--open", target])
subprocess.run(["dig", "+short", domain])
subprocess.run(["whois", domain])
subprocess.run(["curl", "-sSI", "-L", url])
```

Online APIs (`requests` module) power the modern features:

- **crt.sh** — certificate transparency subdomain discovery
- **ip-api.com** — IP geolocation
- **NVD NIST API** — CVE search

The phishing detector uses `re` (regular expressions) for pattern matching and a weighted scoring system. A suspicious result **does not** automatically mean a URL is malicious.

---

## 🎯 Learning Objectives

This project was built to practice:

- Python programming & CLI development
- Linux command-line tools
- Network reconnaissance & scanning
- DNS concepts & domain enumeration
- OSINT & information gathering
- HTTP fundamentals & security headers
- Password security & entropy
- Phishing URL analysis
- Regular expressions
- Subprocess management
- API integration (REST/JSON)

---

## 🔮 Future Improvements

- [ ] Automated subdomain brute forcing (wordlist + CT logs)
- [ ] Port scan result parsing & visualization
- [ ] HTML/PDF report generation
- [ ] More DNS record types & DNSSEC checks
- [ ] HTTP security-header scoring (OWASP standards)
- [ ] Better input validation & logging
- [ ] Multi-threaded scanning
- [ ] YAML/JSON configuration files
- [ ] Integration with Shodan / VirusTotal APIs

---

## 📜 License

[MIT](LICENSE) © 2026

---

## ⭐ Support

If you find this project useful, consider starring ⭐ the repository and sharing it with fellow security learners!