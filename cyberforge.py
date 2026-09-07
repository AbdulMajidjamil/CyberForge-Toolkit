#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 CYBERFORGE TOOLKIT  v1.1.0                    ║
║        All-in-one cybersecurity reconnaissance toolkit        ║
║                                                               ║
║   For educational purposes & authorized security testing      ║
║   ONLY. Unauthorized scanning may violate laws/policies.      ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import json
import socket
import datetime
import subprocess
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

try:
    import requests
except ImportError:
    requests = None

# Force UTF-8 output so box-drawing characters render on Windows terminals too
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ------------------------------------------------------------------
#  CONFIGURATION
# ------------------------------------------------------------------
VERSION = "1.1.0"
TIMEOUT = 15
REPORT_DIR = "reports"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BANNER = r"""
╔══════════════════════════════════════════════╗
║         C Y B E R F O R G E  T O O L K I T    ║
║              Version %s                          ║
║   [!] Authorized security testing only.      ║
╚══════════════════════════════════════════════╝
""" % VERSION

MENU = """
 ┌────────────────────────────────────────────────┐
 │            MAIN MENU                           │
 ├────────────────────────────────────────────────┤
 │  1.  Phishing URL Detection                   │
 │  2.  Port Scanner (Nmap)                      │
 │  3.  IP Finder / DNS Lookup                   │
 │  4.  Website Info (WHOIS)                     │
 │  5.  DNS Records (A/AAAA/MX/NS/TXT)           │
 │  6.  Password Strength Analyzer               │
 │  7.  HTTP Headers + Security Audit            │
 │  8.  Subdomain Enumeration (crt.sh)           │
 │  9.  Geolocation Lookup (IP Info)             │
 │ 10.  CMS & Tech Fingerprinting                │
 │ 11.  Directory / Path Brute Force             │
 │ 12.  Hash Identifier & Cracker                │
 │ 13.  Basic SQLi / XSS Parameter Scanner       │
 │ 14.  Email Harvester (OSINT)                  │
 │ 15.  Banner Grabbing                          │
 │ 16.  Google Dork Helper                       │
 │ 17.  CVE Lookup (NVD)                         │
 │ 18.  Export Last Report as JSON               │
 │  0.  Exit                                     │
 └────────────────────────────────────────────────┘
"""

last_report = {}

# ------------------------------------------------------------------
#  COLOR / OUTPUT HELPERS (cross-platform)
# ------------------------------------------------------------------
if os.name == "nt":
    os.system("")  # enable ANSI colors in modern Windows terminals

class C:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"

def info(msg):  print(f"{C.CYAN}[i]{C.RESET} {msg}")
def ok(msg):    print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"{C.RED}[x]{C.RESET} {msg}")

# ------------------------------------------------------------------
#  CORE UTILITIES
# ------------------------------------------------------------------
def run(cmd):
    """Run a subprocess command safely; return combined stdout+stderr."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return r.stdout.strip() or r.stderr.strip()
    except FileNotFoundError:
        err(f"Tool not found: {cmd[0]} - run install.py first.")
    except subprocess.TimeoutExpired:
        err(f"Command timed out after {TIMEOUT}s.")
    except Exception as e:
        err(str(e))
    return ""

def clean_target(t):
    """Strip scheme/path from a user-supplied host."""
    t = t.strip()
    t = re.sub(r"^https?://", "", t, flags=re.I)
    return t.split("/")[0].split("?")[0].split("#")[0]

def has_tool(name):
    return bool(run(["which", name]) if os.name != "nt" else shutil_which(name))

def shutil_which(name):
    import shutil
    return shutil.which(name)

def save_report(name, data):
    """Persist the last result as a JSON file under reports/."""
    os.makedirs(os.path.join(BASE_DIR, REPORT_DIR), exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(BASE_DIR, REPORT_DIR, f"{name}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    ok(f"Report saved: {path}")
    return path

# ------------------------------------------------------------------
#  1. PHISHING URL DETECTION
# ------------------------------------------------------------------
SUSPICIOUS_WORDS = ["login", "verify", "account", "password", "secure",
                    "update", "banking", "confirm", "wallet", "gift",
                    "free", "bonus", "paypal", "signin", "suspend",
                    "unlock", "invoice", "refund", "alert", "prize"]
SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "ow.ly", "buff.ly", "trycloudflare.com", "ngrok.io"]

def phishing_detect():
    url = input("Enter URL: ").strip()
    if not url:
        err("Empty URL."); return
    score, findings = 0, []

    if len(url) > 75:
        score += 2; findings.append("Very long URL (>75 chars)")
    if url.count(".") > 3:
        score += 2; findings.append("Excessive dots/subdomains")
    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 3; findings.append("Raw IP address instead of domain")
    if "@" in url:
        score += 3; findings.append("@ symbol - destination obfuscation")
    if re.search(r"https?://[^/]*\.(?:tk|ml|ga|cf|gq|xyz)\b", url, re.I):
        score += 2; findings.append("Free TLD commonly abused")
    for w in SUSPICIOUS_WORDS:
        if w in url.lower():
            score += 1; findings.append(f"Suspicious keyword: '{w}'")
    for s in SHORTENERS:
        if s in url.lower():
            score += 2; findings.append(f"Tunnel/shortener domain: {s}")
    if url.startswith("http://"):
        score += 1; findings.append("No HTTPS (unencrypted)")

    if score >= 8:   level = "HIGHLY SUSPICIOUS"
    elif score >= 5: level = "SUSPICIOUS"
    elif score >= 2: level = "SLIGHTLY SUSPICIOUS"
    else:            level = "NOT SUSPICIOUS"

    data = {"tool": "phishing", "url": url, "score": score,
            "level": level, "findings": findings}
    print(f"\n{C.BOLD}========== PHISHING URL RESULT =========={C.RESET}")
    print(f" Suspicion Level : {level}")
    print(f" Risk Score      : {score}")
    for f in findings:
        print(f"   - {f}")
    print(f"{C.BOLD}========================================={C.RESET}")
    last_report.update(data)

# ------------------------------------------------------------------
#  2. PORT SCANNER
# ------------------------------------------------------------------
def port_scan():
    target = clean_target(input("Enter target (IP/domain): "))
    ports = input("Ports (default: top 1000, e.g. 22,80,443 or 1-100): ").strip()
    flags = ["nmap", "-sS", "-sV", "--open", "-Pn", target]
    if ports:
        flags += ["-p", ports]
    info(f"SYN scan of {target} (this needs root on Linux)...")
    out = run(flags)
    print(out)
    last_report.update({"tool": "portscan", "target": target,
                        "ports": ports or "top-1000", "result": out})

# ------------------------------------------------------------------
#  3. IP FINDER
# ------------------------------------------------------------------
def ip_finder():
    domain = clean_target(input("Enter domain: "))
    out = run(["dig", "+short", domain])
    ips = [l for l in out.splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l)]
    print(f"IP addresses for {domain}:\n{ips or 'No A records found.'}")
    last_report.update({"tool": "ipfinder", "domain": domain, "ips": ips})

# ------------------------------------------------------------------
#  4. WEBSITE INFO (WHOIS)
# ------------------------------------------------------------------
def website_info():
    domain = clean_target(input("Enter domain: "))
    out = run(["whois", domain])
    keys = r"(Domain Name|Registrar:|Registrar URL|Creation Date|Registry Expiry|Updated Date|Name Server|Status|Registrant Organization)"
    for line in out.splitlines():
        if re.match(r"^\s*" + keys + r":", line, re.I):
            print(line)
    last_report.update({"tool": "whois", "domain": domain, "raw": out[:4000]})

# ------------------------------------------------------------------
#  5. DNS RECORDS
# ------------------------------------------------------------------
def dns_records():
    domain = clean_target(input("Enter domain: "))
    data = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        out = run(["dig", "+short", domain, rtype])
        if out:
            data[rtype] = out.splitlines()
            print(f"{C.BOLD}{rtype}{C.RESET}:\n{out}\n")
    if not data:
        warn("No DNS records found.")
    last_report.update({"tool": "dns", "domain": domain, "records": data})

# ------------------------------------------------------------------
#  6. PASSWORD STRENGTH ANALYZER
# ------------------------------------------------------------------
def password_analyzer():
    import getpass
    if sys.stdin.isatty():
        pw = getpass.getpass("Enter password (hidden input): ")
    else:
        pw = input("Enter password: ")  # fallback for piped/non-tty input
    length = len(pw)
    checks = {
        "length >= 12"      : length >= 12,
        "uppercase letters" : any(c.isupper() for c in pw),
        "lowercase letters" : any(c.islower() for c in pw),
        "digits"            : any(c.isdigit() for c in pw),
        "special characters": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", pw)),
    }
    strength = sum(checks.values())

    # approximate entropy
    pools = 0
    if any(c.islower() for c in pw): pools += 26
    if any(c.isupper() for c in pw): pools += 26
    if any(c.isdigit() for c in pw): pools += 10
    if checks["special characters"]: pools += 33
    entropy = int(length * (pools and __import__("math").log2(pools) or 0))

    if length >= 16 and strength >= 5: label = "STRONGEST"
    elif strength >= 4: label = "STRONG"
    elif strength == 3: label = "MEDIUM"
    elif strength == 2: label = "WEAK"
    else:               label = "VERY WEAK"

    common = ["password", "123456", "qwerty", "admin", "letmein",
              "123456789", "password1", "iloveyou", "abc123"]
    if pw.lower() in common or pw.lower() == "password":
        label, strength, entropy = "VERY WEAK (common password)", 0, 0

    print(f"\n Strength : {C.BOLD}{label}{C.RESET}")
    print(f" Entropy  : ~{entropy} bits")
    print(f" Length   : {length} chars")
    for k, v in checks.items():
        print(f"   [{'+' if v else '-'}] {k}")
    last_report.update({"tool": "password", "strength": label,
                        "entropy": entropy, "checks": checks})

# ------------------------------------------------------------------
#  7. HTTP HEADERS + SECURITY AUDIT
# ------------------------------------------------------------------
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Content-Type-Options", "X-Frame-Options",
                    "Referrer-Policy", "Permissions-Policy"]

def http_headers():
    url = input("Enter URL (e.g. https://example.com): ").strip()
    if not url.startswith("http"):
        url = "https://" + url
    out = run(["curl", "-sSI", "-L", "--max-time", str(TIMEOUT), url])
    if not out:
        err("No response received."); return
    print(out)
    headers = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    print(f"\n{C.BOLD}Security Header Audit:{C.RESET}")
    missing = []
    for h in SECURITY_HEADERS:
        present = h.lower() in headers
        print(f"   [{'+' if present else '-'}] {h}")
        if not present:
            missing.append(h)
    if "server" in headers:
        warn(f"Server disclosure: {headers['server']}")
    if "x-powered-by" in headers:
        warn(f"Tech disclosure: {headers['x-powered-by']}")
    last_report.update({"tool": "headers", "url": url, "missing": missing})

# ------------------------------------------------------------------
#  8. SUBDOMAIN ENUMERATION (crt.sh)
# ------------------------------------------------------------------
def subdomain_enum():
    domain = clean_target(input("Enter domain: "))
    if requests is None:
        err("Module 'requests' required - run: pip3 install requests"); return
    info("Querying crt.sh certificate transparency logs...")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         timeout=TIMEOUT)
        subs = sorted({e["name_value"].lstrip("*.") for e in r.json()})
        for s in subs:
            print(f"   {C.GREEN}>{C.RESET} {s}")
        ok(f"Found {len(subs)} subdomains")
        last_report.update({"tool": "subdomain_enum", "domain": domain,
                            "subdomains": subs})
    except Exception as e:
        err(f"crt.sh query failed: {e}")

# ------------------------------------------------------------------
#  9. GEOLOCATION LOOKUP
# ------------------------------------------------------------------
def geolocation():
    ip = clean_target(input("Enter IP or domain: "))
    if requests is None:
        err("Module 'requests' required - run: pip3 install requests"); return
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        resolved = run(["dig", "+short", ip])
        if resolved:
            ip = resolved.splitlines()[0]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=TIMEOUT).json()
        print(json.dumps(r, indent=2))
        last_report.update({"tool": "geo", "ip": ip, "data": r})
    except Exception as e:
        err(str(e))

# ------------------------------------------------------------------
#  10. CMS & TECH FINGERPRINTING
# ------------------------------------------------------------------
def fingerprint():
    url = input("Enter URL: ").strip()
    if not url.startswith("http"):
        url = "https://" + url
    out = run(["curl", "-sSL", "--max-time", str(TIMEOUT), url])
    sigs = {
        "WordPress" : r"wp-content|wp-includes|wp-json",
        "Joomla"    : r"joomla|com_content",
        "Drupal"    : r"drupal|sites/all/modules",
        "Shopify"   : r"shopify",
        "Wix"       : r"wix\.com|static\.parastorage",
        "React"     : r"__NEXT_DATA__|react",
        "Vue"       : r"vue\.js|__vue__",
        "Bootstrap" : r"bootstrap",
        "jQuery"    : r"jquery",
        "Cloudflare": r"cloudflare",
        "PHP"       : r"\.php|X-Powered-By",
        "nginx"     : r"nginx",
        "Apache"    : r"apache",
    }
    found = [k for k, v in sigs.items() if re.search(v, out, re.I)]
    print(f"Detected technologies: {found or ['None detected']}")
    last_report.update({"tool": "fingerprint", "url": url, "tech": found})

# ------------------------------------------------------------------
#  11. DIRECTORY / PATH BRUTE FORCE
# ------------------------------------------------------------------
def dir_bruteforce():
    url = input("Enter base URL (http://target): ").strip()
    wordlist = input("Wordlist [/usr/share/wordlists/dirb/common.txt]: ").strip() \
               or "/usr/share/wordlists/dirb/common.txt"
    if requests is None:
        err("Module 'requests' required - run: pip3 install requests"); return
    if not os.path.exists(wordlist):
        err("Wordlist not found. Kali: apt install dirb"); return
    info("Starting directory brute force (Ctrl+C to stop)...")
    found = []
    try:
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                path = line.strip().lstrip("/")
                if not path:
                    continue
                if i % 100 == 0:
                    print(f"   ...{i} paths tested", end="\r")
                try:
                    r = requests.get(f"{url}/{path}", timeout=5,
                                     allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403):
                        print(f"   [{r.status_code}] /{path}")
                        found.append({"path": f"/{path}", "status": r.status_code})
                except requests.RequestException:
                    pass
    except KeyboardInterrupt:
        warn("\nScan interrupted by user.")
    ok(f"Done. {len(found)} paths found.")
    last_report.update({"tool": "dirbrute", "url": url, "found": found})

# ------------------------------------------------------------------
#  12. HASH IDENTIFIER & DICTIONARY CRACKER
# ------------------------------------------------------------------
def hash_tool():
    import hashlib
    h = input("Enter hash: ").strip().lower()
    algo = None
    for name, ln in [("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)]:
        if len(h) == ln and re.fullmatch(r"[0-9a-f]+", h):
            algo = name; break
    if not algo:
        err("Unrecognized hash format (supports MD5/SHA1/SHA256/SHA512)."); return
    info(f"Detected algorithm: {algo.upper()}")
    wl = input("Wordlist [/usr/share/wordlists/rockyou.txt]: ").strip() \
         or "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wl):
        err("Wordlist not found."); return
    info("Running dictionary attack...")
    cracked = False
    with open(wl, encoding="latin-1", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if hashlib.new(algo, w.encode()).hexdigest() == h:
                ok(f"CRACKED: {h} -> {C.BOLD}{w}{C.RESET}")
                cracked = True
                break
    if not cracked:
        warn("Not found in wordlist (try a bigger list).")
    last_report.update({"tool": "hash", "hash": h, "algo": algo,
                        "cracked": cracked})

# ------------------------------------------------------------------
#  13. BASIC SQLi / XSS PARAMETER SCANNER
# ------------------------------------------------------------------
def param_scanner():
    url = input("Enter URL with params (http://t/page?id=1&x=2): ").strip()
    if "?" not in url:
        err("No parameters found in URL."); return
    if requests is None:
        err("Module 'requests' required - run: pip3 install requests"); return
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    findings = []
    payloads = {
        "SQLi": ("' OR '1'='1", ["sql", "syntax", "mysql", "warning", "error",
                                 "unterminated", "you have an error"]),
        "XSS" : ("<script>alert(1)</script>", ["<script>alert(1)</script>"]),
    }
    for key in params:
        for vuln, (payload, sigs) in payloads.items():
            test_params = params.copy()
            test_params[key] = payload
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params)))
            try:
                r = requests.get(test_url, timeout=8)
                body = r.text.lower()
                if any(s.lower() in body for s in sigs):
                    ok(f"Possible {vuln} in parameter '{key}'")
                    findings.append({"param": key, "type": vuln})
            except requests.RequestException:
                pass
    if not findings:
        info("No obvious vulnerabilities detected (manual testing still advised).")
    last_report.update({"tool": "paramscan", "url": url, "findings": findings})

# ------------------------------------------------------------------
#  14. EMAIL HARVESTER (OSINT)
# ------------------------------------------------------------------
def email_harvest():
    domain = clean_target(input("Enter domain: "))
    out = run(["curl", "-sSL", "--max-time", "20",
               f"https://www.bing.com/search?q=%22%40{domain}%22&count=50"])
    emails = sorted(set(re.findall(rf"[\w.\-]+@{re.escape(domain)}", out)))
    for e in emails:
        print(f"   {C.GREEN}>{C.RESET} {e}")
    ok(f"Found {len(emails)} emails")
    last_report.update({"tool": "email_harvest", "domain": domain,
                        "emails": emails})

# ------------------------------------------------------------------
#  15. BANNER GRABBING
# ------------------------------------------------------------------
def banner_grab():
    host = clean_target(input("Host: "))
    port = int(input("Port [80]: ") or 80)
    try:
        s = socket.create_connection((host, port), timeout=8)
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\nUser-Agent: CyberForge/1.0\r\n\r\n"
                  % host.encode())
        banner = s.recv(1024).decode(errors="ignore")
        print(banner or "(empty banner)")
        s.close()
    except Exception as e:
        err(str(e))
    last_report.update({"tool": "banner", "host": host, "port": port,
                        "banner": banner if 'banner' in dir() else ""})

# ------------------------------------------------------------------
#  16. GOOGLE DORK HELPER
# ------------------------------------------------------------------
DORKS = {
    "1": ("Admin Panels", "inurl:admin OR inurl:login"),
    "2": ("Exposed Files", "filetype:sql OR filetype:env OR filetype:log"),
    "3": ("Open Directories", "intitle:index.of"),
    "4": ("Sensitive Docs", "filetype:pdf OR filetype:docx site:target.com"),
    "5": ("Backup Files", "filetype:bak OR filetype:old OR filetype:swp"),
    "6": ("Login Pages", "inurl:login OR inurl:signin"),
    "7": ("Exposed Credentials", "filetype:txt intext:password"),
    "8": ("WordPress Files", "inurl:wp-content"),
}

def google_dork():
    print("\n Select a dork category:")
    for k, (name, _) in DORKS.items():
        print(f"   {k}. {name}")
    choice = input("Choice: ").strip()
    domain = input("Target domain (optional, Enter to skip): ").strip()
    if choice not in DORKS:
        err("Invalid choice."); return
    dork = DORKS[choice][1]
    if domain:
        dork += f" site:{domain}"
    print(f"\n{C.BOLD}Google Dork:{C.RESET} {dork}")
    print(f"{C.YELLOW}Use it in google.com/search?q={dork.replace(' ', '%20')}{C.RESET}")
    last_report.update({"tool": "dork", "category": DORKS[choice][0], "dork": dork})

# ------------------------------------------------------------------
#  17. CVE LOOKUP (NVD)
# ------------------------------------------------------------------
def cve_lookup():
    q = input("Search CVE (e.g. 'wordpress plugin', 'CVE-2024-1234'): ").strip()
    if requests is None:
        err("Module 'requests' required - run: pip3 install requests"); return
    try:
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={q}&resultsPerPage=10", timeout=TIMEOUT)
        vulns = r.json().get("vulnerabilities", [])
        for item in vulns:
            c = item["cve"]
            metrics = c.get("metrics", {}).get("cvssMetricV31", [{}])
            score = metrics[0].get("cvssData", {}).get("baseScore", "N/A")
            desc = c["descriptions"][0]["value"][:120]
            print(f"{C.RED}[{c['id']}] CVSS:{score}{C.RESET} {desc}")
        if not vulns:
            info("No CVEs found for that search.")
    except Exception as e:
        err(f"NVD query failed: {e}")

# ------------------------------------------------------------------
#  MAIN ENTRY POINT
# ------------------------------------------------------------------
TOOLS = {1: phishing_detect, 2: port_scan, 3: ip_finder, 4: website_info,
         5: dns_records, 6: password_analyzer, 7: http_headers,
         8: subdomain_enum, 9: geolocation, 10: fingerprint,
         11: dir_bruteforce, 12: hash_tool, 13: param_scanner,
         14: email_harvest, 15: banner_grab, 16: google_dork,
         17: cve_lookup}

def main():
    # root / dependency pre-flight checks
    try:
        if os.geteuid() != 0:
            warn("Some tools (nmap -sS) need root on Linux - use: sudo python3 cyberforge.py")
    except AttributeError:
        pass  # Windows - no geteuid

    if os.name != "nt":
        for t in ["nmap", "dig", "whois", "curl"]:
            if not has_tool(t):
                warn(f"Missing dependency: {t} - run install.py")

    print(BANNER)
    while True:
        print(MENU)
        try:
            choice = int(input("ENTER: ").strip())
        except ValueError:
            continue
        except EOFError:
            print()
            ok("Goodbye. Stay ethical. - CyberForge Toolkit")
            sys.exit(0)
        if choice == 0:
            if last_report:
                save_report("session", last_report)
            ok("Goodbye. Stay ethical. - CyberForge Toolkit")
            sys.exit(0)
        elif choice == 18:
            if last_report:
                save_report("manual", last_report)
            else:
                warn("No results to export yet.")
        elif choice in TOOLS:
            try:
                TOOLS[choice]()
            except KeyboardInterrupt:
                warn("\nCancelled by user.")
            except Exception as e:
                err(f"Unexpected error: {e}")
        else:
            err("Invalid option.")
        print()

if __name__ == "__main__":
    main()