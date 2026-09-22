# ReconX — Bash Reconnaissance & Enumeration Toolkit

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Debian%20%7C%20Ubuntu-lightgrey.svg)](https://www.kali.org)
[![Security](https://img.shields.io/badge/policy-Authorized%20Testing%20Only-red.svg)](README.md#authorization-notice)
[![Report](https://img.shields.io/badge/report-Standalone%20HTML5%20Dashboard-green.svg)](README.md#html-report-architecture)

**ReconX** is a modular, professional Bash-based reconnaissance and attack-surface enumeration framework engineered for authorized penetration testing, red teaming, security auditing, and educational cyber lab environments.

It automates multi-stage intelligence gathering across network targets (domains, hostnames, IPv4 addresses, and CIDR subnet ranges) and synthesizes the findings into a dark-mode, self-contained HTML5 dashboard.

---

## ⚠ Authorization Notice & Rules of Engagement

> **CRITICAL LEGAL NOTICE:**
> This software is created and distributed strictly for **AUTHORIZED SECURITY AUDITING AND LAB PURPOSES ONLY**. 
> - You must possess explicit, written permission from the system/network owner prior to executing any reconnaissance scans against target infrastructure.
> - Scanning targets without authorization is illegal and punishable under computer crime legislation (e.g., US CFAA, UK Computer Misuse Act, and equivalent international statutes).
> - **ReconX is non-exploitative and non-destructive:** It does NOT include brute-force attacks, exploits, denial-of-service (DoS) routines, password cracking, malware payloads, or persistent backdoors.

---

## Features & Capabilities

- **Strict POSIX/Bash Standards:** Designed with `set -o pipefail`, robust signal interception (`SIGINT`/`SIGTERM`), and secure variable/array handling (zero unsafe `eval`).
- **Input Validation:** Automatically distinguishes and verifies Domain names, Hostnames, IPv4 addresses, and CIDR subnets while neutralizing shell metacharacter injections.
- **Dependency Sentinel:** Pre-flight verification of all required system utilities (`ping`, `dig`, `whois`, `nmap`, `awk`, `grep`, `sed`, `sort`, `uniq`, `date`, `mkdir`, `tee`, `hostname`, `ip`).
- **ICMP Reachability Analysis:** 4-probe safe ping with calculation of transmitted/received packets, packet loss percentage, and min/avg/max round-trip latency.
- **Comprehensive DNS Enumeration:** Automated querying across all major resource record types (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `SRV`, `CAA`, `ANY`), authoritative hierarchical delegation tracing (`dig +trace`), and reverse DNS pointer lookups (`dig -x`).
- **WHOIS Registration Intelligence:** Extracts registrant domain metadata, registrar identity, lifecycle dates (created, updated, expired), and geographical origin while handling privacy and missing records gracefully.
- **Nmap Host Discovery & Port Scanning:**
  - Non-intrusive ping-sweeps (`-sn`) for live host identification.
  - Safe TCP connect scanning (`-sT`) across top 100 ports or complete 65,535 TCP range (`-p-`).
  - Service version banner inspection (`-sV --version-light`).
  - Graceful root-aware OS fingerprinting (`-O`) with non-root fallback.
- **Safe NSE Categorization:** Curated, non-intrusive Nmap Scripting Engine (NSE) modules triggered conditionally based on detected services (HTTP headers, SSL/TLS cipher suites and certificates, DNS discovery).
- **Optional Vulnerability Advisory Gathering:** Opt-in non-exploitative advisory correlation (`--vuln`) flagging version-based potential findings for manual verification.
- **Standalone HTML5 Dashboard:**
  - Responsive cybersecurity dark theme (no CDN or external JavaScript dependencies required).
  - Executive KPI metrics, interactive tables, status badges, and collapsible `<details><summary>` raw command archives.
  - Strict HTML entity escaping (`&`, `<`, `>`, `"`, `'`) preventing injection or display distortion.
- **Signal-Safe Partial Recovery:** If interrupted via `Ctrl+C`, ReconX safely terminates background tasks, preserves all accumulated logs, and renders a partial HTML report.

---

## Directory Architecture

```
d:\Recon tool\ (or reconx/)
├── reconx.sh                 # Main executable Bash reconnaissance engine
├── config/
│   └── safe-nse.conf         # Configuration of vetted, non-destructive NSE scripts
├── README.md                 # Technical documentation & reference manual
└── reports/                  # Default output repository
    └── <target>_<timestamp>/ # Isolated folder created per scan run
        ├── report.html       # Standalone interactive cybersecurity dashboard
        ├── reconx.log        # Unified operational log (INFO, WARNING, ERROR, SUCCESS)
        ├── ping.txt          # Raw ICMP echo probe results
        ├── whois.txt         # Raw domain & network registration record
        ├── dns/              # Dedicated directory for all individual DNS outputs
        │   ├── dns_a.txt
        │   ├── dns_aaaa.txt
        │   ├── dns_mx.txt
        │   ├── dns_ns.txt
        │   ├── dns_txt.txt
        │   ├── dns_soa.txt
        │   ├── dns_cname.txt
        │   ├── dns_srv.txt
        │   ├── dns_caa.txt
        │   ├── dns_any.txt
        │   ├── dns_trace.txt
        │   └── reverse_dns.txt
        ├── nmap/             # Nmap discovery, port, service, and OS logs
        │   ├── nmap_host_discovery.txt
        │   ├── nmap_top100.txt
        │   ├── nmap_all_tcp.txt (Full mode)
        │   ├── nmap_service_detection.txt
        │   ├── nmap_os_detection.txt
        │   └── nmap_default_scripts.txt
        └── nse/              # Granular NSE enumeration logs
            ├── nse_safe.txt
            ├── nse_http.txt
            ├── nse_ssl.txt
            ├── nse_dns.txt
            └── nse_vulnerability_scan.txt (When --vuln is specified)
```

---

## Installation & Prerequisites

ReconX is optimized for **Kali Linux**, Debian, and Ubuntu environments.

### 1. Update Package Index & Install Dependencies
```bash
sudo apt update
sudo apt install -y dnsutils whois nmap iputils-ping coreutils iproute2
```

### 2. Clone or Copy the Repository
```bash
git clone https://github.com/your-org/reconx.git
cd reconx
```

### 3. Ensure Execution Permissions & Unix Line Endings
```bash
chmod +x reconx.sh
# Ensure files have Unix LF line endings (especially when moved from Windows)
sed -i 's/\r$//' reconx.sh config/safe-nse.conf
```

---

## CLI Usage & Options

### Command Syntax
```bash
./reconx.sh [TARGET] [OPTIONS]
./reconx.sh -t TARGET [OPTIONS]
```

### Scan Modes
| Option | Mode | Modules Executed |
|---|---|---|
| `-q`, `--quick` | **Quick Scan** | ICMP Ping, DNS Queries, WHOIS, Top 100 TCP Ports, Service Version Detection. |
| `-n`, `--normal` | **Normal Scan** *(Default)* | Quick Scan + Nmap Host Discovery, Default NSE Scripts (`-sC`), Safe Service-conditioned NSE scripts. |
| `-f`, `--full` | **Full Audit** | Normal Scan + Full 65,535 TCP Port Scan (`-p-`), OS Fingerprinting (`-O`), Extended Safe NSE checks. |
| `--vuln` | **Vulnerability Info** | *Optional Add-on:* Runs non-exploitative version checks (`--script vuln`). Flags findings for manual validation. |

### Module Skipping & Customization
| Option | Description |
|---|---|
| `--no-ping` | Bypasses ICMP ping reachability check (useful when firewalls block ICMP echo). |
| `--no-dns` | Skips DNS resolution queries and trace modules. |
| `--no-whois` | Disables external WHOIS server queries. |
| `--no-nse` | Disables all Nmap Scripting Engine enumeration. |
| `-o`, `--output DIR` | Stores results in a custom directory instead of `reports/<target>_<timestamp>`. |
| `-h`, `--help` | Displays the integrated help menu. |
| `-v`, `--version` | Shows toolkit version and license information. |

---

## Usage Examples

### 1. Basic Quick Scan on a Domain
```bash
./reconx.sh example.com --quick
```

### 2. Standard Reconnaissance on an Internal Host
```bash
./reconx.sh -t 192.168.1.50 --normal
```

### 3. Network Discovery on a CIDR Subnet Range
```bash
./reconx.sh -t 192.168.1.0/24 --normal
```

### 4. Full Exhaustive Assessment with Root Privileges (OS Detection + All Ports)
```bash
sudo ./reconx.sh -t 10.10.10.100 --full
```

### 5. Reconnaissance with Non-Exploitative Vulnerability Advisory Checks
```bash
./reconx.sh -t targetlab.local --normal --vuln
```

### 6. Stealthier Profile Disabling Ping and External WHOIS
```bash
./reconx.sh -t targetlab.local --no-ping --no-whois
```

### 7. Custom Report Output Directory
```bash
./reconx.sh -t 192.168.1.25 -o /var/reports/assessment_client_a
```

---

## Explanation of Major Functions

| Function Name | Description & Execution Logic |
|---|---|
| `print_banner()` | Renders the terminal ASCII banner, target details, timestamp, and explicit authorization warning. |
| `show_help()` | Displays the command-line usage guide, argument switches, examples, and security notice. |
| `show_version()` | Prints version information and exits cleanly. |
| `check_dependencies()` | Verifies that all 14 required CLI binaries exist in the current `$PATH`. Exits with targeted installation instructions if any are missing. |
| `validate_target()` | Uses regular expressions to classify the target as IPv4, CIDR, Domain, or Hostname. Sanitizes input to prevent shell metacharacter injection. |
| `setup_output()` | Creates the unique timestamped directory structure under `reports/` and initializes `reconx.log`. |
| `handle_sigint()` | Traps `SIGINT` (`Ctrl+C`) and `SIGTERM`. Terminates child processes, compiles all collected evidence into a partial HTML report, and displays the report path. |
| `log_info()`, `log_success()`, `log_warning()`, `log_error()` | Formats terminal logs with ANSI colors and writes clean, timestamped entries to `reconx.log`. |
| `html_escape()` | Filters dynamic strings and tool outputs through `sed` to escape `&`, `<`, `>`, `"`, and `'`, ensuring that reports remain resilient against XSS and broken HTML layouts. |
| `run_ping()` | Executes a safe 4-probe ping (`ping -c 4 -W 2`) against single targets. Computes packet transmission, loss percentage, and RTT statistics. Skips CIDR ranges gracefully. |
| `run_dns_recon()` | Queries 10 primary DNS record types (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `SRV`, `CAA`, `ANY`), executes hierarchical resolution trace (`dig +trace`), and performs reverse pointer lookup (`dig -x`). |
| `run_whois()` | Queries WHOIS registry databases and extracts registrar information, registration dates, expiration dates, status, organization, and country. Handles private/absent records safely. |
| `run_nmap_discovery()` | Runs `nmap -sn` to discover active live hosts without sending TCP port probes. |
| `run_nmap_ports()` | Scans the top 100 TCP ports using standard TCP Connect (`-sT`). In `--full` mode, scans all 65,535 TCP ports (`-p-`). Extracts discovered open ports for targeted downstream analysis. |
| `run_nmap_version()` | Inspects service banners on discovered open ports using `nmap -sV --version-light` to fingerprint application protocols, products, and version strings. |
| `run_nmap_os()` | Attempts TCP/IP stack OS fingerprinting via `nmap -O`. If executed without root privileges, gracefully explains raw socket constraints and continues the assessment. |
| `run_nmap_default_scripts()` | Runs Nmap's default safe NSE collection (`-sC`) on identified open ports. |
| `run_nse_enum()` | Reads `config/safe-nse.conf` and runs protocol-specific safe enumeration scripts (HTTP headers/titles, SSL/TLS certificates and ciphers, DNS discovery) only against detected ports. |
| `run_nse_vuln_info()` | Optional module triggered via `--vuln`. Executes `nmap --script vuln` to surface advisory correlations, explicitly disclaiming that findings require manual proof-of-concept verification. |
| `compile_findings()` | Evaluates gathered intelligence against a defensible classification model (`INFO`, `LOW`, `MEDIUM`, `HIGH`) for unencrypted protocols, open administrative ports, and CVE indicators. |
| `generate_html_report()` | Generates a standalone, dark-themed HTML5 dashboard (`report.html`) containing 10 interactive sections, KPI metric cards, and collapsible raw data blocks. |
| `show_summary()` | Prints an execution summary table in the terminal with metrics, report paths, and browser open commands. |

---

## Findings Classification Model

ReconX adheres to responsible disclosure principles. Automated scanning results are classified defensibly:

| Severity Badge | Criterion | Example Findings |
|---|---|---|
| **INFO** | Discovered service, protocol availability, or network reachability. | HTTP web server discovered on port 80; Host responded to ICMP echo. |
| **LOW** | Cleartext protocol or exposed administration interface without hardening confirmation. | Unencrypted FTP (port 21); Exposed SMB file sharing (port 445). |
| **MEDIUM** | Deprecated service protocol or legacy administrative channel. | Telnet service (port 23); Expired SSL certificate. |
| **HIGH** | Potential advisory match flagged by NSE version scanning (Manual validation required). | Version signature correlated with known CVE advisory. |

> **Note:** The tool never marks an automated indicator as a "confirmed exploit". All findings must be validated manually within authorized Rules of Engagement.

---

## HTML Report Architecture

The generated `report.html` is **100% standalone**:
- **Zero External Dependencies:** No external stylesheets, Google Fonts, or CDN scripts (e.g., Bootstrap, Tailwind, jQuery).
- **Air-Gapped Ready:** Works offline in isolated lab environments or secure jump boxes.
- **Embedded CSS Grid & Flexbox:** Responsive layout that scales smoothly across mobile, tablet, and widescreen monitors.
- **Collapsible Data Blocks:** `<details>` and `<summary>` tags wrap raw outputs, keeping the interface uncluttered while preserving raw evidentiary outputs for reporting.

To view the report, open it in any standard browser:
```bash
xdg-open reports/example.com_2026-09-19_210500/report.html
# or
firefox reports/example.com_2026-09-19_210500/report.html
# or
google-chrome reports/example.com_2026-09-19_210500/report.html
```

---

## Troubleshooting & FAQs

### 1. "MISSING REQUIRED SYSTEM DEPENDENCIES"
**Cause:** One or more essential utilities (`dig`, `whois`, `nmap`, etc.) are missing from the system.  
**Resolution:**
```bash
sudo apt update && sudo apt install -y dnsutils whois nmap iputils-ping coreutils iproute2
```

### 2. "OS detection requires root privileges"
**Cause:** Nmap OS fingerprinting (`-O`) sends raw IP/TCP packets with custom flags, which requires Linux `CAP_NET_RAW` / `root` permissions.  
**Resolution:** Run ReconX with `sudo` if OS detection is required:
```bash
sudo ./reconx.sh -t 192.168.1.10 --full
```
*Note: If run without root, ReconX skips OS detection gracefully without halting the remaining modules.*

### 3. Ping shows "Unreachable / ICMP Filtered" but target has open ports
**Cause:** Firewalls or cloud security groups often drop ICMP Echo requests (Type 8) by default.  
**Resolution:** Use `--no-ping` to bypass ICMP checks and proceed straight to TCP port and DNS enumeration.

### 4. WHOIS queries return "WHOIS information unavailable"
**Cause:** Some top-level domains (TLDs) or internal/private IP addresses (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`) do not respond to public WHOIS servers, or WHOIS rate limits were exceeded.  
**Resolution:** This is normal for private IP ranges. For public domains, verify public DNS connectivity.

### 5. `\r`: command not found (CRLF line ending error)
**Cause:** The script was edited or saved on Windows using DOS/Windows line endings (`CRLF`).  
**Resolution:**
```bash
sed -i 's/\r$//' reconx.sh config/safe-nse.conf
```

---

## Roadmap & Suggestions for Future Versions

1. **Passive OSINT Integration:**
   - Add safe, unauthenticated passive certificate transparency log lookups (e.g., crt.sh query via `curl`).
   - Add DNS dumpster / Subdomain enumeration via non-intrusive DNS wordlists.
2. **JSON / Machine-Readable Export:**
   - Add `--json` flag producing a `report.json` payload for automated SIEM ingestion or CI/CD pipelines.
3. **Multi-Target Batch Processing:**
   - Support reading targets from a file (`-iL targets.txt`) with sequential report generation.
4. **Custom Port Range Specification:**
   - Allow user-defined ports (e.g., `-p 80,443,8080-8090`).
5. **PDF Report Export:**
   - Optional headless Chromium print-to-PDF generation for instant client deliverable PDFs.

---

## License & Compliance

ReconX is distributed under the **MIT License**. Use of ReconX for unauthorized testing or malicious activities is strictly prohibited. The author and contributors disclaim all liability for misuse or damages resulting from this software.
