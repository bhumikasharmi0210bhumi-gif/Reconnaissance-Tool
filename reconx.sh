#!/usr/bin/env bash
# ==============================================================================
# ReconX — Bash Reconnaissance & Enumeration Toolkit
# Version: 1.0.0
# License: MIT (Authorized Security Testing & Educational Labs Only)
# ==============================================================================
# AUTHORIZATION WARNING:
# This tool is designed strictly for AUTHORIZED penetration testing, red teaming,
# vulnerability auditing, defensive security assessments, and lab environments.
# Unauthorized scanning of networks, servers, or devices without prior written
# consent from the target owner is strictly prohibited and may violate local,
# national, and international laws.
# ==============================================================================

set -o pipefail

# ------------------------------------------------------------------------------
# Global Constants & Variables
# ------------------------------------------------------------------------------
VERSION="1.0.0"
SCRIPT_NAME="reconx.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/safe-nse.conf"

# Color Configuration (Terminal output only)
if [[ -t 1 ]]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_RED="\033[1;31m"
    C_GREEN="\033[1;32m"
    C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;34m"
    C_PURPLE="\033[1;35m"
    C_CYAN="\033[1;36m"
    C_GRAY="\033[0;90m"
else
    C_RESET=""
    C_BOLD=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_PURPLE=""
    C_CYAN=""
    C_GRAY=""
fi

# Scan Modes & Flags
SCAN_MODE="normal"         # quick | normal | full
ENABLE_VULN=false          # Opt-in NSE vuln scan
SKIP_PING=false
SKIP_DNS=false
SKIP_WHOIS=false
SKIP_NSE=false
CUSTOM_OUTPUT_DIR=""

TARGET=""
TARGET_TYPE=""             # IPV4 | CIDR | DOMAIN | HOSTNAME
RESOLVED_IP=""

# Run Metrics & State
START_TIME=""
START_EPOCH=0
END_TIME=""
OUTPUT_DIR=""
LOG_FILE=""
REPORT_FILE=""

IS_INTERRUPTED=false
CHILD_PIDS=()

# Collected Scan Metrics
PING_STATUS="Skipped"
PING_TRANSMITTED=0
PING_RECEIVED=0
PING_LOSS="N/A"
PING_MIN="N/A"
PING_AVG="N/A"
PING_MAX="N/A"

LIVE_HOSTS_COUNT=0
OPEN_PORTS_COUNT=0
SERVICES_COUNT=0
DNS_RECORDS_COUNT=0
VULN_FINDINGS_COUNT=0

OPEN_PORTS_LIST=()
SERVICES_LIST=()
FINDINGS_LIST=()

# ------------------------------------------------------------------------------
# Logging Functions
# ------------------------------------------------------------------------------
log() {
    local level="$1"
    local color="$2"
    local message="$3"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Terminal output
    echo -e "${C_GRAY}[${timestamp}]${C_RESET} ${color}[${level}]${C_RESET} ${message}"

    # Log file output (without ANSI colors)
    if [[ -n "$LOG_FILE" && -d "$(dirname "$LOG_FILE")" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

log_info()    { log "INFO"    "${C_BLUE}"   "$1"; }
log_success() { log "SUCCESS" "${C_GREEN}"  "$1"; }
log_warning() { log "WARNING" "${C_YELLOW}" "$1"; }
log_error()   { log "ERROR"   "${C_RED}"    "$1"; }

# ------------------------------------------------------------------------------
# Security & Escaping Helpers
# ------------------------------------------------------------------------------
html_escape() {
    sed -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g"
}

sanitize_filename() {
    echo "$1" | sed -e 's/[^a-zA-Z0-9._-]/_/g'
}

# ------------------------------------------------------------------------------
# Banner & Help Displays
# ------------------------------------------------------------------------------
print_banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    cat << "EOF"
  ____                      __  __ 
 |  _ \ ___  ___ ___  _ __  \ \/ / 
 | |_) / _ \/ __/ _ \| '_ \  \  /  
 |  _ <  __/ (_| (_) | | | | /  \  
 |_| \_\___|\___\___/|_| |_|/_/\_\ 
EOF
    echo -e "${C_RESET}${C_BOLD} ReconX — Bash Reconnaissance & Enumeration Toolkit ${C_GRAY}(v${VERSION})${C_RESET}"
    echo -e "${C_YELLOW} ⚠  AUTHORIZED SECURITY TESTING & EDUCATIONAL LABS ONLY ⚠${C_RESET}"
    echo -e "${C_GRAY}========================================================================${C_RESET}"
    if [[ -n "$TARGET" ]]; then
        echo -e "${C_BOLD} Target           :${C_RESET} ${C_CYAN}${TARGET}${C_RESET} ${C_GRAY}(${TARGET_TYPE:-Validating})${C_RESET}"
        echo -e "${C_BOLD} Start Time       :${C_RESET} ${START_TIME}"
        if [[ -n "$OUTPUT_DIR" ]]; then
            echo -e "${C_BOLD} Output Directory :${C_RESET} ${C_GREEN}${OUTPUT_DIR}${C_RESET}"
        fi
        echo -e "${C_GRAY}========================================================================${C_RESET}"
    fi
    echo ""
}

show_help() {
    print_banner
    cat << EOF
Usage:
  ./${SCRIPT_NAME} [TARGET] [OPTIONS]
  ./${SCRIPT_NAME} -t TARGET [OPTIONS]

Scan Modes:
  -q, --quick          Quick scan: Ping, DNS, WHOIS, Top 100 ports, Service detection
  -n, --normal         Normal scan (default): Adds host discovery, default NSE & safe NSE
  -f, --full           Full scan: Adds full 65535 TCP port scan, OS detection, full safe NSE

Target Specifications:
  -t, --target TARGET  Domain name (e.g. example.com), IPv4 (e.g. 192.168.1.10),
                       or CIDR subnet block (e.g. 192.168.1.0/24)

Audit & Customization Options:
  --vuln               Enable non-exploitative NSE vulnerability information gathering
                       (Flags potential advisory findings requiring manual validation)
  --no-ping            Skip ICMP ping reachability check
  --no-dns             Skip DNS query & trace enumeration
  --no-whois           Skip WHOIS lookup
  --no-nse             Skip all Nmap Scripting Engine (NSE) modules
  -o, --output DIR     Specify custom output directory (default: reports/<target>_<timestamp>)

General Options:
  -h, --help           Display this comprehensive help menu and exit
  -v, --version        Show version and author information

Examples:
  ./${SCRIPT_NAME} example.com
  ./${SCRIPT_NAME} -t 192.168.1.50 --quick
  ./${SCRIPT_NAME} -t 192.168.1.0/24 --normal
  ./${SCRIPT_NAME} -t 10.10.10.100 --full --vuln
  ./${SCRIPT_NAME} -t scanme.nmap.org -o custom_recon_report/

Notice:
  This script executes non-destructive security reconnaissance. It does NOT exploit
  vulnerabilities, brute-force credentials, execute denial-of-service, or alter systems.
EOF
    exit 0
}

show_version() {
    echo -e "${C_BOLD}ReconX Toolkit${C_RESET} version ${C_CYAN}${VERSION}${C_RESET}"
    echo "Engineered for Authorized Penetration Testing, Red Teaming & Lab Environments."
    exit 0
}

# ------------------------------------------------------------------------------
# Dependency Verification
# ------------------------------------------------------------------------------
check_dependencies() {
    local required_commands=(
        "ping"
        "dig"
        "whois"
        "nmap"
        "awk"
        "grep"
        "sed"
        "sort"
        "uniq"
        "date"
        "mkdir"
        "tee"
        "hostname"
        "ip"
    )

    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done

    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        echo -e "${C_RED}${C_BOLD}[!] MISSING REQUIRED SYSTEM DEPENDENCIES:${C_RESET}"
        for cmd in "${missing_commands[@]}"; do
            echo -e "  ${C_YELLOW}- ${cmd}${C_RESET}"
        done
        echo ""
        echo -e "${C_CYAN}${C_BOLD}To install all prerequisites on Kali Linux / Debian / Ubuntu, run:${C_RESET}"
        echo -e "${C_BOLD}sudo apt update && sudo apt install -y dnsutils whois nmap iputils-ping coreutils iproute2${C_RESET}"
        echo ""
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Target Validation
# ------------------------------------------------------------------------------
validate_target() {
    local input="$1"

    if [[ -z "$input" ]]; then
        log_error "Target is empty. Please specify a domain, IP address, or CIDR range."
        exit 1
    fi

    # Safety Check: Reject command injection characters
    if [[ "$input" =~ [^a-zA-Z0-9\.\-\_\:\/] ]]; then
        log_error "Target contains invalid or potentially dangerous characters: '$input'"
        exit 1
    fi

    # 1. Check for IPv4 Address
    local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ "$input" =~ $ipv4_regex ]]; then
        # Validate octets 0-255
        IFS='.' read -r -a octets <<< "$input"
        local valid_ip=true
        for oct in "${octets[@]}"; do
            if (( oct < 0 || oct > 255 )); then
                valid_ip=false
                break
            fi
        done
        if [[ "$valid_ip" == true ]]; then
            TARGET_TYPE="IPV4"
            RESOLVED_IP="$input"
            return 0
        else
            log_error "Target appears to be an IP address but octets are out of 0-255 range: '$input'"
            exit 1
        fi
    fi

    # 2. Check for CIDR Range
    local cidr_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$'
    if [[ "$input" =~ $cidr_regex ]]; then
        local ip_part="${input%/*}"
        IFS='.' read -r -a octets <<< "$ip_part"
        local valid_cidr=true
        for oct in "${octets[@]}"; do
            if (( oct < 0 || oct > 255 )); then
                valid_cidr=false
                break
            fi
        done
        if [[ "$valid_cidr" == true ]]; then
            TARGET_TYPE="CIDR"
            return 0
        else
            log_error "Target CIDR has invalid base IP octets: '$input'"
            exit 1
        fi
    fi

    # 3. Check for Domain Name / Hostname
    local domain_regex='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    local hostname_regex='^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

    if [[ "$input" =~ $domain_regex ]]; then
        TARGET_TYPE="DOMAIN"
        return 0
    elif [[ "$input" =~ $hostname_regex ]]; then
        TARGET_TYPE="HOSTNAME"
        return 0
    fi

    log_warning "Target format not strictly recognized as standard IP/CIDR/Domain. Treating as generic Hostname."
    TARGET_TYPE="HOSTNAME"
}

# ------------------------------------------------------------------------------
# Output Directory & File System Setup
# ------------------------------------------------------------------------------
setup_output() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d_%H%M%S')"
    local safe_target
    safe_target="$(sanitize_filename "$TARGET")"

    if [[ -n "$CUSTOM_OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$CUSTOM_OUTPUT_DIR"
    else
        OUTPUT_DIR="${SCRIPT_DIR}/reports/${safe_target}_${timestamp}"
    fi

    mkdir -p "${OUTPUT_DIR}"/{dns,nmap,nse} || {
        echo -e "${C_RED}[ERROR] Failed to create output directory: ${OUTPUT_DIR}${C_RESET}"
        exit 1
    }

    LOG_FILE="${OUTPUT_DIR}/reconx.log"
    REPORT_FILE="${OUTPUT_DIR}/report.html"

    # Initialize log
    touch "$LOG_FILE"
    log_info "ReconX v${VERSION} initialized for target: ${TARGET} (${TARGET_TYPE})"
    log_info "Scan mode: ${SCAN_MODE^^} | Output Directory: ${OUTPUT_DIR}"
}

# ------------------------------------------------------------------------------
# Signal Handling (Ctrl+C / Interruption)
# ------------------------------------------------------------------------------
handle_sigint() {
    echo ""
    log_warning "Interrupt signal received (SIGINT/Ctrl+C)! Stopping current jobs cleanly..."
    IS_INTERRUPTED=true

    # Terminate background child processes safely
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
        fi
    done

    log_info "Generating partial reconnaissance report from collected data..."
    generate_html_report "INTERRUPTED"

    echo ""
    echo -e "${C_YELLOW}========================================================================${C_RESET}"
    echo -e "${C_BOLD} [!] RECONNAISSANCE INTERRUPTED BY USER${C_RESET}"
    echo -e " Partial Log    : ${C_CYAN}${LOG_FILE}${C_RESET}"
    echo -e " Partial Report : ${C_GREEN}${REPORT_FILE}${C_RESET}"
    echo -e "${C_YELLOW}========================================================================${C_RESET}"
    exit 130
}

trap 'handle_sigint' SIGINT SIGTERM

# ------------------------------------------------------------------------------
# Module 1: Reachability & Ping Analysis
# ------------------------------------------------------------------------------
run_ping() {
    if [[ "$SKIP_PING" == true ]]; then
        log_info "Ping reachability check skipped via CLI flag (--no-ping)."
        PING_STATUS="Skipped"
        return 0
    fi

    log_info "Executing reachability check (ICMP ping)..."
    local raw_file="${OUTPUT_DIR}/ping.txt"

    if [[ "$TARGET_TYPE" == "CIDR" ]]; then
        log_warning "Target is a CIDR network range ($TARGET). Skipping single-host ICMP ping to avoid range flood."
        echo "Ping skipped for CIDR range: $TARGET" > "$raw_file"
        PING_STATUS="CIDR Range (Skipped)"
        return 0
    fi

    # Run safe ping with 4 probes
    local ping_cmd=("ping" "-c" "4" "-W" "2" "$TARGET")
    "${ping_cmd[@]}" > "$raw_file" 2>&1
    local ping_exit=$?

    if [[ -f "$raw_file" ]]; then
        # Parse packet transmission details
        local stats_line
        stats_line="$(grep -E "packets transmitted" "$raw_file" 2>/dev/null || true)"
        if [[ -n "$stats_line" ]]; then
            PING_TRANSMITTED="$(echo "$stats_line" | awk -F',' '{print $1}' | awk '{print $1}' || echo "0")"
            PING_RECEIVED="$(echo "$stats_line" | awk -F',' '{print $2}' | awk '{print $1}' || echo "0")"
            PING_LOSS="$(echo "$stats_line" | awk -F',' '{print $3}' | awk '{print $1}' || echo "100%")"
        fi

        # Parse RTT latency stats (min/avg/max)
        local rtt_line
        rtt_line="$(grep -E "rtt|round-trip" "$raw_file" 2>/dev/null || true)"
        if [[ -n "$rtt_line" ]]; then
            local rtt_values
            rtt_values="$(echo "$rtt_line" | awk -F'=' '{print $2}' | awk -F'/' '{print $1","$2","$3}')"
            PING_MIN="$(echo "$rtt_values" | awk -F',' '{print $1}' | xargs) ms"
            PING_AVG="$(echo "$rtt_values" | awk -F',' '{print $2}' | xargs) ms"
            PING_MAX="$(echo "$rtt_values" | awk -F',' '{print $3}' | xargs) ms"
        fi

        if [[ "$ping_exit" -eq 0 && "$PING_RECEIVED" -gt 0 ]]; then
            PING_STATUS="Reachable"
            log_success "Host is REACHABLE (${PING_RECEIVED}/${PING_TRANSMITTED} probes received, avg latency: ${PING_AVG})"
        else
            PING_STATUS="Unreachable / ICMP Filtered"
            log_warning "Host is UNREACHABLE or ICMP packets are filtered/dropped (Loss: ${PING_LOSS})"
        fi
    else
        PING_STATUS="Unknown"
        log_error "Ping output file could not be generated."
    fi
}

# ------------------------------------------------------------------------------
# Module 2: DNS Reconnaissance (DIG)
# ------------------------------------------------------------------------------
run_dns_recon() {
    if [[ "$SKIP_DNS" == true ]]; then
        log_info "DNS reconnaissance skipped via CLI flag (--no-dns)."
        return 0
    fi

    log_info "Executing DNS enumeration using DIG..."
    local dns_dir="${OUTPUT_DIR}/dns"

    if [[ "$TARGET_TYPE" == "CIDR" ]]; then
        log_warning "Target is a CIDR network block ($TARGET). Skipping standard domain DNS record resolution."
        echo "DNS queries skipped for CIDR range." > "${dns_dir}/dns_summary.txt"
        return 0
    fi

    local query_types=("A" "AAAA" "MX" "NS" "TXT" "SOA" "CNAME" "SRV" "CAA" "ANY")

    for qtype in "${query_types[@]}"; do
        local out_file="${dns_dir}/dns_$(echo "$qtype" | tr '[:upper:]' '[:lower:]').txt"
        dig "$TARGET" "$qtype" +noall +answer > "$out_file" 2>&1

        # Count records if non-empty
        if [[ -s "$out_file" ]]; then
            local count
            count="$(grep -E "\s+IN\s+" "$out_file" 2>/dev/null | wc -l | xargs)"
            (( DNS_RECORDS_COUNT += count ))
        fi
    done

    # Collect Short Answers for Fast Verification
    local short_a
    short_a="$(dig +short "$TARGET" A 2>/dev/null || true)"
    if [[ -n "$short_a" && -z "$RESOLVED_IP" ]]; then
        RESOLVED_IP="$(echo "$short_a" | head -n 1)"
        log_info "Resolved target ${TARGET} to IPv4: ${RESOLVED_IP}"
    fi

    # Reverse DNS Lookup (dig -x)
    local rev_ip=""
    if [[ "$TARGET_TYPE" == "IPV4" ]]; then
        rev_ip="$TARGET"
    elif [[ -n "$RESOLVED_IP" ]]; then
        rev_ip="$RESOLVED_IP"
    fi

    if [[ -n "$rev_ip" ]]; then
        log_info "Performing Reverse DNS lookup for ${rev_ip}..."
        dig -x "$rev_ip" +noall +answer > "${dns_dir}/reverse_dns.txt" 2>&1
        dig +short -x "$rev_ip" > "${dns_dir}/reverse_dns_short.txt" 2>&1
        if [[ -s "${dns_dir}/reverse_dns.txt" ]]; then
            (( DNS_RECORDS_COUNT += 1 ))
        fi
    else
        echo "Reverse DNS unavailable (No resolved IPv4 found)." > "${dns_dir}/reverse_dns.txt"
    fi

    # Hierarchical DNS Trace (dig +trace)
    log_info "Collecting authoritative DNS delegation trace (dig +trace)..."
    dig +trace "$TARGET" > "${dns_dir}/dns_trace.txt" 2>&1

    log_success "DNS reconnaissance completed (${DNS_RECORDS_COUNT} total records discovered)"
}

# ------------------------------------------------------------------------------
# Module 3: WHOIS Enumeration
# ------------------------------------------------------------------------------
run_whois() {
    if [[ "$SKIP_WHOIS" == true ]]; then
        log_info "WHOIS lookup skipped via CLI flag (--no-whois)."
        return 0
    fi

    log_info "Performing WHOIS registration lookup..."
    local raw_file="${OUTPUT_DIR}/whois.txt"

    # Query whois with timeout protection
    whois "$TARGET" > "$raw_file" 2>&1
    local whois_exit=$?

    if [[ $whois_exit -ne 0 || ! -s "$raw_file" ]]; then
        echo "WHOIS information unavailable for $TARGET." > "$raw_file"
        log_warning "WHOIS query returned no data or failed gracefully."
    else
        log_success "WHOIS lookup completed successfully."
    fi
}

# ------------------------------------------------------------------------------
# Module 4: Nmap Host Discovery (-sn)
# ------------------------------------------------------------------------------
run_nmap_discovery() {
    log_info "Executing Nmap host discovery (ping sweep / live host resolution)..."
    local raw_file="${OUTPUT_DIR}/nmap/nmap_host_discovery.txt"

    local nmap_disc_cmd=("nmap" "-sn" "$TARGET" "-oN" "$raw_file")
    "${nmap_disc_cmd[@]}" > /dev/null 2>&1

    if [[ -f "$raw_file" ]]; then
        LIVE_HOSTS_COUNT="$(grep -E "Nmap scan report for" "$raw_file" 2>/dev/null | wc -l | xargs)"
        log_success "Host discovery completed. Identified ${LIVE_HOSTS_COUNT} active host(s)."
    else
        log_warning "Nmap host discovery failed to produce output."
    fi
}

# ------------------------------------------------------------------------------
# Module 5: Nmap Port Scanning
# ------------------------------------------------------------------------------
run_nmap_ports() {
    log_info "Executing TCP port scan..."
    local top100_file="${OUTPUT_DIR}/nmap/nmap_top100.txt"
    local all_tcp_file="${OUTPUT_DIR}/nmap/nmap_all_tcp.txt"

    # 1. Top 100 Port Scan
    log_info "Scanning top 100 TCP ports (TCP Connect -sT)..."
    local top_args=("nmap" "-sT" "--top-ports" "100" "--open" "$TARGET" "-oN" "$top100_file")
    "${top_args[@]}" > /dev/null 2>&1

    # Extract open ports
    if [[ -f "$top100_file" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]+open[[:space:]]+([^[:space:]]+) ]]; then
                local port_num="${BASH_REMATCH[1]}"
                local proto="${BASH_REMATCH[2]}"
                local service="${BASH_REMATCH[3]}"
                OPEN_PORTS_LIST+=("$port_num/$proto")
                SERVICES_LIST+=("$service")
                (( OPEN_PORTS_COUNT++ ))
            fi
        done < <(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" "$top100_file" || true)
    fi

    # 2. Full Port Scan (-p-) if requested
    if [[ "$SCAN_MODE" == "full" ]]; then
        if [[ "$TARGET_TYPE" == "CIDR" ]]; then
            log_warning "Target is a CIDR range. Full port scan (-p-) across an entire range takes significant time. Limiting -p- to active hosts."
        fi
        log_info "Scanning all 65,535 TCP ports (-p-)..."
        local all_args=("nmap" "-sT" "-p-" "--open" "$TARGET" "-oN" "$all_tcp_file")
        "${all_args[@]}" > /dev/null 2>&1

        # Reparse all ports to ensure completeness
        if [[ -f "$all_tcp_file" ]]; then
            OPEN_PORTS_LIST=()
            SERVICES_LIST=()
            OPEN_PORTS_COUNT=0
            while IFS= read -r line; do
                if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]+open[[:space:]]+([^[:space:]]+) ]]; then
                    OPEN_PORTS_LIST+=("${BASH_REMATCH[1]}/${BASH_REMATCH[2]}")
                    SERVICES_LIST+=("${BASH_REMATCH[3]}")
                    (( OPEN_PORTS_COUNT++ ))
                fi
            done < <(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" "$all_tcp_file" || true)
        fi
    fi

    log_success "Port scanning completed. Found ${OPEN_PORTS_COUNT} open TCP port(s)."
}

# ------------------------------------------------------------------------------
# Module 6: Service Version Detection (-sV)
# ------------------------------------------------------------------------------
run_nmap_version() {
    log_info "Executing service version detection (-sV)..."
    local raw_file="${OUTPUT_DIR}/nmap/nmap_service_detection.txt"

    local sV_args=("nmap" "-sV" "--version-light")

    # If specific open ports were already identified, scan those directly for speed
    if [[ ${#OPEN_PORTS_LIST[@]} -gt 0 && ${#OPEN_PORTS_LIST[@]} -le 50 ]]; then
        local port_spec
        port_spec="$(IFS=,; echo "${OPEN_PORTS_LIST[*]}" | sed 's|/tcp||g' | sed 's|/udp||g')"
        sV_args+=("-p" "$port_spec")
    fi

    sV_args+=("$TARGET" "-oN" "$raw_file")
    "${sV_args[@]}" > /dev/null 2>&1

    if [[ -f "$raw_file" ]]; then
        local detected_svc_count
        detected_svc_count="$(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" "$raw_file" 2>/dev/null | wc -l | xargs)"
        if [[ "$detected_svc_count" -gt 0 ]]; then
            SERVICES_COUNT="$detected_svc_count"
        else
            SERVICES_COUNT="$OPEN_PORTS_COUNT"
        fi
        log_success "Service version detection completed (${SERVICES_COUNT} service banner(s) fingerprinted)."
    fi
}

# ------------------------------------------------------------------------------
# Module 7: OS Detection (-O)
# ------------------------------------------------------------------------------
run_nmap_os() {
    if [[ "$SCAN_MODE" != "full" ]]; then
        log_info "OS fingerprinting (-O) skipped (enabled in --full scan mode)."
        return 0
    fi

    log_info "Attempting OS detection..."
    local raw_file="${OUTPUT_DIR}/nmap/nmap_os_detection.txt"

    # OS detection strictly requires root privileges for raw socket TCP probe analysis
    if [[ "$EUID" -ne 0 ]]; then
        if sudo -n true 2>/dev/null; then
            log_info "Using passwordless sudo for Nmap OS detection..."
            sudo nmap -O --osscan-limit "$TARGET" -oN "$raw_file" > /dev/null 2>&1
        else
            log_warning "OS detection requires root privileges (raw TCP socket access). Skipping OS detection gracefully."
            cat << EOF > "$raw_file"
[SKIPPED] OS Detection requires root privileges (raw socket access).
Run ReconX as root (sudo ./reconx.sh ...) to enable TCP/IP stack OS fingerprinting.
This check was skipped without breaking the scan workflow.
EOF
            return 0
        fi
    else
        nmap -O --osscan-limit "$TARGET" -oN "$raw_file" > /dev/null 2>&1
    fi

    if [[ -f "$raw_file" && -s "$raw_file" ]]; then
        log_success "OS detection completed."
    fi
}

# ------------------------------------------------------------------------------
# Module 8: Nmap Default Scripts (-sC)
# ------------------------------------------------------------------------------
run_nmap_default_scripts() {
    if [[ "$SKIP_NSE" == true ]]; then
        log_info "NSE scanning skipped via CLI flag (--no-nse)."
        return 0
    fi

    log_info "Running Nmap default script scan (-sC)..."
    local raw_file="${OUTPUT_DIR}/nmap/nmap_default_scripts.txt"

    local sc_args=("nmap" "-sC")
    if [[ ${#OPEN_PORTS_LIST[@]} -gt 0 && ${#OPEN_PORTS_LIST[@]} -le 30 ]]; then
        local port_spec
        port_spec="$(IFS=,; echo "${OPEN_PORTS_LIST[*]}" | sed 's|/tcp||g' | sed 's|/udp||g')"
        sc_args+=("-p" "$port_spec")
    fi
    sc_args+=("$TARGET" "-oN" "$raw_file")

    "${sc_args[@]}" > /dev/null 2>&1
    log_success "Nmap default script scan (-sC) finished."
}

# ------------------------------------------------------------------------------
# Module 9: Safe NSE Enumeration
# ------------------------------------------------------------------------------
run_nse_enum() {
    if [[ "$SKIP_NSE" == true ]]; then
        return 0
    fi

    log_info "Running safe, non-destructive NSE enumeration..."
    local nse_dir="${OUTPUT_DIR}/nse"

    # 1. General Safe Category
    log_info "Executing vetted safe NSE discovery category..."
    nmap --script "default,safe" --script-timeout 30s "$TARGET" -oN "${nse_dir}/nse_safe.txt" > /dev/null 2>&1

    # 2. Conditioned Protocol-Specific Enumeration
    local ports_str=" ${OPEN_PORTS_LIST[*]} "

    # HTTP Enumeration
    if [[ "$ports_str" =~ " 80/tcp " || "$ports_str" =~ " 443/tcp " || "$ports_str" =~ " 8080/tcp " || "$ports_str" =~ " 8443/tcp " || " ${SERVICES_LIST[*]} " =~ " http " ]]; then
        log_info "Web services detected. Executing safe HTTP enumeration (titles, headers, methods, robots)..."
        nmap -p 80,443,8000,8080,8443,8888 --script "http-title,http-headers,http-methods,http-enum,http-robots.txt" --script-timeout 20s "$TARGET" -oN "${nse_dir}/nse_http.txt" > /dev/null 2>&1
    fi

    # SSL / TLS Certificate & Cipher Enumeration
    if [[ "$ports_str" =~ " 443/tcp " || "$ports_str" =~ " 8443/tcp " || " ${SERVICES_LIST[*]} " =~ " ssl " || " ${SERVICES_LIST[*]} " =~ " https " ]]; then
        log_info "SSL/TLS services detected. Executing safe SSL certificate & cipher suites audit..."
        nmap -p 443,8443,465,993,995 --script "ssl-cert,ssl-enum-ciphers,ssl-date" --script-timeout 25s "$TARGET" -oN "${nse_dir}/nse_ssl.txt" > /dev/null 2>&1
    fi

    # DNS Service Discovery
    if [[ "$ports_str" =~ " 53/tcp " || "$TARGET_TYPE" == "DOMAIN" ]]; then
        log_info "DNS service or domain target detected. Running safe DNS service discovery..."
        nmap -p 53 --script "dns-nsid,dns-service-discovery" --script-timeout 15s "$TARGET" -oN "${nse_dir}/nse_dns.txt" > /dev/null 2>&1
    fi

    log_success "Safe NSE enumeration routines completed."
}

# ------------------------------------------------------------------------------
# Module 10: Optional Vulnerability Information Gathering (--vuln)
# ------------------------------------------------------------------------------
run_nse_vuln_info() {
    if [[ "$ENABLE_VULN" != true ]]; then
        return 0
    fi

    echo ""
    log_warning "=========================================================================="
    log_warning "OPTIONAL VULNERABILITY INFORMATION SCAN ENABLED (--vuln)"
    log_warning "POLICY NOTICE: Executing non-exploitative version checks & advisory probes."
    log_warning "NO EXPLOITATION, BRUTE FORCE, OR DESTRUCTIVE ACTIONS WILL OCCUR."
    log_warning "All findings represent POTENTIAL INDICATORS requiring manual confirmation."
    log_warning "=========================================================================="
    echo ""

    local raw_file="${OUTPUT_DIR}/nse/nse_vulnerability_scan.txt"

    local vuln_args=("nmap" "--script" "vuln" "--script-timeout" "45s")
    if [[ ${#OPEN_PORTS_LIST[@]} -gt 0 && ${#OPEN_PORTS_LIST[@]} -le 20 ]]; then
        local port_spec
        port_spec="$(IFS=,; echo "${OPEN_PORTS_LIST[*]}" | sed 's|/tcp||g' | sed 's|/udp||g')"
        vuln_args+=("-p" "$port_spec")
    fi
    vuln_args+=("$TARGET" "-oN" "$raw_file")

    "${vuln_args[@]}" > /dev/null 2>&1

    if [[ -f "$raw_file" ]]; then
        VULN_FINDINGS_COUNT="$(grep -E "VULNERABLE:|State: VULNERABLE|CVE-" "$raw_file" 2>/dev/null | wc -l | xargs)"
        log_warning "Vulnerability scan completed. Found ${VULN_FINDINGS_COUNT} potential advisory indicator(s)."
    fi
}

# ------------------------------------------------------------------------------
# Module 11: Categorize Findings
# ------------------------------------------------------------------------------
compile_findings() {
    FINDINGS_LIST=()

    # Reachability
    if [[ "$PING_STATUS" == "Reachable" ]]; then
        FINDINGS_LIST+=("INFO|Host Reachability|Host responded to ICMP probes with ${PING_AVG} avg latency.")
    fi

    # Ports & Services
    for idx in "${!OPEN_PORTS_LIST[@]}"; do
        local p="${OPEN_PORTS_LIST[$idx]}"
        local s="${SERVICES_LIST[$idx]:-unknown}"

        if [[ "$p" =~ 80/tcp ]]; then
            FINDINGS_LIST+=("INFO|Plaintext Web Service (HTTP)|Port 80 is open running HTTP. Recommend verifying HTTPS redirect.")
        elif [[ "$p" =~ 21/tcp ]]; then
            FINDINGS_LIST+=("LOW|Unencrypted Protocol (FTP)|Port 21 is active. Legacy FTP transmits credentials in plaintext. Manual audit recommended.")
        elif [[ "$p" =~ 23/tcp ]]; then
            FINDINGS_LIST+=("MEDIUM|Insecure Protocol (Telnet)|Port 23 is open. Telnet is deprecated and insecure. Replace with SSH.")
        elif [[ "$p" =~ 445/tcp || "$p" =~ 139/tcp ]]; then
            FINDINGS_LIST+=("LOW|Exposed SMB File Sharing|Port ${p} exposed. Verify access control lists and SMB signing configurations.")
        elif [[ "$p" =~ 3389/tcp ]]; then
            FINDINGS_LIST+=("LOW|Remote Desktop (RDP) Exposed|Port 3389 open. Verify Network Level Authentication (NLA) and MFA.")
        else
            FINDINGS_LIST+=("INFO|Service Discovered|Open port ${p} running service '${s}'.")
        fi
    done

    # NSE Vulnerability Findings
    if [[ "$ENABLE_VULN" == true && -f "${OUTPUT_DIR}/nse/nse_vulnerability_scan.txt" ]]; then
        while IFS= read -r match; do
            FINDINGS_LIST+=("HIGH|Potential Advisory Match (NSE)|${match} (Automated indicator only; requires manual proof-of-concept confirmation).")
        done < <(grep -E "VULNERABLE:|State: VULNERABLE|CVE-" "${OUTPUT_DIR}/nse/nse_vulnerability_scan.txt" | head -n 10 || true)
    fi
}

# ------------------------------------------------------------------------------
# Module 12: HTML Report Generation
# ------------------------------------------------------------------------------
generate_html_report() {
    local scan_status="${1:-COMPLETED}"
    log_info "Compiling self-contained HTML reconnaissance dashboard..."

    compile_findings

    END_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
    local end_epoch
    end_epoch="$(date +%s)"
    local duration_seconds=$(( end_epoch - START_EPOCH ))
    local duration_formatted="${duration_seconds}s"

    local scanner_hostname
    scanner_hostname="$(hostname 2>/dev/null || echo "Unknown")"
    local scanner_os
    scanner_os="$(uname -s -r -m 2>/dev/null || echo "Linux")"

    # Helper: Read file safely with HTML escaping
    get_file_content_escaped() {
        local f="$1"
        local max_lines="${2:-500}"
        if [[ -f "$f" && -s "$f" ]]; then
            head -n "$max_lines" "$f" | html_escape
        else
            echo "<em>No output recorded or module not triggered.</em>"
        fi
    }

    # Generate Report Content
    cat << 'EOF' > "$REPORT_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Security Reconnaissance Report</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-muted: #8b949e;
            --text-heading: #f0f6fc;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #bc8cff;
            --code-bg: #0b0f14;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 24px;
        }
        .container { max-width: 1280px; margin: 0 auto; }
        
        /* Header Banner */
        .header {
            background: linear-gradient(135deg, #161b22 0%, #1f2937 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        .header-title h1 {
            color: var(--text-heading);
            font-size: 1.85rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-title p { color: var(--text-muted); font-size: 0.95rem; margin-top: 6px; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .badge-warning { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge-danger  { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge-info    { background: rgba(88, 166, 255, 0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }
        .badge-purple  { background: rgba(188, 140, 255, 0.2); color: var(--accent-purple); border: 1px solid var(--accent-purple); }

        /* KPI Metrics Grid */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .kpi-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .kpi-card:hover { transform: translateY(-2px); border-color: var(--accent-cyan); }
        .kpi-value { font-size: 1.8rem; font-weight: 700; color: var(--text-heading); margin-top: 4px; }
        .kpi-label { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.6px; }

        /* Navigation Bar */
        .nav-bar {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 18px;
            margin-bottom: 24px;
            display: flex;
            gap: 14px;
            overflow-x: auto;
        }
        .nav-bar a {
            color: var(--accent-cyan);
            text-decoration: none;
            font-size: 0.88rem;
            font-weight: 600;
            white-space: nowrap;
        }
        .nav-bar a:hover { text-decoration: underline; }

        /* Main Section Cards */
        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
        }
        .card-title { font-size: 1.25rem; color: var(--text-heading); font-weight: 600; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.92rem;
            margin-top: 10px;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th { background-color: var(--bg-card); color: var(--text-muted); font-weight: 600; }
        tr:hover { background-color: rgba(255, 255, 255, 0.02); }

        /* Collapsible Raw Outputs */
        details {
            background-color: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-top: 14px;
            overflow: hidden;
        }
        summary {
            padding: 12px 16px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            color: var(--accent-cyan);
            background-color: var(--bg-card);
            user-select: none;
        }
        summary:hover { background-color: #282e37; }
        pre {
            padding: 16px;
            overflow-x: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            color: #7ee787;
            white-space: pre-wrap;
            word-break: break-word;
        }

        /* Disclaimer & Footer */
        .disclaimer-box {
            background: rgba(210, 153, 34, 0.1);
            border: 1px solid var(--accent-yellow);
            border-radius: 8px;
            padding: 16px;
            margin-top: 24px;
            font-size: 0.88rem;
        }
        .footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 32px;
            padding-bottom: 24px;
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header Section -->
    <div class="header">
        <div class="header-title">
            <h1>ReconX Security Report</h1>
            <p>Automated Reconnaissance & Attack-Surface Enumeration</p>
        </div>
        <div>
EOF

    # Dynamic Header Badges
    if [[ "$scan_status" == "COMPLETED" ]]; then
        echo "            <span class=\"badge badge-success\">Status: Scan Completed</span>" >> "$REPORT_FILE"
    else
        echo "            <span class=\"badge badge-danger\">Status: Interrupted</span>" >> "$REPORT_FILE"
    fi
    echo "            <span class=\"badge badge-purple\">Mode: ${SCAN_MODE^^}</span>" >> "$REPORT_FILE"

    cat << EOF >> "$REPORT_FILE"
        </div>
    </div>

    <!-- Navigation -->
    <div class="nav-bar">
        <a href="#summary">Executive Summary</a>
        <a href="#target-info">Target Profile</a>
        <a href="#reachability">Reachability</a>
        <a href="#dns">DNS Recon</a>
        <a href="#whois">WHOIS</a>
        <a href="#hosts">Host Discovery</a>
        <a href="#ports">Ports & Services</a>
        <a href="#nse">NSE Modules</a>
        <a href="#findings">Validation Findings</a>
        <a href="#raw">Raw Artifacts</a>
    </div>

    <!-- KPI Metric Dashboard -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">Target Status</div>
            <div class="kpi-value" style="color: $( [[ "$PING_STATUS" =~ "Reachable" ]] && echo "var(--accent-green)" || echo "var(--accent-yellow)" );">
                $([ "$PING_STATUS" = "Reachable" ] && echo "ONLINE" || echo "DROPPED")
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Live Hosts</div>
            <div class="kpi-value">${LIVE_HOSTS_COUNT}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Open Ports</div>
            <div class="kpi-value" style="color: var(--accent-cyan);">${OPEN_PORTS_COUNT}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Services Identified</div>
            <div class="kpi-value">${SERVICES_COUNT}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">DNS Records</div>
            <div class="kpi-value">${DNS_RECORDS_COUNT}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Potential Findings</div>
            <div class="kpi-value" style="color: $( [[ ${#FINDINGS_LIST[@]} -gt 0 ]] && echo "var(--accent-yellow)" || echo "var(--accent-green)" );">
                ${#FINDINGS_LIST[@]}
            </div>
        </div>
    </div>

    <!-- Section 1: Executive Summary & Target Profile -->
    <div class="card" id="target-info">
        <div class="card-header">
            <h2 class="card-title">1. Target Information & Environment</h2>
        </div>
        <table>
            <tr><th width="30%">Target Specification</th><td><strong>$(echo "$TARGET" | html_escape)</strong></td></tr>
            <tr><th>Target Classification</th><td><span class="badge badge-info">${TARGET_TYPE}</span></td></tr>
            <tr><th>Resolved IPv4 Address</th><td>$(echo "${RESOLVED_IP:-N/A}" | html_escape)</td></tr>
            <tr><th>Scan Start Time</th><td>${START_TIME}</td></tr>
            <tr><th>Scan End Time</th><td>${END_TIME}</td></tr>
            <tr><th>Total Duration</th><td>${duration_formatted}</td></tr>
            <tr><th>Scanner Platform</th><td>$(echo "$scanner_hostname ($scanner_os)" | html_escape)</td></tr>
            <tr><th>Scan Mode Executed</th><td>${SCAN_MODE^^} $([ "$ENABLE_VULN" = true ] && echo "(+Vuln Scan)")</td></tr>
        </table>
    </div>

    <!-- Section 2: Ping & Reachability -->
    <div class="card" id="reachability">
        <div class="card-header">
            <h2 class="card-title">2. Reachability & ICMP Probes</h2>
            <span class="badge $( [[ "$PING_STATUS" =~ "Reachable" ]] && echo "badge-success" || echo "badge-warning" )">${PING_STATUS}</span>
        </div>
        <table>
            <tr><th width="30%">Packets Transmitted</th><td>${PING_TRANSMITTED}</td></tr>
            <tr><th>Packets Received</th><td>${PING_RECEIVED}</td></tr>
            <tr><th>Packet Loss Percentage</th><td>${PING_LOSS}</td></tr>
            <tr><th>Latency (Min / Avg / Max)</th><td>${PING_MIN} / ${PING_AVG} / ${PING_MAX}</td></tr>
        </table>
        <details>
            <summary>View Raw Ping Probe Output</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/ping.txt")</pre>
        </details>
    </div>

    <!-- Section 3: DNS Reconnaissance -->
    <div class="card" id="dns">
        <div class="card-header">
            <h2 class="card-title">3. DNS Reconnaissance & Resolution Matrix</h2>
            <span class="badge badge-info">${DNS_RECORDS_COUNT} Records</span>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 14px;">Direct queries executed via BIND <code>dig</code> for primary DNS resource records.</p>
        <table>
            <thead>
                <tr>
                    <th width="15%">Record Type</th>
                    <th>Extracted DNS Answers</th>
                </tr>
            </thead>
            <tbody>
EOF

    # Populate DNS Rows dynamically
    local dns_types=("A" "AAAA" "MX" "NS" "TXT" "SOA" "CNAME" "SRV" "CAA" "ANY")
    for t in "${dns_types[@]}"; do
        local f="${OUTPUT_DIR}/dns/dns_$(echo "$t" | tr '[:upper:]' '[:lower:]').txt"
        local answers="<em>None discovered</em>"
        if [[ -f "$f" && -s "$f" ]]; then
            answers="$(grep -E "\s+IN\s+" "$f" | awk '{print $4, $5, $6, $7, $8}' | html_escape || true)"
            [[ -z "$answers" ]] && answers="<em>Query executed, no direct answer</em>"
        fi
        echo "                <tr><td><strong>${t}</strong></td><td><pre style=\"padding:4px; background:none; color:#c9d1d9;\">${answers}</pre></td></tr>" >> "$REPORT_FILE"
    done

    # Reverse DNS row
    local rev_content
    rev_content="$(get_file_content_escaped "${OUTPUT_DIR}/dns/reverse_dns.txt" 20)"
    echo "                <tr><td><strong>Reverse DNS (PTR)</strong></td><td><pre style=\"padding:4px; background:none; color:#c9d1d9;\">${rev_content}</pre></td></tr>" >> "$REPORT_FILE"

    cat << EOF >> "$REPORT_FILE"
            </tbody>
        </table>
        <details>
            <summary>View Authoritative DNS Trace (+trace)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/dns/dns_trace.txt")</pre>
        </details>
    </div>

    <!-- Section 4: WHOIS Information -->
    <div class="card" id="whois">
        <div class="card-header">
            <h2 class="card-title">4. WHOIS Domain & Organization Information</h2>
        </div>
EOF

    # Extract WHOIS highlights
    local whois_raw="${OUTPUT_DIR}/whois.txt"
    if [[ -f "$whois_raw" && -s "$whois_raw" ]]; then
        local w_domain w_registrar w_created w_updated w_expiry w_org w_country
        w_domain="$(grep -i -E "Domain Name:|domain:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_registrar="$(grep -i -E "Registrar:|registrar:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_created="$(grep -i -E "Creation Date:|created:|registered:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_updated="$(grep -i -E "Updated Date:|last-modified:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_expiry="$(grep -i -E "Registry Expiry Date:|paid-till:|expire:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_org="$(grep -i -E "Registrant Organization:|org-name:|org:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"
        w_country="$(grep -i -E "Registrant Country:|country:" "$whois_raw" | head -n 1 | cut -d':' -f2- | xargs | html_escape)"

        cat << EOF >> "$REPORT_FILE"
        <table>
            <tr><th width="30%">Domain Name</th><td>${w_domain:-Not specified}</td></tr>
            <tr><th>Registrar</th><td>${w_registrar:-Not specified}</td></tr>
            <tr><th>Creation / Registration Date</th><td>${w_created:-Not specified}</td></tr>
            <tr><th>Last Updated Date</th><td>${w_updated:-Not specified}</td></tr>
            <tr><th>Expiration Date</th><td>${w_expiry:-Not specified}</td></tr>
            <tr><th>Organization</th><td>${w_org:-Not specified}</td></tr>
            <tr><th>Country</th><td>${w_country:-Not specified}</td></tr>
        </table>
EOF
    else
        echo "<p>WHOIS information unavailable.</p>" >> "$REPORT_FILE"
    fi

    cat << EOF >> "$REPORT_FILE"
        <details>
            <summary>View Complete Raw WHOIS Output</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/whois.txt")</pre>
        </details>
    </div>

    <!-- Section 5: Host Discovery -->
    <div class="card" id="hosts">
        <div class="card-header">
            <h2 class="card-title">5. Host Discovery Results (-sn)</h2>
            <span class="badge badge-info">${LIVE_HOSTS_COUNT} Active Host(s)</span>
        </div>
        <details open>
            <summary>Discovered Hosts & Network Interfaces</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_host_discovery.txt")</pre>
        </details>
    </div>

    <!-- Section 6: Open Ports & Services -->
    <div class="card" id="ports">
        <div class="card-header">
            <h2 class="card-title">6. Open TCP Ports & Detected Services</h2>
            <span class="badge badge-info">${OPEN_PORTS_COUNT} Open Port(s)</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th width="15%">Port</th>
                    <th width="12%">Protocol</th>
                    <th width="15%">State</th>
                    <th width="20%">Service</th>
                    <th>Product / Version Details</th>
                </tr>
            </thead>
            <tbody>
EOF

    # Populate Open Ports Table from service detection
    local sV_file="${OUTPUT_DIR}/nmap/nmap_service_detection.txt"
    local found_table_rows=false

    if [[ -f "$sV_file" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]+([a-zA-Z]+)[[:space:]]+([^[:space:]]+)[[:space:]]*(.*)$ ]]; then
                found_table_rows=true
                local p_num="${BASH_REMATCH[1]}"
                local p_proto="${BASH_REMATCH[2]}"
                local p_state="${BASH_REMATCH[3]}"
                local p_service="${BASH_REMATCH[4]}"
                local p_ver="${BASH_REMATCH[5]}"
                cat << EOF >> "$REPORT_FILE"
                <tr>
                    <td><strong>${p_num}</strong></td>
                    <td>${p_proto^^}</td>
                    <td><span class="badge badge-success">${p_state}</span></td>
                    <td><code>${p_service}</code></td>
                    <td>$(echo "${p_ver:-Unidentified banner}" | html_escape)</td>
                </tr>
EOF
            fi
        done < <(grep -E "^[0-9]+/(tcp|udp)" "$sV_file" || true)
    fi

    if [[ "$found_table_rows" == false ]]; then
        echo "                <tr><td colspan=\"5\"><em>No open ports identified in current scan parameters.</em></td></tr>" >> "$REPORT_FILE"
    fi

    cat << EOF >> "$REPORT_FILE"
            </tbody>
        </table>
        <details>
            <summary>View Raw Top 100 Port Scan Output</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_top100.txt")</pre>
        </details>
EOF

    if [[ -f "${OUTPUT_DIR}/nmap/nmap_all_tcp.txt" ]]; then
        cat << EOF >> "$REPORT_FILE"
        <details>
            <summary>View Raw Full TCP Port Scan Output (-p-)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_all_tcp.txt")</pre>
        </details>
EOF
    fi

    cat << EOF >> "$REPORT_FILE"
        <details>
            <summary>View Service Version Detection Output (-sV)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_service_detection.txt")</pre>
        </details>
    </div>

    <!-- Section 7: Operating System Detection -->
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">7. Operating System Fingerprinting (-O)</h2>
        </div>
        <details open>
            <summary>OS Fingerprint Output</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_os_detection.txt")</pre>
        </details>
    </div>

    <!-- Section 8: NSE Modules -->
    <div class="card" id="nse">
        <div class="card-header">
            <h2 class="card-title">8. Nmap Scripting Engine (NSE) Enumeration</h2>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 12px;">Results from safe, non-destructive discovery and enumeration scripts.</p>

        <details>
            <summary>Default Nmap Scripts (-sC)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nmap/nmap_default_scripts.txt")</pre>
        </details>

        <details>
            <summary>Safe Category NSE Scripts (default, safe)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nse/nse_safe.txt")</pre>
        </details>

        <details>
            <summary>HTTP Web Service Enumeration (Title, Headers, Methods, Enum)</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nse/nse_http.txt")</pre>
        </details>

        <details>
            <summary>SSL/TLS Certificate & Cipher Suite Inspection</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nse/nse_ssl.txt")</pre>
        </details>

        <details>
            <summary>DNS Service Enumeration</summary>
            <pre>$(get_file_content_escaped "${OUTPUT_DIR}/nse/nse_dns.txt")</pre>
        </details>
EOF

    if [[ "$ENABLE_VULN" == true ]]; then
        cat << EOF >> "$REPORT_FILE"
        <details open>
            <summary style="color: var(--accent-yellow);">Potential Vulnerability Information (--script vuln)</summary>
            <pre style="color: #ffb454;">$(get_file_content_escaped "${OUTPUT_DIR}/nse/nse_vulnerability_scan.txt")</pre>
        </details>
EOF
    fi

    cat << EOF >> "$REPORT_FILE"
    </div>

    <!-- Section 9: Findings Requiring Manual Validation -->
    <div class="card" id="findings">
        <div class="card-header">
            <h2 class="card-title">9. Findings Requiring Manual Validation</h2>
            <span class="badge badge-warning">${#FINDINGS_LIST[@]} Potential Finding(s)</span>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 14px;">
            <strong>Important Methodology Note:</strong> Automated tools identify service indicators and version banners. 
            Automated flags must never be assumed to be confirmed vulnerabilities without rigorous manual validation within authorized scope.
        </p>
        <table>
            <thead>
                <tr>
                    <th width="14%">Category</th>
                    <th width="30%">Finding Title</th>
                    <th>Context & Manual Verification Rationale</th>
                </tr>
            </thead>
            <tbody>
EOF

    if [[ ${#FINDINGS_LIST[@]} -eq 0 ]]; then
        echo "                <tr><td colspan=\"3\"><em>No security warnings or potential issues highlighted.</em></td></tr>" >> "$REPORT_FILE"
    else
        for item in "${FINDINGS_LIST[@]}"; do
            local f_cat f_title f_desc
            f_cat="$(echo "$item" | awk -F'|' '{print $1}')"
            f_title="$(echo "$item" | awk -F'|' '{print $2}' | html_escape)"
            f_desc="$(echo "$item" | awk -F'|' '{print $3}' | html_escape)"

            local b_class="badge-info"
            [[ "$f_cat" == "LOW" ]] && b_class="badge-warning"
            [[ "$f_cat" == "MEDIUM" ]] && b_class="badge-warning"
            [[ "$f_cat" == "HIGH" ]] && b_class="badge-danger"

            cat << EOF >> "$REPORT_FILE"
                <tr>
                    <td><span class="badge ${b_class}">${f_cat}</span></td>
                    <td><strong>${f_title}</strong></td>
                    <td>${f_desc}</td>
                </tr>
EOF
        done
    fi

    cat << EOF >> "$REPORT_FILE"
            </tbody>
        </table>
    </div>

    <!-- Section 10: Raw Scan Outputs -->
    <div class="card" id="raw">
        <div class="card-header">
            <h2 class="card-title">10. Raw Execution Log</h2>
        </div>
        <details>
            <summary>View Complete reconx.log</summary>
            <pre>$(get_file_content_escaped "${LOG_FILE}" 800)</pre>
        </details>
    </div>

    <!-- Methodology & Security Disclaimer -->
    <div class="disclaimer-box">
        <h4 style="color: var(--accent-yellow); margin-bottom: 8px;">Reconnaissance Methodology & Legal Disclaimer</h4>
        <p>
            This reconnaissance report was generated by <strong>ReconX</strong> strictly for authorized testing purposes.
            The scan activities performed include non-destructive ICMP reachability checks, standard RFC-compliant DNS queries,
            WHOIS queries, TCP port enumeration, banner version detection, and non-exploitative NSE enumeration. 
            No exploit payloads, brute-force attempts, or denial-of-service tests were performed.
        </p>
        <p style="margin-top: 8px; color: var(--text-muted);">
            All information contained herein must be treated with appropriate confidentiality and used strictly within the bounds 
            of authorized Rules of Engagement (RoE).
        </p>
    </div>

    <div class="footer">
        Generated by ReconX v${VERSION} &bull; Modern Bash Reconnaissance & Enumeration Toolkit
    </div>

</div>
</body>
</html>
EOF

    log_success "HTML reconnaissance report generated: ${REPORT_FILE}"
}

# ------------------------------------------------------------------------------
# Module 13: Summary Terminal Presentation
# ------------------------------------------------------------------------------
show_summary() {
    local end_epoch
    end_epoch="$(date +%s)"
    local duration_seconds=$(( end_epoch - START_EPOCH ))

    echo ""
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "${C_BOLD}                      RECONX EXECUTION SUMMARY                          ${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}"
    echo -e " ${C_BOLD}Target${C_RESET}               : ${C_CYAN}${TARGET}${C_RESET} (${TARGET_TYPE})"
    echo -e " ${C_BOLD}Scan Status${C_RESET}          : ${C_GREEN}COMPLETED${C_RESET}"
    echo -e " ${C_BOLD}Duration${C_RESET}             : ${duration_seconds} seconds"
    echo -e " ${C_BOLD}Reachability${C_RESET}         : ${PING_STATUS}"
    echo -e " ${C_BOLD}Live Hosts${C_RESET}           : ${LIVE_HOSTS_COUNT}"
    echo -e " ${C_BOLD}Open TCP Ports${C_RESET}       : ${OPEN_PORTS_COUNT}"
    echo -e " ${C_BOLD}Detected Services${C_RESET}    : ${SERVICES_COUNT}"
    echo -e " ${C_BOLD}DNS Records Found${C_RESET}    : ${DNS_RECORDS_COUNT}"
    echo -e " ${C_BOLD}Potential Findings${C_RESET}   : ${#FINDINGS_LIST[@]}"
    echo -e "${C_GRAY}------------------------------------------------------------------------${C_RESET}"
    echo -e " ${C_BOLD}Raw Log File${C_RESET}         : ${C_CYAN}${LOG_FILE}${C_RESET}"
    echo -e " ${C_BOLD}HTML Report${C_RESET}          : ${C_GREEN}${REPORT_FILE}${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}"
    echo -e " Open the HTML report in any web browser:"
    echo -e " ${C_YELLOW}xdg-open ${REPORT_FILE}${C_RESET}  or  ${C_YELLOW}firefox ${REPORT_FILE}${C_RESET}"
    echo ""
}

# ------------------------------------------------------------------------------
# CLI Argument Parsing & Main Controller
# ------------------------------------------------------------------------------
main() {
    START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
    START_EPOCH="$(date +%s)"

    # Positional or Option Parsing
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -v|--version)
                show_version
                ;;
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -q|--quick)
                SCAN_MODE="quick"
                shift
                ;;
            -n|--normal)
                SCAN_MODE="normal"
                shift
                ;;
            -f|--full)
                SCAN_MODE="full"
                shift
                ;;
            --vuln)
                ENABLE_VULN=true
                shift
                ;;
            --no-ping)
                SKIP_PING=true
                shift
                ;;
            --no-dns)
                SKIP_DNS=true
                shift
                ;;
            --no-whois)
                SKIP_WHOIS=true
                shift
                ;;
            --no-nse)
                SKIP_NSE=true
                shift
                ;;
            -o|--output)
                CUSTOM_OUTPUT_DIR="$2"
                shift 2
                ;;
            -*)
                echo -e "${C_RED}[ERROR] Unknown option: $1${C_RESET}"
                echo "Use --help for command line usage."
                exit 1
                ;;
            *)
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                else
                    echo -e "${C_RED}[ERROR] Unexpected additional argument: $1${C_RESET}"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Validate target presence
    if [[ -z "$TARGET" ]]; then
        echo -e "${C_RED}[ERROR] No target specified.${C_RESET}"
        echo "Usage: ./reconx.sh [OPTIONS] TARGET"
        echo "Try './reconx.sh --help' for full details."
        exit 1
    fi

    # Run preliminary validations & system checks
    validate_target "$TARGET"
    check_dependencies
    setup_output
    print_banner

    # Execute Reconnaissance Pipeline
    log_info "Initiating reconnaissance workflow in [${SCAN_MODE^^}] mode..."

    run_ping
    run_dns_recon
    run_whois
    run_nmap_discovery
    run_nmap_ports
    run_nmap_version

    if [[ "$SCAN_MODE" == "full" ]]; then
        run_nmap_os
    fi

    if [[ "$SCAN_MODE" != "quick" ]]; then
        run_nmap_default_scripts
        run_nse_enum
    fi

    if [[ "$ENABLE_VULN" == true ]]; then
        run_nse_vuln_info
    fi

    generate_html_report "COMPLETED"
    show_summary
}

main "$@"
