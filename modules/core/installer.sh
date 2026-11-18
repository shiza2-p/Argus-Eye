#!/bin/bash
# ================================================
# ARGUS-EYE - Tool Installer Module
# Handles installation of all required tools
# ================================================

INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$INSTALLER_DIR"

if [[ -z "$SCRIPT_DIR" ]]; then
    export SCRIPT_DIR="$(cd "$INSTALLER_DIR/../.." && pwd)"
fi

TOOLS_DIR="$SCRIPT_DIR/tools"
LOGS_DIR="$SCRIPT_DIR/logs"
mkdir -p "$TOOLS_DIR" "$LOGS_DIR" 2>/dev/null

if [[ -f "$CORE_DIR/utils.sh" ]]; then
    source "$CORE_DIR/utils.sh"
else
    echo -e "\033[0;31m[!] CRITICAL: Cannot find utils.sh at $CORE_DIR/utils.sh\033[0m"
    return 1 2>/dev/null || exit 1
fi

declare -A INSTALL_STATUS=()
INSTALL_LOG="$LOGS_DIR/install_$(date +%Y%m%d).log"

# ================================================
# BOX / MENU DRAWING HELPERS
# All boxes are exactly 68 chars wide:
#   ╔ + 66×═ + ╗  → 68 total
#   ║ + space + %-65s + ║  → 1+1+65+1 = 68 total
#   ┌ + 66×─ + ┐  → 68 total
#   │ + space + %-65s + │  → 68 total
# ================================================
_box_top()  { echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"; }
_box_bot()  { echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"; }
_box_row()  { echo -e "${CYAN}$(printf "║ %-65s║" "$1")${NC}"; }
_menu_top() { echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"; }
_menu_sep() { echo -e "${CYAN}├──────────────────────────────────────────────────────────────────┤${NC}"; }
_menu_bot() { echo -e "${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"; }
_menu_row() { echo -e "${CYAN}$(printf "│ %-65s│" "$1")${NC}"; }

# ================================================
# CHECK IF TOOL IS INSTALLED
# ================================================
is_tool_installed() {
    local tool=$1

    if [[ "$tool" == "custom_tests" ]]; then
        INSTALL_STATUS["$tool"]=1
        return 0
    fi

    if [[ -n "${INSTALL_STATUS[$tool]}" ]] && [[ "${INSTALL_STATUS[$tool]}" -eq 1 ]]; then
        return 0
    fi

    if command -v "$tool" &>/dev/null; then
        INSTALL_STATUS["$tool"]=1
        return 0
    fi

    for ext in "" ".py" ".rb" ".sh"; do
        if [[ -f "$TOOLS_DIR/$tool/$tool$ext" ]]; then
            export PATH="$TOOLS_DIR/$tool:$PATH"
            INSTALL_STATUS["$tool"]=1
            return 0
        fi
    done

    # Special case: XXEinjector
    if [[ "$tool" == "xxeinjector" ]] && \
       [[ -f "$TOOLS_DIR/XXEinjector/XXEinjector.rb" ]]; then
        INSTALL_STATUS["$tool"]=1
        return 0
    fi

    # Special case: SSRFmap
    if [[ "$tool" == "ssrfmap" ]] && \
       [[ -f "$TOOLS_DIR/SSRFmap/ssrfmap.py" ]]; then
        INSTALL_STATUS["$tool"]=1
        return 0
    fi

    # FIX: XSStrike wrapper is named 'xsstrike' (lowercase), not 'XSStrike'
    # command -v "XSStrike" always fails → always reinstalls without this check
    if [[ "$tool" == "XSStrike" ]]; then
        if command -v xsstrike &>/dev/null || [[ -f "$TOOLS_DIR/XSStrike/xsstrike.py" ]]; then
            INSTALL_STATUS["$tool"]=1
            return 0
        fi
    fi

    # FIX: PwnXSS wrapper is named 'pwnxss' (lowercase), not 'PwnXSS'
    if [[ "$tool" == "PwnXSS" ]]; then
        if command -v pwnxss &>/dev/null || [[ -f "$TOOLS_DIR/PwnXSS.py" ]]; then
            INSTALL_STATUS["$tool"]=1
            return 0
        fi
    fi

    INSTALL_STATUS["$tool"]=0
    return 1
}

# ================================================
# LOG INSTALLATION
# ================================================
log_install() {
    local tool=$1
    local status=$2
    local message=$3
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$tool] $status - $message" >> "$INSTALL_LOG"
}

# ================================================
# INSTALL DOCKER (dependency for many tools)
# ================================================
install_docker() {
    echo -e "${YELLOW}[*] Installing Docker...${NC}"

    if command -v docker &>/dev/null; then
        echo -e "${GREEN}[✓] Docker already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get update
        sudo apt-get install -y docker.io
        sudo systemctl start docker
        sudo systemctl enable docker
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y docker
        sudo systemctl start docker
        sudo systemctl enable docker
    else
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        rm get-docker.sh
    fi

    sudo usermod -aG docker "$USER"

    if command -v docker &>/dev/null; then
        echo -e "${GREEN}[✓] Docker installed successfully${NC}"
        log_install "docker" "SUCCESS" "Installed via system package"
        return 0
    else
        echo -e "${RED}[!] Failed to install Docker${NC}"
        log_install "docker" "FAILED" "Installation failed"
        return 1
    fi
}

# ================================================
# INSTALL GO (dependency for Go-based tools)
# ================================================
install_go() {
    echo -e "${YELLOW}[*] Installing Go...${NC}"

    if command -v go &>/dev/null; then
        echo -e "${GREEN}[✓] Go already installed ($(go version | awk '{print $3}'))${NC}"
        return 0
    fi

    local GO_VERSION="1.21.0"
    local GO_ARCH="amd64"

    if [[ "$(uname -m)" == "armv7l" ]] || [[ "$(uname -m)" == "aarch64" ]]; then
        GO_ARCH="arm64"
    fi

    echo -e "${CYAN}[*] Downloading Go ${GO_VERSION} (${GO_ARCH})...${NC}"
    wget -q "https://golang.org/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz || {
        echo -e "${RED}[!] Failed to download Go${NC}"
        log_install "go" "FAILED" "Download failed"
        return 1
    }

    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    if command -v go &>/dev/null; then
        echo -e "${GREEN}[✓] Go installed successfully ($(go version | awk '{print $3}'))${NC}"
        log_install "go" "SUCCESS" "Installed version $GO_VERSION"
        return 0
    else
        echo -e "${RED}[!] Failed to install Go${NC}"
        log_install "go" "FAILED" "Installation failed"
        return 1
    fi
}

# ================================================
# INSTALL PYTHON AND PIP
# ================================================
install_python() {
    echo -e "${YELLOW}[*] Checking Python installation...${NC}"

    if ! command -v python3 &>/dev/null; then
        echo -e "${YELLOW}[*] Installing Python3...${NC}"
        if [[ -f /etc/debian_version ]]; then
            sudo apt-get install -y python3 python3-pip python3-venv
        elif [[ -f /etc/redhat-release ]]; then
            sudo yum install -y python3 python3-pip
        else
            echo -e "${RED}[!] Cannot install Python automatically${NC}"
            return 1
        fi
    fi

    if command -v python3 &>/dev/null; then
        echo -e "${GREEN}[✓] Python3 available ($(python3 --version | awk '{print $2}'))${NC}"
        return 0
    else
        return 1
    fi
}

# ================================================
# INSTALL RUBY (dependency for Ruby-based tools)
# ================================================
install_ruby() {
    echo -e "${YELLOW}[*] Checking Ruby installation...${NC}"

    if command -v ruby &>/dev/null; then
        local ruby_ver
        ruby_ver=$(ruby --version 2>/dev/null | awk '{print $2}')
        echo -e "${GREEN}[✓] Ruby already installed (version: $ruby_ver)${NC}"
        return 0
    fi

    echo -e "${YELLOW}[*] Installing Ruby...${NC}"

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get update -q
        sudo apt-get install -y ruby ruby-dev build-essential
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y ruby ruby-devel gcc make
    else
        echo -e "${RED}[!] Cannot install Ruby automatically on this platform${NC}"
        echo -e "${YELLOW}    Please install Ruby manually: https://www.ruby-lang.org/en/downloads/${NC}"
        return 1
    fi

    if command -v ruby &>/dev/null; then
        local ruby_ver
        ruby_ver=$(ruby --version | awk '{print $2}')
        echo -e "${GREEN}[✓] Ruby installed successfully (version: $ruby_ver)${NC}"
        log_install "ruby" "SUCCESS" "Installed via system package, version $ruby_ver"
        return 0
    else
        echo -e "${RED}[!] Failed to install Ruby${NC}"
        log_install "ruby" "FAILED" "Package installation failed"
        return 1
    fi
}

# ================================================
# TOOL-SPECIFIC INSTALLERS
# ================================================

# ── XSS ─────────────────────────────────────────

# Install dalfox (Go-based XSS scanner) - project local preferred
install_dalfox() {
    echo -e "${YELLOW}[*] Installing dalfox...${NC}"

    mkdir -p "$TOOLS_DIR/dalfox" "$TOOLS_DIR/bin"

    # Already available inside project?
    if [[ -x "$TOOLS_DIR/dalfox/dalfox" ]] || [[ -x "$TOOLS_DIR/bin/dalfox" ]]; then
        echo -e "${GREEN}[✓] dalfox already present in tools/${NC}"
        return 0
    fi
    if command -v dalfox &>/dev/null; then
        echo -e "${GREEN}[✓] dalfox already available in PATH${NC}"
        return 0
    fi

    if ! command -v go &>/dev/null; then
        install_go || return 1
    fi

    echo -e "${CYAN}[*] Installing dalfox via Go into tools/...${NC}"
    GOBIN="$TOOLS_DIR/bin" go install github.com/hahwul/dalfox/v2@latest 2>/dev/null ||         go install github.com/hahwul/dalfox/v2@latest

    # Copy from default Go bin if GOBIN didn't work
    if [[ ! -x "$TOOLS_DIR/bin/dalfox" && -f "$HOME/go/bin/dalfox" ]]; then
        cp "$HOME/go/bin/dalfox" "$TOOLS_DIR/bin/dalfox"
        chmod +x "$TOOLS_DIR/bin/dalfox"
    fi

    if [[ -x "$TOOLS_DIR/bin/dalfox" ]] || [[ -x "$TOOLS_DIR/dalfox/dalfox" ]] || command -v dalfox &>/dev/null; then
        echo -e "${GREEN}[✓] dalfox installed successfully (project-local)${NC}"
        log_install "dalfox" "SUCCESS" "Installed into tools/"
        return 0
    else
        echo -e "${RED}[!] Failed to install dalfox${NC}"
        log_install "dalfox" "FAILED" "Go installation failed"
        return 1
    fi
}

# Install XSStrike (Python-based XSS scanner) - project local
install_xsstrike() {
    echo -e "${YELLOW}[*] Installing XSStrike...${NC}"

    install_python || return 1
    mkdir -p "$TOOLS_DIR/bin"

    if [[ -f "$TOOLS_DIR/XSStrike/xsstrike.py" ]]; then
        echo -e "${GREEN}[✓] XSStrike already present in tools/${NC}"
        # Ensure wrapper exists
        if [[ ! -x "$TOOLS_DIR/bin/xsstrike" ]]; then
            cat > "$TOOLS_DIR/bin/xsstrike" << 'WRAP'
#!/bin/bash
DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$DIR/XSStrike/xsstrike.py" "$@"
WRAP
            chmod +x "$TOOLS_DIR/bin/xsstrike"
        fi
        return 0
    fi

    # Remove broken/partial install
    if [[ -d "$TOOLS_DIR/XSStrike" ]]; then
        echo -e "${YELLOW}[*] Removing incomplete XSStrike directory...${NC}"
        rm -rf "$TOOLS_DIR/XSStrike"
    fi

    echo -e "${CYAN}[*] Cloning XSStrike into tools/...${NC}"
    local clone_ok=0
    if command -v git >/dev/null 2>&1; then
        if git clone --depth 1 https://github.com/s0md3v/XSStrike.git "$TOOLS_DIR/XSStrike"; then
            clone_ok=1
        else
            echo -e "${YELLOW}[!] git clone failed – trying zip download...${NC}"
            rm -rf "$TOOLS_DIR/XSStrike" 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}[!] git not found – trying zip download...${NC}"
    fi

    # Fallback: download zip from GitHub
    if [[ $clone_ok -eq 0 ]]; then
        local tmpzip
        tmpzip=$(mktemp /tmp/xsstrike_XXXXXX.zip 2>/dev/null || echo /tmp/xsstrike_$$.zip)
        if command -v curl >/dev/null 2>&1; then
            curl -L --fail -o "$tmpzip" "https://github.com/s0md3v/XSStrike/archive/refs/heads/master.zip" 2>&1 | tail -3
        elif command -v wget >/dev/null 2>&1; then
            wget -O "$tmpzip" "https://github.com/s0md3v/XSStrike/archive/refs/heads/master.zip" 2>&1 | tail -3
        else
            echo -e "${RED}[!] Neither git, curl, nor wget available${NC}"
            log_install "XSStrike" "FAILED" "no download tool"
            return 1
        fi

        if [[ -f "$tmpzip" && -s "$tmpzip" ]]; then
            mkdir -p "$TOOLS_DIR"
            unzip -q -o "$tmpzip" -d "$TOOLS_DIR" 2>/dev/null || true
            # GitHub zip extracts as XSStrike-master
            if [[ -d "$TOOLS_DIR/XSStrike-master" ]]; then
                mv "$TOOLS_DIR/XSStrike-master" "$TOOLS_DIR/XSStrike"
            elif [[ -d "$TOOLS_DIR/XSStrike-main" ]]; then
                mv "$TOOLS_DIR/XSStrike-main" "$TOOLS_DIR/XSStrike"
            fi
            rm -f "$tmpzip"
        fi
    fi

    if [[ -f "$TOOLS_DIR/XSStrike/requirements.txt" ]]; then
        echo -e "${CYAN}[*] Installing XSStrike dependencies...${NC}"
        pip3 install -r "$TOOLS_DIR/XSStrike/requirements.txt" -q 2>/dev/null || true
    fi

    # Local wrapper (no sudo) - robust path handling
    mkdir -p "$TOOLS_DIR/bin"
    cat > "$TOOLS_DIR/bin/xsstrike" << 'WRAP'
#!/bin/bash
DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$DIR/XSStrike/xsstrike.py" "$@"
WRAP
    chmod +x "$TOOLS_DIR/bin/xsstrike"

    if [[ -f "$TOOLS_DIR/XSStrike/xsstrike.py" ]]; then
        echo -e "${GREEN}[✓] XSStrike installed successfully (project-local)${NC}"
        log_install "XSStrike" "SUCCESS" "Installed into tools/"
        return 0
    else
        echo -e "${RED}[!] XSStrike installation failed${NC}"
        echo -e "${YELLOW}[*] Manual fix:${NC}"
        echo "    cd "$TOOLS_DIR""
        echo "    git clone https://github.com/s0md3v/XSStrike.git"
        log_install "XSStrike" "FAILED" "clone/download failed"
        return 1
    fi
}

# Install PwnXSS (Python-based XSS scanner)
# Install PwnXSS (Python-based XSS scanner) - project local
install_pwnxss() {
    echo -e "${YELLOW}[*] Installing PwnXSS...${NC}"

    install_python || return 1
    mkdir -p "$TOOLS_DIR/bin"

    if [[ -f "$TOOLS_DIR/PwnXSS/pwnxss.py" ]] || [[ -f "$TOOLS_DIR/PwnXSS/PwnXSS.py" ]]; then
        echo -e "${GREEN}[✓] PwnXSS already present in tools/${NC}"
        return 0
    fi

    echo -e "${CYAN}[*] Cloning PwnXSS into tools/...${NC}"
    git clone --depth 1 https://github.com/pwn0sec/PwnXSS.git "$TOOLS_DIR/PwnXSS" 2>/dev/null

    local pwn_script=""
    if [[ -f "$TOOLS_DIR/PwnXSS/pwnxss.py" ]]; then
        pwn_script="$TOOLS_DIR/PwnXSS/pwnxss.py"
    elif [[ -f "$TOOLS_DIR/PwnXSS/PwnXSS.py" ]]; then
        pwn_script="$TOOLS_DIR/PwnXSS/PwnXSS.py"
    fi

    if [[ -n "$pwn_script" ]]; then
        mkdir -p "$TOOLS_DIR/bin"
        cat > "$TOOLS_DIR/bin/pwnxss" << 'WRAP'
#!/bin/bash
DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$DIR/PwnXSS/pwnxss.py" ]]; then
    exec python3 "$DIR/PwnXSS/pwnxss.py" "$@"
elif [[ -f "$DIR/PwnXSS/PwnXSS.py" ]]; then
    exec python3 "$DIR/PwnXSS/PwnXSS.py" "$@"
else
    echo "PwnXSS script not found" >&2
    exit 1
fi
WRAP
        chmod +x "$TOOLS_DIR/bin/pwnxss"
        echo -e "${GREEN}[✓] PwnXSS installed successfully (project-local)${NC}"
        log_install "PwnXSS" "SUCCESS" "Installed into tools/"
        return 0
    else
        echo -e "${RED}[!] PwnXSS installation failed${NC}"
        return 1
    fi
}

install_sqlmap() {
    echo -e "${YELLOW}[*] Installing sqlmap...${NC}"

    if command -v sqlmap &>/dev/null; then
        echo -e "${GREEN}[✓] sqlmap already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y sqlmap
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y sqlmap
    else
        echo -e "${CYAN}[*] Cloning sqlmap from GitHub...${NC}"
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git \
            "$TOOLS_DIR/sqlmap" 2>/dev/null
        sudo ln -sf "$TOOLS_DIR/sqlmap/sqlmap.py" "/usr/local/bin/sqlmap" 2>/dev/null
    fi

    if command -v sqlmap &>/dev/null; then
        echo -e "${GREEN}[✓] sqlmap installed successfully${NC}"
        log_install "sqlmap" "SUCCESS" "Installed via package/git"
        return 0
    else
        echo -e "${RED}[!] Failed to install sqlmap${NC}"
        log_install "sqlmap" "FAILED" "Installation failed"
        return 1
    fi
}

# Install nosqli (Go-based NoSQL injection scanner)
install_nosqli() {
    echo -e "${CYAN}[*] Installing nosqli (Go-based NoSQLi scanner)...${NC}"

    if command -v nosqli &>/dev/null; then
        echo -e "${GREEN}[✓] nosqli already installed${NC}"
        return 0
    fi

    mkdir -p "$TOOLS_DIR"

    if command -v go &>/dev/null; then
        echo -e "${CYAN}[*] Building nosqli from source with Go...${NC}"
        local _orig="$PWD"
        cd "$TOOLS_DIR" || return 1
        git clone https://github.com/Charlie-belmer/nosqli.git --depth 1 2>/dev/null || true
        cd nosqli 2>/dev/null || { cd "$_orig"; return 1; }
        go install ./...
        cd "$_orig"
        if [[ -f "$HOME/go/bin/nosqli" ]]; then
            cp "$HOME/go/bin/nosqli" "$TOOLS_DIR/"
            sudo ln -sf "$TOOLS_DIR/nosqli" "/usr/local/bin/nosqli" 2>/dev/null
        fi
        echo -e "${GREEN}[✓] nosqli installed via Go${NC}"
    else
        echo -e "${CYAN}[*] Downloading nosqli pre-built Linux binary...${NC}"
        wget -q https://github.com/Charlie-belmer/nosqli/releases/download/v0.5.4/nosqli_linux_amd64 \
            -O "$TOOLS_DIR/nosqli"
        chmod +x "$TOOLS_DIR/nosqli"
        sudo ln -sf "$TOOLS_DIR/nosqli" "/usr/local/bin/nosqli" 2>/dev/null
        echo -e "${GREEN}[✓] nosqli binary installed${NC}"
    fi

    if command -v nosqli &>/dev/null; then
        log_install "nosqli" "SUCCESS" "Installed via Go or binary"
        return 0
    else
        echo -e "${RED}[!] Failed to install nosqli${NC}"
        log_install "nosqli" "FAILED" "Installation failed"
        return 1
    fi
}

# ── LFI / Directory ──────────────────────────────

# Install ffuf
install_ffuf() {
    echo -e "${YELLOW}[*] Installing ffuf...${NC}"

    if command -v ffuf &>/dev/null; then
        echo -e "${GREEN}[✓] ffuf already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y ffuf
    else
        if ! command -v go &>/dev/null; then
            install_go || return 1
        fi
        go install github.com/ffuf/ffuf@latest
        sudo ln -sf "$HOME/go/bin/ffuf" "/usr/local/bin/ffuf" 2>/dev/null
    fi

    if command -v ffuf &>/dev/null; then
        echo -e "${GREEN}[✓] ffuf installed successfully${NC}"
        log_install "ffuf" "SUCCESS" "Installed via apt/go"
        return 0
    else
        echo -e "${RED}[!] Failed to install ffuf${NC}"
        return 1
    fi
}

# Install gobuster
install_gobuster() {
    echo -e "${YELLOW}[*] Installing gobuster...${NC}"

    if command -v gobuster &>/dev/null; then
        echo -e "${GREEN}[✓] gobuster already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y gobuster
    else
        if ! command -v go &>/dev/null; then
            install_go || return 1
        fi
        go install github.com/OJ/gobuster/v3@latest
        sudo ln -sf "$HOME/go/bin/gobuster" "/usr/local/bin/gobuster" 2>/dev/null
    fi

    if command -v gobuster &>/dev/null; then
        echo -e "${GREEN}[✓] gobuster installed successfully${NC}"
        log_install "gobuster" "SUCCESS" "Installed via apt/go"
        return 0
    else
        echo -e "${RED}[!] Failed to install gobuster${NC}"
        return 1
    fi
}

# Install dirsearch
install_dirsearch() {
    echo -e "${YELLOW}[*] Installing dirsearch...${NC}"

    if command -v dirsearch &>/dev/null; then
        echo -e "${GREEN}[✓] dirsearch already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y dirsearch
    else
        echo -e "${RED}[!] dirsearch only available via apt on Debian/Kali${NC}"
        return 1
    fi

    if command -v dirsearch &>/dev/null; then
        echo -e "${GREEN}[✓] dirsearch installed successfully${NC}"
        log_install "dirsearch" "SUCCESS" "Installed via apt"
        return 0
    else
        echo -e "${RED}[!] Failed to install dirsearch${NC}"
        log_install "dirsearch" "FAILED" "apt install failed"
        return 1
    fi
}

# Install nikto
install_nikto() {
    echo -e "${YELLOW}[*] Installing nikto...${NC}"

    if command -v nikto &>/dev/null; then
        echo -e "${GREEN}[✓] nikto already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y nikto
    else
        echo -e "${CYAN}[*] Cloning nikto from GitHub...${NC}"
        git clone https://github.com/sullo/nikto.git "$TOOLS_DIR/nikto" 2>/dev/null
        sudo ln -sf "$TOOLS_DIR/nikto/program/nikto.pl" "/usr/local/bin/nikto" 2>/dev/null
    fi

    if command -v nikto &>/dev/null; then
        echo -e "${GREEN}[✓] nikto installed successfully${NC}"
        log_install "nikto" "SUCCESS" "Installed via apt/git"
        return 0
    else
        echo -e "${RED}[!] Failed to install nikto${NC}"
        log_install "nikto" "FAILED" "Installation failed"
        return 1
    fi
}

# Install dotdotpwn (LFI/directory traversal scanner)
install_dotdotpwn() {
    echo -e "${YELLOW}[*] Installing dotdotpwn...${NC}"

    if command -v dotdotpwn &>/dev/null; then
        echo -e "${GREEN}[✓] dotdotpwn already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y dotdotpwn
    else
        echo -e "${RED}[!] dotdotpwn only available via apt on Debian/Kali${NC}"
        return 1
    fi

    if command -v dotdotpwn &>/dev/null; then
        echo -e "${GREEN}[✓] dotdotpwn installed successfully${NC}"
        log_install "dotdotpwn" "SUCCESS" "Installed via apt"
        return 0
    else
        echo -e "${RED}[!] Failed to install dotdotpwn${NC}"
        log_install "dotdotpwn" "FAILED" "apt install failed"
        return 1
    fi
}

# ── Command Injection ─────────────────────────────

# Install commix
install_commix() {
    echo -e "${YELLOW}[*] Installing commix...${NC}"

    if command -v commix &>/dev/null; then
        echo -e "${GREEN}[✓] commix already installed${NC}"
        return 0
    fi

    if [[ ! -d "$TOOLS_DIR/commix" ]]; then
        echo -e "${CYAN}[*] Cloning commix from GitHub...${NC}"
        git clone https://github.com/commixproject/commix.git "$TOOLS_DIR/commix" 2>/dev/null || {
            echo -e "${RED}[!] commix clone failed${NC}"
            log_install "commix" "FAILED" "git clone failed"
            return 1
        }
    fi

    sudo ln -sf "$TOOLS_DIR/commix/commix.py" "/usr/local/bin/commix" 2>/dev/null

    if command -v commix &>/dev/null; then
        echo -e "${GREEN}[✓] commix installed successfully${NC}"
        log_install "commix" "SUCCESS" "Installed from GitHub"
        return 0
    else
        echo -e "${RED}[!] Failed to install commix — symlink may have failed${NC}"
        log_install "commix" "FAILED" "symlink to commix.py failed"
        return 1
    fi
}

# ── IDOR ─────────────────────────────────────────

# Install nuclei (template-based vulnerability scanner)
install_nuclei() {
    echo -e "${YELLOW}[*] Installing nuclei...${NC}"

    if command -v nuclei &>/dev/null; then
        echo -e "${GREEN}[✓] nuclei already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get update -q && sudo apt-get install -y nuclei
    else
        if ! command -v go &>/dev/null; then
            install_go || return 1
        fi
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        sudo ln -sf "$HOME/go/bin/nuclei" "/usr/local/bin/nuclei" 2>/dev/null
    fi

    if command -v nuclei &>/dev/null; then
        echo -e "${CYAN}[*] Updating nuclei templates...${NC}"
        nuclei -update-templates -silent 2>/dev/null || true
        echo -e "${GREEN}[✓] nuclei installed successfully${NC}"
        log_install "nuclei" "SUCCESS" "Installed via apt/go"
        return 0
    else
        echo -e "${RED}[!] Failed to install nuclei${NC}"
        log_install "nuclei" "FAILED" "Installation failed"
        return 1
    fi
}

# Install wfuzz (web fuzzer)
install_wfuzz() {
    echo -e "${YELLOW}[*] Installing wfuzz...${NC}"

    if command -v wfuzz &>/dev/null; then
        echo -e "${GREEN}[✓] wfuzz already installed${NC}"
        return 0
    fi

    if [[ -f /etc/debian_version ]]; then
        sudo apt-get install -y wfuzz
    else
        pip3 install wfuzz --break-system-packages 2>/dev/null || pip3 install wfuzz 2>/dev/null
    fi

    if command -v wfuzz &>/dev/null; then
        echo -e "${GREEN}[✓] wfuzz installed successfully${NC}"
        log_install "wfuzz" "SUCCESS" "Installed via apt/pip"
        return 0
    else
        echo -e "${RED}[!] Failed to install wfuzz${NC}"
        log_install "wfuzz" "FAILED" "Installation failed"
        return 1
    fi
}

# Install arjun (HTTP parameter discovery)
install_arjun() {
    echo -e "${YELLOW}[*] Installing arjun...${NC}"

    if command -v arjun &>/dev/null; then
        echo -e "${GREEN}[✓] arjun already installed${NC}"
        return 0
    fi

    pip3 install arjun --break-system-packages 2>/dev/null || pip3 install arjun 2>/dev/null

    if command -v arjun &>/dev/null; then
        echo -e "${GREEN}[✓] arjun installed successfully${NC}"
        log_install "arjun" "SUCCESS" "Installed via pip"
        return 0
    else
        echo -e "${RED}[!] Failed to install arjun${NC}"
        log_install "arjun" "FAILED" "pip install failed"
        return 1
    fi
}

# ── SSRF ─────────────────────────────────────────

# Install SSRFmap (SSRF vulnerability scanner)
install_ssrfmap() {
    echo -e "${YELLOW}[*] Installing SSRFmap...${NC}"

    local ssrfmap_dir="$TOOLS_DIR/SSRFmap"

    if [[ -f "$ssrfmap_dir/ssrfmap.py" ]]; then
        echo -e "${GREEN}[✓] SSRFmap already installed${NC}"
        return 0
    fi

    mkdir -p "$TOOLS_DIR"
    echo -e "${CYAN}[*] Cloning SSRFmap from GitHub...${NC}"
    git clone https://github.com/swisskyrepo/SSRFmap.git "$ssrfmap_dir" 2>/dev/null || {
        echo -e "${RED}[!] SSRFmap clone failed${NC}"
        log_install "ssrfmap" "FAILED" "git clone failed"
        return 1
    }

    if [[ -f "$ssrfmap_dir/requirements.txt" ]]; then
        echo -e "${CYAN}[*] Installing SSRFmap Python dependencies...${NC}"
        pip3 install -r "$ssrfmap_dir/requirements.txt" \
            --break-system-packages -q 2>/dev/null || \
        pip3 install -r "$ssrfmap_dir/requirements.txt" -q 2>/dev/null
    fi

    if [[ -f "$ssrfmap_dir/ssrfmap.py" ]]; then
        echo -e "${GREEN}[✓] SSRFmap installed at $ssrfmap_dir${NC}"
        log_install "ssrfmap" "SUCCESS" "Cloned from GitHub"
        return 0
    else
        echo -e "${RED}[!] Failed to install SSRFmap${NC}"
        log_install "ssrfmap" "FAILED" "Clone failed or file missing"
        return 1
    fi
}

# ── XXE ──────────────────────────────────────────

# Install XXEinjector (Ruby-based XXE exploitation tool)
# Architecture notes:
#   - Pure Ruby script — no gems required beyond stdlib
#   - Invoked as: ruby XXEinjector.rb [args]
#   - Wrapper created at /usr/local/bin/xxeinjector for easy CLI use
#   - Scanner (xxe_scanner.sh) looks for:
#       $SCRIPT_DIR/tools/XXEinjector/XXEinjector.rb  <- primary
#       /opt/XXEinjector/XXEinjector.rb               <- fallback
install_xxeinjector() {
    echo -e "${YELLOW}[*] Installing XXEinjector...${NC}"

    local xxe_dir="$TOOLS_DIR/XXEinjector"
    local xxe_script="$xxe_dir/XXEinjector.rb"
    local wrapper="/usr/local/bin/xxeinjector"

    if [[ -f "$xxe_script" ]]; then
        echo -e "${GREEN}[✓] XXEinjector already installed at $xxe_dir${NC}"
        if [[ ! -f "$wrapper" ]]; then
            echo -e "${CYAN}[*] Creating wrapper at $wrapper...${NC}"
            sudo tee "$wrapper" > /dev/null << EOF
#!/bin/bash
# XXEinjector wrapper — created by ARGUS-EYE installer
exec ruby "$xxe_script" "\$@"
EOF
            sudo chmod +x "$wrapper"
            echo -e "${GREEN}[✓] Wrapper created at $wrapper${NC}"
        fi
        return 0
    fi

    if ! command -v ruby &>/dev/null; then
        echo -e "${YELLOW}[*] Ruby not found — installing Ruby first...${NC}"
        install_ruby || {
            echo -e "${RED}[!] Ruby installation failed — cannot install XXEinjector${NC}"
            log_install "xxeinjector" "FAILED" "Ruby dependency missing"
            return 1
        }
    fi
    local ruby_ver
    ruby_ver=$(ruby --version | awk '{print $2}')
    echo -e "${GREEN}[✓] Ruby available: $ruby_ver${NC}"

    echo -e "${CYAN}[*] Cloning XXEinjector from GitHub...${NC}"
    mkdir -p "$TOOLS_DIR"

    if ! git clone --depth 1 https://github.com/enjoiz/XXEinjector.git "$xxe_dir" 2>/dev/null; then
        echo -e "${RED}[!] Git clone failed${NC}"
        log_install "xxeinjector" "FAILED" "git clone failed"
        return 1
    fi

    if [[ ! -f "$xxe_script" ]]; then
        echo -e "${RED}[!] XXEinjector.rb not found after clone — unexpected repo structure${NC}"
        log_install "xxeinjector" "FAILED" "XXEinjector.rb missing after clone"
        return 1
    fi

    chmod +x "$xxe_script"

    if ! ruby -c "$xxe_script" &>/dev/null; then
        echo -e "${RED}[!] Ruby syntax error in XXEinjector.rb — installation may be corrupt${NC}"
        log_install "xxeinjector" "FAILED" "Ruby syntax check failed"
        return 1
    fi
    echo -e "${GREEN}[✓] Ruby syntax check passed${NC}"

    sudo tee "$wrapper" > /dev/null << EOF
#!/bin/bash
# XXEinjector wrapper — created by ARGUS-EYE installer
exec ruby "$xxe_script" "\$@"
EOF
    sudo chmod +x "$wrapper"
    mkdir -p "$xxe_dir/Injections"

    echo -e "${GREEN}[✓] XXEinjector installed successfully${NC}"
    echo -e "${GREEN}    Location : $xxe_dir${NC}"
    echo -e "${GREEN}    Script   : $xxe_script${NC}"
    echo -e "${GREEN}    Wrapper  : $wrapper${NC}"
    echo -e "${CYAN}    Usage    : xxeinjector --file=req.txt --path=/etc/passwd --direct=START,END${NC}"
    log_install "xxeinjector" "SUCCESS" "Cloned from GitHub, wrapper at $wrapper"
    return 0
}

# ================================================
# MAIN INSTALLATION FUNCTION
# ================================================
install_tool() {
    local tool=$1
    local force=${2:-false}

    echo ""
    _box_top
    _box_row "INSTALLING: $tool"
    _box_bot

    if ! $force && is_tool_installed "$tool"; then
        echo -e "${GREEN}[✓] $tool is already installed${NC}"
        return 0
    fi

    mkdir -p "$TOOLS_DIR"

    case $tool in
        "dalfox")      install_dalfox ;;
        "XSStrike")    install_xsstrike ;;
        "PwnXSS")      install_pwnxss ;;
        "sqlmap")      install_sqlmap ;;
        "nosqli")      install_nosqli ;;
        "ffuf")        install_ffuf ;;
        "gobuster")    install_gobuster ;;
        "dirsearch")   install_dirsearch ;;
        "nikto")       install_nikto ;;
        "commix")      install_commix ;;
        "dotdotpwn")   install_dotdotpwn ;;
        "nuclei")      install_nuclei ;;
        "wfuzz")       install_wfuzz ;;
        "arjun")       install_arjun ;;
        "ssrfmap")     install_ssrfmap ;;
        "xxeinjector") install_xxeinjector ;;
        "docker")      install_docker ;;
        "go")          install_go ;;
        "python")      install_python ;;
        "ruby")        install_ruby ;;
        *)
            echo -e "${RED}[!] No installer available for $tool${NC}"
            log_install "$tool" "FAILED" "No installer available"
            return 1
            ;;
    esac

    local result=$?

    if [[ $result -eq 0 ]]; then
        INSTALL_STATUS["$tool"]=1
        log_install "$tool" "SUCCESS" "Installation completed"
    else
        INSTALL_STATUS["$tool"]=2
        log_install "$tool" "FAILED" "Installation failed"
    fi

    return $result
}

# ================================================
# INSTALL MULTIPLE TOOLS
# ================================================
install_tools() {
    local tools=("$@")
    local success=0
    local failed=0

    echo ""
    _box_top
    _box_row "BULK TOOL INSTALLATION"
    _box_bot
    echo ""

    for tool in "${tools[@]}"; do
        if install_tool "$tool"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
        echo ""
    done

    echo -e "${GREEN}[✓] Installation complete: $success succeeded, $failed failed${NC}"
    echo -e "${YELLOW}[*] Installation log: $INSTALL_LOG${NC}"
}

# ================================================
# SHOW INSTALLATION STATUS
# ================================================
_print_status() {
    local tool=$1
    if is_tool_installed "$tool"; then
        echo -e "${GREEN}  ✓ $tool: Installed${NC}"
    else
        echo -e "${RED}  ✗ $tool: Not installed${NC}"
    fi
}

show_status() {
    echo ""
    _box_top
    _box_row "TOOL INSTALLATION STATUS"
    _box_bot
    echo ""

    echo -e "${CYAN}  ── XSS Tools ────────────────────────────────────────${NC}"
    for tool in "dalfox" "XSStrike" "PwnXSS"; do
        _print_status "$tool"
    done

    echo ""
    echo -e "${CYAN}  ── SQLi / NoSQLi Tools ──────────────────────────────${NC}"
    for tool in "sqlmap" "nosqli"; do
        _print_status "$tool"
    done

    echo ""
    echo -e "${CYAN}  ── LFI / Directory Tools ───────────────────────────${NC}"
    for tool in "ffuf" "gobuster" "dirsearch" "nikto" "dotdotpwn"; do
        _print_status "$tool"
    done

    echo ""
    echo -e "${CYAN}  ── Command Injection Tools ─────────────────────────${NC}"
    for tool in "commix"; do
        _print_status "$tool"
    done

    echo ""
    echo -e "${CYAN}  ── IDOR Tools ───────────────────────────────────────${NC}"
    for tool in "nuclei" "wfuzz" "arjun"; do
        _print_status "$tool"
    done

    echo ""
    echo -e "${CYAN}  ── SSRF Tools ───────────────────────────────────────${NC}"
    _print_status "ssrfmap"

    echo ""
    echo -e "${CYAN}  ── XXE Tools ────────────────────────────────────────${NC}"
    _print_status "xxeinjector"

    echo ""
    echo -e "${CYAN}  ── Runtime Dependencies ────────────────────────────${NC}"
    for dep in "ruby" "python3" "go" "docker"; do
        if command -v "$dep" &>/dev/null; then
            local ver
            case $dep in
                ruby)    ver=$(ruby --version    2>/dev/null | awk '{print $2}') ;;
                python3) ver=$(python3 --version 2>/dev/null | awk '{print $2}') ;;
                go)      ver=$(go version        2>/dev/null | awk '{print $3}') ;;
                docker)  ver=$(docker --version  2>/dev/null | awk '{print $3}' | tr -d ',') ;;
            esac
            echo -e "${GREEN}  ✓ $dep: Installed ($ver)${NC}"
        else
            echo -e "${RED}  ✗ $dep: Not installed${NC}"
        fi
    done
    echo ""
}

# ================================================
# INTERACTIVE INSTALLATION MENU
# ================================================
show_install_menu() {
    echo -e "${CYAN}"
    _menu_top
    _menu_row "TOOL INSTALLATION MENU"
    _menu_sep
    _menu_row "1.  Install ALL tools"
    _menu_row "2.  Install XSS tools      (dalfox, XSStrike, PwnXSS)"
    _menu_row "3.  Install SQLi tools     (sqlmap, nosqli)"
    _menu_row "4.  Install LFI tools      (ffuf, gobuster, dirsearch, nikto)"
    _menu_row "                             + dotdotpwn"
    _menu_row "5.  Install CMD tools      (commix)"
    _menu_row "6.  Install IDOR tools     (nuclei, wfuzz, arjun)"
    _menu_row "7.  Install SSRF tools     (ssrfmap)"
    _menu_row "8.  Install XXE tools      (xxeinjector)"
    _menu_row "9.  Install single tool    (choose from list)"
    _menu_row "10. Show installation status"
    _menu_row "11. View installation log"
    _menu_row "12. Exit"
    _menu_bot
    echo -e "${NC}"
}

interactive_install() {
    while true; do
        show_install_menu
        echo -ne "${YELLOW}[?] Select option (1-12): ${NC}"
        read -r choice

        case $choice in
            1)
                install_tools \
                    dalfox XSStrike PwnXSS \
                    sqlmap nosqli \
                    ffuf gobuster dirsearch nikto commix dotdotpwn \
                    nuclei wfuzz arjun \
                    ssrfmap \
                    xxeinjector
                ;;
            2)  install_tools dalfox XSStrike PwnXSS ;;
            3)  install_tools sqlmap nosqli ;;
            4)  install_tools ffuf gobuster dirsearch nikto dotdotpwn ;;
            5)  install_tools commix ;;
            6)  install_tools nuclei wfuzz arjun ;;
            7)  install_tools ssrfmap ;;
            8)  install_tools xxeinjector ;;
            9)
                echo -e "${CYAN}"
                _menu_top
                _menu_row "Available tools:"
                _menu_row "dalfox  XSStrike  PwnXSS  sqlmap  nosqli"
                _menu_row "ffuf  gobuster  dirsearch  nikto  commix  dotdotpwn"
                _menu_row "nuclei  wfuzz  arjun  ssrfmap  xxeinjector"
                _menu_row "Dependencies: ruby  python  go  docker"
                _menu_bot
                echo -e "${NC}"
                echo -ne "${YELLOW}[?] Enter tool name: ${NC}"
                read -r single_tool
                install_tool "$single_tool"
                ;;
            10) show_status ;;
            11)
                if [[ -f "$INSTALL_LOG" ]]; then
                    less "$INSTALL_LOG"
                else
                    echo -e "${YELLOW}[!] No installation log found${NC}"
                fi
                ;;
            12)
                echo -e "${GREEN}[+] Exiting installer${NC}"
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid choice — enter a number from 1 to 12${NC}"
                ;;
        esac
        echo ""
        echo -ne "${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# ================================================
# SCRIPT ENTRY POINT
# ================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        interactive_install
    else
        install_tools "$@"
    fi
fi

export -f is_tool_installed install_tool install_tools
export INSTALL_STATUS
