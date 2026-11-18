#!/bin/bash
# ================================================
# ARGUS-EYE - Directory & File Discovery Scanner
# Tools: gobuster, ffuf, dirsearch, dotdotpwn, custom_tests
# Supports DVWA authentication and generic targets
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"

source "$CORE_DIR/utils.sh"
source "$CORE_DIR/installer.sh"
source "$CORE_DIR/tool_selection.sh"

# ================================================
# GLOBALS
# ================================================
DVWA_BASE=""
DVWA_COOKIE_JAR=""
TEMP_DIR="/tmp/argus_dir_$$"
mkdir -p "$TEMP_DIR"

# ================================================
# PROGRESS TRACKING
# ================================================
TOTAL_STEPS=0; CURRENT_STEP=0; PROGRESS_BAR_WIDTH=40
init_progress() {
    TOTAL_STEPS=$1; CURRENT_STEP=0
    >&2 echo ""
    >&2 echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    >&2 echo -e "${CYAN}║                DIRECTORY SCAN PROGRESS                      ║${NC}"
    >&2 echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    >&2 echo ""
}
update_progress() {
    CURRENT_STEP=$((CURRENT_STEP+1))
    local p=$((CURRENT_STEP*100/TOTAL_STEPS))
    local f=$((p*PROGRESS_BAR_WIDTH/100))
    local e=$((PROGRESS_BAR_WIDTH-f))
    >&2 printf "\r${YELLOW}[${NC}"
    for ((i=0;i<f;i++)); do >&2 printf "${GREEN}▓${NC}"; done
    for ((i=0;i<e;i++)); do >&2 printf "${WHITE}░${NC}"; done
    >&2 printf "${YELLOW}] ${p}%% ${CYAN}($CURRENT_STEP/$TOTAL_STEPS)${NC} $1\n"
}
complete_progress() {
    >&2 echo ""; >&2 echo ""; >&2 echo -e "${GREEN}✓ Scan completed!${NC}"
}
show_step() {
    local s=$1 t=$2 tool=$3 st=$4
    case $st in
        "start") >&2 echo -ne "\n  ${CYAN}▶ Step $s/$t:${NC} Running $tool... " ;;
        "complete") >&2 echo -e "${GREEN}✓${NC}" ;;
        "fail") >&2 echo -e "${RED}✗${NC}" ;;
    esac
}
spinner() {
    local pid=$1 delay=0.1 spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        >&2 printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        >&2 printf "\b\b\b\b\b\b"
    done
    >&2 printf "    \b\b\b\b"
}

# ================================================
# DVWA AUTO-DETECT
# ================================================
detect_dvwa_base() {
    local target=$1
    local candidates=("$target" "${target}/dvwa" "${target}/DVWA")
    for candidate in "${candidates[@]}"; do
        local page
        page=$(curl -s --max-time 5 "${candidate}/login.php" 2>/dev/null)
        if echo "$page" | grep -qi "dvwa\|damn vulnerable"; then
            DVWA_BASE="$candidate"
            >&2 echo -e "${GREEN}[✓] DVWA detected at: $DVWA_BASE${NC}"
            return 0
        fi
    done
    >&2 echo -e "${YELLOW}[*] DVWA not detected — treating as generic target${NC}"
    DVWA_BASE=""
    return 1
}

# ================================================
# DVWA AUTO-LOGIN (uses process‑unique cookie jar)
# ================================================
dvwa_autologin() {
    local base_url=$1
    DVWA_COOKIE_JAR="/tmp/dvwa_cookies_$$"
    rm -f "$DVWA_COOKIE_JAR"

    >&2 echo -e "\n${CYAN}[*] Logging into DVWA at ${base_url}...${NC}"

    # Get CSRF token (if any) and login
    local token
    token=$(curl -s -c "$DVWA_COOKIE_JAR" "${base_url}/login.php" | grep -oP 'user_token"\s*value="\K[^"]+' | head -1)
    curl -s -b "$DVWA_COOKIE_JAR" -c "$DVWA_COOKIE_JAR" \
        -X POST "${base_url}/login.php" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=password" \
        --data-urlencode "user_token=$token" \
        --data-urlencode "Login=Login" \
        -L -o /dev/null 2>/dev/null

    # Set security to low
    curl -s -b "$DVWA_COOKIE_JAR" -c "$DVWA_COOKIE_JAR" \
        -X POST "${base_url}/security.php" \
        --data "security=low&seclev_submit=Submit" \
        -o /dev/null 2>/dev/null

    local check
    check=$(curl -s -b "$DVWA_COOKIE_JAR" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        >&2 echo -e "${GREEN}[✓] Login successful (admin/password)${NC}"
        return 0
    fi

    >&2 echo -e "${RED}[!] Login failed — check DVWA credentials${NC}"
    return 1
}

# ================================================
# HELPER: get wordlist
# ================================================
get_wordlist() {
    local wordlist="/usr/share/wordlists/dirb/common.txt"
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    fi
    echo "$wordlist"
}

# ================================================
# TOOL FUNCTIONS
# ================================================

run_gobuster() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "gobuster" "start"

    if ! command -v gobuster &>/dev/null; then
        echo "gobuster not installed" >> "$out"
        show_step "$step" "$total" "gobuster" "fail"
        update_progress "gobuster failed (not installed)"
        return 1
    fi

    local wordlist=$(get_wordlist)
    > "$out"

    local target_url="$target"
    local cookie_arg=()
    if [[ -n "$DVWA_BASE" && -f "$DVWA_COOKIE_JAR" ]]; then
        cookie_arg=(-c "$DVWA_COOKIE_JAR")
    fi

    >&2 echo -e "\n  ${CYAN}└─ Running gobuster directory enumeration... ${NC}"

    gobuster dir -u "$target_url" -w "$wordlist" -t 50 -o "$out" "${cookie_arg[@]}" 2>&1 &
    spinner $!
    wait $!

    local findings=0
    if [[ -f "$out" ]]; then
        grep -E "Status: 20[0-9]|Status: 30[0-9]|Status: 403" "$out" | while read -r line; do
            echo "Directory Found: $line" >> "$findings_file"
            findings=$((findings+1))
        done
    fi

    show_step "$step" "$total" "gobuster" "complete"
    update_progress "gobuster completed ($findings findings)"
    return 0
}

run_ffuf() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "ffuf" "start"

    if ! command -v ffuf &>/dev/null; then
        echo "ffuf not installed" >> "$out"
        show_step "$step" "$total" "ffuf" "fail"
        update_progress "ffuf failed (not installed)"
        return 1
    fi

    local wordlist=$(get_wordlist)
    > "$out"

    local fuzz_url="${target}/FUZZ"
    local cookie_arg=()
    if [[ -n "$DVWA_BASE" && -f "$DVWA_COOKIE_JAR" ]]; then
        local phpsessid
        phpsessid=$(grep -i "PHPSESSID" "$DVWA_COOKIE_JAR" | awk '{print $NF}' | head -1)
        [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")
    fi

    >&2 echo -e "\n  ${CYAN}└─ Fuzzing directories with ffuf... ${NC}"

    ffuf -u "$fuzz_url" -w "$wordlist" -c -t 50 "${cookie_arg[@]}" >> "$out" 2>&1 &
    spinner $!
    wait $!

    local findings=0
    if [[ -f "$out" ]]; then
        grep -E "Status: 20[0-9]|Status: 30[0-9]|Status: 403" "$out" | while read -r line; do
            echo "Directory Found: $line" >> "$findings_file"
            findings=$((findings+1))
        done
    fi

    show_step "$step" "$total" "ffuf" "complete"
    update_progress "ffuf completed ($findings findings)"
    return 0
}

run_dirsearch() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "dirsearch" "start"

    local cmd=""
    if command -v dirsearch &>/dev/null; then
        cmd="dirsearch"
    elif [[ -f "$SCRIPT_DIR/tools/dirsearch/dirsearch.py" ]]; then
        cmd="python3 $SCRIPT_DIR/tools/dirsearch/dirsearch.py"
    else
        echo "dirsearch not installed" >> "$out"
        show_step "$step" "$total" "dirsearch" "fail"
        update_progress "dirsearch failed (not installed)"
        return 1
    fi

    > "$out"

    local dirsearch_url="$target"
    local cookie_arg=()
    if [[ -n "$DVWA_BASE" && -f "$DVWA_COOKIE_JAR" ]]; then
        local phpsessid
        phpsessid=$(grep -i "PHPSESSID" "$DVWA_COOKIE_JAR" | awk '{print $NF}' | head -1)
        [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")
    fi

    >&2 echo -e "\n  ${CYAN}└─ Running dirsearch... ${NC}"

    # Run dirsearch with plain output format
    $cmd -u "$dirsearch_url" -e php,html,txt,asp,aspx,jsp -t 50 "${cookie_arg[@]}" -o "$out" --format=plain 2>&1 &
    spinner $!
    wait $!

    local findings=0
    if [[ -f "$out" ]]; then
        # Parse lines that start with a 3-digit status code and contain "http"
        while IFS= read -r line; do
            # Check if line matches pattern: status code, then spaces, then size, then http
            if [[ "$line" =~ ^[0-9]{3}[[:space:]]+[0-9]+B[[:space:]]+http ]]; then
                echo "Directory Found: $line" >> "$findings_file"
                findings=$((findings+1))
            fi
        done < "$out"
    fi

    show_step "$step" "$total" "dirsearch" "complete"
    update_progress "dirsearch completed ($findings findings)"
    return 0
}

run_dotdotpwn() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "dotdotpwn" "start"

    if ! command -v dotdotpwn &>/dev/null; then
        echo "dotdotpwn not installed" >> "$out"
        show_step "$step" "$total" "dotdotpwn" "fail"
        update_progress "dotdotpwn failed (not installed)"
        return 1
    fi

    > "$out"
    >&2 echo -ne "\n  ${CYAN}   └─ Testing for path traversal... ${NC}"

    local host=$(echo "$target" | sed -E 's#^https?://([^/:]+).*#\1#')
    local port=$(echo "$target" | sed -E 's#^https?://[^/:]+:?([0-9]*).*#\1#')
    [[ -z "$port" ]] && port=80

    dotdotpwn -m http -h "$host" -p "$port" -f "/etc/passwd" -k "root" -o "$out" 2>&1 &
    spinner $!
    wait $!

    local findings=0
    if [[ -f "$out" ]]; then
        grep -i "vulnerable" "$out" | while read -r line; do
            echo "Path Traversal Found (dotdotpwn): $line" >> "$findings_file"
            findings=$((findings+1))
        done
    fi

    show_step "$step" "$total" "dotdotpwn" "complete"
    update_progress "dotdotpwn completed ($findings findings)"
    return 0
}

run_custom_dir_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    {
        echo "=== CUSTOM DIRECTORY TESTS ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo ""
    } >> "$out"

    local common_dirs=(
        "/admin" "/backup" "/images" "/css" "/js" "/uploads" "/includes" "/config" "/tmp" "/logs"
    )
    local common_files=(
        "/robots.txt" "/.git/HEAD" "/phpinfo.php" "/info.php" "/test.php" "/config.php"
        "/.env" "/backup.zip" "/database.sql"
    )

    local cookie_opt=()
    if [[ -n "$DVWA_BASE" && -f "$DVWA_COOKIE_JAR" ]]; then
        cookie_opt=(-b "$DVWA_COOKIE_JAR")
    fi

    local findings=0
    for item in "${common_dirs[@]}" "${common_files[@]}"; do
        test_url="${target}${item}"
        echo -n "  Checking $test_url... " >> "$out"
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "${cookie_opt[@]}" "$test_url")
        if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" || "$status" == "403" ]]; then
            echo "FOUND (HTTP $status)" >> "$out"
            echo "Directory Found: $test_url (HTTP $status)" >> "$findings_file"
            findings=$((findings+1))
        else
            echo "Not found" >> "$out"
        fi
    done

    echo "" >> "$out"
    echo "Custom tests completed with $findings findings" >> "$out"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed"
}

# ================================================
# MAIN DIRECTORY SCAN FUNCTION
# ================================================
scan_dir() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/dir_findings.txt"
    local summary_file="$output_dir/raw_output/dir_summary.txt"

    # Clean up on exit
    trap 'rm -rf "$TEMP_DIR" "$DVWA_COOKIE_JAR"' EXIT

    detect_dvwa_base "$target"
    if [[ -n "$DVWA_BASE" ]]; then
        dvwa_autologin "$DVWA_BASE"
    fi

    {
        echo "========================================"
        echo "DIRECTORY DISCOVERY RESULTS"
        echo "========================================"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "Tools used: $selected_tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐\n│                 DIRECTORY & FILE DISCOVERY SCANNER                │\n└─────────────────────────────────────────────────────────────────────┘${NC}"
    >&2 echo -e "${YELLOW}[*] Target: $target${NC}"
    >&2 echo -e "${YELLOW}[*] Tools: $selected_tools${NC}\n"

    IFS=' ' read -ra TOOL_ARRAY <<< "$selected_tools"
    local total_tools=${#TOOL_ARRAY[@]}
    init_progress $total_tools

    local total_findings=0 tools_run=0 tools_success=0

    for tool in "${TOOL_ARRAY[@]}"; do
        tools_run=$((tools_run+1))
        local tool_output="$output_dir/raw_output/${tool}_dir.txt"
        local tool_findings=0

        case $tool in
            "gobuster")
                if run_gobuster "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                ;;
            "ffuf")
                if run_ffuf "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                ;;
            "dirsearch")
                if run_dirsearch "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                ;;
            "dotdotpwn")
                if run_dotdotpwn "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                ;;
            "custom_tests")
                run_custom_dir_tests "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                ;;
            *)  >&2 echo -e "${YELLOW}  [!] Unknown tool: $tool${NC}" ;;
        esac

        >&2 echo ""
    done

    # Count total findings from the findings file (lines starting with "Directory Found:")
    total_findings=$(grep -c "^Directory Found:" "$findings_file" 2>/dev/null || echo 0)

    {
        echo ""
        echo "========================================"
        echo "SCAN SUMMARY"
        echo "========================================"
        echo "Tools run: $tools_run"
        echo "Tools successful: $tools_success"
        echo "Total findings: $total_findings"
        echo "========================================"
    } >> "$findings_file"

    echo "$total_findings" > "$summary_file"
    complete_progress

    >&2 echo -e "${GREEN}[✓] Directory scan completed${NC}"
    >&2 echo -e "${YELLOW}[*] Tools run: $tools_run/$total_tools${NC}"
    >&2 echo -e "${RED}[*] Total findings: $total_findings${NC}\n"
    echo "$total_findings"
}

# ================================================
# SCRIPT ENTRY POINT
# ================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $# -lt 3 ]] && { >&2 echo -e "${RED}[!] Usage: $0 <target_url> <output_dir> <selected_tools>${NC}"; exit 1; }
    findings=$(scan_dir "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
