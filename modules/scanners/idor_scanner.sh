#!/bin/bash
# ================================================
# ARGUS-EYE - IDOR Scanner Module
# Tools: nuclei, wfuzz, arjun, ffuf, custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TEMP_DIR="/tmp/argus_idor_$$"
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
    >&2 echo -e "${CYAN}║                   IDOR SCAN PROGRESS                        ║${NC}"
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
    # Strip trailing path — only probe host-level /dvwa, not /mutillidae/dvwa
    local host_base
    host_base=$(echo "$target" | grep -oP 'https?://[^/]+')
    local candidates=("${host_base}/dvwa" "${host_base}/DVWA" "$target")
    for candidate in "${candidates[@]}"; do
        local page
        page=$(curl -s --max-time 5 "${candidate}/login.php" 2>/dev/null)
        # Must have login form AND DVWA branding — avoids false positives
        if echo "$page" | grep -qi "damn vulnerable" && \
           echo "$page" | grep -qi "username\|password\|Login"; then
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

    >&2 echo -e "${RED}[!] Login failed${NC}"
    return 1
}

# ================================================
# SHARED HELPER — build cookie args
# ================================================
get_cookie_args() {
    # Returns: phpsessid value
    if [[ -n "$DVWA_BASE" && -f /tmp/dvwa_cookies ]]; then
        grep -i "PHPSESSID" /tmp/dvwa_cookies | awk '{print $NF}' | head -1
    fi
}

get_idor_url() {
    # DVWA on OWASP BWA does NOT have /vulnerabilities/idor/ — that page
    # was added in newer DVWA versions. Use Mutillidae user-info for IDOR.
    local target=$1
    if [[ "$target" == *"mutillidae"* ]] || [[ "$target" == *"Mutillidae"* ]]; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        echo "${mutil_base}/index.php?page=user-info.php&username=FUZZ"
    elif [[ -n "$DVWA_BASE" ]]; then
        # DVWA — test user enumeration via brute force page as IDOR proxy
        # (actual IDOR page doesn't exist on BWA's DVWA version)
        echo "${DVWA_BASE}/vulnerabilities/brute/?username=FUZZ&password=test&Login=Login"
    else
        echo "${target}?id=FUZZ"
    fi
}

# ================================================
# TOOL: nuclei
# ================================================
run_nuclei_idor() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "nuclei (IDOR)" "start"

    if ! command -v nuclei &>/dev/null; then
        >&2 echo -e "${YELLOW}[*] nuclei not installed — install: sudo apt install nuclei${NC}"
        echo "nuclei not installed — skipped" > "$out"
        show_step "$step" "$total" "nuclei" "fail"
        update_progress "nuclei skipped (not installed)"
        echo "0" > "$TEMP_DIR/nuclei_count.tmp"
        return 1
    fi

    > "$out"
    local counter_file="$TEMP_DIR/nuclei_count_$$.tmp"
    echo "0" > "$counter_file"

    # Build scan target — Mutillidae user-info is the real IDOR target
    local scan_target
    if [[ "$target" == *"mutillidae"* ]] || [[ "$target" == *"Mutillidae"* ]]; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        scan_target="${mutil_base}/index.php?page=user-info.php&username=admin"
    elif [[ -n "$DVWA_BASE" ]]; then
        scan_target="${DVWA_BASE}/vulnerabilities/sqli/"
    else
        scan_target="$target"
    fi

    # Cookie header for authenticated scan
    local phpsessid
    phpsessid=$(get_cookie_args)
    local header_arg=()
    [[ -n "$phpsessid" ]] && header_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")

    >&2 echo -e "\n  ${CYAN}└─ nuclei: scanning $scan_target${NC}"

    # Locate nuclei templates directory
    local templates_dir=""
    for tdir in "$HOME/nuclei-templates" "/root/nuclei-templates" \
                "$HOME/.local/nuclei-templates" "/usr/share/nuclei-templates"; do
        [[ -d "$tdir" ]] && { templates_dir="$tdir"; break; }
    done

    # Update templates if missing
    if [[ -z "$templates_dir" ]]; then
        >&2 echo -e "${YELLOW}[*] nuclei templates not found — running update...${NC}"
        nuclei -update-templates -silent 2>/dev/null
        templates_dir="$HOME/nuclei-templates"
    fi

    # Build template args — use fuzzing + idor tags if templates exist
    local template_args=()
    if [[ -d "$templates_dir" ]]; then
        template_args=(-t "$templates_dir" -tags idor,exposure,misconfig)
        >&2 echo -e "  ${CYAN}└─ Using templates: $templates_dir${NC}"
    else
        # No templates — run with -nt (no templates) just for basic checks
        >&2 echo -e "${YELLOW}[*] No templates found — running basic nuclei scan${NC}"
        template_args=(-nt)
    fi

    # Run nuclei
    nuclei -u "$scan_target" \
        "${template_args[@]}" \
        -severity low,medium,high,critical \
        "${header_arg[@]}" \
        -timeout 10 \
        -o "$TEMP_DIR/nuclei_idor_out.txt" \
        -silent >> "$out" 2>&1 &
    spinner $!
    wait $!

    # Parse results
    local result_file="$TEMP_DIR/nuclei_idor_out.txt"
    if [[ -f "$result_file" && -s "$result_file" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            {
                echo "[HIGH] IDOR/Exposure Detected by nuclei"
                echo "  Tool     : nuclei"
                echo "  Target   : $scan_target"
                echo "  Finding  : $line"
                echo "  Severity : HIGH"
                echo ""
            } >> "$findings_file"
            echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
        done < "$result_file"
    fi

    # Also parse stdout output
    if [[ -f "$out" && -s "$out" ]]; then
        while IFS= read -r line; do
            echo "$line" | grep -qiE "\[high\]|\[critical\]|\[medium\]|idor" || continue
            {
                echo "[HIGH] nuclei finding"
                echo "  Tool    : nuclei"
                echo "  Finding : $line"
                echo ""
            } >> "$findings_file"
            echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
        done < "$out"
    fi

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file" "$result_file"
    show_step "$step" "$total" "nuclei" "complete"
    update_progress "nuclei completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/nuclei_count.tmp"
    return 0
}

# ================================================
# TOOL: wfuzz
# ================================================
run_wfuzz_idor() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "wfuzz (IDOR)" "start"

    if ! command -v wfuzz &>/dev/null; then
        >&2 echo -e "${YELLOW}[*] wfuzz not installed — install: sudo apt install wfuzz${NC}"
        echo "wfuzz not installed — skipped" > "$out"
        show_step "$step" "$total" "wfuzz" "fail"
        update_progress "wfuzz skipped (not installed)"
        echo "0" > "$TEMP_DIR/wfuzz_count.tmp"
        return 1
    fi

    > "$out"
    local counter_file="$TEMP_DIR/wfuzz_idor_count_$$.tmp"
    echo "0" > "$counter_file"

    # Determine fuzz URL and appropriate wordlist
    local fuzz_url
    fuzz_url=$(get_idor_url "$target")

    # Build wordlist — usernames for Mutillidae, numbers for generic/DVWA
    local wordlist="$TEMP_DIR/wfuzz_idor_words.txt"
    if [[ "$fuzz_url" == *"username=FUZZ"* ]]; then
        # Mutillidae user-info needs usernames, not numbers
        cat > "$wordlist" << 'WORDS'
admin
user
guest
test
john
jane
bob
alice
root
administrator
operator
manager
staff
moderator
demo
WORDS
        >&2 echo -e "\n  ${CYAN}└─ wfuzz: fuzzing $fuzz_url with username wordlist${NC}"
        # Use --ss to match responses that contain user data
        local match_str="Password"
    else
        seq 1 30 > "$wordlist"
        >&2 echo -e "\n  ${CYAN}└─ wfuzz: fuzzing $fuzz_url with IDs 1-30${NC}"
        local match_str=""
    fi

    # Cookie header
    local phpsessid
    phpsessid=$(get_cookie_args)
    local cookie_arg=()
    [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")

    # Run wfuzz — for Mutillidae use --ss to find responses with user data
    if [[ -n "$match_str" ]]; then
        wfuzz -c -z file,"$wordlist" \
            "${cookie_arg[@]}" \
            --ss "$match_str" \
            "$fuzz_url" >> "$out" 2>&1 &
    else
        # Generic — filter by baseline size
        local baseline_url="${fuzz_url/FUZZ/1}"
        local baseline_size
        if [[ -f /tmp/dvwa_cookies ]]; then
            baseline_size=$(curl -s -L --max-time 5 -b /tmp/dvwa_cookies "$baseline_url" 2>/dev/null | wc -c)
        else
            baseline_size=$(curl -s -L --max-time 5 "$baseline_url" 2>/dev/null | wc -c)
        fi
        >&2 echo -e "  ${CYAN}└─ Baseline size: ${baseline_size} bytes${NC}"
        wfuzz -c -z file,"$wordlist" \
            "${cookie_arg[@]}" \
            --hh "$baseline_size" \
            "$fuzz_url" >> "$out" 2>&1 &
    fi
    spinner $!
    wait $!

    # Parse wfuzz output — lines shown are hits (not filtered)
    if [[ -f "$out" ]]; then
        while IFS= read -r line; do
            # Skip headers/warnings/empty
            echo "$line" | grep -qE "^\s*0+[0-9]+" || continue
            echo "$line" | grep -qi "warning\|pycurl\|fatal\|UserWarning\|^\*\|====\|Total\|Processed\|Filtered" && continue

            local fuzz_val
            fuzz_val=$(echo "$line" | grep -oP '"[^"]+"$' | tr -d '"' | head -1)
            [[ -z "$fuzz_val" ]] && fuzz_val=$(echo "$line" | awk '{print $NF}' | tr -d '"')
            local hit_url="${fuzz_url/FUZZ/$fuzz_val}"

            {
                echo "[HIGH] IDOR Confirmed — User Data Accessible"
                echo "  Tool     : wfuzz"
                echo "  Target   : $fuzz_url"
                echo "  URL      : $hit_url"
                echo "  Value    : $fuzz_val"
                echo "  Evidence : Response contains user data (Password field found)"
                echo "  Severity : HIGH"
                echo ""
            } >> "$findings_file"
            echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
        done < <(grep -v "^$\|UserWarning\|Pycurl\|pkg_resources\|^\*\|====\|-----\|Total\|Processed\|Filtered\|Target\|Wfuzz\|Version\|Christian\|Carlos\|Xavier" "$out" 2>/dev/null \
                 | grep -E "[0-9]{9}:")
    fi

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file" "$wordlist"
    show_step "$step" "$total" "wfuzz" "complete"
    update_progress "wfuzz completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/wfuzz_count.tmp"
    return 0
}

# ================================================
# TOOL: arjun
# ================================================
run_arjun_idor() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "arjun (IDOR)" "start"

    if ! command -v arjun &>/dev/null; then
        >&2 echo -e "${YELLOW}[*] arjun not installed — install: pip3 install arjun${NC}"
        echo "arjun not installed — skipped" > "$out"
        show_step "$step" "$total" "arjun" "fail"
        update_progress "arjun skipped (not installed)"
        echo "0" > "$TEMP_DIR/arjun_count.tmp"
        return 1
    fi

    > "$out"
    local counter_file="$TEMP_DIR/arjun_count_$$.tmp"
    echo "0" > "$counter_file"

    # Arjun discovers hidden parameters — point at correct page per target
    local scan_target
    if [[ "$target" == *"mutillidae"* ]] || [[ "$target" == *"Mutillidae"* ]]; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        scan_target="${mutil_base}/index.php?page=user-info.php"
    elif [[ -n "$DVWA_BASE" ]]; then
        scan_target="${DVWA_BASE}/vulnerabilities/sqli/"
    else
        scan_target="$target"
    fi

    local phpsessid
    phpsessid=$(get_cookie_args)
    local cookie_arg=()
    [[ -n "$phpsessid" ]] && cookie_arg=(--headers "Cookie: PHPSESSID=${phpsessid}; security=low")

    >&2 echo -e "\n  ${CYAN}└─ arjun: discovering hidden parameters on $scan_target${NC}"

    arjun -u "$scan_target" \
        "${cookie_arg[@]}" \
        -oJ "$TEMP_DIR/arjun_out.json" \
        -t 10 >> "$out" 2>&1 &
    spinner $!
    wait $!

    # Parse arjun output — try JSON first, fall back to stdout parsing
    local params=""

    if [[ -f "$TEMP_DIR/arjun_out.json" ]]; then
        params=$(python3 -c "
import json
try:
    data = json.load(open('$TEMP_DIR/arjun_out.json'))
    if isinstance(data, dict):
        # format: {url: [params]} or {url: {params: [...]}}
        for url, val in data.items():
            if isinstance(val, list):
                for p in val: print(p)
            elif isinstance(val, dict):
                for p in val.get('params', []): print(p)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for p in item.get('params', []): print(p)
except: pass
" 2>/dev/null)
    fi

    # Fallback — parse stdout output directly
    if [[ -z "$params" && -f "$out" ]]; then
        params=$(grep -oP '(?<=Parameters found: ).*' "$out" | tr ',' '\n' | tr -d ' ')
    fi

    if [[ -n "$params" ]]; then
        >&2 echo -e "${GREEN}[*] arjun found parameters: $(echo "$params" | tr '\n' ' ')${NC}"

        while IFS= read -r param; do
            [[ -z "$param" ]] && continue
            >&2 echo -e "  ${CYAN}└─ Testing discovered param: $param${NC}"

            # For 'page' param on Mutillidae — test with usernames (IDOR via username)
            if [[ "$param" == "page" && "$scan_target" == *"mutillidae"* ]]; then
                local mutil_base
                mutil_base=$(echo "$scan_target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
                local test_users=("admin" "user" "guest" "test")
                for username in "${test_users[@]}"; do
                    local test_url="${mutil_base}/index.php?page=user-info.php&username=${username}"
                    local response
                    response=$(curl -s -L --max-time 5 "$test_url" 2>/dev/null)
                    if echo "$response" | grep -qi "Password\|account\|email"; then
                        {
                            echo "[HIGH] IDOR Confirmed via arjun-discovered Parameter"
                            echo "  Tool       : arjun"
                            echo "  Target     : $scan_target"
                            echo "  URL        : $test_url"
                            echo "  Param      : username (via page=user-info.php)"
                            echo "  Value      : $username"
                            echo "  Evidence   : User account data returned without authentication"
                            echo "  Severity   : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                        break
                    fi
                done
            else
                # Generic — test numeric IDs
                local baseline
                baseline=$(curl -s -L --max-time 5 "${scan_target}?${param}=1" 2>/dev/null | wc -c)
                for id_val in 2 3 4 5; do
                    local response_size
                    response_size=$(curl -s -L --max-time 5 \
                        "${scan_target}?${param}=${id_val}" 2>/dev/null | wc -c)
                    if [[ "$response_size" -ne "$baseline" && "$response_size" -gt 50 ]]; then
                        {
                            echo "[HIGH] IDOR — arjun Parameter Vulnerable"
                            echo "  Tool       : arjun"
                            echo "  Target     : $scan_target"
                            echo "  URL        : ${scan_target}?${param}=${id_val}"
                            echo "  Param      : $param (discovered by arjun)"
                            echo "  ID Value   : $id_val"
                            echo "  Evidence   : Response size ${response_size} differs from baseline ${baseline}"
                            echo "  Severity   : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                        break
                    fi
                done
            fi
        done <<< "$params"

        # Always log param discovery — but don't count as a finding
        {
            echo "[INFO] Parameters Discovered by arjun"
            echo "  Tool   : arjun"
            echo "  Target : $scan_target"
            echo "  Params : $(echo "$params" | tr '\n' ' ')"
            echo "  Note   : These parameters were found and tested for IDOR"
            echo ""
        } >> "$findings_file"
    else
        >&2 echo -e "${YELLOW}[*] arjun found no parameters${NC}"
    fi
    rm -f "$TEMP_DIR/arjun_out.json"

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file"
    show_step "$step" "$total" "arjun" "complete"
    update_progress "arjun completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/arjun_count.tmp"
    return 0
}

# ================================================
# TOOL: ffuf
# ================================================
run_ffuf_idor() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "ffuf (IDOR)" "start"

    if ! command -v ffuf &>/dev/null; then
        echo "ffuf not installed — skipped" > "$out"
        show_step "$step" "$total" "ffuf" "fail"
        update_progress "ffuf skipped (not installed)"
        echo "0" > "$TEMP_DIR/ffuf_count.tmp"
        return 1
    fi

    local id_wordlist="$TEMP_DIR/ids_ffuf.txt"
    seq 1 50 > "$id_wordlist"

    > "$out"
    local counter_file="$TEMP_DIR/ffuf_idor_count_$$.tmp"
    echo "0" > "$counter_file"

    local phpsessid
    phpsessid=$(get_cookie_args)
    local cookie_arg=()
    [[ -n "$phpsessid" ]] && cookie_arg=(-H "Cookie: PHPSESSID=${phpsessid}; security=low")

    local fuzz_url
    fuzz_url=$(get_idor_url "$target")

    # Baseline size — use cookie jar if available
    local baseline_url="${fuzz_url/FUZZ/1}"
    local baseline_size
    if [[ -f /tmp/dvwa_cookies ]]; then
        baseline_size=$(curl -s -L --max-time 5 -b /tmp/dvwa_cookies "$baseline_url" 2>/dev/null | wc -c)
    else
        baseline_size=$(curl -s -L --max-time 5 "$baseline_url" 2>/dev/null | wc -c)
    fi
    >&2 echo -e "  ${CYAN}└─ Baseline (id=1): ${baseline_size} bytes${NC}"

    ffuf -u "$fuzz_url" -w "$id_wordlist" -c -t 10 \
        "${cookie_arg[@]}" \
        -fs "$baseline_size" \
        -o "$TEMP_DIR/ffuf_idor_out.json" -of json \
        >> "$out" 2>&1

    if [[ -f "$TEMP_DIR/ffuf_idor_out.json" ]]; then
        while IFS= read -r id_val; do
            [[ -z "$id_val" ]] && continue
            local hit_url="${fuzz_url/FUZZ/$id_val}"
            {
                echo "[HIGH] IDOR Detected — Different Response for ID ${id_val}"
                echo "  Tool     : ffuf"
                echo "  Target   : $fuzz_url"
                echo "  URL      : $hit_url"
                echo "  Param    : $(echo "$fuzz_url" | grep -oP '\w+(?==FUZZ)')"
                echo "  ID Value : $id_val"
                echo "  Evidence : Response size differs from baseline (id=1, size=${baseline_size})"
                echo "  Severity : HIGH"
                echo ""
            } >> "$findings_file"
            echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
        done < <(python3 -c "
import json
try:
    data = json.load(open('$TEMP_DIR/ffuf_idor_out.json'))
    for r in data.get('results', []):
        print(r['input']['FUZZ'])
except: pass
" 2>/dev/null)
        rm -f "$TEMP_DIR/ffuf_idor_out.json"
    fi

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file" "$id_wordlist"
    show_step "$step" "$total" "ffuf" "complete"
    update_progress "ffuf completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/ffuf_count.tmp"
    return 0
}

# ================================================
# TOOL: custom_tests
# ================================================
run_custom_idor_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    local counter_file="$TEMP_DIR/idor_count_$$.tmp"
    echo "0" > "$counter_file"

    {
        echo "=== CUSTOM IDOR TESTS ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo ""

        # ── DVWA ─────────────────────────────────────────────────────────────
        if [[ -n "$DVWA_BASE" ]]; then
            local cjar="/tmp/dvwa_cookies"
            >&2 echo -e "${CYAN}[*] DVWA IDOR — Note: /vulnerabilities/idor/ not in BWA version${NC}"
            >&2 echo -e "${CYAN}[*] Testing user enumeration via SQLi page (id param) + user-info${NC}"
            echo "--- DVWA IDOR Tests (User Enumeration via id parameter) ---"
            echo "Note: BWA's DVWA does not have /vulnerabilities/idor/ — testing via sqli page"
            echo ""

            # DVWA SQLi page exposes user data via id= — same IDOR concept
            local sqli_url="${DVWA_BASE}/vulnerabilities/sqli/"

            # Get baseline for id=1 (admin)
            local baseline
            baseline=$(curl -s -L --max-time 5 -b "$cjar" "${sqli_url}?id=1&Submit=Submit" 2>/dev/null)
            local baseline_user
            baseline_user=$(echo "$baseline" | grep -oP '(?<=First name: ).*' | head -1 | tr -d '\r')
            >&2 echo -e "${CYAN}[*] Baseline (id=1): ${baseline_user:-admin}${NC}"
            echo "  Baseline (id=1): ${baseline_user:-admin}"

            for id_val in 2 3 4 5; do
                echo -n "  sqli/?id=${id_val}&Submit=Submit... "
                local response
                response=$(curl -s -L --max-time 5 -b "$cjar" \
                    "${sqli_url}?id=${id_val}&Submit=Submit" 2>/dev/null)

                local first_name surname
                first_name=$(echo "$response" | grep -oP '(?<=First name: ).*' | head -1 | tr -d '\r')
                surname=$(echo "$response" | grep -oP '(?<=Surname: ).*' | head -1 | tr -d '\r')

                if [[ -n "$first_name" && -n "$surname" ]]; then
                    echo "IDOR CONFIRMED — Got user: $first_name $surname"
                    {
                        echo "[HIGH] IDOR Confirmed — Unauthorized User Data Access"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $DVWA_BASE (DVWA)"
                        echo "  URL      : ${sqli_url}?id=${id_val}&Submit=Submit"
                        echo "  Param    : id"
                        echo "  ID Value : $id_val"
                        echo "  Evidence : Accessed data of user: $first_name $surname"
                        echo "  Severity : HIGH"
                        echo "  Note     : id parameter exposes other users data without authorization"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "No user data"
                fi
            done

        # ── Mutillidae ────────────────────────────────────────────────────────
        elif [[ "$target" == *"mutillidae"* ]] || [[ "$target" == *"Mutillidae"* ]]; then
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            >&2 echo -e "${CYAN}[*] Testing Mutillidae IDOR${NC}"
            echo "--- Mutillidae IDOR Tests ---"

            local test_users=("admin" "user" "guest" "test" "1" "2" "3")
            for username in "${test_users[@]}"; do
                echo -n "  username=${username}... "
                local response
                # Must include submit button AND password param
                response=$(curl -s -L --max-time 5 \
                    "${mutil_base}/index.php?page=user-info.php&username=${username}&password=&user-info-php-submit-button=View+Account+Details" 2>/dev/null)
                # Mutillidae shows "Signature" column only when results are returned
                # Also check for "record" count text shown above results table
                if echo "$response" | grep -qi "Signature\|records found\|record(s) found"; then
                    local record_count
                    record_count=$(echo "$response" | grep -oiP '\d+\s+record' | head -1)
                    echo "IDOR — User data exposed (${record_count:-data found})"
                    {
                        echo "[HIGH] IDOR Confirmed — User Data Exposed"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : ${mutil_base}/index.php?page=user-info.php&username=${username}&password=&user-info-php-submit-button=View+Account+Details"
                        echo "  Param    : username"
                        echo "  Value    : $username"
                        echo "  Evidence : User account data (Username/Password/Signature) returned without authorization"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "No data returned"
                fi
            done

            # Also test with SQL wildcard to dump all users at once
            echo -n "  username=% (SQL wildcard)... "
            local wildcard_response
            wildcard_response=$(curl -s -L --max-time 5 \
                "${mutil_base}/index.php?page=user-info.php&username=%25&password=&user-info-php-submit-button=View+Account+Details" 2>/dev/null)
            if echo "$wildcard_response" | grep -qi "Signature\|records found"; then
                local count
                count=$(echo "$wildcard_response" | grep -oiP '\d+\s+record' | head -1)
                echo "IDOR — All users dumped (${count:-multiple records})"
                {
                    echo "[CRITICAL] IDOR — All User Records Dumped"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  URL      : ${mutil_base}/index.php?page=user-info.php&username=%25&password=&user-info-php-submit-button=View+Account+Details"
                    echo "  Param    : username"
                    echo "  Value    : % (SQL wildcard)"
                    echo "  Evidence : All user records returned — ${count:-multiple users exposed}"
                    echo "  Severity : CRITICAL"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "No data"
            fi

        # ── Generic ───────────────────────────────────────────────────────────
        else
            >&2 echo -e "${CYAN}[*] Testing generic target for IDOR${NC}"
            echo "--- Generic IDOR Tests ---"

            local params=("id" "user_id" "uid" "account_id" "order_id" "doc_id" "file_id" "profile_id")
            local sensitive_patterns="password|email|ssn|credit|card|address|phone|secret|token|api_key"

            for param in "${params[@]}"; do
                local baseline
                baseline=$(curl -s -L --max-time 5 "${target}?${param}=1" 2>/dev/null)
                local baseline_size=${#baseline}

                for id_val in 2 3 4 5 10 100; do
                    echo -n "  ?${param}=${id_val}... "
                    local response
                    response=$(curl -s -L --max-time 5 "${target}?${param}=${id_val}" 2>/dev/null)
                    local resp_size=${#response}

                    if echo "$response" | grep -qiE "$sensitive_patterns"; then
                        echo "IDOR — Sensitive data exposed"
                        {
                            echo "[HIGH] IDOR Confirmed — Sensitive Data Exposed"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $target (generic)"
                            echo "  URL      : ${target}?${param}=${id_val}"
                            echo "  Param    : $param"
                            echo "  ID Value : $id_val"
                            echo "  Evidence : Sensitive keywords (password/email/etc) in response"
                            echo "  Severity : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    elif [[ $resp_size -gt 100 && $resp_size -ne $baseline_size ]]; then
                        echo "Possible IDOR (size: ${resp_size} vs ${baseline_size})"
                        {
                            echo "[MEDIUM] Possible IDOR — Response Size Differs"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $target (generic)"
                            echo "  URL      : ${target}?${param}=${id_val}"
                            echo "  Param    : $param"
                            echo "  ID Value : $id_val"
                            echo "  Evidence : Size ${resp_size} vs baseline ${baseline_size}"
                            echo "  Severity : MEDIUM — manual verification needed"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "No difference"
                    fi
                done
            done
        fi

        local final_count
        final_count=$(cat "$counter_file")
        echo ""
        echo "Custom IDOR tests completed with $final_count findings"

    } > "$out" 2>&1

    local custom_findings
    custom_findings=$(cat "$counter_file")
    rm -f "$counter_file"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed ($custom_findings findings)"
    echo "$custom_findings" > "$TEMP_DIR/custom_idor_count.tmp"
}

# ================================================
# MAIN IDOR SCAN FUNCTION
# ================================================
scan_idor() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/idor_findings.txt"
    local summary_file="$output_dir/raw_output/idor_summary.txt"

    detect_dvwa_base "$target"
    if [[ -n "$DVWA_BASE" ]]; then
        dvwa_autologin "$DVWA_BASE"
    fi

    {
        echo "========================================"
        echo "IDOR SCAN RESULTS"
        echo "========================================"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "Tools used: $selected_tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐"
    >&2 echo -e "│              INSECURE DIRECT OBJECT REFERENCE SCANNER              │"
    >&2 echo -e "└─────────────────────────────────────────────────────────────────────┘${NC}"
    >&2 echo -e "${YELLOW}[*] Target: $target${NC}"
    >&2 echo -e "${YELLOW}[*] Tools:  $selected_tools${NC}\n"

    IFS=' ' read -ra TOOL_ARRAY <<< "$selected_tools"
    local total_tools=${#TOOL_ARRAY[@]}
    init_progress $total_tools
    local total_findings=0 tools_run=0 tools_success=0

    for tool in "${TOOL_ARRAY[@]}"; do
        tools_run=$((tools_run+1))
        local tool_output="$output_dir/raw_output/${tool}_idor.txt"
        local tool_findings=0

        case $tool in
            "nuclei")
                if run_nuclei_idor "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/nuclei_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/nuclei_count.tmp")
                    rm -f "$TEMP_DIR/nuclei_count.tmp"
                fi
                ;;
            "wfuzz")
                if run_wfuzz_idor "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/wfuzz_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/wfuzz_count.tmp")
                    rm -f "$TEMP_DIR/wfuzz_count.tmp"
                fi
                ;;
            "arjun")
                if run_arjun_idor "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/arjun_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/arjun_count.tmp")
                    rm -f "$TEMP_DIR/arjun_count.tmp"
                fi
                ;;
            "ffuf")
                if run_ffuf_idor "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/ffuf_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/ffuf_count.tmp")
                    rm -f "$TEMP_DIR/ffuf_count.tmp"
                fi
                ;;
            "custom_tests")
                run_custom_idor_tests "$target" "$tool_output" "$findings_file" \
                    "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                if [[ -f "$TEMP_DIR/custom_idor_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/custom_idor_count.tmp")
                    rm -f "$TEMP_DIR/custom_idor_count.tmp"
                fi
                ;;
            "autorize"|"idor_advanced"|"idor_crawler")
                >&2 echo -e "${YELLOW}[*] $tool — not supported for CLI scanning. Skipping.${NC}"
                echo "$tool not supported — skipped" > "$tool_output"
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

    rm -rf "$TEMP_DIR"
    echo "$total_findings" > "$summary_file"
    complete_progress
    >&2 echo -e "${GREEN}[✓] IDOR scan completed${NC}"
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
    findings=$(scan_idor "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
