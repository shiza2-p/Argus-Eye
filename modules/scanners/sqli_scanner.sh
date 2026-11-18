#!/bin/bash
# ================================================
# ARGUS-EYE - SQL Injection Scanner (Generic)
# Fully target-agnostic. Portable tool paths.
# Tools: sqlmap | nosqli | custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
source "$CORE_DIR/utils.sh" 2>/dev/null || true
source "$CORE_DIR/installer.sh" 2>/dev/null || true

SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"

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
# URL / PARAMETER HELPERS
# ================================================
get_base_url() {
    local url=$1
    echo "$url" | sed -E 's/[?#].*//'
}

build_url() {
    local target=$1 param=$2 value=$3
    local pure_base existing_qs
    pure_base=$(echo "$target" | sed -E 's/[?#].*//')
    existing_qs=$(echo "$target" | grep -oE '\?[^#]*' | sed 's/^?//' || true)

    local encoded_value
    encoded_value=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$value" 2>/dev/null || \
                    echo "$value" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g; s/"/%22/g; s/'"'"'/%27/g; s/&/%26/g')

    if [[ -z "$existing_qs" ]]; then
        echo "${pure_base}?${param}=${encoded_value}"
        return
    fi

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
# sqlmap (portable)
# ================================================
run_sqlmap() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "sqlmap" "start"

    local sqlmap_bin=""
    if [[ -x "$SCRIPT_DIR/tools/bin/sqlmap" ]]; then
        sqlmap_bin="$SCRIPT_DIR/tools/bin/sqlmap"
    elif [[ -f "$SCRIPT_DIR/tools/sqlmap/sqlmap.py" ]]; then
        sqlmap_bin="python3 $SCRIPT_DIR/tools/sqlmap/sqlmap.py"
    elif command -v sqlmap >/dev/null 2>&1; then
        sqlmap_bin="$(command -v sqlmap)"
    fi

    if [[ -z "$sqlmap_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] sqlmap not found – attempting install into tools/...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "sqlmap" 2>&1 | tail -8 || true
        fi
        if [[ -f "$SCRIPT_DIR/tools/sqlmap/sqlmap.py" ]]; then
            sqlmap_bin="python3 $SCRIPT_DIR/tools/sqlmap/sqlmap.py"
        elif command -v sqlmap >/dev/null 2>&1; then
            sqlmap_bin="$(command -v sqlmap)"
        fi
    fi

    if [[ -z "$sqlmap_bin" ]]; then
        >&2 echo -e "${RED}[!] sqlmap still not available – skipping${NC}"
        show_step "$step" "$total" "sqlmap" "skip"
        echo "0"
        return
    fi

    >&2 echo -e "  ${CYAN}[*] sqlmap: $sqlmap_bin${NC}"
    >&2 echo -e "  ${CYAN}[*] target: $target (timeout 300s)${NC}"

    : > "$out"

    local cookie_args=()
    local header_args=()
    [[ -n "$COOKIE" ]] && cookie_args=(--cookie="$COOKIE")
    [[ -n "$HEADER" ]] && header_args=(--headers="$HEADER")

    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/argus_sqlmap_XXXXXX 2>/dev/null || echo "/tmp/argus_sqlmap_$$")

    # If URL has no query parameters, enable form detection + light crawl
    local extra_sqlmap=()
    if [[ "$target" != *\?* ]]; then
        # Prefer forms only (faster/more reliable than deep crawl on login pages)
        >&2 echo -e "  ${CYAN}[*] No GET params – enabling --forms (no deep crawl)${NC}"
        extra_sqlmap=(--forms)
    fi

    set +e
    # Generic defaults: --batch, level 2, risk 1
    # Answer cookie prompts automatically via --batch
    if [[ "$sqlmap_bin" == python3* ]]; then
        local script_path="${sqlmap_bin#python3 }"
        timeout --signal=TERM 360 python3 "$script_path" -u "$target" \
            --batch \
            --level=2 \
            --risk=1 \
            --threads=3 \
            --timeout=15 \
            --retries=1 \
            --random-agent \
            --output-dir="$tmp_dir" \
            "${extra_sqlmap[@]}" \
            "${cookie_args[@]}" \
            "${header_args[@]}" \
            >> "$out" 2>&1
    else
        timeout --signal=TERM 360 "$sqlmap_bin" -u "$target" \
            --batch \
            --level=2 \
            --risk=1 \
            --threads=3 \
            --timeout=15 \
            --retries=1 \
            --random-agent \
            --output-dir="$tmp_dir" \
            "${extra_sqlmap[@]}" \
            "${cookie_args[@]}" \
            "${header_args[@]}" \
            >> "$out" 2>&1
    fi
    local rc=$?
    set -e

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        >&2 echo -e "  ${YELLOW}[!] sqlmap timed out after 360s – partial raw output kept${NC}"
        echo "" >> "$out"
        echo "[Argus-Eye] sqlmap timed out after 360s – partial results above" >> "$out"
    elif [[ $rc -ne 0 ]]; then
        >&2 echo -e "  ${YELLOW}[!] sqlmap exit code: $rc (raw output still saved)${NC}"
    fi

    # Merge any log files sqlmap wrote into raw output
    if [[ -d "$tmp_dir" ]]; then
        find "$tmp_dir" -type f \( -name "*.log" -o -name "*.txt" -o -name "log" \) 2>/dev/null | while read -r f; do
            echo "" >> "$out"
            echo "=== sqlmap file: $f ===" >> "$out"
            head -200 "$f" >> "$out" 2>/dev/null || true
        done
        rm -rf "$tmp_dir" 2>/dev/null || true
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        local lines
        lines=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
        count=$(grep -ciE 'is vulnerable|sqlmap identified|parameter .* is vulnerable|Type:.*injection|Payload:' "$out" 2>/dev/null || echo 0)
        [[ "$count" =~ ^[0-9]+$ ]] || count=0

        >&2 echo -e "  ${CYAN}[*] sqlmap raw lines: $lines | vuln-like: $count${NC}"

        {
            echo "=== SQLMAP RAW OUTPUT SAVED ==="
            echo "File: $out"
            echo "Lines: $lines"
            echo "Vuln-like matches: $count"
            if [[ $count -gt 0 ]]; then
                echo "--- Extracted lines ---"
                grep -iE 'is vulnerable|sqlmap identified|parameter .* is vulnerable|Type:.*injection|Payload:' "$out" | head -40 || true
            fi
        } >> "$findings_file"
    else
        echo "=== SQLMAP: empty output ===" >> "$findings_file"
    fi

    show_step "$step" "$total" "sqlmap" "complete"
    echo "$count"
}

# ================================================
# nosqli (portable)
# ================================================
run_nosqli() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "nosqli" "start"

    local nosqli_bin=""
    if [[ -x "$SCRIPT_DIR/tools/bin/nosqli" ]]; then
        nosqli_bin="$SCRIPT_DIR/tools/bin/nosqli"
    elif [[ -f "$SCRIPT_DIR/tools/nosqli/nosqli" ]]; then
        nosqli_bin="$SCRIPT_DIR/tools/nosqli/nosqli"
    elif command -v nosqli >/dev/null 2>&1; then
        nosqli_bin="$(command -v nosqli)"
    fi

    if [[ -z "$nosqli_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] nosqli not found – attempting install into tools/...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "nosqli" 2>&1 | tail -8 || true
        fi
        if [[ -x "$SCRIPT_DIR/tools/bin/nosqli" ]]; then
            nosqli_bin="$SCRIPT_DIR/tools/bin/nosqli"
        elif command -v nosqli >/dev/null 2>&1; then
            nosqli_bin="$(command -v nosqli)"
        fi
    fi

    if [[ -z "$nosqli_bin" ]]; then
        >&2 echo -e "${RED}[!] nosqli still not available – skipping${NC}"
        show_step "$step" "$total" "nosqli" "skip"
        echo "0"
        return
    fi

    >&2 echo -e "  ${CYAN}[*] nosqli: $nosqli_bin${NC}"

    : > "$out"

    set +e
    timeout --signal=TERM 120 "$nosqli_bin" scan -t "$target" >> "$out" 2>&1
    local rc=$?
    set -e

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        >&2 echo -e "  ${YELLOW}[!] nosqli timed out – partial raw output kept${NC}"
        echo "[Argus-Eye] nosqli timed out" >> "$out"
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        count=$(grep -ciE 'vulnerable|injection|found|success|bypass' "$out" 2>/dev/null || echo 0)
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        {
            echo "=== NOSQLI RAW OUTPUT SAVED ==="
            echo "File: $out"
            if [[ $count -gt 0 ]]; then
                grep -iE 'vulnerable|injection|found|success|bypass' "$out" | head -30 || true
            fi
        } >> "$findings_file"
    fi

    show_step "$step" "$total" "nosqli" "complete"
    echo "$count"
}

# ================================================
# GENERIC CUSTOM SQLi TESTS
# ================================================
run_custom_sqli_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom SQLi Tests" "start"

    local counter=0
    local base_url
    base_url=$(get_base_url "$target")

    # Focused payloads (fast, high-signal)
    local payloads=(
        "'"
        "\""
        "' OR '1'='1"
        "' OR '1'='1' --"
        "1' OR '1'='1"
        "1 AND 1=1"
        "1 AND 1=2"
        "admin'--"
        "1 UNION SELECT NULL--"
    )

    # Prioritized parameter names (shorter list = much faster)
    local params=(
        "id" "cat" "category" "page" "user" "username" "uid"
        "search" "q" "query" "keyword" "tfSearch" "name"
        "product" "pid" "item" "article" "order" "sort"
    )

    # If URL already has a query param, only test those names first
    if [[ "$target" == *\?* ]]; then
        local existing
        existing=$(echo "$target" | grep -oE '[?&][^=]+=' | sed 's/^[?&]//;s/=$//' | head -10)
        if [[ -n "$existing" ]]; then
            local merged=()
            while read -r p; do [[ -n "$p" ]] && merged+=("$p"); done <<< "$existing"
            for p in "${params[@]}"; do
                local seen=0
                for m in "${merged[@]}"; do [[ "$m" == "$p" ]] && seen=1 && break; done
                [[ $seen -eq 0 ]] && merged+=("$p")
            done
            params=("${merged[@]}")
        fi
    fi

    {
        echo "=== GENERIC CUSTOM SQLi TESTS ==="
        echo "Target        : $target"
        echo "Base URL      : $base_url"
        echo "Date          : $(date)"
        echo "Payloads      : ${#payloads[@]}"
        echo "Parameters    : ${#params[@]}"
        echo ""
    } > "$out"

    local baseline=""
    if [[ -n "$COOKIE" ]]; then
        baseline=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye)" -H "Cookie: $COOKIE" "$target" 2>/dev/null || true)
    else
        baseline=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye)" "$target" 2>/dev/null || true)
    fi
    local baseline_len=${#baseline}

    local error_patterns='sql syntax|mysql_fetch|ORA-[0-9]+|PostgreSQL|SQLite|ODBC|Jdbc|Unclosed quotation|quoted string not properly|SQLSTATE|Microsoft OLE DB|mysql_num_rows|pg_query|Warning:.*mysql|valid MySQL result|MySqlClient|com\.mysql|Syntax error|MariaDB|PDOException|SQLException'

    >&2 echo -e "  ${CYAN}[*] Probing ${#params[@]} params × ${#payloads[@]} payloads (fast mode)...${NC}"

    for param in "${params[@]}"; do
        for payload in "${payloads[@]}"; do
            local test_url
            test_url=$(build_url "$target" "$param" "$payload")

            local response=""
            if [[ -n "$COOKIE" ]]; then
                response=$(curl -s -L --max-time 5 -A "Mozilla/5.0 (Argus-Eye SQLi)" -H "Cookie: $COOKIE" "$test_url" 2>/dev/null || true)
            else
                response=$(curl -s -L --max-time 5 -A "Mozilla/5.0 (Argus-Eye SQLi)" "$test_url" 2>/dev/null || true)
            fi

            local is_interesting=false
            if echo "$response" | grep -qiE "$error_patterns"; then
                is_interesting=true
            fi

            if $is_interesting; then
                echo "[POTENTIAL SQLi] param=$param payload=$(echo "$payload" | head -c 40) | $test_url" | tee -a "$out" >> "$findings_file"
                ((counter++))
                break  # next parameter
            fi
        done
        # Cap total custom findings to keep scan fast
        [[ $counter -ge 8 ]] && break
    done

    # One light time-based probe on id/cat only
    >&2 echo -e "  ${CYAN}[*] Light time-based check...${NC}"
    for param in id cat page; do
        local test_url
        test_url=$(build_url "$target" "$param" "1' AND SLEEP(3)--")
        local start_ts end_ts dur
        start_ts=$(date +%s)
        curl -s -L --max-time 8 -A "Mozilla/5.0 (Argus-Eye SQLi)" "$test_url" >/dev/null 2>&1 || true
        end_ts=$(date +%s)
        dur=$((end_ts - start_ts))
        if [[ $dur -ge 3 ]]; then
            echo "[POTENTIAL SQLi TIME-BASED] param=$param delay=${dur}s | $test_url" | tee -a "$out" >> "$findings_file"
            ((counter++))
            break
        fi
    done

    echo "" >> "$out"
    echo "Custom SQLi tests finished. Potential findings: $counter" >> "$out"
    show_step "$step" "$total" "Custom SQLi Tests" "complete"
    echo "$counter"
}

# ================================================
# MAIN SCAN
# ================================================
scan_sqli() {
    local target=$1
    local output_dir=$2
    local tools=${3:-"sqlmap custom_tests"}

    mkdir -p "$output_dir/raw_output" "$output_dir/findings"
    local findings_file="$output_dir/raw_output/sqli_findings.txt"
    local summary_file="$output_dir/raw_output/sqli_summary.txt"

    {
        echo "========================================"
        echo "SQL INJECTION SCAN RESULTS"
        echo "========================================"
        echo "Target : $target"
        echo "Date   : $(date)"
        echo "Tools  : $tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}"
    >&2 echo "╔══════════════════════════════════════════════════════════════╗"
    >&2 echo "║           SQLi SCANNER (Generic / Best Effort)               ║"
    >&2 echo "╚══════════════════════════════════════════════════════════════╝"
    >&2 echo -e "${NC}"
    >&2 echo -e "  Target : ${GREEN}$target${NC}"
    >&2 echo -e "  Tools  : ${YELLOW}$tools${NC}"

    # Normalize tool list
    local tool_array=()
    if [[ "$tools" == "ALL" || "$tools" == "all" ]]; then
        tool_array=(sqlmap nosqli custom_tests)
    else
        read -ra tool_array <<< "$tools"
    fi

    local total_tools=${#tool_array[@]}
    local tools_run=0
    local total_findings=0

    for tool in "${tool_array[@]}"; do
        tools_run=$((tools_run + 1))
        local tool_output="$output_dir/raw_output/${tool}_sqli.txt"
        local tool_findings=0

        # Each tool runs in isolation – failures never stop the scan
        set +e
        case "$tool" in
            sqlmap)
                tool_findings=$(run_sqlmap "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            nosqli)
                tool_findings=$(run_nosqli "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            custom_tests)
                tool_findings=$(run_custom_sqli_tests "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            *)
                >&2 echo -e "${YELLOW}[!] Unknown tool: $tool – skipping${NC}"
                tool_findings=0
                ;;
        esac
        set -e

        [[ "$tool_findings" =~ ^[0-9]+$ ]] || tool_findings=0
        total_findings=$((total_findings + tool_findings))
        >&2 echo -e "  ${CYAN}[*] $tool finished (findings: $tool_findings)${NC}"
    done

    {
        echo ""
        echo "========================================"
        echo "SQLi SCAN SUMMARY"
        echo "========================================"
        echo "Target          : $target"
        echo "Tools requested : ${tool_array[*]}"
        echo "Total findings  : $total_findings"
        echo "Timestamp       : $(date)"
        echo "========================================"
    } | tee -a "$findings_file" >&2

    echo "$total_findings" > "$summary_file"
    echo "$total_findings"
}

# CLI entry
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <target_url> <output_dir> [tools]"
        echo "  tools: sqlmap nosqli custom_tests  (default: sqlmap custom_tests)"
        echo "  Example: $0 'http://target.example/page?id=1' /tmp/sqli 'sqlmap custom_tests'"
        exit 1
    fi
    findings=$(scan_sqli "$1" "$2" "${3:-sqlmap custom_tests}")
    echo "$findings"
fi
