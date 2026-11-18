#!/bin/bash
# ================================================
# ARGUS-EYE - Main Orchestrator (with Professional Report)
# ================================================

export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source core modules
source "$SCRIPT_DIR/modules/core/utils.sh"
source "$SCRIPT_DIR/modules/core/banner.sh"
source "$SCRIPT_DIR/modules/core/target.sh"
source "$SCRIPT_DIR/modules/core/output.sh"
source "$SCRIPT_DIR/modules/core/tool_selection.sh"
source "$SCRIPT_DIR/modules/core/progress.sh"
source "$SCRIPT_DIR/modules/reports/report_gen.sh"   # Your report generator


# Helper to strip ANSI codes (used in scan_info.txt)
strip_ansi() {
    echo "$1" | sed -E 's/\x1b\[[0-9;]*[mK]//g'
}

# Vulnerability mappings
declare -A VULN_NAMES=(
    [1]="XSS" [2]="SQLi" [3]="LFI" [4]="RFI" [5]="DIR_TRAVERSAL"
    [6]="CMD_INJECTION" [7]="IDOR" [8]="SSRF" [9]="XXE" [A]="ALL"
)
declare -A VULN_SCRIPTS=(
    ["XSS"]="scanners/xss_scanner.sh"
    ["SQLi"]="scanners/sqli_scanner.sh"
    ["LFI"]="scanners/lfi_scanner.sh"
    ["RFI"]="scanners/rfi_scanner.sh"
    ["DIR_TRAVERSAL"]="scanners/dir_scanner.sh"
    ["CMD_INJECTION"]="scanners/cmd_scanner.sh"
    ["IDOR"]="scanners/idor_scanner.sh"
    ["SSRF"]="scanners/ssrf_scanner.sh"
    ["XXE"]="scanners/xxe_scanner.sh"
)

# ================================================
# MENU FUNCTION (unchanged)
# ================================================
show_advanced_menu() {
    echo -e "${CYAN}"
    echo "┌─────────────────────────────────────────────────────────────────────┐"
    echo "│                   ARGUS-EYE VULNERABILITY SCANNER                   │"
    echo "├─────────────────────────────────────────────────────────────────────┤"
    echo "│                                                                     │"
    local vulnerabilities=(
        "1) XSS (Cross-Site Scripting)          - Inject malicious scripts"
        "2) SQL Injection                       - Database manipulation   "
        "3) LFI (Local File Inclusion)          - Read local system files "
        "4) RFI (Remote File Inclusion)         - Include remote files    "
        "5) Directory Traversal                 - Unauthorized Access     "
        "6) Command Injection                   - Execute system commands "
        "7) IDOR (Insecure Direct Object Ref)   - Access other users' data"
        "8) SSRF (Server-Side Request Forgery)  - Server request forgery  "
        "9) XXE (XML External Entity)           - XML parsing attacks     "
    )
    for vuln in "${vulnerabilities[@]}"; do
        printf "│   ${YELLOW}%-60s${CYAN} │\n" "$vuln"
    done
    echo "│                                                                     │"
    echo "├─────────────────────────────────────────────────────────────────────┤"
    echo -e "│   ${GREEN}A${CYAN}) ${RED}RUN COMPREHENSIVE SCAN${CYAN} (All vulnerabilities)                   │"
    echo -e "│   ${GREEN}Q${CYAN}) ${RED}EXIT${CYAN}                                                           │"
    echo "└─────────────────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
    echo -e "${YELLOW}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     RECOMMENDED FOR testphp.vulnweb.com: 1 (XSS), 2 (SQLi)       ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================
# PROCESS SELECTION (unchanged)
# ================================================
process_selection() {
    local choice=$1
    case $choice in
        1) SELECTED_VULN="XSS" ;;
        2) SELECTED_VULN="SQLi" ;;
        3) SELECTED_VULN="LFI" ;;
        4) SELECTED_VULN="RFI" ;;
        5) SELECTED_VULN="DIR_TRAVERSAL" ;;
        6) SELECTED_VULN="CMD_INJECTION" ;;
        7) SELECTED_VULN="IDOR" ;;
        8) SELECTED_VULN="SSRF" ;;
        9) SELECTED_VULN="XXE" ;;
        A|a) SELECTED_VULN="ALL" ;;
        Q|q) echo -e "${GREEN}[+] Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}[!] Invalid selection${NC}"; return 1 ;;
    esac
    echo -e "${GREEN}[+] Selected: $SELECTED_VULN${NC}"
    export SELECTED_VULN
    return 0
}

# ================================================
# EXECUTE SCAN (UPDATED to capture only the number)
# ================================================
execute_scan() {
    local vuln=$1 target=$2 output=$3 tools=$4
    local total_findings=0

    >&2 echo -e "${CYAN}"
    >&2 echo "╔══════════════════════════════════════════════════════════════╗"
    >&2 echo "║                    EXECUTING VULNERABILITY SCAN              ║"
    >&2 echo "╚══════════════════════════════════════════════════════════════╝"
    >&2 echo -e "${NC}"

    if [[ "$vuln" == "ALL" ]]; then
        >&2 echo -e "${YELLOW}[*] Running comprehensive scan...${NC}"
        local vuln_list=(XSS SQLi LFI RFI DIR_TRAVERSAL CMD_INJECTION IDOR SSRF XXE)
        local total=${#vuln_list[@]}
        local current=0
        for v in "${vuln_list[@]}"; do
            current=$((current + 1))
            >&2 echo -e "\n${CYAN}[$current/$total] Running $v scanner${NC}"
            script="$SCRIPT_DIR/modules/${VULN_SCRIPTS[$v]}"
            [[ ! -f "$script" ]] && { >&2 echo -e "${YELLOW}  [!] Scanner not found${NC}"; continue; }
            v_tools="${TOOL_LISTS[$v]:-custom_tests}"
            >&2 echo -e "${BLUE}  Using tools: $v_tools${NC}"
            # Capture only a pure number from the scanner's output
            output_line=$(bash "$script" "$target" "$output" "$v_tools" 2>&1 | grep -E '^[0-9]+$' | tail -1)
            if [[ -n "$output_line" ]]; then
                findings=$output_line
            else
                # Fallback: look for FINDINGS_COUNT=...
                output_line=$(bash "$script" "$target" "$output" "$v_tools" 2>&1 | grep -E 'FINDINGS_COUNT=[0-9]+' | tail -1 | sed -E 's/.*FINDINGS_COUNT=([0-9]+).*/\1/')
                findings=${output_line:-0}
            fi
            total_findings=$((total_findings + findings))
            >&2 echo -e "${GREEN}  [✓] $v completed with $findings findings${NC}"
        done
    else
        script="$SCRIPT_DIR/modules/${VULN_SCRIPTS[$vuln]}"
        [[ ! -f "$script" ]] && { echo -e "${RED}[!] Scanner not found for $vuln${NC}"; return 1; }
        # Capture only a pure number from the scanner's output
        output_line=$(bash "$script" "$target" "$output" "$tools" 2>&1 | grep -E '^[0-9]+$' | tail -1)
        if [[ -n "$output_line" ]]; then
            findings=$output_line
        else
            # Fallback: look for FINDINGS_COUNT=...
            output_line=$(bash "$script" "$target" "$output" "$tools" 2>&1 | grep -E 'FINDINGS_COUNT=[0-9]+' | tail -1 | sed -E 's/.*FINDINGS_COUNT=([0-9]+).*/\1/')
            findings=${output_line:-0}
        fi
        total_findings=$findings
    fi
    # Output only the number, no newline (to avoid capturing extra garbage)
    printf "%s" "$total_findings"
}

# ================================================
# MAIN PROGRAM FLOW
# ================================================

show_banner
setup_target
show_advanced_menu

echo -ne "${YELLOW}[?] Select option (1-9, A, Q): ${NC}"
read -r USER_CHOICE

if process_selection "$USER_CHOICE"; then
    echo ""
    if [[ "$SELECTED_VULN" != "ALL" ]]; then
        if ! select_tools "$SELECTED_VULN"; then
            echo -e "${YELLOW}[!] Tool selection cancelled${NC}"
            exit 0
        fi
    else
        SELECTED_TOOLS="ALL"
    fi

    OUTPUT_DIR=$(create_output_directory "$TARGET_URL" "$SELECTED_VULN")
    [[ -z "$OUTPUT_DIR" || ! -d "$OUTPUT_DIR" ]] && { echo -e "${RED}[!] Failed to create output directory${NC}"; exit 1; }

    echo ""
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}           SCAN CONFIGURATION SUMMARY            ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${CYAN}Target:${NC} $TARGET_URL"
    echo -e "${CYAN}Vulnerability:${NC} $SELECTED_VULN"
    echo -e "${CYAN}Selected Tools:${NC} $SELECTED_TOOLS"
    echo -e "${GREEN}=================================================${NC}"
    echo ""

    echo -ne "${YELLOW}[?] Start scanning with selected tools? (Y/N): ${NC}"
    read -r CONFIRM

    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[+] Starting scan...${NC}"

        TOTAL_FINDINGS=$(execute_scan "$SELECTED_VULN" "$TARGET_URL" "$OUTPUT_DIR" "$SELECTED_TOOLS")

        # Strip ANSI from TOTAL_FINDINGS before writing to text file
        CLEAN_FINDINGS=$(strip_ansi "$TOTAL_FINDINGS")
        {
            echo "Status: Completed"
            echo "Completion Time: $(date)"
            echo "Total Findings: $CLEAN_FINDINGS"
        } >> "$OUTPUT_DIR/scan_info.txt"

        # Generate professional HTML report
        generate_report "$OUTPUT_DIR" "$TARGET_URL" "$SELECTED_VULN"

        echo -e "${GREEN}[+] Scan completed successfully!${NC}"
        echo -e "${YELLOW}[*] Results saved in: $OUTPUT_DIR${NC}"
    else
        echo -e "${YELLOW}[!] Scan cancelled${NC}"
    fi
fi

echo ""
echo -e "${GREEN}[+] Argus-Eye session completed${NC}"
