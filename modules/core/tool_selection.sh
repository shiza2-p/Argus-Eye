#!/bin/bash
# ================================================
# ARGUS-EYE - Tool Selection Module (Generic)
# No lab-specific recommendations or hardcoding.
# ================================================

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# ================================================
# TOOL LISTS PER VULNERABILITY CATEGORY
# ================================================
declare -A TOOL_LISTS=(
    ["XSS"]="dalfox XSStrike PwnXSS custom_tests"
    ["SQLi"]="sqlmap nosqli custom_tests"
    ["LFI"]="ffuf dirsearch dotdotpwn custom_tests"
    ["RFI"]="ffuf wfuzz custom_tests"
    ["DIR_TRAVERSAL"]="gobuster dirsearch ffuf custom_tests"
    ["CMD_INJECTION"]="commix custom_tests"
    ["IDOR"]="nuclei wfuzz arjun ffuf custom_tests"
    ["SSRF"]="ssrfmap nuclei custom_tests"
    ["XXE"]="xxeinjector custom_tests"
    ["ALL"]="dalfox sqlmap ffuf gobuster nikto dirsearch commix nuclei custom_tests"
)

# ================================================
# TOOL DESCRIPTIONS (generic, no lab references)
# ================================================
declare -A TOOL_DESCRIPTIONS=(
    ["dalfox"]="Fast and powerful XSS scanner"
    ["XSStrike"]="Advanced XSS detection and exploitation suite"
    ["PwnXSS"]="XSS crawler and scanner"
    ["custom_tests"]="Built-in generic payload tests"
    ["sqlmap"]="Automatic SQL injection and database takeover tool"
    ["nosqli"]="NoSQL injection testing"
    ["ffuf"]="Fast web fuzzer"
    ["dirsearch"]="Web path scanner"
    ["gobuster"]="Directory/file & DNS busting tool"
    ["nikto"]="Web server scanner"
    ["commix"]="Automated command injection tool"
    ["nuclei"]="Fast and customizable vulnerability scanner (templates)"
    ["wfuzz"]="Web application fuzzer"
    ["arjun"]="HTTP parameter discovery suite"
    ["dotdotpwn"]="Directory traversal fuzzer"
    ["ssrfmap"]="SSRF exploitation tool"
    ["xxeinjector"]="XXE injection tool"
    ["wafwoof"]="WAF detection tool"
)

# ================================================
# SHOW SCAN MODE MENU (always generic)
# ================================================
show_recommendation_menu() {
    echo ""
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                     SCAN MODE SELECTION                                  │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  Target mode   : ${GREEN}Generic${NC}                                                ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  ${YELLOW}1${CYAN}. ${GREEN}Full Scan${NC} — run all vulnerability categories                     ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW}2${CYAN}. ${GREEN}Select Vulnerability Type${NC} — choose one category                  ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW}3${CYAN}. ${GREEN}Manual Tool Selection${NC} — pick tools yourself                     ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW}4${CYAN}. ${GREEN}GO BACK${NC}                                                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ================================================
# SHOW VULNERABILITY CATEGORY MENU
# ================================================
show_vuln_menu() {
    echo ""
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                   SELECT VULNERABILITY CATEGORY                          │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  ${YELLOW} 1${CYAN}. ${GREEN}XSS${NC}            Cross-Site Scripting                              ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 2${CYAN}. ${GREEN}SQLi${NC}           SQL Injection                                    ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 3${CYAN}. ${GREEN}LFI${NC}            Local File Inclusion                             ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 4${CYAN}. ${GREEN}RFI${NC}            Remote File Inclusion                            ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 5${CYAN}. ${GREEN}DIR_TRAVERSAL${NC}  Directory Traversal / Discovery                  ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 6${CYAN}. ${GREEN}CMD_INJECTION${NC}  Command Injection                                ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 7${CYAN}. ${GREEN}IDOR${NC}           Insecure Direct Object Reference                 ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 8${CYAN}. ${GREEN}SSRF${NC}           Server-Side Request Forgery                      ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW} 9${CYAN}. ${GREEN}XXE${NC}            XML External Entity Injection                    ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW}10${CYAN}. ${GREEN}GO BACK${NC}                                                          ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ================================================
# SHOW TOOL SELECTION MENU (per vulnerability)
# ================================================
show_tool_menu() {
    local vuln=$1
    local tools=(${TOOL_LISTS[$vuln]})

    echo ""
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                       TOOL SELECTION MENU                                  │${NC}"
    echo -e "${CYAN}├────────────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${CYAN}│  Vulnerability : ${GREEN}%-57s${CYAN}  │${NC}\n" "$vuln"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"

    local i=1
    for tool in "${tools[@]}"; do
        local desc="${TOOL_DESCRIPTIONS[$tool]:-No description available}"
        printf "${CYAN}│   ${YELLOW}%2d${CYAN}. ${GREEN}%-14s${NC} %-50s${CYAN}│${NC}\n" \
            "$i" "$tool" "$desc"
        ((i++))
    done

    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  ${YELLOW}A${CYAN}. ${GREEN}USE ALL TOOLS${NC}                                                    ${CYAN}│${NC}"
    echo -e "${CYAN}│  ${YELLOW}C${CYAN}. ${GREEN}GO BACK${NC}                                                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ================================================
# SELECT TOOLS FOR A VULNERABILITY
# ================================================
select_tools() {
    local vuln=$1
    local tools=(${TOOL_LISTS[$vuln]})
    local selected=()

    while true; do
        show_tool_menu "$vuln"
        echo -ne "${YELLOW}[?] Select tools (numbers, A=all, C=back): ${NC}"
        read -r choice

        case $choice in
            [Aa])
                selected=("${tools[@]}")
                break
                ;;
            [Cc])
                return 1
                ;;
            *)
                # Parse comma or space separated numbers
                IFS=', ' read -ra nums <<< "$choice"
                selected=()
                local valid=true
                for n in "${nums[@]}"; do
                    if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#tools[@]} )); then
                        selected+=("${tools[$((n-1))]}")
                    else
                        echo -e "${RED}[!] Invalid selection: $n${NC}"
                        valid=false
                        break
                    fi
                done
                if $valid && [[ ${#selected[@]} -gt 0 ]]; then
                    break
                fi
                ;;
        esac
    done

    SELECTED_TOOLS="${selected[*]}"
    export SELECTED_TOOLS
    echo -e "${GREEN}[✓] Selected tools: $SELECTED_TOOLS${NC}"
    return 0
}

# ================================================
# RUN COMPREHENSIVE SCAN (all categories)
# ================================================
run_comprehensive_scan() {
    local target_url=$1
    SCAN_VULNS="XSS SQLi LFI RFI DIR_TRAVERSAL CMD_INJECTION IDOR SSRF XXE"
    SELECTED_TOOLS="all"
    export SCAN_VULNS SELECTED_TOOLS
    echo -e "${GREEN}[✓] Comprehensive scan selected (all categories)${NC}"
}

# ================================================
# HANDLE SCAN MODE SELECTION
# ================================================
handle_scan_mode() {
    local target_url=$1

    while true; do
        show_recommendation_menu
        echo -ne "${YELLOW}[?] Select scan mode (1/2/3/4): ${NC}"
        read -r mode_choice

        case $mode_choice in
            1)
                run_comprehensive_scan "$target_url"
                return 0
                ;;
            2)
                show_vuln_menu
                echo -ne "${YELLOW}[?] Select vulnerability category (1-9): ${NC}"
                read -r vuln_choice
                local vuln_map=('' XSS SQLi LFI RFI DIR_TRAVERSAL CMD_INJECTION IDOR SSRF XXE)
                local chosen_vuln="${vuln_map[$vuln_choice]}"
                if [[ -z "$chosen_vuln" || "$vuln_choice" == "10" ]]; then
                    echo -e "${RED}[!] Invalid choice${NC}"
                    continue
                fi
                select_tools "$chosen_vuln"
                SCAN_VULNS="$chosen_vuln"
                export SCAN_VULNS
                return 0
                ;;
            3)
                show_vuln_menu
                echo -ne "${YELLOW}[?] Select vulnerability category (1-9): ${NC}"
                read -r vuln_choice
                local vuln_map=('' XSS SQLi LFI RFI DIR_TRAVERSAL CMD_INJECTION IDOR SSRF XXE)
                local chosen_vuln="${vuln_map[$vuln_choice]}"
                if [[ -z "$chosen_vuln" || "$vuln_choice" == "10" ]]; then
                    echo -e "${RED}[!] Invalid choice${NC}"
                    continue
                fi
                select_tools "$chosen_vuln"
                SCAN_VULNS="$chosen_vuln"
                export SCAN_VULNS
                return 0
                ;;
            4)
                return 1
                ;;
            *)
                echo -e "${RED}[!] Invalid choice — enter 1, 2, 3, or 4${NC}"
                ;;
        esac
    done
}

# ================================================
# GET DEFAULT TOOLS (generic)
# ================================================
get_default_tools() {
    local vuln=$1
    case $vuln in
        "XSS")           echo "dalfox XSStrike custom_tests" ;;
        "SQLi")          echo "sqlmap custom_tests" ;;
        "LFI")           echo "ffuf dirsearch custom_tests" ;;
        "RFI")           echo "ffuf custom_tests" ;;
        "DIR_TRAVERSAL") echo "gobuster dirsearch custom_tests" ;;
        "CMD_INJECTION") echo "commix custom_tests" ;;
        "IDOR")          echo "nuclei wfuzz custom_tests" ;;
        "SSRF")          echo "ssrfmap nuclei custom_tests" ;;
        "XXE")           echo "xxeinjector custom_tests" ;;
        *)               echo "custom_tests" ;;
    esac
}

# ================================================
# EXPORTS
# ================================================
export -f show_tool_menu show_vuln_menu show_recommendation_menu
export -f select_tools run_comprehensive_scan handle_scan_mode get_default_tools
export TOOL_LISTS TOOL_DESCRIPTIONS
