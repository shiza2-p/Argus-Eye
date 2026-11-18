#!/bin/bash
# ================================================
# ARGUS-EYE - Banner Module
# ================================================

# Get the directory where this script is located
BANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source utils.sh from the same directory
if [[ -f "$BANNER_DIR/utils.sh" ]]; then
    source "$BANNER_DIR/utils.sh"
else
    # Try relative path
    source "$(dirname "$0")/utils.sh" 2>/dev/null || {
        echo -e "\033[0;31m[!] Cannot find utils.sh\033[0m"
        exit 1
    }
fi

# Typewriter function
typewriter() {
    local text=$1
    local color=$2
    local delay=$3
    
    echo -ne "$color"
    for (( i=0; i<${#text}; i++ )); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo -e "${NC}"
}

# Show banner
show_banner() {
    clear
    
    typewriter ">>> CONNECTING TO ARGUS-EYE MAINFRAME..." "$CYAN" 0.03
    sleep 0.5

    echo -e "${GREEN}"
    echo "Establishing secure connection..."
    echo -n "Encryption: "
    for i in {1..20}; do
        echo -n "#"
        sleep 0.05
    done
    echo " [SECURE]"
    sleep 0.3

    echo -e "${CYAN}"
    echo "Authentication: *********** [VERIFIED]"
    sleep 0.5

    echo -e "${GREEN}"
    echo "Loading intrusion detection matrix..."
    for i in {1..5}; do
        echo -n "["
        for j in {1..20}; do
            echo -n "■"
            sleep 0.01
        done
        echo "] Layer $i/5"
    done
    sleep 0.5

    clear

    # Main banner with glitch effect
    echo -e "${GREEN}"
    echo " ╔═══════════════════════════════════════════════════════════════════════╗"

    # Glitch effect
    echo -ne "${RED}"
    sleep 0.2
    echo -e " ║   ▓▓▓▓▓ ▓▓▓▓▓▓  ▓▓▓▓▓▓ ▓▓▓   ▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓▓▓${GREEN} ║"
    sleep 0.1
    clear
    sleep 0.05

    # Real banner
    echo -e " ╔═══════════════════════════════════════════════════════════════════════╗"
    echo -e " ║${RED} █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗    ███████╗██╗   ██╗███████╗${GREEN}║"
    echo -e " ║${RED}██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝${GREEN}║"
    echo -e " ║${RED}███████║██████╔╝██║  ███╗██║   ██║███████╗    █████╗   ╚████╔╝ █████╗  ${GREEN}║"
    echo -e " ║${RED}██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║    ██╔══╝    ╚██╔╝  ██╔══╝  ${GREEN}║"
    echo -e " ║${RED}██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║██╗███████╗   ██║   ███████╗${GREEN} ║"
    echo -e " ║${RED}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝${GREEN} ║"
    echo " ╠═══════════════════════════════════════════════════════════════════════╣"
    echo -e " ║${CYAN}    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${GREEN}    ║"
    echo -e " ║${CYAN}    ░░▒▒▓▓██   A R G U S   E Y E   S C A N N E R   V1.0    ██▓▓▒▒░░${GREEN}    ║"
    echo -e " ║${CYAN}    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${GREEN}    ║"
    echo " ╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Final activation
    echo ""
    typewriter "          Initializing 100-eye surveillance grid..." "$YELLOW" 0.03
    echo ""

    # Eye grid
    echo -ne "          "
    for row in {1..5}; do
        for col in {1..20}; do
            echo -ne "${GREEN}◉${NC}"
            sleep 0.01
        done
        echo ""
        echo -ne "          "
    done

    echo ""
    echo -e "${CYAN}          ███████████████████████████████████████████████████████${NC}"
    echo -e "${GREEN}          [✓] ARGUS-EYE FULLY OPERATIONAL - READY TO SCAN${NC}"
    echo ""
    
    log "INFO" "Banner displayed"
}

# Export functions
export -f typewriter show_banner
