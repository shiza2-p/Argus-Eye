#!/bin/bash
# ================================================
# ARGUS-EYE - Global Progress Tracker
# ================================================

# Color codes (if not already defined)
if [[ -z "$RED" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    NC='\033[0m'
fi

PROGRESS_WIDTH=50
CURRENT_GLOBAL=0
TOTAL_GLOBAL=0

# Initialize global progress
init_global_progress() {
    TOTAL_GLOBAL=$1
    CURRENT_GLOBAL=0
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                 MASTER SCAN PROGRESS                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Update global progress bar
update_global_progress() {
    local message=$1
    CURRENT_GLOBAL=$((CURRENT_GLOBAL + 1))
    local percentage=$((CURRENT_GLOBAL * 100 / TOTAL_GLOBAL))
    local filled=$((percentage * PROGRESS_WIDTH / 100))
    local empty=$((PROGRESS_WIDTH - filled))
    
    printf "\r${YELLOW}Overall Progress: [${NC}"
    for ((i=0; i<filled; i++)); do printf "${GREEN}▓${NC}"; done
    for ((i=0; i<empty; i++)); do printf "${WHITE}░${NC}"; done
    printf "${YELLOW}] ${percentage}%% ${CYAN}($CURRENT_GLOBAL/$TOTAL_GLOBAL)${NC} ${message}"
}

# Complete global progress
complete_global_progress() {
    echo ""
    echo ""
    echo -e "${GREEN}✓ Master scan completed!${NC}"
}

# Export functions
export -f init_global_progress update_global_progress complete_global_progress
