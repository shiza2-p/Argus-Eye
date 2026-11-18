#!/bin/bash
# ================================================
# ARGUS-EYE - Core Utilities
# ================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Export colors
export RED GREEN YELLOW BLUE PURPLE CYAN WHITE NC

# Get script directory
if [[ -z "$SCRIPT_DIR" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export SCRIPT_DIR
fi

# Set directories
RESULTS_DIR="$SCRIPT_DIR/results"
LOGS_DIR="$SCRIPT_DIR/logs"
TOOLS_DIR="$SCRIPT_DIR/tools"
CONFIG_DIR="$SCRIPT_DIR/config"
PAYLOADS_DIR="$SCRIPT_DIR/payloads"

# Create directories if they don't exist
mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$TOOLS_DIR" "$CONFIG_DIR" "$PAYLOADS_DIR" 2>/dev/null

# Logging function
log() {
    local level=$1
    local message=$2
    local log_file="${LOGS_DIR}/argus-eye-$(date +%Y%m%d).log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$log_file"
}

# Error handler
error_exit() {
    echo -e "${RED}[!] $1${NC}"
    log "ERROR" "$1"
    exit 1
}
# Debug function (optional)
debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${CYAN}[DEBUG] $1${NC}"
    fi
}

export -f debug
# Export functions
export -f log error_exit
