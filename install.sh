#!/bin/bash
# ================================================
# ARGUS-EYE - Main Installer Script
# Run this to install all required tools
# ================================================

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Clear screen
clear

# Display banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              ARGUS-EYE TOOL INSTALLER                        ║"
echo "║                    Version 1.0                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Check if installer module exists
if [[ ! -f "$SCRIPT_DIR/modules/core/installer.sh" ]]; then
    echo -e "${RED}[!] ERROR: Installer module not found!${NC}"
    echo -e "${YELLOW}[*] Expected at: $SCRIPT_DIR/modules/core/installer.sh${NC}"
    exit 1
fi

# Source the installer module
echo -e "${YELLOW}[*] Loading installer module...${NC}"
source "$SCRIPT_DIR/modules/core/installer.sh"

# Check if sourcing was successful
if [[ $? -ne 0 ]]; then
    echo -e "${RED}[!] Failed to load installer module${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Installer module loaded successfully${NC}"
echo ""

# Start interactive installer
interactive_install
