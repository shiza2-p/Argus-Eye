#!/bin/bash
# ================================================
# ARGUS-EYE - Target Validation Module (Generic)
# Fully target-agnostic. No lab-specific logic.
# ================================================

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# ================================================
# VALIDATE AND NORMALISE TARGET URL
# Strips whitespace, adds protocol if missing,
# removes trailing slashes
# ================================================
validate_target() {
    local target=$1

    # Strip leading/trailing whitespace
    target=$(echo "$target" | xargs)

    # Empty target is not allowed in generic mode
    if [[ -z "$target" ]]; then
        echo -e "${RED}[!] No target provided${NC}" >&2
        return 1
    fi

    # Remove trailing slashes
    target=$(echo "$target" | sed 's:/*$::')

    # Add http:// if no protocol present
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi

    echo "$target"
}

# ================================================
# CHECK TARGET IS REACHABLE
# Uses a simple GET with short timeout
# ================================================
check_target_reachable() {
    local target=$1

    echo -e "${YELLOW}[*] Checking if target is reachable...${NC}"

    # Prefer HEAD, fall back to GET if server rejects HEAD
    if curl -s -o /dev/null -w "%{http_code}" --max-time 8 -L "$target" 2>/dev/null | grep -qE '^[2-4][0-9]{2}$'; then
        echo -e "${GREEN}[✓] Target is reachable: $target${NC}"
        return 0
    else
        echo -e "${RED}[!] Target is not reachable: $target${NC}"
        return 1
    fi
}

# ================================================
# SCOPE CHECK
# Always requires explicit confirmation for any
# non-local target. Local ranges are accepted
# with a note.
# ================================================
check_scope() {
    local target=$1
    local domain
    domain=$(echo "$target" | sed -E 's#^https?://([^/]+).*#\1#')

    # Local / private ranges – accepted with a note
    if [[ "$domain" =~ ^192\.168\. ]] || \
       [[ "$domain" =~ ^10\. ]] || \
       [[ "$domain" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
       [[ "$domain" == "localhost" ]] || \
       [[ "$domain" =~ ^127\. ]]; then
        echo -e "${GREEN}[✓] Local / private target accepted: $domain${NC}"
        return 0
    fi

    # Everything else requires explicit consent
    echo ""
    echo -e "${YELLOW}[!] Warning: $domain is an external target${NC}"
    echo -e "${YELLOW}[*] You must have explicit written permission to scan this target${NC}"
    echo -e "${YELLOW}[*] Unauthorized scanning is illegal in most jurisdictions${NC}"
    echo -ne "${YELLOW}[?] Do you have permission and want to continue? (y/N): ${NC}"
    read -r continue_anyway
    if [[ "$continue_anyway" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[✓] Scope accepted by user${NC}"
        return 0
    else
        echo -e "${RED}[!] Scope check failed – aborting${NC}"
        return 1
    fi
}

# ================================================
# DETECT TARGET TYPE
# Always returns "generic". Kept only for
# backward compatibility with older scanners.
# ================================================
detect_target_type() {
    echo "generic"
}

# ================================================
# SHOW TARGET SUMMARY BOX
# ================================================
show_target_summary() {
    local target=$1

    WIDTH=63

    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                         TARGET SUMMARY                                   │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${CYAN}│  ${YELLOW}URL   ${CYAN}: ${GREEN}%-${WIDTH}.${WIDTH}s${CYAN} │${NC}\n" "$target"
    printf "${CYAN}│  ${YELLOW}Mode  ${CYAN}: ${GREEN}%-${WIDTH}.${WIDTH}s${CYAN} │${NC}\n" "Generic (no lab assumptions)"
    printf "${CYAN}│  ${YELLOW}Scope ${CYAN}: ${GREEN}%-${WIDTH}.${WIDTH}s${CYAN} │${NC}\n" "Verified by user"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
}

# ================================================
# MAIN: INTERACTIVE TARGET SETUP
# ================================================
setup_target() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                       TARGET CONFIGURATION                               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}│  Enter any URL you have permission to test.                              │${NC}"
    echo -e "${CYAN}│  Examples:                                                               │${NC}"
    echo -e "${CYAN}│    https://example.com                                                   │${NC}"
    echo -e "${CYAN}│    http://192.168.1.50:8080                                              │${NC}"
    echo -e "${CYAN}│    https://target.tld/app                                                │${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${YELLOW}[?] Enter target URL: ${NC}"
    read -r raw_target

    # Validate and normalise
    TARGET_URL=$(validate_target "$raw_target")
    if [[ $? -ne 0 || -z "$TARGET_URL" ]]; then
        echo -e "${RED}[!] Invalid target. Exiting.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Target set to: $TARGET_URL${NC}"
    echo ""

    # Reachability check — retry once on failure
    if ! check_target_reachable "$TARGET_URL"; then
        echo -ne "${YELLOW}[?] Target unreachable — try a different URL? (y/N): ${NC}"
        read -r retry
        if [[ "$retry" =~ ^[Yy]$ ]]; then
            setup_target
            return
        else
            echo -e "${RED}[!] Cannot proceed with unreachable target. Exiting.${NC}"
            exit 1
        fi
    fi

    # Scope check
    if ! check_scope "$TARGET_URL"; then
        echo -e "${RED}[!] Scope check failed. Exiting.${NC}"
        exit 1
    fi

    # Show summary and export
    show_target_summary "$TARGET_URL"
    echo -e "${GREEN}[✓] Target validation complete${NC}"
    echo ""

    export TARGET_URL
    export TARGET_TYPE="generic"
}

# ================================================
# EXPORTS
# ================================================
export -f validate_target check_target_reachable check_scope detect_target_type show_target_summary setup_target
