#!/bin/bash
# ================================================
# ARGUS-EYE - Output Management Module (Improved)
# ================================================

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

create_output_directory() {
    local target=$1
    local vuln=$2

    # Validate input
    if [[ -z "$target" || -z "$vuln" ]]; then
        echo -e "${RED}[!] Target or vulnerability not provided${NC}" >&2
        return 1
    fi

    # Timestamp for scan
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    # Sanitize target safely (remove protocol + unsafe chars)
    local clean_target
    clean_target=$(echo "$target" | \
        sed -E 's#https?://##' | \
        sed -E 's#[^a-zA-Z0-9._-]#_#g')

    # Structured directory layout
    # results/
    #   └── example.com/
    #         └── 20260227_204207/
    local base_dir="results/$clean_target/$timestamp"

    # Create directory tree
    mkdir -p "$base_dir"/{raw_output,screenshots,reports,findings} || {
        echo -e "${RED}[!] Failed to create output directory${NC}" >&2
        return 1
    }

    echo -e "${GREEN}[✓] Output directory created:${NC} $base_dir" >&2

    # Generate unique Scan ID
    local scan_id="${clean_target}_${timestamp}"

    # Create detailed scan info file
    cat > "$base_dir/scan_info.txt" << EOF
=================================================
              ARGUS-EYE SCAN INFORMATION
=================================================

Scan ID:        $scan_id
Date:           $(date)
Target:         $target
Vulnerability:  $vuln
Host Machine:   $(hostname)
User:           $(whoami)
OS:             $(uname -s) $(uname -r)
Tool Version:   1.0
Status:         Started

Directory Structure:
 - raw_output/     → Tool raw outputs
 - findings/       → Parsed vulnerability results
 - screenshots/    → Captured screenshots
 - reports/        → HTML reports

=================================================
EOF

    # Return directory path to main script
    echo "$base_dir"
}
