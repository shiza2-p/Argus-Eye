#!/bin/bash

source "$(dirname "$0")/../core/utils.sh"
source "$(dirname "$0")/../core/output.sh"

# Helper: escape HTML (only &, <, >)
html_escape() {
    echo "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

generate_report() {
    local output=$1 target=$2 vuln=$3
    mkdir -p "$output/reports"
    local report_file="$output/reports/scan_report.html"

    # Find findings file
    local findings_file
    findings_file=$(find "$output/findings" -maxdepth 1 -iname "*findings*.txt" 2>/dev/null | head -1)

    # Severity mapping
    get_severity() {
        case "$1" in
            XSS|SQLi|CMD_INJECTION|RFI|XXE) echo "High" ;;
            LFI|SSRF|DIR_TRAVERSAL) echo "Medium" ;;
            IDOR) echo "Low" ;;
            *) echo "Info" ;;
        esac
    }

    local severity
    severity=$(get_severity "$vuln")
    local severity_class
    severity_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]')

    # ===== Findings HTML (UPDATED to include SQLi and NoSQLi) =====
    local findings_html=""
    local findings_count=0

    if [[ -n "$findings_file" && -s "$findings_file" ]]; then
        while IFS= read -r line; do
            clean_line=$(echo "$line" | sed -E 's/\x1b\[[0-9;]*m//g')
            clean_line=$(echo "$clean_line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -z "$clean_line" ]] && continue

            # Match lines that indicate a finding:
            # - dalfox: lines starting with [POC]
            # - XSStrike: lines starting with [+] (payload lines)
            # - custom_tests and others: lines containing "XSS Found", "SQLi Found", or "NoSQLi Found" (case‑insensitive)
            if [[ "$clean_line" =~ ^\[POC\] ]] || \
               [[ "$clean_line" =~ ^\[[+!]\] ]] || \
               [[ "$clean_line" =~ [Xx][Ss][Ss][[:space:]]*[Ff]ound ]] || \
               [[ "$clean_line" =~ [Ss][Qq][Ll][Ii][[:space:]]*[Ff]ound ]] || \
               [[ "$clean_line" =~ [Nn][Oo][Ss][Qq][Ll][Ii][[:space:]]*[Ff]ound ]]; then
                findings_html+="
                <div class='finding-item'>
                    <span class='vuln-badge'>$vuln</span>
                    <span class='vuln-url'>$(html_escape "$clean_line")</span>
                </div>"
                findings_count=$((findings_count + 1))
            fi
        done < "$findings_file"
    fi

    if [[ -z "$findings_html" ]]; then
        # Fallback: if no findings lines, show raw file content (if exists)
        if [[ -n "$findings_file" && -s "$findings_file" ]]; then
            raw_content=$(cat "$findings_file" | sed -E 's/\x1b\[[0-9;]*m//g' | html_escape)
            findings_html="<div class='finding-item'><pre>$raw_content</pre></div>"
        else
            findings_html="<div class='finding-item none'>No vulnerabilities detected.</div>"
        fi
    fi

    # ===== Raw Output HTML =====
    local raw_html=""
    for file in "$output/raw_output/"*; do
        if [[ -f "$file" ]]; then
            filename=$(basename "$file")
            raw_content=$(LC_ALL=C cat "$file" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g')
            if [[ -z "$raw_content" ]]; then
                raw_content=$(LC_ALL=C od -An -v -tx1 "$file" | tr -d '\n' | sed 's/  / /g')
            fi
            raw_content=$(echo "$raw_content" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
            raw_html+="
            <h3 style='color:#facc15; margin-top:1.5rem;'>$filename</h3>
            <pre class='raw-pre'>$raw_content</pre>
            <p><a href='../raw_output/$filename' target='_blank'>📄 View full output</a></p>"
        fi
    done

    # ===== HTML Template (unchanged) =====
    cat > "$report_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARGUS-EYE Security Report</title>
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f7fb;
    color: #0f172a;
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2.5rem 2rem;
}

/* HEADER */
.report-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    padding: 2.5rem;
    border-radius: 1.6rem;
    margin-bottom: 2.2rem;
    color: white;
    box-shadow: 0 18px 35px rgba(15, 23, 42, 0.18);
    text-align: center;
}

.report-header h1 {
    font-size: 2.4rem;
    font-weight: 600;
    color: #38bdf8;
}

.report-header .target {
    font-size: 1.05rem;
    opacity: 0.9;
    margin-top: 0.4rem;
}

/* DASHBOARD GRID (CENTERED) */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.4rem;
    margin-bottom: 2.4rem;
    justify-items: center;
}

/* STAT CARDS */
.stat-card {
    background: white;
    border-radius: 1.4rem;
    padding: 1.6rem;
    width: 100%;
    max-width: 280px;
    text-align: center;
    border: 1px solid #e2e8f0;
    box-shadow: 0 10px 22px rgba(15, 23, 42, 0.05);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.stat-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08);
}

.stat-card .icon {
    font-size: 1.4rem;
    margin-bottom: 0.4rem;
    color: #38bdf8;
}

.stat-card .label {
    font-size: 0.8rem;
    text-transform: uppercase;
    color: #64748b;
    letter-spacing: 0.04em;
}

.stat-card .value {
    font-size: 1rem;
    font-weight: 650;
    margin-top: 0.3rem;
    color: #0f172a;
}

/* SEVERITY COLOR STATES */
.stat-card.severity-high {
    border-left: 6px solid #ef4444;
}

.stat-card.severity-high .value {
    color: #ef4444;
}

.stat-card.severity-medium {
    border-left: 6px solid #f97316;
}

.stat-card.severity-medium .value {
    color: #f97316;
}

.stat-card.severity-low {
    border-left: 6px solid #22c55e;
}

.stat-card.severity-low .value {
    color: #22c55e;
}

.stat-card.severity-info {
    border-left: 6px solid #38bdf8;
}

.stat-card.severity-info .value {
    color: #38bdf8;
}

/* SECTIONS */
.section-card {
    background: white;
    border-radius: 1.5rem;
    padding: 1.9rem;
    margin-bottom: 2rem;
    border: 1px solid #e2e8f0;
    box-shadow: 0 10px 22px rgba(15, 23, 42, 0.05);
}

.section-title {
    font-size: 1.45rem;
    font-weight: 600;
    margin-bottom: 1.2rem;
    color: #0f172a;
}

/* FINDINGS */
.findings-list {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
}

.finding-item {
    background: #f1f5f9;
    padding: 1.1rem 1.3rem;
    border-radius: 1rem;
    border-left: 5px solid #ef4444;
    display: flex;
    gap: 1rem;
    word-break: break-word;
}

.finding-item.none {
    border-left-color: #94a3b8;
    color: #64748b;
    font-style: italic;
}

.stat-card .value,
.report-header .target {
    word-break: break-word;
    overflow-wrap: anywhere;
    white-space: normal;
}

.vuln-badge {
    background: #ef4444;
    color: white;
    font-weight: 600;
    font-size: 0.72rem;
    padding: 0.25rem 0.7rem;
    border-radius: 1.4rem;
    text-transform: uppercase;
}

.vuln-url {
    font-family: 'Fira Code', monospace;
    font-size: 0.9rem;
    flex: 1;
}

/* RAW OUTPUT */
.raw-pre {
    background: #0f172a;
    color: #22c55e;
    padding: 1rem;
    border-radius: 0.8rem;
    overflow: auto;
    white-space: pre-wrap;
}

/* FOOTER */
.report-footer {
    text-align: center;
    color: #64748b;
    font-size: 0.9rem;
    margin-top: 3rem;
}
</style>
</head>
<body>
<div class="container">
    <div class="report-header">
        <h1>🔎 ARGUS-EYE Security Report</h1>
        <div class="target">$target</div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="icon">📅</div>
            <div class="label">Scan Date</div>
            <div class="value">$(date +"%Y-%m-%d %H:%M")</div>
        </div>

        <div class="stat-card">
            <div class="icon">⚠️</div>
            <div class="label">Findings</div>
            <div class="value">$findings_count</div>
        </div>

        <div class="stat-card severity-$severity_class">
            <div class="icon">🔒</div>
            <div class="label">Severity</div>
            <div class="value">$severity</div>
        </div>

        <div class="stat-card">
            <div class="icon">🎯</div>
            <div class="label">Target</div>
            <div class="value">$target</div>
        </div>
    </div>

    <div class="section-card">
        <h2 class="section-title">Findings</h2>
        <div class="findings-list">$findings_html</div>
    </div>

    <div class="section-card">
        <h2 class="section-title">Raw Tool Outputs</h2>
        $raw_html
    </div>

    <div class="report-footer">Generated by ARGUS-EYE v1.0 on $(date)</div>
</div>
</body>
</html>
EOF

    echo -e "${GREEN}[✓] Professional HTML report generated: $report_file${NC}"
}
