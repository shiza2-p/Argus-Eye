# Argus-Eye

**Modular web vulnerability scanner for authorized security testing and bug bounty–style workflows.**

Argus-Eye orchestrates common open-source tools and custom probes (XSS, SQLi, LFI, and more), saves raw tool output, and is being refactored from a lab-oriented design into a **target-agnostic** framework.

> **Status:** Work in progress — core XSS / SQLi / LFI modules are generalized; other scanners still need the same cleanup. AI-assisted triage of raw results is planned.

---

## Features

| Area | Status |
|------|--------|
| Generic XSS module (dalfox, XSStrike, PwnXSS, custom tests) | Done |
| Generic SQLi module (sqlmap, nosqli, custom tests) | Done |
| Generic LFI / path traversal (ffuf, dotdotpwn, custom tests) | Done |
| Portable tool install under `./tools/` | Done |
| Consistent raw output for later analysis | Done |
| Cmd / SSRF / IDOR / RFI / XXE / directory modules | In progress (still partly lab-oriented) |
| AI integration (ranking / explaining findings) | Planned |

---

## Requirements

- Linux (Kali / Debian / Ubuntu recommended)
- `bash`, `curl`, `python3`, `git`
- Optional: Go (for some tool installs), network access to install dependencies

---

## Quick start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/argus-eye.git
cd argus-eye

# Install tools (project-local when possible)
bash install.sh
# or
bash modules/core/installer.sh

# Run main menu
bash argus-eye.sh
```

### Example: run a single scanner

```bash
# XSS
bash modules/scanners/xss_scanner.sh \
  "https://example.com/search?q=test" \
  ./results/xss_run \
  "dalfox XSStrike custom_tests"

# SQLi
bash modules/scanners/sqli_scanner.sh \
  "https://example.com/item?id=1" \
  ./results/sqli_run \
  "sqlmap custom_tests"

# LFI
bash modules/scanners/lfi_scanner.sh \
  "https://example.com/page?file=index" \
  ./results/lfi_run \
  "ffuf custom_tests"
```

Raw logs are written under the output directory’s `raw_output/` folder.

---

## Project layout

```text
argus-eye/
├── argus-eye.sh              # Main orchestrator
├── install.sh                # Entry installer
├── modules/
│   ├── core/                 # installer, target, tool selection, utils
│   ├── scanners/             # xss, sqli, lfi, cmd, ssrf, ...
│   └── reports/              # report generation
├── tools/                    # Third-party tools (not committed; installed locally)
├── results/                  # Scan output (gitignored)
└── logs/                     # Install/run logs (gitignored)
```

---

## Disclaimer

This project is intended **only** for:

- Systems you own
- Labs and intentionally vulnerable applications
- Targets you have **explicit written authorization** to test (e.g. bug bounty programs)

Unauthorized scanning may be illegal. You are solely responsible for how you use this software. The authors assume no liability for misuse or damage.

---

## Third-party tools

Argus-Eye invokes external projects (e.g. sqlmap, dalfox, XSStrike, PwnXSS, ffuf). Those tools keep their own licenses and copyrights. Install them via the built-in installer or according to each project’s documentation. Do not treat vendored copies as part of Argus-Eye’s original code.

---

## Roadmap

1. Finish generic refactor for remaining scanners (cmd, SSRF, IDOR, RFI, XXE, directory)
2. Stronger false-positive filtering and reporting
3. **AI integration** — interpret raw tool output, rank findings, reduce noise
4. Packaging and docs for easier public use

---

## Contributing

Issues and PRs are welcome once the repo is public. Please keep changes focused, avoid committing scan results or secrets, and only test against authorized targets.

---

## License

See [LICENSE](LICENSE) (MIT).
