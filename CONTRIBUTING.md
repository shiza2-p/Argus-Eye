# Contributing to Argus-Eye

Thanks for your interest.

## Guidelines

- Only test against systems you are authorized to assess.
- Do not commit scan results, cookies, API keys, or personal data.
- Prefer small, focused pull requests.
- Match existing style in shell modules under `modules/`.
- New scanner work should stay **target-agnostic** (no hardcoding for specific labs).

## Development notes

- Generalized modules today: `xss_scanner.sh`, `sqli_scanner.sh`, `lfi_scanner.sh`.
- Other scanners may still contain lab-specific logic; refactors toward the same generic pattern are welcome.
