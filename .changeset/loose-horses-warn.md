---
"@vulcn/plugin-passive": minor
"@vulcn/plugin-report": minor
"vulcn": minor
"@vulcn/engine": minor
---

### @vulcn/plugin-report

- **SARIF v2.1.0 output** — new `generateSarif()` generator produces reports compatible with GitHub Code Scanning, Azure DevOps, and other SARIF-consuming tools
- Added `"sarif"` to the `format` config option (`html | json | yaml | sarif | all`)
- CWE mappings for all vulnerability types including passive scan categories
- CVSS-like security-severity scores for GitHub Security tab sorting
- Fingerprinting and deduplication for stable result tracking across runs

### @vulcn/plugin-passive

- **New plugin** — passive security scanner that analyzes HTTP responses during session replay without injecting payloads
- Detects missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) with value validation
- Detects insecure cookie configurations (missing Secure, HttpOnly, SameSite flags)
- Detects information disclosure (Server version, X-Powered-By, debug tokens)
- Detects CORS misconfigurations (wildcard origins, credentials with wildcards)
- Detects mixed content (HTTP resources on HTTPS pages)
- Automatic deduplication — each unique issue reported once per origin
- Configurable severity levels and per-check enable/disable toggles

### @vulcn/engine

- Added `"security-misconfiguration"` and `"information-disclosure"` to `PayloadCategory` type
- These new categories support passive scanner findings in reports and SARIF output

### vulcn (CLI)

- Added `--passive` flag to `vulcn run` to enable the passive security scanner
- Added `"sarif"` to the `--report` format option
- Auto-loads `@vulcn/plugin-passive` when `--passive` is specified
- Updated help text with passive scanning and SARIF examples
