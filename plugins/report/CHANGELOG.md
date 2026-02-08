# @vulcn/plugin-report

## 0.4.0

### Minor Changes

- 56eb043: ### @vulcn/plugin-report
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

### Patch Changes

- Updated dependencies [56eb043]
  - @vulcn/engine@0.5.0

## 0.2.0

### Patch Changes

- Updated dependencies [d4fd4df]
  - @vulcn/engine@0.4.0

## 0.1.1

### Patch Changes

- c62a3dc: ### `@vulcn/plugin-report` — New Package

  Introducing the **Report Generation Plugin** — generate professional security reports at the end of every `vulcn run`.
  - **HTML**: Modern dark-themed dashboard with risk gauge, severity breakdown bars, expandable finding cards, Vulcn branding, Inter + JetBrains Mono typography, and print-friendly CSS
  - **JSON**: Machine-readable structured output for CI/CD pipelines — includes severity counts, risk score, vuln types, affected URLs
  - **YAML**: Human-readable YAML with descriptive header comment — same data model as JSON
  - Uses the `onRunEnd` plugin hook to intercept results after execution completes
  - Exports `generateHtml`, `generateJson`, `generateYaml` for programmatic use

  ### `@vulcn/engine`
  - **Plugin lifecycle hooks**: `DriverManager.execute()` now invokes `onRunStart` and `onRunEnd` plugin hooks around the driver runner, enabling plugins like the report generator to intercept and process results
  - Removed legacy `Runner` and `Recorder` exports — all execution now goes through `DriverManager`
  - Updated package description and SEO keywords for npm discoverability

  ### `vulcn` (CLI)
  - Added `--report <format>` flag (`html`, `json`, `yaml`, `all`) to generate security reports after test runs
  - Added `--report-output <dir>` flag to specify output directory for generated reports
  - Report plugin is auto-loaded when `--report` flag is used
  - Updated package description and SEO keywords — positioned as a modern, fast alternative to legacy security scanners

  ### `@vulcn/driver-browser`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-payloads`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-detect-xss`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-detect-reflection`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability
