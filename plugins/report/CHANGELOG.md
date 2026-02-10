# @vulcn/plugin-report

## 0.6.3

### Patch Changes

- 800f9db: Fix multi-session report aggregation and CLI exit code behavior.
  - **`@vulcn/plugin-report`**: Added `onScanEnd` hook for aggregate report generation. Multi-session scans (`vulcn run <session-dir>`) now produce a single report containing all findings instead of overwriting per-session. Per-session `onRunEnd` reports are skipped during scans; single-session runs are unaffected. Extracted `writeReports()` helper shared by both hooks.
  - **`vulcn` CLI**: `vulcn run` now exits with code `0` on successful completion regardless of whether findings were detected. Exit code indicates tool success, not vulnerability presence — consistent with standard security tooling (OWASP ZAP, Nuclei, etc.).
  - **Benchmark runner**: Fixed report path to read from `<dir>/vulcn-report.json` (matching plugin output). Bumped per-command timeout from 2min to 5min for CI. Added `VULCN_KEY` env default for non-interactive credential encryption.

## 0.6.2

### Patch Changes

- Updated dependencies [5011ca5]
  - @vulcn/engine@0.9.0

## 0.6.1

### Patch Changes

- Updated dependencies [15d8504]
  - @vulcn/engine@0.8.0

## 0.6.0

### Patch Changes

- Updated dependencies [458572e]
  - @vulcn/engine@0.7.0

## 0.5.0

### Minor Changes

- 78339ad: ### @vulcn/plugin-report — Canonical Report Model

  Introduced `VulcnReport` — a unified data model from which all output formats (HTML, JSON, YAML, SARIF) are derived. This eliminates duplicate logic across generators and establishes a single source of truth for CWE mappings, severity scoring, risk assessment, fingerprinting, and passive analysis categorization.

  **New: `buildReport()` function**
  - Transforms raw `RunResult + Session` into the canonical `VulcnReport` model
  - Enriches every finding with CWE entry, CVSS-like security severity score, stable fingerprint, and detection classification (active vs passive)
  - Computes risk assessment, severity counts, and passive analysis summary in one pass
  - All output formats are now pure projections of this model

  **New: `VulcnReport` type (exported)**
  - `reportVersion`, `engineVersion`, `generatedAt` — report metadata
  - `session` — session context (name, driver, config, step count)
  - `stats` — execution statistics (steps, payloads, duration, errors)
  - `summary` — aggregated overview (total findings, severity counts, risk assessment, affected URLs)
  - `rules` — one rule per unique finding type, with CWE and severity data
  - `findings` / `activeFindings` — enriched findings with CWE, fingerprints, classification
  - `passiveAnalysis` — structured passive check results grouped by category

  **Refactored generators (breaking internal API, public output unchanged)**
  - `generateHtml(report)` — consumes `VulcnReport` directly; removed ~120 lines of duplicate severity/risk/passive logic; `HtmlReportData` type removed
  - `generateJson(report)` — now includes passive analysis summary, rules, and enriched findings in JSON output
  - `generateYaml(report)` — delegates to JSON generator as before
  - `generateSarif(report)` — CWE mappings and fingerprints now come from enriched findings; SARIF is a pure projection

  **Centralized registries**
  - `CWE_MAP` — single source for all vulnerability type → CWE ID mappings (was duplicated in sarif.ts)
  - `PASSIVE_CATEGORIES` — single source for passive check definitions, remediation guidance, and check lists (was duplicated in html.ts)
  - `SECURITY_SEVERITY` — CVSS-like scores per severity level (was duplicated in sarif.ts)

  ### vulcn (CLI)
  - Passive scanning now enabled by default (`--passive` flag defaults to `true`)
  - Added `--no-passive` flag to explicitly disable passive scanning
  - Report generation uses the canonical `VulcnReport` model internally

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
