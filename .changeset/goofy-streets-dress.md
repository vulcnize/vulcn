---
"@vulcn/plugin-report": minor
"vulcn": minor
---

### @vulcn/plugin-report — Canonical Report Model

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
