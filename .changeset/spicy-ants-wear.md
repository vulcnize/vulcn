---
"@vulcn/plugin-report": patch
"vulcn": patch
"@vulcn/engine": patch
---

Fix multi-session report aggregation and CLI exit code behavior.

- **`@vulcn/plugin-report`**: Added `onScanEnd` hook for aggregate report generation. Multi-session scans (`vulcn run <session-dir>`) now produce a single report containing all findings instead of overwriting per-session. Per-session `onRunEnd` reports are skipped during scans; single-session runs are unaffected. Extracted `writeReports()` helper shared by both hooks.
- **`vulcn` CLI**: `vulcn run` now exits with code `0` on successful completion regardless of whether findings were detected. Exit code indicates tool success, not vulnerability presence — consistent with standard security tooling (OWASP ZAP, Nuclei, etc.).
- **Benchmark runner**: Fixed report path to read from `<dir>/vulcn-report.json` (matching plugin output). Bumped per-command timeout from 2min to 5min for CI. Added `VULCN_KEY` env default for non-interactive credential encryption.
