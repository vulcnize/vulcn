---
"vulcn": patch
"@vulcn/engine": patch
---

Migrate `vulcn crawl` to v2 session directory format and add benchmark pipeline.

- **`vulcn crawl`**: Now uses `saveSessionDir()` to output v2 session directories (`manifest.yml` + `sessions/` + `auth/`) instead of individual `.vulcn.yml` files. `vulcn run <dir>` loads these directly via `loadSessionDir()`.
- **Benchmark runner** (`benchmarks/run.ts`): Automated pipeline that crawls + scans 5 benchmark targets (Acunetix test sites + DVWA + WebGoat), scores findings against ground truth (TPR/FPR/Youden), and publishes results to vulcn.dev.
- **Benchmark CI** (`.github/workflows/benchmark.yml`): GitHub Action triggered on release — spins up DVWA, runs benchmarks, uploads artifacts, and comments scorecard on the release.
- **www**: Added `POST /api/benchmarks` endpoint (API_SECRET auth) to receive benchmark results from CI, and `GET /api/benchmarks` for the upcoming `/benchmarks` page. New `BenchmarkRun` + `BenchmarkTarget` Prisma models.
