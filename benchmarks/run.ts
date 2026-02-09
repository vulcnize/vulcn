#!/usr/bin/env tsx

/**
 * Vulcn Benchmark Runner
 *
 * Runs Vulcn against each target in ground-truth.json, scores the results,
 * and optionally publishes them to vulcn.dev/api/benchmarks.
 *
 * Usage:
 *   pnpm tsx benchmarks/run.ts                       # Run all targets
 *   pnpm tsx benchmarks/run.ts --skip-docker          # Skip DVWA/WebGoat (remote only)
 *   pnpm tsx benchmarks/run.ts --publish              # Run + publish to vulcn.dev
 *   pnpm tsx benchmarks/run.ts --publish --dry-run    # Score without publishing
 */

import { execSync, type ExecSyncOptions } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ── Paths ──────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, "..");
const GROUND_TRUTH_PATH = resolve(__dirname, "ground-truth.json");
const RESULTS_DIR = resolve(__dirname, "results");

// ── Types ──────────────────────────────────────────────────────────────

interface GroundTruthVuln {
  type: string;
  url: string;
  field: string;
  method: string;
  description: string;
}

interface GroundTruthTarget {
  name: string;
  url: string;
  authRequired: boolean;
  credentials?: { username: string; password: string; loginUrl: string };
  vulns: GroundTruthVuln[];
}

interface Finding {
  type: string;
  url: string;
  payload: string;
  severity: string;
  title: string;
  metadata?: Record<string, unknown>;
}

interface TargetResult {
  name: string;
  url: string;
  authRequired: boolean;
  knownVulns: number;
  detected: number;
  missed: number;
  falsePositives: number;
  tpr: number;
  fpr: number;
  score: number;
  duration: number;
  findings: Finding[];
  details: {
    formsCrawled?: number;
    pagesCrawled?: number;
    payloadsTested?: number;
    error?: string;
  };
}

interface BenchmarkPayload {
  version: string;
  commitSha?: string;
  duration: number;
  score: number;
  tpr: number;
  fpr: number;
  summary: {
    totalKnown: number;
    detected: number;
    falsePositives: number;
    missed: number;
    targetsRun: number;
    targetsSkipped: number;
  };
  targets: TargetResult[];
}

// ── CLI Args ───────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const SKIP_DOCKER = args.includes("--skip-docker");
const PUBLISH = args.includes("--publish");
const DRY_RUN = args.includes("--dry-run");

// ── Main ───────────────────────────────────────────────────────────────

async function main() {
  console.log("🏁 Vulcn Benchmark Runner\n");

  // Load ground truth
  const groundTruth: { targets: GroundTruthTarget[] } = JSON.parse(
    readFileSync(GROUND_TRUTH_PATH, "utf-8"),
  );

  // Get version from package.json
  const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf-8"));
  const version: string = pkg.version;
  const commitSha = getCommitSha();

  console.log(`📦 Version: ${version}`);
  console.log(`🔗 Commit: ${commitSha ?? "unknown"}`);
  console.log(`📋 Targets: ${groundTruth.targets.length}`);
  console.log(`⏭  Skip Docker: ${SKIP_DOCKER}`);
  console.log("");

  // Ensure results directory exists
  mkdirSync(RESULTS_DIR, { recursive: true });

  const totalStart = Date.now();
  const targetResults: TargetResult[] = [];
  let targetsSkipped = 0;

  for (const target of groundTruth.targets) {
    // Skip Docker-based targets if requested
    if (SKIP_DOCKER && target.authRequired) {
      console.log(`⏭  Skipping ${target.name} (requires Docker)`);
      targetsSkipped++;
      continue;
    }

    // Check if target is reachable
    if (!(await isReachable(target.url))) {
      console.log(
        `⚠️  ${target.name} is unreachable at ${target.url}, skipping`,
      );
      targetsSkipped++;
      continue;
    }

    console.log(`\n${"─".repeat(60)}`);
    console.log(`🎯 ${target.name} (${target.url})`);
    console.log(`   Known vulns: ${target.vulns.length}`);
    console.log(`${"─".repeat(60)}\n`);

    const result = await runTarget(target);
    targetResults.push(result);

    console.log(`   ✅ TPR: ${(result.tpr * 100).toFixed(1)}%`);
    console.log(`   ❌ FPR: ${(result.fpr * 100).toFixed(1)}%`);
    console.log(`   📊 Youden: ${result.score.toFixed(3)}`);
    console.log(`   ⏱  ${(result.duration / 1000).toFixed(1)}s`);
  }

  const totalDuration = Date.now() - totalStart;

  // Aggregate scores
  const aggResult = aggregate(targetResults);

  // Build payload
  const payload: BenchmarkPayload = {
    version,
    commitSha: commitSha ?? undefined,
    duration: totalDuration,
    score: aggResult.score,
    tpr: aggResult.tpr,
    fpr: aggResult.fpr,
    summary: {
      totalKnown: aggResult.totalKnown,
      detected: aggResult.detected,
      falsePositives: aggResult.falsePositives,
      missed: aggResult.missed,
      targetsRun: targetResults.length,
      targetsSkipped,
    },
    targets: targetResults,
  };

  // Save results locally
  const outPath = resolve(RESULTS_DIR, `${version}.json`);
  writeFileSync(outPath, JSON.stringify(payload, null, 2));
  console.log(`\n💾 Results saved to ${outPath}`);

  // Print summary
  console.log(`\n${"═".repeat(60)}`);
  console.log(`📊 BENCHMARK SUMMARY — Vulcn v${version}`);
  console.log(`${"═".repeat(60)}`);
  console.log(`   Targets run:     ${targetResults.length}`);
  console.log(`   Targets skipped: ${targetsSkipped}`);
  console.log(`   Known vulns:     ${aggResult.totalKnown}`);
  console.log(`   Detected (TP):   ${aggResult.detected}`);
  console.log(`   Missed (FN):     ${aggResult.missed}`);
  console.log(`   False pos (FP):  ${aggResult.falsePositives}`);
  console.log(`   TPR:             ${(aggResult.tpr * 100).toFixed(1)}%`);
  console.log(`   FPR:             ${(aggResult.fpr * 100).toFixed(1)}%`);
  console.log(`   Youden Score:    ${aggResult.score.toFixed(3)}`);
  console.log(`   Duration:        ${(totalDuration / 1000).toFixed(1)}s`);
  console.log(`${"═".repeat(60)}\n`);

  // Publish if requested
  if (PUBLISH && !DRY_RUN) {
    await publish(payload);
  } else if (PUBLISH && DRY_RUN) {
    console.log("🏜  Dry run — not publishing to vulcn.dev");
  }

  // Exit with non-zero if score is below threshold
  // (but only warn — still publish the results above)
  if (aggResult.score < 0.5) {
    console.log("⚠️  Benchmark score below 0.5 threshold");
    // Don't exit 1 — let CI publish results even with low scores
  }
}

// ── Target Runner ──────────────────────────────────────────────────────

async function runTarget(target: GroundTruthTarget): Promise<TargetResult> {
  const start = Date.now();
  const sessionDir = resolve(
    RESULTS_DIR,
    `sessions-${target.name.replace(/\./g, "_")}`,
  );

  mkdirSync(sessionDir, { recursive: true });

  try {
    // Step 1: Crawl the target
    console.log("   📡 Crawling...");
    const crawlArgs = [
      "crawl",
      target.url,
      "--depth",
      "2",
      "--max-pages",
      "30",
      "--output",
      sessionDir,
      "--headless",
    ];

    // Add auth for Docker targets
    if (target.authRequired && target.credentials) {
      // Store creds first
      const credsPath = resolve(sessionDir, "auth.enc");
      // Login URL must be absolute
      const loginUrl = target.credentials.loginUrl.startsWith("http")
        ? target.credentials.loginUrl
        : `${target.url}${target.credentials.loginUrl}`;
      vulcnExec([
        "store",
        target.credentials.username,
        target.credentials.password,
        "--login-url",
        loginUrl,
        "--output",
        credsPath,
      ]);
      crawlArgs.push("--creds", credsPath);
    }

    vulcnExec(crawlArgs);

    // Step 2: Run scan with payloads
    console.log("   🔍 Scanning...");
    const reportPath = resolve(sessionDir, "report.json");

    vulcnExec([
      "run",
      sessionDir,
      "-p",
      "xss,sqli",
      "-r",
      "json",
      "--report-output",
      reportPath,
      "--headless",
    ]);

    // Step 3: Read findings
    let findings: Finding[] = [];
    try {
      const report = JSON.parse(readFileSync(reportPath, "utf-8"));
      findings = report.findings ?? report.results?.findings ?? [];
    } catch {
      console.log("   ⚠️  Could not parse report, assuming no findings");
    }

    // Step 4: Score against ground truth
    return scoreTarget(target, findings, Date.now() - start);
  } catch (error) {
    console.log(
      `   ❌ Error: ${error instanceof Error ? error.message : error}`,
    );
    return {
      name: target.name,
      url: target.url,
      authRequired: target.authRequired,
      knownVulns: target.vulns.length,
      detected: 0,
      missed: target.vulns.length,
      falsePositives: 0,
      tpr: 0,
      fpr: 0,
      score: 0,
      duration: Date.now() - start,
      findings: [],
      details: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

// ── Scoring ────────────────────────────────────────────────────────────

function scoreTarget(
  target: GroundTruthTarget,
  findings: Finding[],
  duration: number,
): TargetResult {
  // Match findings to known vulns
  let detected = 0;
  const matchedVulns = new Set<number>();

  for (const finding of findings) {
    let matched = false;
    for (let i = 0; i < target.vulns.length; i++) {
      if (matchedVulns.has(i)) continue;
      if (isMatch(finding, target.vulns[i], target.url)) {
        matchedVulns.add(i);
        detected++;
        matched = true;
        break;
      }
    }
    // If finding doesn't match any known vuln, it's a false positive
    if (!matched) {
      // Don't count info-level as false positives
      if (finding.severity !== "info") {
        // Will be counted below
      }
    }
  }

  const missed = target.vulns.length - detected;
  const falsePositives = findings.filter((f) => {
    if (f.severity === "info") return false;
    return !target.vulns.some((v) => isMatch(f, v, target.url));
  }).length;

  const totalAlerts = findings.filter((f) => f.severity !== "info").length;
  const tpr = target.vulns.length > 0 ? detected / target.vulns.length : 0;
  const fpr = totalAlerts > 0 ? falsePositives / totalAlerts : 0;
  const score = Math.max(0, tpr - fpr); // Youden's J statistic

  return {
    name: target.name,
    url: target.url,
    authRequired: target.authRequired,
    knownVulns: target.vulns.length,
    detected,
    missed,
    falsePositives,
    tpr,
    fpr,
    score,
    duration,
    findings,
    details: {},
  };
}

/**
 * Check if a finding matches a known vulnerability.
 * Fuzzy match on type + URL path.
 */
function isMatch(
  finding: Finding,
  vuln: GroundTruthVuln,
  targetBaseUrl: string,
): boolean {
  // Type must match
  if (finding.type !== vuln.type) return false;

  // URL must contain the vuln's path
  const findingPath = finding.url.replace(targetBaseUrl, "");
  const vulnPath = vuln.url;

  // Fuzzy URL match — the finding URL should contain the vuln's path
  return (
    findingPath.includes(vulnPath) ||
    finding.url.includes(vulnPath) ||
    vulnPath.includes(findingPath)
  );
}

function aggregate(results: TargetResult[]) {
  if (results.length === 0) {
    return {
      totalKnown: 0,
      detected: 0,
      missed: 0,
      falsePositives: 0,
      tpr: 0,
      fpr: 0,
      score: 0,
    };
  }

  const totalKnown = results.reduce((s, r) => s + r.knownVulns, 0);
  const detected = results.reduce((s, r) => s + r.detected, 0);
  const missed = results.reduce((s, r) => s + r.missed, 0);
  const falsePositives = results.reduce((s, r) => s + r.falsePositives, 0);

  const tpr = totalKnown > 0 ? detected / totalKnown : 0;
  const totalAlerts = detected + falsePositives;
  const fpr = totalAlerts > 0 ? falsePositives / totalAlerts : 0;
  const score = Math.max(0, tpr - fpr);

  return { totalKnown, detected, missed, falsePositives, tpr, fpr, score };
}

// ── Helpers ────────────────────────────────────────────────────────────

function vulcnExec(args: string[]) {
  const cmd = `node ${resolve(ROOT, "cli/dist/index.js")} ${args.join(" ")}`;
  const opts: ExecSyncOptions = {
    cwd: ROOT,
    stdio: "pipe",
    timeout: 120_000, // 2 min per command
    env: {
      ...process.env,
      FORCE_COLOR: "0",
      VULCN_KEY: process.env.VULCN_KEY ?? "benchmark",
    },
  };

  try {
    const result = execSync(cmd, opts);
    return result.toString();
  } catch (error: unknown) {
    // Show full stderr for debugging
    const err = error as { stderr?: Buffer; stdout?: Buffer; message?: string };
    const stderr = err.stderr?.toString().trim() ?? "";
    const stdout = err.stdout?.toString().trim() ?? "";
    const output = stderr || stdout || err.message || String(error);
    throw new Error(`vulcn ${args[0]} failed: ${output}`);
  }
}

function getCommitSha(): string | null {
  try {
    return execSync("git rev-parse HEAD", {
      cwd: ROOT,
      encoding: "utf-8",
    }).trim();
  } catch {
    return null;
  }
}

async function isReachable(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timer);
    return res.ok || res.status < 500;
  } catch {
    return false;
  }
}

async function publish(payload: BenchmarkPayload) {
  const apiUrl =
    process.env.BENCHMARK_API_URL ?? "https://vulcn.dev/api/benchmarks";
  const apiSecret = process.env.API_SECRET;

  if (!apiSecret) {
    console.log("⚠️  API_SECRET not set, skipping publish");
    return;
  }

  console.log(`📤 Publishing to ${apiUrl}...`);

  try {
    const res = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiSecret}`,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const body = await res.text();
      console.log(`❌ Publish failed: ${res.status} ${body}`);
      return;
    }

    const result = await res.json();
    console.log(`✅ Published! ID: ${result.id}, Score: ${result.score}`);
  } catch (error) {
    console.log(
      `❌ Publish error: ${error instanceof Error ? error.message : error}`,
    );
  }
}

// ── Run ────────────────────────────────────────────────────────────────

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
