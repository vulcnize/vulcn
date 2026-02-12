#!/usr/bin/env tsx
/**
 * Vulcn Benchmark — Honest, Per-Case DAST Evaluation
 *
 * The correct way to benchmark a DAST tool:
 *
 *   1. Load ground truth (every test case with its known TP/TN label)
 *   2. For each test case, run Vulcn's engine directly against that URL
 *   3. Check if Vulcn detects the correct vulnerability type
 *   4. Score: TP, FP, FN, TN per CWE → TPR, FPR, Youden
 *
 * This is how every serious DAST vendor benchmarks. The crawler's job is
 * to DISCOVER pages — that's a separate metric (coverage). Detection
 * accuracy must be tested against known ground-truth cases.
 *
 * The benchmark uses the @vulcn/engine API directly (not the CLI), so it
 * shares a single browser instance across all tests and avoids per-case
 * process overhead.
 *
 * Usage:
 *   tsx benchmarks/bench.ts                          # Default: WAVSEP
 *   tsx benchmarks/bench.ts --target wavsep          # WAVSEP
 *   tsx benchmarks/bench.ts --target owasp           # OWASP Benchmark
 *   tsx benchmarks/bench.ts --categories xss sqli    # Test specific categories
 *   tsx benchmarks/bench.ts --verbose                # Per-case breakdown
 *   tsx benchmarks/bench.ts --json results.json      # Machine-readable output
 *   tsx benchmarks/bench.ts --dry-run                # List test cases without running
 *
 * Prerequisites:
 *   docker compose -f benchmarks/docker-compose.yml up -d
 *   pnpm build
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { DriverManager, PluginManager } from "@vulcn/engine";
import type { Session, RunResult, Finding } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import {
  score,
  classify,
  formatScoreTable,
  formatMarkdownSummary,
  type TestCase,
  type PerCaseResult,
} from "./score";

// ── Config ─────────────────────────────────────────────────────────────

const TARGETS: Record<
  string,
  { url: string; port: number; healthcheck: string }
> = {
  wavsep: {
    url: "http://localhost:8080/wavsep/",
    port: 8080,
    healthcheck: "http://localhost:8080/wavsep/",
  },
  owasp: {
    url: "http://localhost:8443/benchmark/",
    port: 8443,
    healthcheck: "http://localhost:8443/benchmark/",
  },
};

// Categories Vulcn currently supports — expand as detection matures.
// The benchmark ONLY measures categories Vulcn claims to detect, so
// adding a new category before implementing detection will correctly
// yield Youden=0 for that category (honest signal).
const SUPPORTED_CATEGORIES = new Set(["xss", "sqli"]);

// ── CLI Args ───────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const targetName = getArg("--target") ?? "wavsep";
const verbose = args.includes("--verbose");
const jsonOutput = getArg("--json");
const summaryFile = getArg("--summary");
const filterCategories = getListArg("--categories");
const grepPattern = getArg("--grep");
const tnOnly = args.includes("--tn-only");
const tpOnly = args.includes("--tp-only");
const dryRun = args.includes("--dry-run");

function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

function getListArg(flag: string): string[] | undefined {
  const idx = args.indexOf(flag);
  if (idx < 0) return undefined;
  const values: string[] = [];
  for (let i = idx + 1; i < args.length; i++) {
    if (args[i].startsWith("--")) break;
    values.push(args[i]);
  }
  return values.length > 0 ? values : undefined;
}

// ── Main ───────────────────────────────────────────────────────────────

async function main() {
  const target = TARGETS[targetName];
  if (!target) {
    console.error(
      `Unknown target: ${targetName}. Available: ${Object.keys(TARGETS).join(", ")}`,
    );
    process.exit(1);
  }

  console.log(`\n🎯 Vulcn Benchmark — ${targetName.toUpperCase()}`);
  console.log(`   Target: ${target.url}`);

  // 1. Health check
  console.log(`\n⏳ Waiting for target...`);
  await waitForTarget(target.healthcheck);
  console.log(`   ✅ Target is up`);

  // 2. Load ground truth
  console.log(`\n📋 Loading ground truth...`);
  let groundTruth = await loadGroundTruth(targetName, target.url);

  // Filter to tested categories
  const activeCategories = filterCategories ?? [...SUPPORTED_CATEGORIES];
  groundTruth = groundTruth.filter((tc) =>
    activeCategories.includes(tc.category),
  );

  // Filter by name pattern (--grep)
  if (grepPattern) {
    const pat = grepPattern.toLowerCase();
    groundTruth = groundTruth.filter((tc) => tc.id.toLowerCase().includes(pat));
    console.log(
      `   Grep filter: "${grepPattern}" → ${groundTruth.length} matches`,
    );
  }

  // Filter to TN-only or TP-only
  if (tnOnly) {
    groundTruth = groundTruth.filter((tc) => !tc.isVulnerable);
    console.log(`   TN-only mode: ${groundTruth.length} cases`);
  } else if (tpOnly) {
    groundTruth = groundTruth.filter((tc) => tc.isVulnerable);
    console.log(`   TP-only mode: ${groundTruth.length} cases`);
  }

  const tpCount = groundTruth.filter((tc) => tc.isVulnerable).length;
  const tnCount = groundTruth.filter((tc) => !tc.isVulnerable).length;
  console.log(
    `   ${groundTruth.length} test cases (${tpCount} TP, ${tnCount} TN)`,
  );
  console.log(
    `   Categories: ${[...new Set(groundTruth.map((tc) => tc.category))].join(", ")}`,
  );

  if (groundTruth.length === 0) {
    console.error(
      `\n❌ No test cases found. Check target and category filters.`,
    );
    process.exit(1);
  }

  if (dryRun) {
    console.log(`\n🔍 Dry run — listing test cases:`);
    for (const tc of groundTruth) {
      console.log(
        `   ${tc.isVulnerable ? "🔴 TP" : "🟢 TN"} ${tc.id} — ${tc.url}`,
      );
    }
    return;
  }

  // 3. Workspace
  const workDir = resolve("benchmarks/results");
  await mkdir(workDir, { recursive: true });

  // 4. Run Vulcn against each test case using the engine API
  console.log(`\n🚀 Testing ${groundTruth.length} cases...`);
  const results = await runBenchmark(groundTruth, activeCategories);

  // 5. Score
  const pkg = JSON.parse(await readFile("package.json", "utf-8"));
  const scorecard = score(results, targetName.toUpperCase(), pkg.version);

  // 6. Output
  console.log(formatScoreTable(scorecard));

  if (verbose) {
    printPerCaseBreakdown(results);
  }

  if (jsonOutput) {
    await writeFile(jsonOutput, JSON.stringify(scorecard, null, 2));
    console.log(`📄 Results saved to ${jsonOutput}`);
  }

  if (summaryFile) {
    await writeFile(summaryFile, formatMarkdownSummary(scorecard));
    console.log(`📄 Summary saved to ${summaryFile}`);
  }

  console.log("");
}

// ── Ground Truth Loading ───────────────────────────────────────────────

async function loadGroundTruth(
  target: string,
  baseUrl: string,
): Promise<TestCase[]> {
  const cacheFile = resolve(`benchmarks/ground-truth/${target}.json`);

  if (existsSync(cacheFile)) {
    console.log(`   Using cached ground truth: ${cacheFile}`);
    return JSON.parse(await readFile(cacheFile, "utf-8"));
  }

  console.log(`   Generating ground truth from live target...`);

  switch (target) {
    case "wavsep": {
      const { buildWavsepGroundTruth } = await import("./ground-truth/wavsep");
      const cases = await buildWavsepGroundTruth(baseUrl);
      await mkdir(resolve("benchmarks/ground-truth"), { recursive: true });
      await writeFile(cacheFile, JSON.stringify(cases, null, 2));
      console.log(`   Cached ${cases.length} test cases to ${cacheFile}`);
      return cases;
    }
    case "owasp": {
      const { fetchOwaspGroundTruth } = await import("./ground-truth/owasp");
      const cases = await fetchOwaspGroundTruth(baseUrl, true);
      await mkdir(resolve("benchmarks/ground-truth"), { recursive: true });
      await writeFile(cacheFile, JSON.stringify(cases, null, 2));
      console.log(`   Cached ${cases.length} test cases to ${cacheFile}`);
      return cases;
    }
    default:
      throw new Error(`No ground truth loader for: ${target}`);
  }
}

// ── Engine-Based Benchmark Runner ──────────────────────────────────────

/**
 * Run the benchmark using @vulcn/engine directly.
 *
 * For each test case, we build a minimal Session with injection steps
 * and run it through the engine. All sessions share a single browser
 * via executeScan(), which is dramatically faster than spawning
 * a browser for each case.
 *
 * Results are matched per-session: we check if Vulcn correctly
 * detected (TP) or didn't detect (TN) the expected vulnerability.
 */
async function runBenchmark(
  testCases: TestCase[],
  categories: string[],
): Promise<PerCaseResult[]> {
  // 1. Initialize engine
  const drivers = new DriverManager();
  drivers.register(browserDriver);

  // Payloads are now loaded per-batch inside the loop to optimize performance

  // 2. Build sessions — one per test case
  const sessions = testCases.map((tc) => buildSession(tc));

  // 3. Execute all sessions via executeScan (shared browser)
  const startTime = Date.now();
  // 3. Execute in batches per category (Safety + Performance)
  // We split test cases by category and run them with ONLY that category's payloads.
  // This prevents XSS payloads from being sent to SQLi targets (waste of time)
  // and vice versa.
  const batchCategories = [...new Set(testCases.map((tc) => tc.category))];
  const scanResult: RunResult = {
    findings: [],
    stepsExecuted: 0,
    payloadsTested: 0,
    duration: 0,
    errors: [],
  };
  const sessionResults: (RunResult | undefined)[] = new Array(testCases.length);

  let completed = 0;
  const total = testCases.length;

  for (const category of batchCategories) {
    // Filter cases for this category
    const categoryCases = testCases.filter((tc) => tc.category === category);
    const categorySessions = categoryCases.map((tc) => buildSession(tc));

    // Load ONLY relevant payloads for this category
    // Map benchmark categories to Vulcn payload types
    let payloadType = category;
    switch (category) {
      case "xss":
        payloadType = "xss";
        break;
      case "sqli":
        payloadType = "sqli";
        break;
      case "cmdi":
        payloadType = "cmd";
        break;
      case "pathtraver":
        payloadType = "path-traversal";
        break;
    }

    // Re-initialize a fresh plugin manager for this batch to ensure clean payload state
    const batchManager = new PluginManager();
    await batchManager.loadDefaults([payloadType], { passive: false });

    console.log(
      `\n   Running ${category} batch (${categoryCases.length} cases)...`,
    );

    const batchResult = await drivers.executeScan(
      categorySessions,
      batchManager,
      {
        headless: true,
        timeout: 30_000,
        onSessionStart: (_session, index) => {
          // Calculate global progress
          const currentGlobal = completed + index;
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
          const pct = ((currentGlobal / total) * 100).toFixed(0);
          process.stdout.write(
            `\r   [${pct}%] ${currentGlobal}/${total} cases (${elapsed}s)`,
          );
        },
      },
    );

    // Merge results
    scanResult.stepsExecuted += batchResult.aggregate.stepsExecuted;
    scanResult.payloadsTested += batchResult.aggregate.payloadsTested;
    scanResult.errors.push(...batchResult.aggregate.errors);
    scanResult.findings.push(...batchResult.aggregate.findings);

    // Store per-session results in the correct original index
    batchResult.results.forEach((res, batchIdx) => {
      // Find original index in testCases
      const originalIdx = testCases.indexOf(categoryCases[batchIdx]);
      sessionResults[originalIdx] = res;
    });

    completed += categoryCases.length;
  }

  process.stdout.write(
    `\r   [100%] ${total}/${total} cases (${((Date.now() - startTime) / 1000).toFixed(0)}s)\n`,
  );

  const errCount = scanResult.errors.length;
  if (errCount > 0) {
    console.log(`   ⚠️  ${errCount} execution errors (see --verbose)`);
  }

  // 4. Match results back to test cases
  const results: PerCaseResult[] = [];

  for (let i = 0; i < testCases.length; i++) {
    const tc = testCases[i];
    const sessionResult = sessionResults[i];

    // Determine if this case was detected as vulnerable.
    // Only count ACTIVE findings that match the expected CWE.
    const detected = sessionResult
      ? hasRelevantFinding(sessionResult.findings, tc)
      : false;

    const findingTypes = sessionResult
      ? sessionResult.findings
          .filter((f) => f.type !== "security-misconfiguration")
          .map((f) => f.type)
      : [];

    results.push({
      testCase: tc,
      detected,
      findingTypes: [...new Set(findingTypes)],
      classification: classify(tc, detected),
    });
  }

  return results;
}

// ── Session Builder ────────────────────────────────────────────────────

/**
 * Build a minimal Vulcn Session for a single test case.
 *
 * Two session types based on whether the test case is GET or POST:
 *
 * GET (URL has ?param=value):
 *   → browser.navigate with injectable=true + parameter name
 *   → The runner rewrites the URL param and navigates directly.
 *   → No form fill needed — fast and reliable.
 *
 * POST (no URL params — page has a form):
 *   → browser.navigate + browser.input (injectable) + browser.click
 *   → The runner fills the form field and clicks submit.
 */
function buildSession(tc: TestCase): Session {
  const param = tc.parameter;
  const method = tc.method ?? "GET";
  const hasUrlParam = tc.url.includes("?");

  // POST-based: inject via form fill + submit
  // Check method first — if it requires POST, we must use the form path,
  // even if the URL has parameters (e.g., login.jsp?mode=1).
  if (method === "POST") {
    return {
      name: tc.id,
      driver: "browser",
      driverConfig: {
        browser: "chromium",
        headless: true,
        startUrl: tc.url,
      },
      steps: [
        {
          id: "step-1",
          type: "browser.navigate",
          timestamp: Date.now(),
          url: tc.url,
        },
        {
          id: "step-2",
          type: "browser.input",
          timestamp: Date.now(),
          selector: `input[name='${param}'], input[id='${param}'], textarea[name='${param}']`,
          value: "test",
          injectable: true,
        },
        {
          id: "step-3",
          type: "browser.click",
          timestamp: Date.now(),
          selector:
            "input[type='submit'], button[type='submit'], input[value='submit' i], button:has-text('Submit')",
        },
      ],
      metadata: {
        benchmarkId: tc.id,
        cwe: tc.cwe,
        category: tc.category,
        isVulnerable: tc.isVulnerable,
      },
    };
  }

  // GET-based: inject via URL parameter rewriting
  if (method === "GET" || hasUrlParam) {
    return {
      name: tc.id,
      driver: "browser",
      driverConfig: {
        browser: "chromium",
        headless: true,
        startUrl: tc.url,
      },
      steps: [
        {
          id: "step-1",
          type: "browser.navigate",
          timestamp: Date.now(),
          url: tc.url,
          injectable: true,
          parameter: param,
          value: new URL(tc.url).searchParams.get(param) ?? "test",
        },
      ],
      metadata: {
        benchmarkId: tc.id,
        cwe: tc.cwe,
        category: tc.category,
        isVulnerable: tc.isVulnerable,
      },
    };
  }

  // POST-based: inject via form fill + submit
  return {
    name: tc.id,
    driver: "browser",
    driverConfig: {
      browser: "chromium",
      headless: true,
      startUrl: tc.url,
    },
    steps: [
      {
        id: "step-1",
        type: "browser.navigate",
        timestamp: Date.now(),
        url: tc.url,
      },
      {
        id: "step-2",
        type: "browser.input",
        timestamp: Date.now(),
        selector: `input[name='${param}'], input[id='${param}'], textarea[name='${param}']`,
        value: "test",
        injectable: true,
      },
      {
        id: "step-3",
        type: "browser.click",
        timestamp: Date.now(),
        selector:
          "input[type='submit'], button[type='submit'], input[value='submit' i], button:has-text('Submit')",
      },
    ],
    metadata: {
      benchmarkId: tc.id,
      cwe: tc.cwe,
      category: tc.category,
      isVulnerable: tc.isVulnerable,
    },
  };
}

// ── Finding Matching ───────────────────────────────────────────────────

/**
 * Check if a session's findings contain a detection relevant to the
 * expected vulnerability type.
 *
 * Rules:
 *   - Only ACTIVE findings count (passive header checks are excluded)
 *   - The finding type must match the expected CWE category
 *   - Cross-category matches are NOT allowed (they inflate TP counts)
 */
function hasRelevantFinding(findings: Finding[], tc: TestCase): boolean {
  return findings.some((f) => {
    // Skip passive findings
    if (f.metadata?.detectionMethod === "passive") return false;
    if (f.type === "security-misconfiguration") return false;
    if (f.type === "information-disclosure") return false;

    // Strict exclusion: Reflection is NOT XSS until proven by execution
    if (tc.category === "xss" && f.type === "reflection") {
      // console.log(`[DEBUG] Excluding reflection finding for XSS case ${tc.id}`);
      return false;
    }

    // Check if finding type matches expected category
    return categoryMatchesCwe(f.type, tc.category, tc.cwe);
  });
}

/**
 * Strict category matching.
 *
 * A finding type must correctly identify the specific vulnerability
 * category. Cross-category matches are NOT allowed because they would
 * inflate TP counts dishonestly.
 */
function categoryMatchesCwe(
  findingType: string,
  testCategory: string,
  testCwe: string,
): boolean {
  // Direct match
  if (findingType === testCategory) return true;

  // Explicit CWE matches
  if (findingType === "xss" && testCwe === "CWE-79") return true;
  if (findingType === "sqli" && testCwe === "CWE-89") return true;
  if (findingType === "command-injection" && testCwe === "CWE-78") return true;
  if (findingType === "path-traversal" && testCwe === "CWE-22") return true;

  return false;
}

// ── Output Helpers ─────────────────────────────────────────────────────

function printPerCaseBreakdown(results: PerCaseResult[]) {
  console.log(`\n📊 Per-case breakdown:`);

  const grouped = {
    fn: results.filter((r) => r.classification === "fn"),
    fp: results.filter((r) => r.classification === "fp"),
    tp: results.filter((r) => r.classification === "tp"),
    tn: results.filter((r) => r.classification === "tn"),
  };

  // Show missed detections first (most actionable for improvement)
  if (grouped.fn.length > 0) {
    console.log(
      `\n   ❌ False Negatives (missed vulnerabilities): ${grouped.fn.length}`,
    );
    for (const r of grouped.fn.slice(0, 30)) {
      console.log(`      ${r.testCase.id}`);
      console.log(`         ${r.testCase.url}`);
    }
    if (grouped.fn.length > 30) {
      console.log(`      ... and ${grouped.fn.length - 30} more`);
    }
  }

  // Show false alarms
  if (grouped.fp.length > 0) {
    console.log(
      `\n   ⚠️  False Positives (false alarms): ${grouped.fp.length}`,
    );
    for (const r of grouped.fp) {
      console.log(
        `      ${r.testCase.id} — detected as: ${r.findingTypes?.join(", ") ?? "?"}`,
      );
      console.log(`         ${r.testCase.url}`);
    }
  }

  // Correct detections
  if (grouped.tp.length > 0) {
    console.log(
      `\n   ✅ True Positives (correct detections): ${grouped.tp.length}`,
    );
    for (const r of grouped.tp.slice(0, 10)) {
      console.log(
        `      ${r.testCase.id} — ${r.findingTypes?.join(", ") ?? "?"}`,
      );
    }
    if (grouped.tp.length > 10) {
      console.log(`      ... and ${grouped.tp.length - 10} more`);
    }
  }

  // Summary
  console.log(`\n   Summary:`);
  console.log(`   ✅ True Positives:  ${grouped.tp.length}`);
  console.log(`   ✅ True Negatives:  ${grouped.tn.length}`);
  console.log(`   ❌ False Negatives: ${grouped.fn.length}`);
  console.log(`   ⚠️  False Positives: ${grouped.fp.length}`);

  // Youden's J = Sensitivity + Specificity - 1
  const tp = grouped.tp.length;
  const fn = grouped.fn.length;
  const tn = grouped.tn.length;
  const fp = grouped.fp.length;
  const sensitivity = tp + fn > 0 ? tp / (tp + fn) : 0;
  const specificity = tn + fp > 0 ? tn / (tn + fp) : 0;
  const youdenJ = sensitivity + specificity - 1;
  const jLabel =
    youdenJ >= 0.8
      ? "Excellent"
      : youdenJ >= 0.6
        ? "Good"
        : youdenJ >= 0.4
          ? "Fair"
          : "Poor";
  console.log(
    `\n   📐 Youden's J: ${youdenJ.toFixed(3)} — ${jLabel} (TPR=${(sensitivity * 100).toFixed(1)}%, TNR=${(specificity * 100).toFixed(1)}%)`,
  );

  // Show aggregate errors
  if (verbose) {
    const errorCases = results.filter(
      (r) => r.findingTypes && r.findingTypes.length === 0 && !r.detected,
    );
    if (errorCases.length > 0) {
      console.log(
        `\n   ℹ️  ${errorCases.length} cases with no findings at all`,
      );
    }
  }
}

// ── Utilities ──────────────────────────────────────────────────────────

async function waitForTarget(url: string, maxWaitMs = 60_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await fetch(url, { redirect: "follow" });
      if (res.ok || res.status === 302) return;
    } catch {
      /* not ready */
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Target not ready after ${maxWaitMs / 1000}s: ${url}`);
}

// ── Run ────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error(
    `\n❌ Benchmark failed:`,
    err instanceof Error ? err.message : err,
  );
  process.exit(1);
});
