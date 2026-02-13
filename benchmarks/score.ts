/**
 * Vulcn Benchmark Scoring Engine
 *
 * Implements the same scoring methodology as the OWASP Benchmark Scorecard:
 *
 *   TPR  = TP / (TP + FN)                 True Positive Rate (Sensitivity / Recall)
 *   FPR  = FP / (FP + TN)                 False Positive Rate
 *   Youden = TPR - FPR                     The single metric that matters
 *   Precision = TP / (TP + FP)
 *   F1   = 2 × (Precision × TPR) / (Precision + TPR)
 *
 * Youden's J ranges from -1 to 1:
 *   - 1.0 = perfect detection (100% TP, 0% FP)
 *   - 0.0 = random guessing (equivalent to coin flip)
 *   - <0  = worse than random (anti-correlated detection)
 *
 * The OWASP Benchmark scales this to 0–100 for their "Accuracy Score."
 * We keep the raw -1 to 1 range for honesty.
 */

// ── Types ──────────────────────────────────────────────────────────────

export interface TestCase {
  /** Unique identifier for the test case (e.g., "WAVSEP-XSS-TP-Case01.jsp") */
  id: string;
  /** CWE identifier (e.g., "CWE-79") */
  cwe: string;
  /** Vulnerability category (e.g., "xss", "sqli") */
  category: string;
  /** Full URL of the test case */
  url: string;
  /** HTTP method — defaults to GET */
  method?: string;
  /** The vulnerable parameter name */
  parameter: string;
  /** Selector for the input element in a browser (for form-based tests) */
  inputSelector?: string;
  /** Selector for the submit button (for form-based tests) */
  submitSelector?: string;
  /** TRUE = this test case IS vulnerable (TP); FALSE = safe (TN) */
  isVulnerable: boolean;
  /** Optional human-readable description */
  description?: string;
}

export interface PerCaseResult {
  testCase: TestCase;
  /** Did Vulcn detect this as a vulnerability? */
  detected: boolean;
  /** Which finding types were reported for this case */
  findingTypes?: string[];
  /** Classification: tp, fp, fn, tn */
  classification: "tp" | "fp" | "fn" | "tn";
}

export interface CategoryScore {
  cwe: string;
  category: string;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  total: number;
  tpr: number;
  fpr: number;
  youden: number;
  precision: number;
  f1: number;
}

export interface BenchmarkScore {
  /** Per-CWE category breakdowns */
  categories: CategoryScore[];
  /** Aggregate across all categories */
  aggregate: CategoryScore;
  /** When the benchmark was run */
  timestamp: string;
  /** Benchmark target name (WAVSEP, OWASP, etc.) */
  target: string;
  /** Version of Vulcn being tested */
  vulcnVersion: string;
  /** Total test cases in the ground truth */
  totalCases: number;
  /** How many were actually tested (should equal totalCases for honest benchmarks) */
  testedCases: number;
}

// ── Classification ─────────────────────────────────────────────────────

/**
 * Classify a single test case result.
 */
export function classify(
  testCase: TestCase,
  detected: boolean,
): PerCaseResult["classification"] {
  if (testCase.isVulnerable) {
    return detected ? "tp" : "fn";
  }
  return detected ? "fp" : "tn";
}

// ── Scoring ────────────────────────────────────────────────────────────

function computeCategory(
  cwe: string,
  category: string,
  results: PerCaseResult[],
): CategoryScore {
  let tp = 0,
    fp = 0,
    fn = 0,
    tn = 0;

  for (const r of results) {
    switch (r.classification) {
      case "tp":
        tp++;
        break;
      case "fp":
        fp++;
        break;
      case "fn":
        fn++;
        break;
      case "tn":
        tn++;
        break;
    }
  }

  const tpr = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const f1 =
    precision + tpr > 0 ? (2 * precision * tpr) / (precision + tpr) : 0;

  return {
    cwe,
    category,
    tp,
    fp,
    fn,
    tn,
    total: tp + fp + fn + tn,
    tpr,
    fpr,
    youden: tpr - fpr,
    precision,
    f1,
  };
}

/**
 * Compute the full benchmark scorecard from per-case results.
 */
export function score(
  results: PerCaseResult[],
  target: string,
  version: string,
): BenchmarkScore {
  // Group by CWE
  const byCwe = new Map<string, PerCaseResult[]>();
  for (const r of results) {
    const key = r.testCase.cwe;
    if (!byCwe.has(key)) byCwe.set(key, []);
    byCwe.get(key)!.push(r);
  }

  const categories: CategoryScore[] = [];
  for (const [cwe, items] of byCwe) {
    categories.push(computeCategory(cwe, items[0].testCase.category, items));
  }

  const aggregate = computeCategory("ALL", "aggregate", results);

  return {
    categories: categories.sort((a, b) => a.cwe.localeCompare(b.cwe)),
    aggregate,
    timestamp: new Date().toISOString(),
    target,
    vulcnVersion: version,
    totalCases: results.length,
    testedCases: results.length,
  };
}

// ── Formatting ─────────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.padEnd(n);
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

export function formatScoreTable(result: BenchmarkScore): string {
  const lines: string[] = [];
  const W = 86;

  lines.push("");
  lines.push(
    `🎯 Vulcn Benchmark Scorecard — ${result.target} — v${result.vulcnVersion}`,
  );
  lines.push(
    `   ${result.totalCases} test cases · ${result.timestamp.split("T")[0]}`,
  );
  lines.push("━".repeat(W));
  lines.push(
    pad("Category", 22) +
      pad("TP", 5) +
      pad("FP", 5) +
      pad("FN", 5) +
      pad("TN", 5) +
      pad("Total", 7) +
      pad("TPR", 8) +
      pad("FPR", 8) +
      pad("Prec", 8) +
      pad("Youden", 8),
  );
  lines.push("─".repeat(W));

  for (const c of result.categories) {
    const label = `${c.cwe} (${c.category})`;
    lines.push(
      pad(label, 22) +
        pad(String(c.tp), 5) +
        pad(String(c.fp), 5) +
        pad(String(c.fn), 5) +
        pad(String(c.tn), 5) +
        pad(String(c.total), 7) +
        pad(pct(c.tpr), 8) +
        pad(pct(c.fpr), 8) +
        pad(pct(c.precision), 8) +
        pad(c.youden.toFixed(3), 8),
    );
  }

  lines.push("━".repeat(W));
  const a = result.aggregate;
  lines.push(
    pad("OVERALL", 22) +
      pad(String(a.tp), 5) +
      pad(String(a.fp), 5) +
      pad(String(a.fn), 5) +
      pad(String(a.tn), 5) +
      pad(String(a.total), 7) +
      pad(pct(a.tpr), 8) +
      pad(pct(a.fpr), 8) +
      pad(pct(a.precision), 8) +
      pad(a.youden.toFixed(3), 8),
  );
  lines.push("");

  // Interpretation
  const youden = a.youden;
  let grade: string;
  if (youden >= 0.8) grade = "🏆 Excellent";
  else if (youden >= 0.6) grade = "✅ Good";
  else if (youden >= 0.4) grade = "⚠️  Fair";
  else if (youden >= 0.2) grade = "🔶 Needs improvement";
  else if (youden >= 0.0) grade = "❌ Poor (near random)";
  else grade = "🚫 Anti-correlated (worse than random)";

  lines.push(`   Overall Youden: ${youden.toFixed(3)} — ${grade}`);
  lines.push("");

  return lines.join("\n");
}

export function formatMarkdownSummary(result: BenchmarkScore): string {
  const lines: string[] = [];

  lines.push(`## 🎯 Vulcn Benchmark — ${result.target}`);
  lines.push("");
  lines.push(
    `**Version:** v${result.vulcnVersion} · **Date:** ${result.timestamp.split("T")[0]} · **Test Cases:** ${result.totalCases}`,
  );
  lines.push("");
  lines.push(
    `**Overall Youden Score: ${result.aggregate.youden.toFixed(3)}** (TPR ${pct(result.aggregate.tpr)} · FPR ${pct(result.aggregate.fpr)} · Precision ${pct(result.aggregate.precision)})`,
  );
  lines.push("");
  lines.push(
    "| Category | TP | FP | FN | TN | Total | TPR | FPR | Precision | Youden |",
  );
  lines.push(
    "|----------|----|----|----|----|-------|-----|-----|-----------|--------|",
  );

  for (const c of result.categories) {
    lines.push(
      `| ${c.cwe} (${c.category}) | ${c.tp} | ${c.fp} | ${c.fn} | ${c.tn} | ${c.total} | ${pct(c.tpr)} | ${pct(c.fpr)} | ${pct(c.precision)} | ${c.youden.toFixed(3)} |`,
    );
  }

  const a = result.aggregate;
  lines.push(
    `| **OVERALL** | **${a.tp}** | **${a.fp}** | **${a.fn}** | **${a.tn}** | **${a.total}** | **${pct(a.tpr)}** | **${pct(a.fpr)}** | **${pct(a.precision)}** | **${a.youden.toFixed(3)}** |`,
  );
  lines.push("");

  return lines.join("\n");
}
