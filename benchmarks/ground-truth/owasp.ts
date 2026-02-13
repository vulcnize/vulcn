/**
 * OWASP Benchmark Ground Truth
 *
 * The OWASP Benchmark ships with an official expectedresults CSV.
 * This parses the CSV into our standard TestCase format.
 *
 * The CSV format per line:
 *   test_name, category, cwe_number, is_real_vulnerability
 *
 * For DAST tools, not all OWASP Benchmark tests are reachable via HTTP.
 * The benchmark categorizes tests by vulnerability type (cmdi, crypto,
 * hash, ldapi, pathtraver, securecookie, sqli, trustbound, weakrand, xpathi, xss).
 * DAST tools should only be measured against categories that are testable
 * via HTTP (cmdi, pathtraver, sqli, xss) — the rest are SAST-only.
 */

import type { TestCase } from "../score";

// CWE number to our category and CWE string
const CWE_MAP: Record<number, { category: string; cwe: string }> = {
  78: { category: "cmdi", cwe: "CWE-78" },
  22: { category: "pathtraver", cwe: "CWE-22" },
  89: { category: "sqli", cwe: "CWE-89" },
  79: { category: "xss", cwe: "CWE-79" },
  // SAST-only categories (included for completeness but filtered during scoring)
  327: { category: "crypto", cwe: "CWE-327" },
  328: { category: "hash", cwe: "CWE-328" },
  90: { category: "ldapi", cwe: "CWE-90" },
  614: { category: "securecookie", cwe: "CWE-614" },
  501: { category: "trustbound", cwe: "CWE-501" },
  330: { category: "weakrand", cwe: "CWE-330" },
  643: { category: "xpathi", cwe: "CWE-643" },
};

// Categories DAST tools can actually test
const DAST_TESTABLE = new Set(["cmdi", "pathtraver", "sqli", "xss"]);

/**
 * Parse the OWASP Benchmark expected results CSV into TestCases.
 *
 * @param csv - Raw CSV content from expectedresults-X.X.csv
 * @param baseUrl - Base URL of running OWASP Benchmark instance
 * @param dastOnly - If true, only include categories testable by DAST tools
 */
export function parseOwaspExpectedResults(
  csv: string,
  baseUrl: string,
  dastOnly = true,
): TestCase[] {
  const testCases: TestCase[] = [];

  for (const line of csv.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const parts = trimmed.split(",");
    if (parts.length < 4) continue;

    const [testName, , cweNumStr, isRealStr] = parts;
    const cweNum = parseInt(cweNumStr.trim(), 10);
    if (isNaN(cweNum)) continue;

    const mapping = CWE_MAP[cweNum];
    if (!mapping) continue;

    // Skip SAST-only categories for DAST benchmarking
    if (dastOnly && !DAST_TESTABLE.has(mapping.category)) continue;

    const name = testName.trim();
    testCases.push({
      id: name,
      cwe: mapping.cwe,
      category: mapping.category,
      // OWASP Benchmark servlets follow the pattern:
      //   /benchmark/CATEGORY-NN/BenchmarkTestNNNNN
      url: `${baseUrl.replace(/\/$/, "")}/${name}`,
      parameter: "BenchmarkTest",
      isVulnerable: isRealStr.trim().toUpperCase() === "TRUE",
    });
  }

  return testCases;
}

/**
 * Fetch the OWASP Benchmark expected results CSV.
 * Tries the running server first, falls back to GitHub.
 */
export async function fetchOwaspGroundTruth(
  baseUrl: string,
  dastOnly = true,
): Promise<TestCase[]> {
  let csv: string;

  try {
    const res = await fetch(`${baseUrl}expectedresults-1.2.csv`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    csv = await res.text();
  } catch {
    console.warn(
      "  ⚠️  Could not fetch CSV from server, falling back to GitHub...",
    );
    const res = await fetch(
      "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv",
    );
    if (!res.ok)
      throw new Error(`Could not fetch OWASP expected results from GitHub`);
    csv = await res.text();
  }

  return parseOwaspExpectedResults(csv, baseUrl, dastOnly);
}
