/**
 * WAVSEP Ground Truth
 *
 * Generates a complete, deterministic test case map from a running WAVSEP
 * container. Each test case has:
 *   - A unique ID derived from the filepath
 *   - The full URL with default parameter
 *   - The CWE and category
 *   - Whether it's a true-positive (vulnerable) or true-negative (FP case)
 *
 * This can be run standalone to export a static JSON snapshot:
 *   tsx benchmarks/ground-truth/wavsep.ts > benchmarks/ground-truth/wavsep.json
 *
 * Or imported by the benchmark runner.
 */

import type { TestCase } from "../score";

// ── WAVSEP URL Categories ──────────────────────────────────────────────
//
// WAVSEP's directory structure IS the ground truth:
//   - "Detection-Evaluation" paths are TP (actually vulnerable)
//   - "FalsePositives" paths are TN (safe, should NOT be flagged)
//
// Each category index page links to sub-category pages which list the
// individual .jsp test cases.

interface WavsepCategory {
  indexPath: string;
  cwe: string;
  category: string;
  // Some index pages (like index-false.jsp) aggregate FP cases for
  // multiple CWEs. We handle those via sub-link sniffing.
  mixedFP?: boolean;
}

const CATEGORIES: WavsepCategory[] = [
  {
    indexPath: "active/index-xss.jsp",
    cwe: "CWE-79",
    category: "xss",
  },
  {
    indexPath: "active/index-sql.jsp",
    cwe: "CWE-89",
    category: "sqli",
  },
  {
    indexPath: "active/index-lfi.jsp",
    cwe: "CWE-22",
    category: "lfi",
  },
  {
    indexPath: "active/index-rfi.jsp",
    cwe: "CWE-98",
    category: "rfi",
  },
  {
    indexPath: "active/index-redirect.jsp",
    cwe: "CWE-601",
    category: "redirect",
  },
  {
    indexPath: "active/index-false.jsp",
    cwe: "",
    category: "",
    mixedFP: true,
  },
];

// ── Scraper Utilities ──────────────────────────────────────────────────

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.text();
}

function extractHrefs(html: string): string[] {
  const hrefs: string[] = [];
  const re = /href="([^"]+)"/gi;
  let m;
  while ((m = re.exec(html)) !== null) hrefs.push(m[1]);
  return [...new Set(hrefs)];
}

function resolveUrl(base: string, currentPath: string, href: string): string {
  if (href.startsWith("http")) return href;
  if (href.startsWith("/")) return new URL(href, base).href;
  const dir = currentPath.substring(0, currentPath.lastIndexOf("/") + 1);
  return `${base.replace(/\/$/, "")}/${dir}${href}`
    .replace(/\/+/g, "/")
    .replace(":/", "://");
}

// ── Ground Truth Builder ───────────────────────────────────────────────

/**
 * Build the complete WAVSEP ground truth from a running instance.
 *
 * This is a one-time operation per WAVSEP version — the output should be
 * cached as JSON for deterministic benchmark runs.
 */
export async function buildWavsepGroundTruth(
  baseUrl: string,
): Promise<TestCase[]> {
  const testCases: TestCase[] = [];
  const seen = new Set<string>();

  for (const cat of CATEGORIES) {
    const pageUrl = `${baseUrl}${cat.indexPath}`;
    let html: string;
    try {
      html = await fetchText(pageUrl);
    } catch (err) {
      console.warn(
        `⚠️  Could not fetch ${pageUrl}: ${err instanceof Error ? err.message : err}`,
      );
      continue;
    }

    const subLinks = extractHrefs(html);

    for (const subLink of subLinks) {
      const subUrl = resolveUrl(baseUrl, cat.indexPath, subLink);

      // Determine CWE for mixed-FP pages
      let cwe = cat.cwe;
      let category = cat.category;
      if (cat.mixedFP) {
        if (subLink.includes("XSS")) {
          cwe = "CWE-79";
          category = "xss";
        } else if (subLink.includes("SQL") || subLink.includes("SInjection")) {
          cwe = "CWE-89";
          category = "sqli";
        } else if (subLink.includes("LFI")) {
          cwe = "CWE-22";
          category = "lfi";
        } else if (subLink.includes("RFI")) {
          cwe = "CWE-98";
          category = "rfi";
        } else if (subLink.includes("Redirect")) {
          cwe = "CWE-601";
          category = "redirect";
        } else {
          continue;
        }
      }

      // Fetch subcategory page → lists individual test cases
      let subHtml: string;
      try {
        subHtml = await fetchText(subUrl);
      } catch {
        continue;
      }

      const caseLinks = extractHrefs(subHtml);
      for (const caseLink of caseLinks) {
        if (!caseLink.includes(".jsp")) continue;
        if (caseLink.includes("index")) continue;

        const fullUrl = resolveUrl(
          baseUrl,
          subUrl.replace(baseUrl, ""),
          caseLink,
        );

        // Classify: TP vs TN based on path structure
        const pathLower = fullUrl.toLowerCase();
        const isTP =
          pathLower.includes("detection-evaluation") &&
          !pathLower.includes("falsepositive");
        const isTN = pathLower.includes("falsepositive");

        if (!isTP && !isTN) continue;

        // Extract the parameter name from the URL if present
        const urlObj = new URL(fullUrl);
        const paramName =
          urlObj.searchParams.keys().next().value ?? "userinput";

        // Derive a stable test case ID from filepath
        const filename = caseLink.split("?")[0];
        const relPath = fullUrl.replace(baseUrl, "");
        const id = `WAVSEP-${category.toUpperCase()}-${isTP ? "TP" : "TN"}-${filename}`;

        // Deduplicate
        if (seen.has(id)) continue;
        seen.add(id);

        testCases.push({
          id,
          cwe,
          category,
          url: fullUrl,
          parameter: paramName,
          isVulnerable: isTP,
        });
      }
    }
  }

  return testCases;
}

// ── Standalone CLI ─────────────────────────────────────────────────────

if (import.meta.url === `file://${process.argv[1]}`) {
  const baseUrl = process.argv[2] ?? "http://localhost:8080/wavsep/";
  console.error(`Generating WAVSEP ground truth from ${baseUrl}...`);

  buildWavsepGroundTruth(baseUrl).then((cases) => {
    const tp = cases.filter((c) => c.isVulnerable).length;
    const tn = cases.filter((c) => !c.isVulnerable).length;
    console.error(`  ${cases.length} test cases (${tp} TP, ${tn} TN)`);

    // Output JSON to stdout
    console.log(JSON.stringify(cases, null, 2));
  });
}
