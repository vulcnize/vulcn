/**
 * HTML Report Generator for Vulcn
 *
 * Generates a modern, dark-themed security report with:
 * - Vulcn branding (shield gradient logo)
 * - Executive summary with severity donut chart
 * - Detailed findings with expandable evidence
 * - Timeline of execution
 * - Responsive design
 */

import type { Finding, RunResult, Session } from "@vulcn/engine";

export interface HtmlReportData {
  session: Session;
  result: RunResult;
  generatedAt: string;
  engineVersion: string;
}

// Vulcn brand colors
const COLORS = {
  bg: "#0a0a0f",
  surface: "#12121a",
  surfaceHover: "#1a1a26",
  border: "#1e1e2e",
  borderActive: "#2a2a3e",
  text: "#e4e4ef",
  textMuted: "#8888a0",
  textDim: "#555570",
  accent: "#fa1b1b",
  accentGlow: "rgba(250, 27, 27, 0.15)",
  accentLight: "#ff9c9c",
  critical: "#ff1744",
  high: "#ff5252",
  medium: "#ffab40",
  low: "#66bb6a",
  info: "#42a5f5",
  success: "#00e676",
};

function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return COLORS.critical;
    case "high":
      return COLORS.high;
    case "medium":
      return COLORS.medium;
    case "low":
      return COLORS.low;
    case "info":
      return COLORS.info;
    default:
      return COLORS.textMuted;
  }
}

function severityOrder(severity: string): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default:
      return 5;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = (ms / 1000).toFixed(1);
  return `${seconds}s`;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

// Inline SVG logo matching the vulcn shield branding
const VULCN_LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="32" height="32">
  <defs>
    <linearGradient id="lg1" x1="0" x2="1" y1="0" y2="0" gradientTransform="matrix(7 -13 13 7 7 17)" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#fa1b1b"/>
      <stop offset="1" stop-color="#ff9c9c"/>
    </linearGradient>
    <linearGradient id="lg2" x1="0" x2="1" y1="0" y2="0" gradientTransform="matrix(3 -6 6 3 13 14)" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#ff9c9c"/>
      <stop offset="1" stop-color="#ffffff"/>
    </linearGradient>
  </defs>
  <path fill="url(#lg1)" d="m 11,17 c 0,0.552 -0.448,1 -1,1 -0.552,0 -1,-0.448 -1,-1 0,-0.552 0.448,-1 1,-1 0.552,0 1,0.448 1,1 z M 10,15 C 8,15 7.839,16.622 7.803,16.68 7.51,17.147 6.892,17.288 6.425,16.995 3.592,15.216 2.389,11.366 2.014,9.168 1.977,8.951 1.952,8.743 1.936,8.547 1.936,8.544 1.935,8.541 1.935,8.538 1.844,7.291 2.572,6.13 3.733,5.667 3.736,5.666 3.738,5.665 3.74,5.664 4.948,5.193 5.913,4.705 6.583,3.641 6.586,3.636 6.588,3.632 6.591,3.628 7.235,2.637 8.332,2.035 9.506,2.023 9.817,2.001 10.141,2 10.451,2 c 0,0 0,0 0,0 1.202,0 2.322,0.608 2.977,1.616 0.005,0.008 0.01,0.017 0.015,0.025 0.651,1.07 1.614,1.554 2.817,2.022 0.002,0 0.005,10e-4 0.007,0.002 1.162,0.463 1.89,1.626 1.799,2.873 0,0.006 -10e-4,0.012 -10e-4,0.018 -0.018,0.193 -0.043,0.397 -0.079,0.612 -0.375,2.198 -1.578,6.048 -4.411,7.827 C 13.108,17.288 12.49,17.147 12.197,16.68 12.161,16.622 12,15 10,15 Z"/>
  <path fill="#dc2626" d="m 13.0058,9.89 c -0.164,1.484 -0.749,2.568 -1.659,3.353 -0.418,0.36 -0.465,0.992 -0.104,1.41 0.36,0.418 0.992,0.465 1.41,0.104 1.266,-1.092 2.112,-2.583 2.341,-4.647 0.061,-0.548 -0.335,-1.043 -0.884,-1.104 -0.548,-0.061 -1.043,0.335 -1.104,0.884 z"/>
  <path fill="url(#lg2)" d="m 14.0058,8.89 c -0.164,1.484 -0.749,2.568 -1.659,3.353 -0.418,0.36 -0.465,0.992 -0.104,1.41 0.36,0.418 0.992,0.465 1.41,0.104 1.266,-1.092 2.112,-2.583 2.341,-4.647 0.061,-0.548 -0.335,-1.043 -0.884,-1.104 -0.548,-0.061 -1.043,0.335 -1.104,0.884 z"/>
</svg>`;

export function generateHtml(data: HtmlReportData): string {
  const { session, result, generatedAt, engineVersion } = data;
  const findings = [...result.findings].sort(
    (a, b) => severityOrder(a.severity) - severityOrder(b.severity),
  );

  // Severity counts for donut chart
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const totalFindings = findings.length;
  const hasFindings = totalFindings > 0;

  // Overall risk score
  const riskScore =
    counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low * 1;
  const maxRisk = totalFindings * 10 || 1;
  const riskPercent = Math.min(100, Math.round((riskScore / maxRisk) * 100));
  const riskLabel =
    riskPercent >= 80
      ? "Critical"
      : riskPercent >= 50
        ? "High"
        : riskPercent >= 25
          ? "Medium"
          : riskPercent > 0
            ? "Low"
            : "Clear";
  const riskColor =
    riskPercent >= 80
      ? COLORS.critical
      : riskPercent >= 50
        ? COLORS.high
        : riskPercent >= 25
          ? COLORS.medium
          : riskPercent > 0
            ? COLORS.low
            : COLORS.success;

  // Donut chart SVG segments
  const donutSvg = generateDonut(counts, totalFindings);

  // Unique URLs affected
  const affectedUrls = [...new Set(findings.map((f) => f.url))];

  // Unique vuln types
  const vulnTypes = [...new Set(findings.map((f) => f.type))];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulcn Security Report — ${escapeHtml(session.name)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: ${COLORS.bg};
      --surface: ${COLORS.surface};
      --surface-hover: ${COLORS.surfaceHover};
      --border: ${COLORS.border};
      --border-active: ${COLORS.borderActive};
      --text: ${COLORS.text};
      --text-muted: ${COLORS.textMuted};
      --text-dim: ${COLORS.textDim};
      --accent: ${COLORS.accent};
      --accent-glow: ${COLORS.accentGlow};
      --accent-light: ${COLORS.accentLight};
      --radius: 12px;
      --radius-sm: 8px;
      --radius-xs: 6px;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }

    /* Ambient gradient background */
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 600px;
      background: radial-gradient(ellipse 80% 50% at 50% -20%, ${COLORS.accentGlow} 0%, transparent 100%);
      pointer-events: none;
      z-index: 0;
    }

    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 40px 24px;
      position: relative;
      z-index: 1;
    }

    /* Header */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 48px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
    }

    .header-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .header-brand svg {
      filter: drop-shadow(0 0 8px rgba(250, 27, 27, 0.3));
    }

    .header-brand h1 {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #fa1b1b, #ff9c9c);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .header-brand span {
      font-size: 11px;
      font-weight: 500;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }

    .header-meta {
      text-align: right;
      font-size: 12px;
      color: var(--text-dim);
      line-height: 1.8;
    }

    /* Session info */
    .session-info {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 24px;
      margin-bottom: 32px;
    }

    .session-info h2 {
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 16px;
      letter-spacing: -0.02em;
    }

    .session-meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }

    .meta-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .meta-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
    }

    .meta-value {
      font-size: 14px;
      font-weight: 500;
      color: var(--text);
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
    }

    /* Stats grid */
    .stats-grid {
      display: grid;
      grid-template-columns: 1fr 1.5fr;
      gap: 24px;
      margin-bottom: 32px;
    }

    @media (max-width: 768px) {
      .stats-grid { grid-template-columns: 1fr; }
    }

    /* Risk gauge */
    .risk-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 32px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 20px;
    }

    .risk-card h3 {
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
      width: 100%;
    }

    .risk-gauge {
      position: relative;
      width: 160px;
      height: 160px;
    }

    .risk-gauge svg {
      transform: rotate(-90deg);
    }

    .risk-gauge-label {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }

    .risk-gauge-label .score {
      font-size: 36px;
      font-weight: 800;
      letter-spacing: -0.03em;
    }

    .risk-gauge-label .label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
    }

    /* Summary card */
    .summary-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 32px;
    }

    .summary-card h3 {
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
      margin-bottom: 20px;
    }

    .summary-stats {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
    }

    .stat-box {
      padding: 16px;
      background: rgba(255,255,255,0.02);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      transition: border-color 0.2s;
    }

    .stat-box:hover { border-color: var(--border-active); }

    .stat-number {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.03em;
      line-height: 1;
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
    }

    /* Severity breakdown */
    .severity-breakdown {
      margin-bottom: 32px;
    }

    .severity-section-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }

    .severity-section-header h3 {
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
    }

    .severity-bars {
      display: flex;
      gap: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px 24px;
    }

    .severity-bar-item {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 8px;
      align-items: center;
    }

    .severity-bar-track {
      width: 100%;
      height: 6px;
      background: rgba(255,255,255,0.04);
      border-radius: 3px;
      overflow: hidden;
    }

    .severity-bar-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.5s ease;
    }

    .severity-bar-label {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-dim);
    }

    .severity-bar-count {
      font-size: 18px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }

    /* Findings section */
    .findings-section {
      margin-bottom: 32px;
    }

    .findings-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    .findings-header h3 {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }

    .findings-count {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-dim);
      padding: 4px 12px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 100px;
    }

    /* Finding card */
    .finding-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 12px;
      overflow: hidden;
      transition: border-color 0.2s;
    }

    .finding-card:hover { border-color: var(--border-active); }

    .finding-header {
      padding: 20px 24px;
      display: flex;
      align-items: flex-start;
      gap: 16px;
      cursor: pointer;
      user-select: none;
    }

    .finding-severity-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
      margin-top: 6px;
      box-shadow: 0 0 8px currentColor;
    }

    .finding-info {
      flex: 1;
      min-width: 0;
    }

    .finding-title {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 4px;
      letter-spacing: -0.01em;
    }

    .finding-subtitle {
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }

    .finding-tag {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }

    .finding-expand-icon {
      font-size: 18px;
      color: var(--text-dim);
      transition: transform 0.2s;
      flex-shrink: 0;
      margin-top: 2px;
    }

    .finding-card.open .finding-expand-icon {
      transform: rotate(180deg);
    }

    .finding-details {
      display: none;
      padding: 0 24px 20px;
      border-top: 1px solid var(--border);
    }

    .finding-card.open .finding-details {
      display: block;
      padding-top: 20px;
    }

    .detail-row {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 8px;
      margin-bottom: 12px;
      align-items: baseline;
    }

    .detail-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-dim);
    }

    .detail-value {
      font-size: 13px;
      color: var(--text);
      word-break: break-all;
    }

    .evidence-box {
      background: rgba(255,255,255,0.02);
      border: 1px solid var(--border);
      border-radius: var(--radius-xs);
      padding: 12px 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    .payload-box {
      background: rgba(250, 27, 27, 0.06);
      border: 1px solid rgba(250, 27, 27, 0.15);
      border-radius: var(--radius-xs);
      padding: 8px 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--accent-light);
      word-break: break-all;
    }

    /* No findings */
    .no-findings {
      text-align: center;
      padding: 60px 24px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
    }

    .no-findings .icon { font-size: 48px; margin-bottom: 16px; }
    .no-findings h3 { font-size: 20px; font-weight: 700; color: ${COLORS.success}; margin-bottom: 8px; }
    .no-findings p { font-size: 14px; color: var(--text-muted); }

    /* Errors section */
    .errors-section {
      margin-bottom: 32px;
    }

    .errors-section h3 {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 12px;
    }

    .error-item {
      padding: 10px 16px;
      background: rgba(255, 171, 64, 0.04);
      border: 1px solid rgba(255, 171, 64, 0.1);
      border-radius: var(--radius-xs);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: ${COLORS.medium};
      margin-bottom: 6px;
    }

    /* Footer */
    .footer {
      text-align: center;
      padding: 32px 0;
      border-top: 1px solid var(--border);
      margin-top: 48px;
      color: var(--text-dim);
      font-size: 12px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }

    .footer a {
      color: var(--accent-light);
      text-decoration: none;
    }

    .footer a:hover { text-decoration: underline; }

    /* Animations */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .animate-in {
      animation: fadeIn 0.4s ease-out;
    }

    .animate-in-delay { animation: fadeIn 0.4s ease-out 0.1s both; }
    .animate-in-delay-2 { animation: fadeIn 0.4s ease-out 0.2s both; }
    .animate-in-delay-3 { animation: fadeIn 0.4s ease-out 0.3s both; }

    /* Print styles */
    @media print {
      body { background: white; color: #111; }
      body::before { display: none; }
      .finding-details { display: block !important; padding-top: 12px !important; }
      .finding-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header animate-in">
      <div class="header-brand">
        ${VULCN_LOGO_SVG}
        <div>
          <h1>vulcn</h1>
          <span>Security Report</span>
        </div>
      </div>
      <div class="header-meta">
        <div>${formatDate(generatedAt)}</div>
        <div>Engine v${escapeHtml(engineVersion)}</div>
      </div>
    </div>

    <!-- Session info -->
    <div class="session-info animate-in-delay">
      <h2>${escapeHtml(session.name)}</h2>
      <div class="session-meta">
        <div class="meta-item">
          <span class="meta-label">Driver</span>
          <span class="meta-value">${escapeHtml(session.driver)}</span>
        </div>
        ${session.driverConfig?.startUrl ? `<div class="meta-item"><span class="meta-label">Target URL</span><span class="meta-value">${escapeHtml(String(session.driverConfig.startUrl))}</span></div>` : ""}
        <div class="meta-item">
          <span class="meta-label">Duration</span>
          <span class="meta-value">${formatDuration(result.duration)}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Generated</span>
          <span class="meta-value">${formatDate(generatedAt)}</span>
        </div>
      </div>
    </div>

    <!-- Stats grid: Risk + Summary -->
    <div class="stats-grid animate-in-delay-2">
      <div class="risk-card">
        <h3>Risk Level</h3>
        <div class="risk-gauge">
          <svg viewBox="0 0 160 160" width="160" height="160">
            <circle cx="80" cy="80" r="68" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="10"/>
            <circle cx="80" cy="80" r="68" fill="none" stroke="${riskColor}" stroke-width="10"
              stroke-dasharray="${(riskPercent / 100) * 427} 427"
              stroke-linecap="round"
              style="filter: drop-shadow(0 0 6px ${riskColor});"/>
          </svg>
          <div class="risk-gauge-label">
            <div class="score" style="color: ${riskColor}">${hasFindings ? riskPercent : 0}</div>
            <div class="label">${riskLabel}</div>
          </div>
        </div>
      </div>

      <div class="summary-card">
        <h3>Execution Summary</h3>
        <div class="summary-stats">
          <div class="stat-box">
            <div class="stat-number" style="color: ${hasFindings ? COLORS.high : COLORS.success}">${totalFindings}</div>
            <div class="stat-label">Findings</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${result.payloadsTested}</div>
            <div class="stat-label">Payloads Tested</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${result.stepsExecuted}</div>
            <div class="stat-label">Steps Executed</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${affectedUrls.length}</div>
            <div class="stat-label">URLs Affected</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Severity breakdown -->
    <div class="severity-breakdown animate-in-delay-2">
      <div class="severity-bars">
        ${["critical", "high", "medium", "low", "info"]
          .map(
            (sev) => `
          <div class="severity-bar-item">
            <div class="severity-bar-count" style="color: ${severityColor(sev)}">${counts[sev]}</div>
            <div class="severity-bar-track">
              <div class="severity-bar-fill" style="width: ${totalFindings ? (counts[sev] / totalFindings) * 100 : 0}%; background: ${severityColor(sev)};"></div>
            </div>
            <div class="severity-bar-label">${sev}</div>
          </div>
        `,
          )
          .join("")}
      </div>
    </div>

    <!-- Findings -->
    <div class="findings-section animate-in-delay-3">
      <div class="findings-header">
        <h3>Findings</h3>
        <span class="findings-count">${totalFindings} total</span>
      </div>

      ${
        hasFindings
          ? findings
              .map(
                (f, i) => `
        <div class="finding-card" onclick="this.classList.toggle('open')">
          <div class="finding-header">
            <div class="finding-severity-dot" style="color: ${severityColor(f.severity)}; background: ${severityColor(f.severity)};"></div>
            <div class="finding-info">
              <div class="finding-title">${escapeHtml(f.title)}</div>
              <div class="finding-subtitle">
                <span class="finding-tag" style="color: ${severityColor(f.severity)}">${f.severity.toUpperCase()}</span>
                <span class="finding-tag">${escapeHtml(f.type)}</span>
                <span class="finding-tag">${escapeHtml(f.stepId)}</span>
              </div>
            </div>
            <span class="finding-expand-icon">▾</span>
          </div>
          <div class="finding-details">
            <div class="detail-row">
              <span class="detail-label">Description</span>
              <span class="detail-value">${escapeHtml(f.description)}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">URL</span>
              <span class="detail-value">${escapeHtml(f.url)}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Payload</span>
              <div class="payload-box">${escapeHtml(f.payload)}</div>
            </div>
            ${
              f.evidence
                ? `
            <div class="detail-row">
              <span class="detail-label">Evidence</span>
              <div class="evidence-box">${escapeHtml(f.evidence)}</div>
            </div>
            `
                : ""
            }
            ${
              f.metadata
                ? `
            <div class="detail-row">
              <span class="detail-label">Metadata</span>
              <div class="evidence-box">${escapeHtml(JSON.stringify(f.metadata, null, 2))}</div>
            </div>
            `
                : ""
            }
          </div>
        </div>
      `,
              )
              .join("")
          : `
        <div class="no-findings">
          <div class="icon">🛡️</div>
          <h3>No Vulnerabilities Detected</h3>
          <p>${result.payloadsTested} payloads were tested across ${result.stepsExecuted} steps with no findings.</p>
        </div>
      `
      }
    </div>

    ${
      result.errors.length > 0
        ? `
    <div class="errors-section">
      <h3>⚠️ Errors During Execution (${result.errors.length})</h3>
      ${result.errors.map((e) => `<div class="error-item">${escapeHtml(e)}</div>`).join("")}
    </div>
    `
        : ""
    }

    <!-- Footer -->
    <div class="footer">
      <div>Generated by ${VULCN_LOGO_SVG.replace(/width="32"/g, 'width="16"').replace(/height="32"/g, 'height="16"')} <strong>Vulcn</strong> — Security Testing Engine</div>
      <div><a href="https://docs.vulcn.dev">docs.vulcn.dev</a></div>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Generate SVG donut chart segments (unused in current layout but available)
 */
function generateDonut(counts: Record<string, number>, total: number): string {
  if (total === 0) return "";
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  const segments = ["critical", "high", "medium", "low", "info"]
    .filter((sev) => counts[sev] > 0)
    .map((sev) => {
      const pct = counts[sev] / total;
      const dash = pct * circumference;
      const seg = `<circle cx="80" cy="80" r="${radius}" fill="none" stroke="${severityColor(sev)}" stroke-width="14"
        stroke-dasharray="${dash} ${circumference - dash}"
        stroke-dashoffset="${-offset}"
        opacity="0.9"/>`;
      offset += dash;
      return seg;
    });

  return `<svg viewBox="0 0 160 160" width="120" height="120" style="transform:rotate(-90deg)">
    <circle cx="80" cy="80" r="${radius}" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="14"/>
    ${segments.join("\n    ")}
  </svg>`;
}
