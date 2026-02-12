---
"@vulcn/plugin-detect-reflection": patch
"@vulcn/plugin-detect-sqli": patch
"@vulcn/plugin-detect-xss": patch
"@vulcn/plugin-payloads": patch
"@vulcn/driver-browser": patch
"@vulcn/plugin-passive": patch
"@vulcn/plugin-report": patch
"vulcn": patch
"@vulcn/engine": patch
---

Improve reflection detection accuracy — eliminate XSS false positives

**@vulcn/driver-browser**

- `checkReflection`: verbatim-only matches now use type `"reflection"` instead of the payload category, distinguishing low-confidence reflection from confirmed exploitation
- `checkReflection`: detect patterns only run when the payload appears verbatim in rendered content, preventing false matches on partially-encoded reflections
- `checkReflection`: encoding suppression now explicitly checks for dangerous HTML chars before calling `isHtmlEncoded`
- `confirmedTypes` early-exit now only triggers on high-confidence findings (type matches payload category), allowing the scanner to continue trying payloads that may trigger actual execution (e.g. `alert()`)

**@vulcn/plugin-detect-reflection**

- Skip payloads without dangerous HTML characters — reflecting plain text like `alert(1)` is not a vulnerability
- Include authentication cookies when fetching raw content for encoding checks
- Simplified encoding check flow

**benchmarks**

- Exclude `"reflection"` findings from XSS benchmark evaluation (reflection ≠ confirmed XSS)
- Add Youden's J score with qualitative label to per-case summary output

**WAVSEP XSS benchmark (before → after)**

- False Positives: 6 → 0
- True Negatives: 1 → 7
- Precision: 88.5% → 100%
- Youden's J: 0.051 → 0.479
