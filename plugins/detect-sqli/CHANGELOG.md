# @vulcn/plugin-detect-sqli

## 0.1.2

### Patch Changes

- 90b60ed: Docs: align all documentation with v0.9 refactored architecture
  - Replace all `vulcn.config.yml` references with `.vulcn.yml` flat config
  - Remove `vulcn plugin` command (deleted `cli/plugin.mdx`, removed from nav)
  - Update `vulcn run` examples to argless format (auto-discovers sessions from `sessions/`)
  - Update auth path from `.vulcn/auth.enc` to `auth/state.enc`
  - Replace `driverManager`/`pluginManager` singletons with `new DriverManager()`/`new PluginManager()` + `loadFromConfig()`
  - Replace `Runner.execute()` with `DriverManager.executeScan()`
  - Remove legacy exports section from API overview, add Project Config exports
  - Rewrite plugins overview to document auto-loading from flat config keys
  - Update drivers/browser config, auth workflow, and programmatic examples
  - Update drivers/creating-drivers to remove config-based driver registration
  - Rewrite plugin-api.mdx Session/Step types and PluginManager methods
  - Fix plugin-report, plugin-passive, plugin-payloads, plugin-detect-sqli examples

- 90b60ed: Improve reflection detection accuracy — eliminate XSS false positives

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

## 0.1.1

### Patch Changes

- d4fd4df: ### Breaking: Remove built-in payloads, PayloadBox is now the default

  All hardcoded built-in payloads have been removed. Payloads are now fetched on demand from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), the largest community-curated security payload collection.

  **`@vulcn/engine`**
  - Removed `"builtin"` from `PayloadSource` type — valid sources are now `"custom" | "payloadbox" | "plugin"`

  **`@vulcn/plugin-payloads`**
  - Removed all built-in payload sets and the `builtin`, `include`, `exclude`, `payloadbox` config options
  - New config: `types` (short aliases), `limit`, `files`
  - Short aliases for payload types: `xss`, `sqli`, `xxe`, `cmd`, `redirect`, `traversal`
  - Removed legacy `payloadbox:` prefix — use short aliases directly

  **`vulcn` (CLI)**
  - Default payload changed from `xss-basic` to `xss` (PayloadBox)
  - `vulcn payloads` now lists PayloadBox types with short aliases
  - `vulcn run` help updated with payload type reference
  - Auto-loads `@vulcn/plugin-detect-sqli` when `sqli` payloads are used

  **`@vulcn/plugin-detect-sqli`**
  - SQL injection detection plugin with error-based, response diffing, and timing-based strategies
  - Auto-loaded by CLI when SQLi payloads are selected
