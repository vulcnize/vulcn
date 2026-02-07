# @vulcn/plugin-detect-sqli

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
