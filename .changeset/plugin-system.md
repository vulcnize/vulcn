---
"@vulcn/plugin-detect-reflection": minor
"@vulcn/plugin-detect-xss": minor
"@vulcn/plugin-payloads": minor
"vulcn": minor
"@vulcn/engine": minor
---

## v0.2.0 - Plugin System & CLI Enhancements

### @vulcn/engine

- **Plugin System**: Complete hook-based plugin architecture with lifecycle management
- **PluginManager**: New class for loading, configuring, and orchestrating plugins
- Added `hasPlugin()` method to check if a plugin is already loaded
- Added `reflection` as a valid `PayloadCategory` type
- Full TypeScript types for plugin development (`VulcnPlugin`, `PluginContext`, `DetectContext`, etc.)

### vulcn (CLI)

- **`vulcn init`**: Create `vulcn.config.yml` with default plugins pre-configured
- **`vulcn plugin` commands**:
  - `vulcn plugin list` - List configured plugins
  - `vulcn plugin add <name>` - Add a plugin to configuration
  - `vulcn plugin remove <name>` - Remove a plugin from configuration
  - `vulcn plugin enable <name>` - Re-enable a disabled plugin
  - `vulcn plugin disable <name>` - Disable a plugin without removing it
- **Auto-loading**: CLI automatically loads `@vulcn/plugin-detect-xss` if not already configured

### @vulcn/plugin-payloads

- Official payload loader plugin
- Built-in payloads (13 sets, 91 payloads): XSS, SQLi, SSRF, XXE, command injection, path traversal, open redirect
- PayloadsAllTheThings integration for fetching community payloads
- Custom payload file loading (YAML/JSON)

### @vulcn/plugin-detect-xss

- Execution-based XSS detection plugin
- Monitors `alert()`, `confirm()`, `prompt()` dialogs
- Console marker detection (`console.log('VULCN_XSS:...')`)
- Configurable alert patterns and severity levels

### @vulcn/plugin-detect-reflection (NEW)

- Pattern-based reflection detection plugin
- Detects when payloads appear in response HTML
- Context-aware detection (body, script, attribute)
- Dangerous pattern proximity detection (onerror, onclick, javascript:, etc.)
- Configurable severity per context type
