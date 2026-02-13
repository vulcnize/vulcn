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

Docs: align all documentation with v0.9 refactored architecture

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
