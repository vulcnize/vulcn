# 🔐 Vulcn

**Security testing made simple.** Record once, test with payloads, find vulnerabilities.

[![CI](https://github.com/vulcnize/vulcn/actions/workflows/ci.yml/badge.svg)](https://github.com/vulcnize/vulcn/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/vulcn.svg)](https://www.npmjs.com/package/vulcn)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## ⚡ Quick Start

```bash
# Install globally
npm install -g vulcn

# Record a session (opens browser)
vulcn record https://example.com/login

# Run with security payloads
vulcn run session.vulcn.yml
```

**Zero-config browser support** — Vulcn uses your existing Chrome or Edge. No browser downloads needed.

---

## 🎯 What is Vulcn?

Vulcn is a **driver-based security testing framework** that:

1. **Records** interactions (browser clicks, API requests, CLI commands)
2. **Replays** them with security payloads injected
3. **Detects** vulnerabilities via plugins (XSS, SQLi, reflection, etc.)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     vulcn CLI                           │
├─────────────────────────────────────────────────────────┤
│                   @vulcn/engine                         │
│  ┌─────────────────────┐  ┌──────────────────────────┐  │
│  │   DriverManager     │  │    PluginManager         │  │
│  │   • browser         │  │    • payloads            │  │
│  │   • api (soon)      │  │    • detect-xss          │  │
│  │   • cli (soon)      │  │    • detect-reflection   │  │
│  └─────────────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Packages

| Package                                                                                            | Description                              |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| [`vulcn`](https://www.npmjs.com/package/vulcn)                                                     | CLI tool                                 |
| [`@vulcn/engine`](https://www.npmjs.com/package/@vulcn/engine)                                     | Core engine with driver & plugin systems |
| [`@vulcn/driver-browser`](https://www.npmjs.com/package/@vulcn/driver-browser)                     | Browser recording with Playwright        |
| [`@vulcn/plugin-payloads`](https://www.npmjs.com/package/@vulcn/plugin-payloads)                   | XSS, SQLi, SSRF payloads                 |
| [`@vulcn/plugin-detect-xss`](https://www.npmjs.com/package/@vulcn/plugin-detect-xss)               | Execution-based XSS detection            |
| [`@vulcn/plugin-detect-reflection`](https://www.npmjs.com/package/@vulcn/plugin-detect-reflection) | Pattern-based reflection detection       |

---

## 📚 Documentation

**Full documentation is available at [docs.vulcn.dev](https://docs.vulcn.dev)**

- [Quickstart Guide](https://docs.vulcn.dev/quickstart)
- [CLI Reference](https://docs.vulcn.dev/cli/overview)
- [Driver System](https://docs.vulcn.dev/drivers/overview)
- [Plugin System](https://docs.vulcn.dev/plugins/overview)
- [API Reference](https://docs.vulcn.dev/api/overview)

---

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and guidelines.

---

## 📝 License

[AGPL-3.0](./LICENSE) © [rawlab](https://rawlab.dev)

---

<p align="center">
  Made with ❤️ by <a href="https://rawlab.dev">rawlab</a>
</p>
