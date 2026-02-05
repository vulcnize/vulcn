# 🔐 Vulcn

**Security testing made simple.** Record once, test with payloads, find vulnerabilities.

[![CI](https://github.com/vulcnize/vulcn/actions/workflows/ci.yml/badge.svg)](https://github.com/vulcnize/vulcn/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/vulcn.svg)](https://www.npmjs.com/package/vulcn)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Quick Start

```bash
# Install globally
npm install -g vulcn

# Record a session
vulcn record --url https://example.com/login

# Run with XSS payloads
vulcn run session.vulcn.yml --payload xss-basic
```

**Zero-config browser support** — Vulcn uses your existing Chrome or Edge. No browser downloads needed.

---

## 🎯 What is Vulcn?

Vulcn is a security testing tool that:

1. **Records** your browser interactions (clicks, form inputs, navigation)
2. **Replays** them with security payloads injected into input fields
3. **Detects** vulnerabilities like XSS and SQL injection

Think of it as **Playwright + Burp Suite**, but simpler and focused on automated payload testing.

---

## 🚀 Features

| Feature               | Description                                         |
| --------------------- | --------------------------------------------------- |
| 🎬 **Record**         | Capture browser sessions as replayable YAML files   |
| 🔍 **Test**           | Inject XSS, SQLi, and custom payloads automatically |
| 🌐 **Cross-platform** | Works on macOS, Linux, and Windows                  |
| 🚫 **Zero-config**    | Uses system Chrome/Edge by default                  |
| 📊 **CI/CD Ready**    | Exit codes for pipeline integration                 |
| 🔧 **Extensible**     | Add custom payloads and detection patterns          |

---

## 📦 Installation

### CLI

```bash
npm install -g vulcn
```

### Programmatic API

```bash
npm install @vulcn/engine
```

```typescript
import { Recorder, Runner, parseSession } from "@vulcn/engine";

// Record programmatically
const session = await Recorder.start("https://example.com");
// ... user interacts ...
const recorded = await session.stop();

// Run with payloads
const result = await Runner.execute(recorded, ["xss-basic"]);
console.log(result.findings);
```

---

## 🎬 Recording

Start recording a session:

```bash
vulcn record --url https://target.com/login
```

Options:

- `--url, -u` — Start URL (required)
- `--output, -o` — Output file (default: `session.vulcn.yml`)
- `--browser, -b` — Browser (`chromium`, `firefox`, `webkit`)
- `--headless` — Run headless

When recording:

1. Browser opens to your start URL
2. Interact normally (fill forms, click buttons)
3. Press `Ctrl+C` to stop and save

---

## 🔍 Running Tests

Run a recorded session with payloads:

```bash
vulcn run session.vulcn.yml --payload xss-basic --payload sqli-basic
```

Options:

- `--payload, -p` — Payload to use (can specify multiple)
- `--headless` — Run headless (default: true)
- `--browser, -b` — Browser to use

### Built-in Payloads

| Payload      | Category | Description                    |
| ------------ | -------- | ------------------------------ |
| `xss-basic`  | XSS      | Script tags and event handlers |
| `xss-event`  | XSS      | Event handler injection        |
| `xss-svg`    | XSS      | SVG-based XSS                  |
| `sqli-basic` | SQLi     | Basic SQL injection            |
| `sqli-error` | SQLi     | Error-based SQLi detection     |
| `sqli-blind` | SQLi     | Blind SQLi payloads            |

List all payloads:

```bash
vulcn payloads
```

---

## 📄 Session Format

Sessions are stored as YAML:

```yaml
version: "1"
name: Login Test
recordedAt: "2026-02-05T12:00:00Z"
browser: chromium
viewport:
  width: 1280
  height: 720
startUrl: https://example.com/login
steps:
  - id: step_001
    type: navigate
    url: https://example.com/login
    timestamp: 0
  - id: step_002
    type: input
    selector: input[name="username"]
    value: testuser
    injectable: true
    timestamp: 1500
  - id: step_003
    type: click
    selector: button[type="submit"]
    timestamp: 3000
```

---

## 🩺 Browser Management

Check available browsers:

```bash
vulcn doctor
```

Install Playwright browsers (if needed):

```bash
vulcn install chromium
vulcn install --all  # Install all browsers
```

---

## 🔧 CI/CD Integration

Vulcn returns exit code `1` when vulnerabilities are found:

```yaml
# GitHub Actions example
- name: Security Test
  run: |
    npm install -g vulcn
    vulcn run tests/login.vulcn.yml --payload xss-basic --headless
```

---

## 📚 Documentation

- [Contributing Guide](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)

---

## 🛣️ Roadmap

- [ ] HTML/JSON reports
- [ ] Custom payload definitions
- [ ] SSRF and path traversal payloads
- [ ] Authenticated session support
- [ ] API endpoint testing
- [ ] Vulnerability severity scoring

---

## 📝 License

[MIT](./LICENSE) © [rawlab](https://rawlab.dev)

---

<p align="center">
  Made with ❤️ by <a href="https://rawlab.dev">rawlab</a>
</p>
