# Vulcn Examples

Example usage of Vulcn for security testing.

## Basic Usage

```bash
# Record a session
vulcn record --url https://example.com -o login-flow.vulcn.yml

# Run with XSS payloads
vulcn run login-flow.vulcn.yml --payload xss-basic

# Run with multiple payloads
vulcn run login-flow.vulcn.yml --payload xss-basic sqli-basic
```

## Programmatic Usage

```typescript
import { Recorder, Runner, parseSession } from "@vulcn/core";
import { readFile } from "node:fs/promises";

// Recording
const session = await Recorder.start("https://example.com");
// ... user interacts ...
const recorded = await session.stop();

// Running
const yaml = await readFile("session.vulcn.yml", "utf-8");
const session = parseSession(yaml);

const result = await Runner.execute(session, ["xss-basic"], {
  headless: true,
  onFinding: (finding) => {
    console.log("Found:", finding.title);
  },
});

console.log(`Found ${result.findings.length} vulnerabilities`);
```
