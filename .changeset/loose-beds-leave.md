---
"@vulcn/plugin-payloads": minor
"@vulcn/driver-browser": minor
"@vulcn/engine": minor
---

## Driver-Based Architecture

Introduces a modular driver system that makes Vulcn extensible to different recording targets beyond web browsers.

### New Package: `@vulcn/driver-browser`

A new package that encapsulates all Playwright-based browser recording and replay functionality:

- **BrowserRecorder** - Records browser interactions (clicks, inputs, navigation)
- **BrowserRunner** - Replays sessions with payload injection and detection
- **Browser utilities** - Smart browser launching with system Chrome/Edge fallback

Step types: `browser.navigate`, `browser.click`, `browser.input`, `browser.keypress`, `browser.scroll`, `browser.wait`

### New in `@vulcn/engine`

#### DriverManager

New `DriverManager` class for loading and orchestrating drivers:

- `register(driver)` - Register a driver
- `load(nameOrPath)` - Load driver from npm or local file
- `startRecording(driverName, config)` - Start recording with a driver
- `execute(session, pluginManager)` - Execute session with payloads
- `getForSession(session)` - Get driver for a session

#### Driver Interfaces

New TypeScript interfaces for building custom drivers:

- `VulcnDriver` - Main driver definition
- `RecorderDriver` - Recording interface
- `RunnerDriver` - Replay/execution interface
- `RecordingHandle` - Handle for controlling active recordings
- `Session` - Generic session format with `driver` field
- `Step` - Generic step format with namespaced types

### Session Format Changes

Sessions now include a `driver` field to specify which driver handles them:

```yaml
name: My Session
driver: browser
driverConfig:
  browser: chromium
  startUrl: https://example.com
steps:
  - type: browser.navigate
  - type: browser.input
```

### Documentation

- New "Drivers" tab in docs with overview, browser driver reference, and custom driver guide
- Updated API reference with DriverManager documentation
- Simplified README pointing to docs.vulcn.dev

### Breaking Changes

None - existing code continues to work. Legacy `Recorder` and `Runner` exports are preserved but deprecated.
