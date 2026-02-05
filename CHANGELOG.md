# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-05

### Added

- Initial release of Vulcn - Security testing recorder & runner
- **Session Recording** - Record browser interactions (clicks, form fills, navigation)
- **Session Replay** - Replay sessions with security payloads injected
- **Smart Browser Detection** - Uses system Chrome/Edge first, Playwright fallback
- **Built-in Payloads** - XSS and SQL injection payload sets
- **YAML Sessions** - Human-readable session format with Zod validation
- **Cross-Platform** - macOS, Linux, and Windows support

### CLI Commands

- `vulcn record` - Record browser interactions
- `vulcn run` - Replay session with payloads
- `vulcn payloads` - List available payloads
- `vulcn doctor` - Check browser availability
- `vulcn install` - Install Playwright browsers

[0.1.0]: https://github.com/rawlab-dev/vulcn/releases/tag/v0.1.0
