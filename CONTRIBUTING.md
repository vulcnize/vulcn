# Contributing to Vulcn

Thank you for your interest in contributing to Vulcn! 🎉

## Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/vulcnize/vulcn.git
   cd vulcn
   ```

2. **Install dependencies**

   ```bash
   pnpm install
   ```

3. **Build**

   ```bash
   pnpm build
   ```

4. **Run the CLI locally**
   ```bash
   pnpm vulcn --help
   ```

## Project Structure

```
vulcn/
├── src/          # @vulcn/engine - Core library
├── cli/          # vulcn - CLI application
├── test/         # Test setup
└── examples/     # Example sessions
```

## Commands

| Command           | Description                            |
| ----------------- | -------------------------------------- |
| `pnpm build`      | Build all packages                     |
| `pnpm test`       | Run tests                              |
| `pnpm lint`       | Lint code with oxlint                  |
| `pnpm format`     | Check formatting with prettier         |
| `pnpm format:fix` | Fix formatting                         |
| `pnpm check`      | Run all checks (typecheck, lint, test) |

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `pnpm check` to ensure everything passes
5. **Add a changeset** (see below)
6. Commit your changes (`git commit -m 'feat: add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Changesets (Versioning)

We use [Changesets](https://github.com/changesets/changesets) to manage versions and changelogs.

When you make a change that should be released:

```bash
pnpm changeset
```

This will prompt you to:

1. Select which packages are affected (`@vulcn/engine`, `vulcn`, or both)
2. Choose the semver bump type (patch, minor, major)
3. Write a summary of the change

**When to add a changeset:**

- ✅ New features, bug fixes, breaking changes
- ❌ Documentation-only changes, internal refactors with no API change

## Release Process

Releases are automated via GitHub Actions:

1. PRs with changesets get merged to `main`
2. A "Release" PR is automatically created/updated
3. The Release PR accumulates changes and updates versions + CHANGELOG
4. When the Release PR is merged → packages are published to npm

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding/updating tests
- `chore:` - Maintenance tasks

## Adding New Payloads

New security payloads can be added to `src/payloads.ts`:

```typescript
"your-payload": {
  name: "your-payload",
  category: "xss", // or "sqli", "ssrf", etc.
  description: "Description of your payload set",
  payloads: [
    // Your payloads here
  ],
  detectPatterns: [
    // Regex patterns to detect vulnerability
  ],
}
```

## Code of Conduct

Be kind. Be respectful. Have fun building security tools! 🔐

## Questions?

Open an issue or reach out on [rawlab.dev](https://rawlab.dev).
