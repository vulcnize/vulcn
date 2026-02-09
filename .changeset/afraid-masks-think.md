---
"@vulcn/driver-browser": minor
"vulcn": minor
"@vulcn/engine": minor
---

### Authenticated Scanning

End-to-end support for scanning applications behind login pages.

#### `@vulcn/engine`

- **Credential encryption module** (`src/auth.ts`): AES-256-GCM encryption/decryption for credentials and Playwright storage state, with PBKDF2 key derivation (600k iterations)
- **Auth types**: `FormCredentials`, `HeaderCredentials`, `AuthConfig` with session expiry detection config
- **Scan-level hooks**: `onScanStart` / `onScanEnd` — fire once per scan wrapping all sessions, with `ScanContext` providing full session list and scan metadata
- **`onScanEnd` result transformation**: uses `callHookPipe` so plugins can transform the aggregate `RunResult` (e.g. deduplication, risk scoring)
- **v2 session format**: `.vulcn/` directory structure with manifest, encrypted auth state, and config alongside session files
- **`CrawlOptions.storageState`**: pass authenticated browser state (cookies + localStorage) to the crawler
- **New exports**: `ScanContext`, `encryptCredentials`, `decryptCredentials`, `encryptStorageState`, `decryptStorageState`, `getPassphrase`

#### `@vulcn/driver-browser`

- **Authenticated crawling**: `crawlAndBuildSessions` accepts `storageState` via `CrawlOptions` and injects it into the Playwright browser context
- **Authenticated scanning**: `BrowserRunner` reads `storageState` from `RunOptions` and applies it to the scanner's browser context
- **Login form auto-detection**: `performLogin` navigates to the login URL, auto-detects username/password fields, fills credentials, and submits
- **Storage state capture**: after successful login, captures full browser storage state (cookies, localStorage, sessionStorage)

#### `vulcn` (CLI)

- **`vulcn store`**: new command to encrypt and save credentials (form-based or header-based) to `.vulcn/auth.enc`
- **`vulcn crawl --creds`**: decrypt credentials → perform login → capture storage state → crawl all authenticated pages
- **`vulcn run --creds`**: decrypt credentials → perform login → inject storage state into scanner browser context → run all payloads authenticated
- **Auth state persistence**: crawl saves encrypted auth state + config alongside sessions in the output directory
