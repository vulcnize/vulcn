import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Use single thread on CI for Windows compatibility
    pool: "threads",
    poolOptions: {
      threads: {
        singleThread: !!process.env.CI,
      },
    },
    include: [
      "src/**/*.test.ts",
      "cli/**/*.test.ts",
      "test/**/*.test.ts",
      "plugins/**/*.test.ts",
      "drivers/**/*.test.ts",
    ],
    exclude: ["**/node_modules/**", "**/dist/**"],
    setupFiles: ["test/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      thresholds: {
        // 60% coverage required for stability
        lines: 60,
        functions: 60,
        branches: 60,
        statements: 60,
      },
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "**/dist/**",
        "src/tsup.config.ts",
        // Browser-dependent modules require real browser for testing
        // These are tested via integration tests
        "src/browser.ts",
        "src/recorder.ts",
        "src/runner.ts",
        // Type-only files
        "src/types.ts",
      ],
    },
  },
});
