import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Use fewer workers on CI to reduce flakiness
    maxWorkers: process.env.CI ? 2 : undefined,
    include: ["src/**/*.test.ts", "cli/**/*.test.ts", "test/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    setupFiles: ["test/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      thresholds: {
        // Start with realistic thresholds for v0.1, increase as we add tests
        lines: 30,
        functions: 20,
        branches: 50,
        statements: 30,
      },
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "**/dist/**", "src/tsup.config.ts"],
    },
  },
});
