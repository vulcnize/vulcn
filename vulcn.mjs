#!/usr/bin/env node

import module from "node:module";

// Enable Node.js module compile cache for faster startup
// https://nodejs.org/api/module.html#module-compile-cache
if (module.enableCompileCache && !process.env.NODE_DISABLE_COMPILE_CACHE) {
  try {
    module.enableCompileCache();
  } catch {
    // Ignore errors (older Node versions)
  }
}

await import("./cli/dist/index.js");
