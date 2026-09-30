import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig, devices } from "@playwright/test";

// The end-to-end suite runs against a scratch stack (scripts/ui_e2e_stack.sh): its own database, the API,
// the worker, an LLM stub and `vite preview` of the production build, all on 127.0.0.1. Playwright starts
// the script as its webServer and stops it with SIGTERM, so the script's trap can drop the database.
const WEB_PORT = 18080;

// The directory the script makes for the run's secrets (a mode-700 directory it removes on exit). It is
// chosen once, in the main process: the workers inherit the variable, and fixtures.ts reads it.
const STATE_DIR =
  process.env.E2E_STATE_DIR ?? join(tmpdir(), `soc-ui-e2e-${randomBytes(6).toString("hex")}`);
process.env.E2E_STATE_DIR = STATE_DIR;

export default defineConfig({
  testDir: "./e2e",
  // One worker, in file order: the specs share one database and one worker process of the stack, and a
  // logout of e2e-t1 (spec "401") ends every token that user holds.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "bash ../scripts/ui_e2e_stack.sh soc_ui_e2e_test",
    url: `http://127.0.0.1:${WEB_PORT}`,
    reuseExistingServer: false,
    // The build of the UI, the migration of the database and the seed of the users all happen first.
    timeout: 240_000,
    gracefulShutdown: { signal: "SIGTERM", timeout: 60_000 },
    stdout: "pipe",
    stderr: "pipe",
    env: { PY: process.env.PY ?? "python3", E2E_STATE_DIR: STATE_DIR },
  },
});
