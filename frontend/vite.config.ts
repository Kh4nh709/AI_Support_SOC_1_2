import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Every entry point runs the tests in UTC: `npm test`, a plain `npx vitest`, an IDE runner, CI. The config is loaded in the
// main process before Vitest forks its workers, so they inherit it. `format.test.ts` proves the +07 display conversion and
// is only meaningful when the host zone is not +07; this host is +07, and the npm script alone used to carry the pin.
process.env.TZ = "UTC";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Development only: the same origin as production, so the client never needs CORS.
    // `ws: true` carries the /api/ws upgrade (DEC-162) to the backend as well.
    proxy: { "/api": { target: "http://127.0.0.1:8000", ws: true } },
  },
  build: {
    // The CSP has `font-src 'self'` and no `data:`: a font Vite inlined as a data: URI would be blocked.
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
