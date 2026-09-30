import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

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
