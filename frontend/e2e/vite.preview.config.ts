// The config `vite preview` runs under in scripts/ui_e2e_stack.sh: the production build in dist/, on the
// e2e port of 127.0.0.1, with /api and its websocket upgrade sent to the e2e API (also 127.0.0.1). The
// main vite.config.ts proxies to :8000 for development; the two must not share a port.
import { defineConfig } from "vite";

export default defineConfig({
  preview: {
    host: "127.0.0.1",
    port: 18080,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:18000", ws: true } },
  },
});
