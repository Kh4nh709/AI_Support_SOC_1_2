// Build a portable preview. The preview server serves a single HTML file.
import { build } from "vite";
import { inventory } from "./string-inventory.mjs";
import react from "@vitejs/plugin-react";
import tailwind from "@tailwindcss/vite";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const result = await build({
  root,
  configFile: false,
  publicDir: false,
  plugins: [react(), tailwind()],
  resolve: {
    alias: [{ find: /^(?:.*\/live\/|\.\/)LiveProvider$/, replacement: resolve(here, "live.js") }],
  },
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __WIRE_STRINGS__: JSON.stringify(inventory(root)),
  },
  build: {
    write: false,
    modulePreload: false,
    reportCompressedSize: false,
    cssCodeSplit: false,
    rolldownOptions: {
      input: resolve(here, "preview.jsx"),
      output: { format: "es", codeSplitting: false },
    },
  },
});
const output = result.output;
const js = output.find((x) => x.type === "chunk").code.replaceAll(/<\/script/gi, "<\\/script");
const css = output.find((x) => x.fileName.endsWith(".css")).source;
await writeFile(
  resolve(root, "../docs/wireframe.html"),
  `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wireframe · AI Support SOC</title><style>${css}</style></head><body><div id="root"></div><script type="module">${js}</script></body></html>\n`,
);
