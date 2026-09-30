// The serving contract of the spec §2 and §6, pinned where a drift would otherwise go unseen: nginx.conf
// (CSP, headers, proxy), the `ui` service of docker-compose.yml (localhost only), the Dockerfile, and
// the "no third-party host" rule for fonts and scripts.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
  "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

const nginx = readFileSync("nginx.conf", "utf8");
const dockerfile = readFileSync("Dockerfile", "utf8");
const compose = readFileSync(join("..", "docker-compose.yml"), "utf8");

/** The body of one `location` block of nginx.conf. */
const location = (path: string): string => {
  const start = nginx.search(new RegExp(`location\\s+${path.replace(/\//g, "\\/")}\\s*\\{`));
  if (start < 0) return "";
  const open = nginx.indexOf("{", start);
  return nginx.slice(open + 1, nginx.indexOf("}", open));
};

/** The block of the `ui` service, up to the next top-level key of `services:`. */
const uiService = (): string => /^ {2}ui:\r?\n((?:(?: {4}.*)?\r?\n)*)/m.exec(compose)?.[1] ?? "";

const walk = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });

describe("nginx.conf", () => {
  it("sends the CSP of the spec, verbatim", () => {
    const sent = /add_header\s+Content-Security-Policy\s+"([^"]*)"\s+always;/.exec(nginx)?.[1];
    expect(sent).toBe(CSP);
  });

  it("sends nosniff and no-referrer, and every header on error pages too", () => {
    expect(nginx).toMatch(/add_header\s+X-Content-Type-Options\s+nosniff\s+always;/);
    expect(nginx).toMatch(/add_header\s+Referrer-Policy\s+no-referrer\s+always;/);
    const headers = nginx.match(/^\s*add_header\s.*$/gm) ?? [];
    expect(headers).toHaveLength(3);
    for (const line of headers) expect(line).toMatch(/\balways;\s*$/);
  });

  it("proxies the WebSocket upgrade on /api/ws to the app", () => {
    const ws = location("/api/ws");
    expect(ws).toMatch(/proxy_pass\s+http:\/\/app:8000;/);
    expect(ws).toMatch(/proxy_http_version\s+1\.1;/);
    expect(ws).toMatch(/proxy_set_header\s+Upgrade\s+\$http_upgrade;/);
    expect(ws).toMatch(/proxy_set_header\s+Connection\s+"upgrade";/);
    expect(ws).toMatch(/proxy_read_timeout\s+1h;/);
  });

  it("proxies /api/ to the app on the same origin and leaves Authorization alone", () => {
    expect(location("/api/")).toMatch(/proxy_pass\s+http:\/\/app:8000;/);
    expect(nginx).not.toMatch(/Authorization/i);
  });

  it("serves the SPA and falls back to index.html for an unknown path", () => {
    expect(nginx).toMatch(/root\s+\/usr\/share\/nginx\/html;/);
    expect(location("/")).toMatch(/try_files\s+\$uri\s+\/index\.html;/);
  });
});

describe("the ui service", () => {
  it("is in docker-compose.yml", () => {
    expect(uiService()).not.toBe("");
  });

  it("binds 127.0.0.1:8080:80 and nothing else", () => {
    const ports = [...uiService().matchAll(/["']?(\d[\d.]*:\d+:\d+|\d+:\d+)["']?/g)].map(
      (m) => m[1],
    );
    expect(ports).toEqual(["127.0.0.1:8080:80"]);
    expect(uiService()).toMatch(/ports:\s*\["127\.0\.0\.1:8080:80"\]/);
  });

  it("builds ./frontend, waits for app and restarts unless stopped", () => {
    const ui = uiService();
    expect(ui).toMatch(/build:\s*\.\/frontend\b/);
    expect(ui).toMatch(/depends_on:\s*\[app\]/);
    expect(ui).toMatch(/restart:\s*unless-stopped/);
  });
});

describe("Dockerfile", () => {
  it("builds with Node 22 from the lockfile and serves dist with nginx", () => {
    expect(dockerfile).toMatch(/FROM node:22-alpine AS build/);
    expect(dockerfile).toMatch(/COPY package\.json package-lock\.json \.\//);
    expect(dockerfile).toMatch(/RUN npm ci\b/);
    expect(dockerfile).toMatch(/RUN npm run build/);
    expect(dockerfile).toMatch(/FROM nginx:alpine/);
    expect(dockerfile).toMatch(/COPY nginx\.conf \/etc\/nginx\/conf\.d\/default\.conf/);
    expect(dockerfile).toMatch(/COPY --from=build \/app\/dist \/usr\/share\/nginx\/html/);
  });

  it("keeps the host's node_modules out of the build context", () => {
    const ignored = readFileSync(".dockerignore", "utf8").split(/\r?\n/);
    expect(ignored).toContain("node_modules");
    expect(ignored).toContain("dist");
  });
});

describe("no third-party host", () => {
  const own = [...walk("src"), "index.html"].filter((p) => !/\.test\./.test(p));

  it("scans the page and the source", () => {
    expect(own).toContain("index.html");
    expect(own).toContain(join("src", "main.tsx"));
    expect(own).toContain(join("src", "styles.css"));
  });

  // Built from parts so this file does not itself carry the names it forbids: the card's own grep
  // for the Google Fonts host over src/ and index.html must count 0 in every file.
  const hosts = [
    ["fonts", "googleapis"],
    ["fonts", "gstatic"],
    ["cdn", "jsdelivr"],
    ["unpkg", "com"],
    ["cdnjs", "cloudflare"],
  ].map((parts) => parts.join("."));

  it.each(hosts)("nothing names %s", (host) => {
    expect(own.filter((p) => readFileSync(p, "utf8").includes(host))).toEqual([]);
  });

  it("index.html has no inline script, no inline style and no absolute URL", () => {
    const html = readFileSync("index.html", "utf8");
    expect(html).not.toMatch(/<script(?![^>]*\ssrc=)/);
    expect(html).not.toMatch(/<style/);
    expect(html).not.toMatch(/\son[a-z]+=/);
    expect(html).not.toMatch(/https?:\/\//);
  });
});
