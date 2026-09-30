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

/** Every `location` block of nginx.conf: what follows the keyword (`= /index.html`) and the body. */
const locations = (): { match: string; body: string }[] =>
  [...nginx.matchAll(/^\s*location\s+([^{\n]+?)\s*\{/gm)].map((m) => {
    const open = (m.index ?? 0) + m[0].length;
    return { match: m[1] ?? "", body: nginx.slice(open, nginx.indexOf("}", open)) };
  });

/** The body of one `location` block, named by its match text (`/api/ws`, `= /index.html`). */
const location = (match: string): string => locations().find((l) => l.match === match)?.body ?? "";

/** nginx.conf with every location block cut out: what the `server` block itself says. */
const serverLevel = (): string => locations().reduce((text, l) => text.replace(l.body, ""), nginx);

const HEADERS = [
  /add_header\s+Content-Security-Policy\s+"[^"]*"\s+always;/,
  /add_header\s+X-Content-Type-Options\s+nosniff\s+always;/,
  /add_header\s+Referrer-Policy\s+no-referrer\s+always;/,
];

/** The block of the `ui` service, up to the next top-level key of `services:`. */
const uiService = (): string => /^ {2}ui:\r?\n((?:(?: {4}.*)?\r?\n)*)/m.exec(compose)?.[1] ?? "";

const walk = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });

describe("nginx.conf", () => {
  it("sends the CSP of the spec, verbatim, wherever nginx.conf sends one", () => {
    const sent = [...nginx.matchAll(/add_header\s+Content-Security-Policy\s+"([^"]*)"\s+always;/g)];
    // The server block, and the `= /index.html` location that has headers of its own.
    expect(sent.length).toBeGreaterThanOrEqual(2);
    for (const m of sent) expect(m[1]).toBe(CSP);
  });

  it("sends nosniff and no-referrer, and every header on error pages too", () => {
    const server = serverLevel();
    for (const header of HEADERS) expect(server).toMatch(header);
    const all = nginx.match(/^\s*add_header\s.*$/gm) ?? [];
    for (const line of all) expect(line).toMatch(/\balways;\s*$/);
  });

  // nginx inherits `add_header` into a location only when that location has none of its own, so a
  // location that adds one header silently drops the CSP unless it repeats all three.
  it("repeats the three headers in every location that adds a header of its own", () => {
    const own = locations().filter((l) => /\badd_header\b/.test(l.body));
    expect(own.map((l) => l.match)).toContain("= /index.html");
    for (const l of own) {
      for (const header of HEADERS) expect(l.body, `location ${l.match}`).toMatch(header);
    }
  });

  it("proxies the WebSocket upgrade on /api/ws to the app", () => {
    const ws = location("/api/ws");
    expect(ws).toMatch(/proxy_pass\s+\$app_upstream;/);
    expect(ws).toMatch(/proxy_http_version\s+1\.1;/);
    expect(ws).toMatch(/proxy_set_header\s+Host\s+\$host;/);
    expect(ws).toMatch(/proxy_set_header\s+Upgrade\s+\$http_upgrade;/);
    expect(ws).toMatch(/proxy_set_header\s+Connection\s+"upgrade";/);
    expect(ws).toMatch(/proxy_read_timeout\s+1h;/);
  });

  it("proxies /api/ to the app on the same origin and leaves Authorization alone", () => {
    const api = location("/api/");
    expect(api).toMatch(/proxy_pass\s+\$app_upstream;/);
    expect(api).toMatch(/proxy_set_header\s+Host\s+\$host;/);
    expect(nginx).not.toMatch(/Authorization/i);
  });

  // `app` gets a new address when its container is recreated. A literal `proxy_pass http://app:8000`
  // resolves the name once, at start, and answers 502 to every call afterwards: the address must come
  // from a variable, asked of Docker's resolver again every few seconds.
  it("asks Docker's resolver for the app again and again, never once at start", () => {
    expect(serverLevel()).toMatch(/^\s*resolver\s+127\.0\.0\.11\s+valid=10s\s+ipv6=off;/m);
    expect(serverLevel()).toMatch(/^\s*set\s+\$app_upstream\s+http:\/\/app:8000;/m);
    expect(nginx).not.toMatch(/proxy_pass\s+https?:\/\//);
    expect((nginx.match(/proxy_pass\s+\$app_upstream;/g) ?? []).length).toBe(2);
  });

  it("serves the SPA and falls back to index.html for an unknown path", () => {
    expect(nginx).toMatch(/root\s+\/usr\/share\/nginx\/html;/);
    expect(location("/")).toMatch(/try_files\s+\$uri\s+\/index\.html;/);
  });

  // After a redeploy the hashed chunks of the old build are gone. A request for one must be a 404,
  // not the HTML of the SPA (which the browser would fail to parse as a script), and index.html
  // itself must be revalidated so the page always points at the chunks that exist.
  it("answers 404 for a missing asset and revalidates index.html", () => {
    expect(location("/assets/")).toMatch(/try_files\s+\$uri\s+=404;/);
    expect(location("= /index.html")).toMatch(/add_header\s+Cache-Control\s+"no-cache"\s+always;/);
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

describe("the Makefile ui targets", () => {
  const makefile = readFileSync(join("..", "Makefile"), "utf8");
  const scripts = (
    JSON.parse(readFileSync("package.json", "utf8")) as {
      scripts: Record<string, string>;
    }
  ).scripts;

  /** The recipe lines of one target, tab-indented up to the next blank line. */
  const recipe = (target: string): string[] =>
    (new RegExp(`^${target}:\\n((?:\\t.*\\n)+)`, "m").exec(makefile)?.[1] ?? "")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

  // Without node_modules, `npx tsc` downloads the unrelated `tsc` package and "passes"; `npm run`
  // uses the project's own binaries or fails loudly.
  it("runs eslint, tsc and prettier through the package scripts, never npx", () => {
    const lint = recipe("ui-lint");
    expect(lint).toContain("cd frontend && npm run lint");
    expect(lint).toContain("cd frontend && npm run typecheck");
    expect(lint).toContain("cd frontend && npm run format:check");
    for (const target of ["ui-install", "ui-lint", "ui-test", "ui-e2e", "ui-build"]) {
      expect(recipe(target), target).not.toEqual([]);
      for (const line of recipe(target)) expect(line, target).not.toMatch(/\bnpx\b/);
    }
  });

  it("maps those scripts to the project's eslint, tsc and prettier", () => {
    expect(scripts["lint"]).toMatch(/^eslint\b/);
    expect(scripts["typecheck"]).toMatch(/^tsc\b/);
    expect(scripts["format:check"]).toMatch(/^prettier\b.*--check/);
  });

  it("keeps the advisory audit from masking a failing step", () => {
    const lint = recipe("ui-lint");
    const audit = lint.filter((line) => /npm audit/.test(line));
    expect(audit).toEqual(["cd frontend && (npm audit --omit=dev || true)"]);
    expect(lint.filter((line) => /\|\|/.test(line))).toEqual(audit);
  });

  it("says in `make help` that `up` also builds and starts ui", () => {
    expect(makefile).toMatch(/@echo "\s+up\s[^"]*\bui\b[^"]*"/);
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
