// The scaffold's smoke test: the built page renders under the exact CSP of nginx.conf, loads its fonts
// from its own origin, and makes no request to any other host. `vite preview` sends no CSP, so the
// header of nginx.conf is applied here to the document response. The admin console is held to the same
// header (P11-T20 part 4, M5): its pages are lazy chunks that no other test loaded under the CSP.
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { S, loginAs } from "./fixtures";

const CSP = /add_header\s+Content-Security-Policy\s+"([^"]*)"\s+always;/.exec(
  readFileSync("nginx.conf", "utf8"),
)?.[1];

type CspWindow = Window & { __csp?: string[]; __inlineRan?: boolean };

async function openUnderCsp(
  page: Page,
  origin: string,
): Promise<{ foreign: string[]; woff2: number[]; scripts: Map<string, number> }> {
  expect(CSP, "nginx.conf must carry the CSP").toBeTruthy();
  await page.route("**/*", async (route) => {
    if (route.request().resourceType() !== "document") return route.continue();
    const response = await route.fetch();
    return route.fulfill({
      response,
      headers: { ...response.headers(), "content-security-policy": CSP ?? "" },
    });
  });
  // Playwright's init script is not subject to the page's CSP; it only records the violations.
  await page.addInitScript(() => {
    const w = window as CspWindow;
    w.__csp = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      w.__csp?.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });

  const foreign: string[] = [];
  const woff2: number[] = [];
  // The scripts the page loaded, by path: the entry and the lazy chunks of the pages it opened.
  const scripts = new Map<string, number>();
  page.on("response", (response) => {
    if (!response.url().startsWith(origin)) foreign.push(response.url());
    const { pathname } = new URL(response.url());
    if (pathname.endsWith(".woff2")) woff2.push(response.status());
    if (pathname.endsWith(".js")) scripts.set(pathname, response.status());
  });
  await page.goto("/");
  return { foreign, woff2, scripts };
}

/** The violations the page has recorded since it was loaded (the init script starts the list at every load). */
const violationsOf = (page: Page): Promise<string[]> =>
  page.evaluate(() => (window as CspWindow).__csp ?? []);

test("the page renders under the CSP with no violation and no foreign request", async ({
  page,
  baseURL,
}) => {
  const seen = await openUnderCsp(page, baseURL ?? "");
  await expect(page.getByText("AI Support SOC")).toBeVisible();
  await expect(page.getByRole("banner")).toBeVisible();
  await page.evaluate(() => document.fonts.ready.then(() => undefined));

  expect(await page.evaluate(() => (window as CspWindow).__csp)).toEqual([]);
  expect(seen.foreign).toEqual([]);
  // The IBM Plex subsets are bundled and served by the page's own origin (font-src 'self').
  expect(seen.woff2.length).toBeGreaterThan(0);
  expect(seen.woff2.every((status) => status === 200)).toBe(true);
});

test("the CSP is really in force: an inline script is refused", async ({ page, baseURL }) => {
  await openUnderCsp(page, baseURL ?? "");
  await expect(page.getByText("AI Support SOC")).toBeVisible();
  await page.evaluate(() => {
    const script = document.createElement("script");
    script.textContent = "window.__inlineRan = true;";
    document.head.append(script);
  });
  expect(await page.evaluate(() => (window as CspWindow).__inlineRan)).toBeUndefined();
  const violations = await page.evaluate(() => (window as CspWindow).__csp ?? []);
  expect(violations.some((v) => v.startsWith("script-src"))).toBe(true);
});

// The admin console under the CSP. Its pages are `React.lazy` chunks (`script-src 'self'`), they style with
// classes only (`style-src 'self'`, so a `style=` attribute or an inline `<style>` would be refused), and the
// API is the page's own origin (`connect-src 'self'`). The whole-branch review found that no test opened an
// admin page under the header: the unit tests have no CSP, and the e2e admin suite runs on `vite preview`, which
// sends none. Sign in as an admin, then open the overview and the audit page (a full load each, as a link
// followed from outside would be) and require no violation, no foreign request and the lazy chunks served 200.
test("the admin console loads under the CSP: /admin/overview and /admin/audit raise no violation", async ({
  page,
  baseURL,
}) => {
  const seen = await openUnderCsp(page, baseURL ?? "");
  await loginAs(page, "admin");
  await expect(page.getByRole("heading", { level: 1, name: S.admin.title.overview })).toBeVisible();
  expect(await violationsOf(page), "the overview after signing in").toEqual([]);

  for (const [path, title] of [
    ["/admin/overview", S.admin.title.overview],
    ["/admin/audit", S.admin.title.audit],
  ] as const) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
    await page.evaluate(() => document.fonts.ready.then(() => undefined));
    expect(await violationsOf(page), `${path} under the CSP`).toEqual([]);
  }

  expect(seen.foreign).toEqual([]);
  // The entry and the pages' own chunks, each the page's own origin and a 200: a chunk the CSP refused would
  // not be here, and neither would the page.
  const chunks = [...seen.scripts.keys()].filter((path) => path.startsWith("/assets/"));
  expect(chunks.length).toBeGreaterThanOrEqual(3);
  expect([...seen.scripts.values()].every((status) => status === 200)).toBe(true);
});
