// Shared helpers of the end-to-end specs (P10-T12). The stack (scripts/ui_e2e_stack.sh) is a scratch one: its
// own database, the API on 18000, the UI on 18080 and a stub for the language model. This file knows where
// those are, reads the secrets the script generated for the run, posts alerts through the real webhook, logs
// in through the real login page, and records what the browser received (API answers, socket frames).
//
// No secret is ever printed: the helpers return values to the specs, and the specs assert on names and
// counts, not on bodies. Playwright prints the headers of an API request in the "Call log" of a network-level
// failure, and a trace holds every value a test typed, so every call of a request context goes through
// `guarded` (a failure is rethrown with the method, the path and the class of the failure, nothing else), a
// password is typed by `fillSecret`, and the config keeps traces and videos off. `make ui-e2e` scans what a run
// leaves behind (scripts/ui_e2e_scan.py) and fails if a secret of the run is in it.
import { execFileSync } from "node:child_process";
import { createHash, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type APIRequestContext, type Locator, type Page } from "@playwright/test";
import { S } from "../src/strings";
import { clearingOnFailure } from "./loginFailure";

export { S };

/** The API, and the webhook that lives at its root (the UI's own server proxies `/api` only). */
export const API = "http://127.0.0.1:18000";

/**
 * The users the script seeds: one of Tier 1, two of Tier 2 (two, so that two conclusions have two authors) and
 * two admins (two, so that one can be the actor of a change of the other's role; P11-T18).
 */
export type Who = "t1" | "t2" | "t2b" | "admin" | "admin2";
const USERNAME: Record<Who, string> = {
  t1: "e2e-t1",
  t2: "e2e-t2",
  t2b: "e2e-t2b",
  admin: "e2e-admin",
  admin2: "e2e-admin2",
};

/** How the API and the pages name a user: the username (a note or a conclusion carries it as `*_name`). */
export const usernameOf = (who: Who): string => USERNAME[who];

type Secrets = {
  webhook_key: string;
  t1_password: string;
  t2_password: string;
  t2b_password: string;
  admin_password: string;
  admin2_password: string;
  /** The password the admin suite types for the account it creates (P11-T18). */
  new_password: string;
  /** PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE of the scratch database. */
  pg: Record<string, string>;
};

let cached: Secrets | undefined;

/** What the script wrote for this run: a mode-600 file in a mode-700 directory it removes on exit. */
function secrets(): Secrets {
  if (cached !== undefined) return cached;
  const dir = process.env.E2E_STATE_DIR;
  if (!dir) throw new Error("E2E_STATE_DIR is not set: run the suite through `make ui-e2e`");
  try {
    cached = JSON.parse(readFileSync(join(dir, "secrets.json"), "utf8")) as Secrets;
  } catch {
    // Not the parser's message: it may quote the text.
    throw new Error("the stack's secrets file is missing or unreadable");
  }
  return cached;
}

const passwordOf = (who: Who): string => secrets()[`${who}_password`];

/** The password the admin suite gives the account it creates. */
export const newUserPassword = (): string => secrets().new_password;

// ---------------------------------------------------------------------------------------------------------
// Failures that never carry a secret.

/** The failures of the network a failing request can be told by (a fixed list: the class is the only thing kept). */
const NETWORK_CODES = [
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EPIPE",
  "ENOTFOUND",
  "EHOSTUNREACH",
];

/** What kind of failure an error is, without its message: a message may carry a header, a body or a value. */
function errorClass(error: unknown): string {
  const text = error instanceof Error ? error.message : "";
  const code = NETWORK_CODES.find((known) => text.includes(known));
  if (code !== undefined) return code;
  if (/Timeout \d+ms/.test(text)) return "timeout";
  return error instanceof Error ? error.name : typeof error;
}

/**
 * Runs one call of a request context. A failure is rethrown as a new error that names the call (`what`, a
 * method and a path) and the class of the failure, never the original message or its call log: Playwright
 * prints the request's headers there, and they hold the webhook key or a bearer token.
 */
export async function guarded<T>(what: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    // No `cause`: it would carry the original message and call log into the report.
    // eslint-disable-next-line preserve-caught-error
    throw new Error(`${what} failed: ${errorClass(error)}`);
  }
}

export type ApiAnswer = { status: number; body: unknown };

/** One call to the API (or the webhook at its root): the status and the JSON body, `null` when there is none. */
async function apiSend(
  request: APIRequestContext,
  method: "GET" | "POST" | "PUT" | "PATCH",
  path: string,
  options: { token?: string; headers?: Record<string, string>; data?: unknown },
): Promise<ApiAnswer> {
  const headers: Record<string, string> = { ...options.headers };
  if (options.token !== undefined) headers.Authorization = `Bearer ${options.token}`;
  return guarded(`${method} ${path}`, async () => {
    const res = await request.fetch(`${API}${path}`, { method, headers, data: options.data });
    // a 204, or a body that is not JSON, has none: the status is what matters
    const body: unknown = await res.json().catch(() => null);
    return { status: res.status(), body };
  });
}

/** One POST to the API (or the webhook at its root): the status and the JSON body, `null` when there is none. */
export function apiPost(
  request: APIRequestContext,
  path: string,
  options: { token?: string; headers?: Record<string, string>; data?: unknown },
): Promise<ApiAnswer> {
  return apiSend(request, "POST", path, options);
}

/** One GET of the API. */
export function apiGet(
  request: APIRequestContext,
  path: string,
  options: { token?: string } = {},
): Promise<ApiAnswer> {
  return apiSend(request, "GET", path, options);
}

/** One PATCH of the API. */
export function apiPatch(
  request: APIRequestContext,
  path: string,
  options: { token?: string; data?: unknown },
): Promise<ApiAnswer> {
  return apiSend(request, "PATCH", path, options);
}

/** One PUT of the API. */
export function apiPut(
  request: APIRequestContext,
  path: string,
  options: { token?: string; data?: unknown },
): Promise<ApiAnswer> {
  return apiSend(request, "PUT", path, options);
}

/** Types a secret into a field. A failure says which field, not what was typed (a call log may quote it). */
export async function fillSecret(field: Locator, value: string, what: string): Promise<void> {
  try {
    await field.fill(value);
  } catch (error) {
    // eslint-disable-next-line preserve-caught-error -- no `cause`, see guarded()
    throw new Error(`could not fill the ${what} field: ${errorClass(error)}`);
  }
}

// ---------------------------------------------------------------------------------------------------------
// The scratch database, for what only it can say: has the worker got to the alert, has the model run.

const ALERT_ID = /^\d+\.\d+$/;

function assertAlertId(id: string): string {
  if (!ALERT_ID.test(id)) throw new Error(`not an alert id: ${id}`);
  return id;
}

/** The environment of a `psql` against the scratch database: credentials by PG* variables, never by argument. */
export function psqlEnv(): Record<string, string> {
  return { PATH: process.env.PATH ?? "", ...secrets().pg };
}

/** The directory the stack made for this run (it holds the scratch repository, see scripts/ui_e2e_stack.sh). */
export function stateDir(): string {
  const dir = process.env.E2E_STATE_DIR;
  if (!dir) throw new Error("E2E_STATE_DIR is not set: run the suite through `make ui-e2e`");
  return dir;
}

/** One statement against the scratch database (`psql`, credentials through the environment). */
export function sql(statement: string): string {
  try {
    return execFileSync("psql", ["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", statement], {
      env: psqlEnv(),
      encoding: "utf8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    throw new Error("psql against the scratch database failed");
  }
}

/** Waits until the worker has taken the alert to `status` (the queue lists `queued_tier1`). */
export async function waitForStatus(id: string, status: string): Promise<void> {
  const query = `SELECT status FROM alerts WHERE alert_id = '${assertAlertId(id)}'`;
  await expect
    .poll(() => sql(query), { message: `alert ${id} reaches ${status}`, timeout: 30_000 })
    .toBe(status);
}

/** Waits until ① has run on the alert: the proposer's and the verifier's `llm_runs` rows are both there. */
export async function waitForTriage(id: string): Promise<void> {
  const query = `SELECT count(*) FROM llm_runs WHERE pipeline = 'triage' AND subject_id = '${assertAlertId(id)}'`;
  await expect
    .poll(() => Number(sql(query)), { message: `① ran on alert ${id}`, timeout: 30_000 })
    .toBeGreaterThanOrEqual(2);
}

/** The count the database holds for a head: what the queue and the alert page are supposed to show. */
export function occurrenceCount(id: string): number {
  return Number(sql(`SELECT occurrence_count FROM alerts WHERE alert_id = '${assertAlertId(id)}'`));
}

// ---------------------------------------------------------------------------------------------------------
// Alerts, through the webhook.

export type Arm = "blind" | "visible";

/**
 * The arm of an alert id (`soar/pipeline._suggestion_visible` at `EVAL_BLIND_FRACTION=0.5`): an even digest
 * shows ①, an odd one hides it. The suite chooses ids by it, so a spec that needs a blind head has one
 * without any change to the product.
 */
export function armOf(id: string): Arm {
  const digest = parseInt(createHash("sha256").update(id, "utf8").digest("hex").slice(0, 8), 16);
  return digest % 2 === 0 ? "visible" : "blind";
}

/** The stub's token for an alert (scripts/e2e_llm_stub.py `claim_token`): in ①'s reason, and nowhere else. */
export function claimToken(id: string): string {
  return "stub-claim-" + createHash("sha1").update(id, "utf8").digest("hex").slice(0, 10);
}

const EPOCH = Math.floor(Date.now() / 1000);
// A random start, so a worker started again after a failure never repeats an id of the run.
let counter = randomInt(1_000, 900_000);

/** An id of the shape Wazuh uses (`<epoch>.<n>`), of the arm asked for when one is. */
export function newAlertId(arm?: Arm): string {
  for (;;) {
    counter += 1;
    const id = `${EPOCH}.${counter}`;
    if (arm === undefined || armOf(id) === arm) return id;
  }
}

export type Posted = {
  id: string;
  agent: string;
  description: string;
  rule: string;
  srcip: string;
  dstip: string;
};

function wazuhBody(alert: Posted, id: string): Record<string, unknown> {
  return {
    id,
    timestamp: new Date().toISOString().slice(0, 19) + ".000+0000",
    rule: { id: alert.rule, level: 5, description: alert.description, groups: ["e2e"] },
    agent: { id: "001", name: alert.agent, ip: alert.dstip },
    manager: { name: "wazuh-e2e" },
    data: { srcip: alert.srcip, dstip: alert.dstip },
    full_log: `e2e raw log of ${alert.agent}: ${alert.description}`,
  };
}

async function postWebhook(request: APIRequestContext, body: Record<string, unknown>) {
  const answer = await apiPost(request, "/webhook/alerts", {
    headers: { "X-API-Key": secrets().webhook_key },
    data: body,
  });
  expect(answer.status, "the webhook takes the alert").toBeLessThan(300);
}

/**
 * Posts one alert to the webhook, as Wazuh would. `tag` names the spec: it is in the agent and the
 * description, so every spec has a head of its own (the dedup key is rule, source, destination and agent).
 */
export async function postAlert(
  request: APIRequestContext,
  options: { tag: string; arm?: Arm },
): Promise<Posted> {
  const id = newAlertId(options.arm);
  const suffix = randomInt(100_000, 999_999);
  const alert: Posted = {
    id,
    agent: `e2e-${options.tag}-${suffix}`,
    description: `E2E ${options.tag} ${suffix} routine event`,
    rule: "99001",
    srcip: `203.0.113.${randomInt(1, 250)}`,
    dstip: `10.9.${randomInt(1, 250)}.${randomInt(1, 250)}`,
  };
  await postWebhook(request, wazuhBody(alert, id));
  return alert;
}

/**
 * Posts one alert on the same agent as `head` under another rule: a head of its own (another dedup key) that
 * is correlated with `head` (same agent, same ±2 h window). Escalating `head` used to sweep it into the case;
 * since T2 (DEC-215) it stays in the queue.
 */
export async function postCorrelated(
  request: APIRequestContext,
  head: Posted,
  options: { arm?: Arm } = {},
): Promise<Posted> {
  const id = newAlertId(options.arm);
  const alert: Posted = {
    ...head,
    id,
    rule: "99002",
    description: `${head.description} (another rule, same agent)`,
  };
  await postWebhook(request, wazuhBody(alert, id));
  return alert;
}

/** Posts `times` more alerts with the same dedup key: each one is a duplicate of the head (its count grows). */
export async function postDuplicates(
  request: APIRequestContext,
  head: Posted,
  times: number,
): Promise<void> {
  for (let i = 0; i < times; i += 1) {
    await postWebhook(request, wazuhBody(head, newAlertId()));
  }
}

// ---------------------------------------------------------------------------------------------------------
// Sessions.

/** The reason of the decision form. Not by label: the panel's own region carries the same words as its name. */
export const reasonBox = (page: Page) =>
  page.getByRole("textbox", { name: S.decision.reason, exact: true });

/**
 * Who logs in: one of the users the stack seeds, or the account the admin suite creates (P11-T18; its password is
 * the run's `new_password`, which the suite types into the create form).
 */
export type Account = Who | { username: string };

function credentialsOf(account: Account): { username: string; password: string } {
  return typeof account === "string"
    ? { username: USERNAME[account], password: passwordOf(account) }
    : { username: account.username, password: newUserPassword() };
}

/** Where a role starts (`roleHome` of src/auth/redirect.ts): the queue, the case list, the console's overview. */
const HOME: Record<Who, RegExp> = {
  t1: /\/queue$/,
  t2: /\/cases$/,
  t2b: /\/cases$/,
  admin: /\/admin\/overview$/,
  admin2: /\/admin\/overview$/,
};

/** Fills the login form and submits it. */
async function submitLogin(page: Page, account: Account): Promise<void> {
  const { username, password } = credentialsOf(account);
  await page.getByLabel(S.login.username).fill(username);
  await fillSecret(page.getByLabel(S.login.password), password, "password");
  await page.getByRole("button", { name: S.login.submit }).click();
}

/**
 * Logs in through the login page and waits for the role's home (`landing` for the account the suite created,
 * whose role the fixtures do not know). A login that does not get there empties the password field before the
 * test fails, so that the failure's snapshot never holds the password (loginFailure.ts).
 */
export async function loginAs(page: Page, account: Account, landing?: RegExp): Promise<void> {
  const home = landing ?? (typeof account === "string" ? HOME[account] : undefined);
  if (home === undefined)
    throw new Error("an account made by the suite needs the page it lands on");
  await page.goto("/login");
  await clearingOnFailure(page.getByLabel(S.login.password), async () => {
    await submitLogin(page, account);
    await expect(page).toHaveURL(home);
  });
}

/** Logs in on the login page a session ended: the page returns to where the user was, so no URL is awaited. */
export async function signIn(page: Page, account: Account): Promise<void> {
  await clearingOnFailure(page.getByLabel(S.login.password), () => submitLogin(page, account));
}

/** A token for `account` from the API, in a context of its own (no page holds it). */
export async function apiLogin(request: APIRequestContext, account: Account): Promise<string> {
  const answer = await apiPost(request, "/api/auth/login", { data: credentialsOf(account) });
  expect(answer.status, "the API takes the login").toBe(200);
  return (answer.body as { token: string }).token;
}

/** A login with a password that is wrong on purpose: the status the API answers with (401, then 423 once locked). */
export async function apiWrongLogin(request: APIRequestContext, username: string): Promise<number> {
  const answer = await apiPost(request, "/api/auth/login", {
    data: { username, password: "this-is-not-the-password" },
  });
  return answer.status;
}

/** Ends every session `who` holds, as the API's logout does (`sessions_invalid_before`), from outside the page. */
export async function apiLogout(request: APIRequestContext, token: string): Promise<void> {
  const answer = await apiPost(request, "/api/auth/logout", { token });
  expect(answer.status, "the API takes the logout").toBe(204);
}

/** The id the database holds for a seeded user: what `concluded_by` of a 409 is compared with. */
export const userIdOf = (who: Who): string =>
  sql(`SELECT user_id FROM users WHERE username = '${USERNAME[who]}'`);

// ---------------------------------------------------------------------------------------------------------
// What the browser received.

export type Answer = { path: string; status: number; text: string };

export type Traffic = {
  /** Every `/api` answer so far (the login's is left out: it carries the token). */
  answers: () => Promise<Answer[]>;
  /** Every frame the live socket received, as text. Frames the page sent are not kept: they carry the token. */
  frames: () => string[];
};

/** Records the API answers and the socket frames of a page, from now on. Call it before the page opens. */
export function captureTraffic(page: Page): Traffic {
  const kept: Answer[] = [];
  const pending: Promise<void>[] = [];
  const frames: string[] = [];
  page.on("response", (res) => {
    const url = new URL(res.url());
    if (!url.pathname.startsWith("/api/") || url.pathname === "/api/auth/login") return;
    if (res.status() === 101) return;
    pending.push(
      res.text().then(
        (text) => {
          kept.push({ path: url.pathname + url.search, status: res.status(), text });
        },
        () => undefined, // a body the browser dropped when the page moved on
      ),
    );
  });
  page.on("websocket", (ws) => {
    ws.on("framereceived", (frame) => {
      frames.push(
        typeof frame.payload === "string" ? frame.payload : frame.payload.toString("utf8"),
      );
    });
  });
  return {
    answers: async () => {
      await Promise.all(pending);
      return [...kept];
    },
    frames: () => [...frames],
  };
}
