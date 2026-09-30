// Shared helpers of the end-to-end specs (P10-T12). The stack (scripts/ui_e2e_stack.sh) is a scratch one: its
// own database, the API on 18000, the UI on 18080 and a stub for the language model. This file knows where
// those are, reads the secrets the script generated for the run, posts alerts through the real webhook, logs
// in through the real login page, and records what the browser received (API answers, socket frames).
//
// No secret is ever printed: the helpers return values to the specs, and the specs assert on names and
// counts, not on bodies.
import { execFileSync } from "node:child_process";
import { createHash, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { S } from "../src/strings";

export { S };

/** The API, and the webhook that lives at its root (the UI's own server proxies `/api` only). */
export const API = "http://127.0.0.1:18000";

/** The two users the script seeds. */
export type Who = "t1" | "t2";
const USERNAME: Record<Who, string> = { t1: "e2e-t1", t2: "e2e-t2" };

type Secrets = {
  webhook_key: string;
  t1_password: string;
  t2_password: string;
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

// ---------------------------------------------------------------------------------------------------------
// The scratch database, for what only it can say: has the worker got to the alert, has the model run.

const ALERT_ID = /^\d+\.\d+$/;

function assertAlertId(id: string): string {
  if (!ALERT_ID.test(id)) throw new Error(`not an alert id: ${id}`);
  return id;
}

/** One statement against the scratch database (`psql`, credentials through the environment). */
export function sql(statement: string): string {
  try {
    return execFileSync("psql", ["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", statement], {
      env: { PATH: process.env.PATH ?? "", ...secrets().pg },
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
  const res = await request.post(`${API}/webhook/alerts`, {
    headers: { "X-API-Key": secrets().webhook_key },
    data: body,
  });
  expect(res.status(), "the webhook takes the alert").toBeLessThan(300);
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

/** Logs in through the login page and waits for the role's home. */
export async function loginAs(page: Page, who: Who): Promise<void> {
  await page.goto("/login");
  await page.getByLabel(S.login.username).fill(USERNAME[who]);
  await page.getByLabel(S.login.password).fill(passwordOf(who));
  await page.getByRole("button", { name: S.login.submit }).click();
  await expect(page).toHaveURL(who === "t1" ? /\/queue$/ : /\/cases$/);
}

/** Logs in on the login page a session ended: the page returns to where the user was, so no URL is awaited. */
export async function signIn(page: Page, who: Who): Promise<void> {
  await page.getByLabel(S.login.username).fill(USERNAME[who]);
  await page.getByLabel(S.login.password).fill(passwordOf(who));
  await page.getByRole("button", { name: S.login.submit }).click();
}

/** A token for `who` from the API, in a context of its own (no page holds it). */
export async function apiLogin(request: APIRequestContext, who: Who): Promise<string> {
  const res = await request.post(`${API}/api/auth/login`, {
    data: { username: USERNAME[who], password: passwordOf(who) },
  });
  expect(res.status(), "the API takes the login").toBe(200);
  return ((await res.json()) as { token: string }).token;
}

/** Ends every session `who` holds, as the API's logout does (`sessions_invalid_before`), from outside the page. */
export async function apiLogout(request: APIRequestContext, token: string): Promise<void> {
  const res = await request.post(`${API}/api/auth/logout`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(res.status(), "the API takes the logout").toBe(204);
}

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
