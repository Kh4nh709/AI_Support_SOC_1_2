// What e2e/soar.spec.ts needs of the stack: n8n's side of the SOAR review tickets. The stack (scripts/ui_e2e_stack.sh) gives the app the
// settings of the page "Phản hồi SOAR" (the key and the loopback allow-list of POST /webhook/soar-notices, and the URL and the secret
// of n8n's `soar-approval` webhook, which is a stand-in on a loopback port), all generated for the run. The helpers here play n8n:
// they push a ticket through the real webhook with the run's key, and they set the mode the stand-in answers in (ok, fail,
// conflict), which it reads from a file of the state directory at every press.
//
// No secret is printed: the key is only ever put in a header of a request made through `apiPost` (whose failures say the method and
// the path, never the headers), and nothing here returns it.
import { randomInt } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type APIRequestContext } from "@playwright/test";
import { apiGet, apiLogin, apiPost, soarNoticeKey, sql, stateDir, type Who } from "./fixtures";

/** A review id: 8 characters of [A-HJ-NP-Z2-9] (spec section 2). */
const REVIEW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/** A notice id: N and twelve letters or digits. */
const NOTICE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const pick = (alphabet: string, length: number): string =>
  Array.from({ length }, () => alphabet[randomInt(alphabet.length)]).join("");

export const newReviewId = (): string => pick(REVIEW_ALPHABET, 8);
export const newNoticeId = (): string => `N${pick(NOTICE_ALPHABET, 12)}`;

/** An instant as n8n writes it: ISO 8601 with an explicit offset. */
const stamp = (offsetMs = 0): string =>
  new Date(Date.now() + offsetMs).toISOString().replace("Z", "+00:00");

export type Button = { decision: "keep" | "undo" | "fp"; label: string };

export type TicketOptions = {
  id?: string;
  title?: string;
  actionText?: string;
  target?: string;
  host?: string;
  scenarioName?: string;
  note?: string;
  buttons?: Button[];
  score?: number;
};

/** A `block_ip` review in the body n8n pushes (the README's), with the buttons "keep" and "undo". */
export function blockIpBody(options: TicketOptions = {}): Record<string, unknown> {
  const id = options.id ?? newReviewId();
  return {
    schema_version: "1.0",
    event: "created",
    kind: "review",
    id,
    sent_at: stamp(),
    status: "open",
    severity: "info",
    title: options.title ?? "ĐÃ TỰ XỬ LÝ",
    simulated: false,
    case: { id: "~4096", number: 65 },
    action: {
      type: "block_ip",
      text: options.actionText ?? "Chặn IP 79.79.78.202 trên pfSense",
      target: options.target ?? "79.79.78.202",
      via: "pfsense",
      agent: null,
    },
    host: options.host ?? "pfSense.home.arpa",
    agent_id: "003",
    src_ip: "79.79.78.202",
    scenario: { id: "SC03", name: options.scenarioName ?? "Quét cổng từ bên ngoài" },
    score: options.score ?? 50,
    note: options.note ?? "Đã chặn 79.79.78.202 trên pfSense, tự gỡ sau một giờ",
    created_at: stamp(-2_000),
    auto_expire_at: stamp(3_600_000),
    buttons: options.buttons ?? [
      { decision: "keep", label: "✅ Giữ chặn" },
      { decision: "undo", label: "↩️ Gỡ chặn IP" },
    ],
  };
}

/** A `kill_process` review: "keep" or "fp"; a killed process has no undo. */
export function killProcessBody(options: TicketOptions = {}): Record<string, unknown> {
  const id = options.id ?? newReviewId();
  return {
    schema_version: "1.0",
    event: "created",
    kind: "review",
    id,
    sent_at: stamp(),
    status: "open",
    severity: "warning",
    title: options.title ?? "ĐÃ KILL TIẾN TRÌNH",
    case: { id: "~8192", number: 71 },
    action: {
      type: "kill_process",
      text: options.actionText ?? "Kết thúc mimikatz.exe trên WIN-DC01",
      target: options.target ?? "mimikatz.exe",
      via: "wazuh",
      agent: "WIN-DC01",
    },
    host: options.host ?? "WIN-DC01",
    agent_id: "005",
    scenario: { id: "MW03", name: options.scenarioName ?? "Mã độc trên endpoint" },
    score: options.score ?? 82,
    created_at: stamp(-2_000),
    buttons: options.buttons ?? [
      { decision: "keep", label: "✅ Giữ (đã kill)" },
      { decision: "fp", label: "🚫 Báo nhầm" },
    ],
  };
}

/** A notice: one line of information, no buttons. */
export function noticeBody(
  options: {
    id?: string;
    title?: string;
    note?: string;
    severity?: "info" | "warning" | "error";
  } = {},
): Record<string, unknown> {
  return {
    schema_version: "1.0",
    event: "created",
    kind: "notice",
    id: options.id ?? newNoticeId(),
    sent_at: stamp(),
    status: "info",
    severity: options.severity ?? "warning",
    title: options.title ?? "SOAR TẠM DỪNG",
    note: options.note ?? "pfSense không phản hồi, các hành động chặn IP được hoãn",
    buttons: [],
  };
}

/** What the webhook answered: the status and the body. */
export type Pushed = { status: number; body: unknown };

/** n8n pushes a ticket through the real webhook with the run's key. Returns the status and the body. */
export async function pushTicket(
  request: APIRequestContext,
  body: Record<string, unknown>,
): Promise<Pushed> {
  return apiPost(request, "/webhook/soar-notices", {
    headers: { "X-API-Key": soarNoticeKey(), "Content-Type": "application/json" },
    data: body,
  });
}

/** Pushes a ticket that must be accepted as new (201), and returns its id. */
export async function pushNew(
  request: APIRequestContext,
  body: Record<string, unknown>,
): Promise<string> {
  const answer = await pushTicket(request, body);
  expect(answer.status, "the webhook takes a new ticket").toBe(201);
  expect(answer.body).toEqual({ id: body.id, created: true });
  return String(body.id);
}

/** A push with a key that is not the run's: the status the webhook answers with (401). */
export async function pushWithWrongKey(
  request: APIRequestContext,
  body: Record<string, unknown>,
): Promise<number> {
  const answer = await apiPost(request, "/webhook/soar-notices", {
    headers: { "X-API-Key": "this-is-not-the-key", "Content-Type": "application/json" },
    data: body,
  });
  return answer.status;
}

export type N8nMode = "ok" | "fail" | "conflict" | "slow";

/** Sets the mode the stand-in of n8n answers a press in (it reads the file at every request; scripts/ui_e2e_n8n.py). */
export function setN8nMode(mode: N8nMode): void {
  writeFileSync(join(stateDir(), "n8n.mode"), `${mode}\n`);
}

/** The requests the stand-in has answered, one line each, without the secret (scripts/mock_n8n_approval.py prints none). */
export function n8nLog(): string[] {
  try {
    return readFileSync(join(stateDir(), "logs", "n8n.log"), "utf8")
      .split("\n")
      .filter(Boolean);
  } catch {
    return [];
  }
}

const REVIEW_ID = /^[A-HJ-NP-Z2-9]{8}$/;
const assertId = (id: string): string => {
  if (!REVIEW_ID.test(id) && !/^N[A-Za-z0-9]{12}$/.test(id))
    throw new Error(`not a ticket id: ${id}`);
  return id;
};

/** `status|decided_by` of a ticket, from the scratch database. */
export function stateOf(id: string): string {
  return sql(
    `SELECT status || '|' || coalesce(decided_by, '') FROM soar_reviews WHERE id = '${assertId(id)}'`,
  );
}

/** The audit events of a ticket, oldest first: `event_type|actor outcome|note`. */
export function eventsOf(id: string): string[] {
  return sql(
    `SELECT event_type || '|' || coalesce(payload->>'outcome', '') || '|' || coalesce(payload->>'decision', '') || '|' || coalesce(payload->>'note', '') ` +
      `FROM audit_events WHERE subject_id = '${assertId(id)}' ORDER BY audit_id`,
  )
    .split("\n")
    .filter(Boolean);
}

/** A press from outside the page, by `who`'s own token: the HTTP status and the body (the page does the same through its client). */
export async function pressFromApi(
  request: APIRequestContext,
  who: Who,
  id: string,
  decision: "keep" | "undo" | "fp",
): Promise<{ status: number; body: unknown }> {
  const token = await apiLogin(request, who);
  return apiPost(request, `/api/soar/reviews/${id}/decision`, { token, data: { decision } });
}

/** The count of open reviews as `who` is served it. */
export async function openCount(request: APIRequestContext, who: Who): Promise<number> {
  const token = await apiLogin(request, who);
  const answer = await apiGet(request, "/api/soar/reviews/count", { token });
  expect(answer.status).toBe(200);
  return (answer.body as { count: number }).count;
}
