// Helpers of the admin console's end-to-end suite (P11-T18, admin.spec.ts), on top of fixtures.ts: the scratch
// repository the labelling page reads, a lock held on the active admins' rows, seeds that only the database can
// take (a month's spend), what the browser sent to the API (names only), and the socket's close code.
//
// Nothing here prints a secret or a body. The password of the account the suite creates comes from
// fixtures.ts (`newUserPassword`), which reads the file the stack wrote for the run.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, sep } from "node:path";
import { expect, type Page } from "@playwright/test";
import { psqlEnv, sql, stateDir } from "./fixtures";

// ---------------------------------------------------------------------------------------------------------
// The scratch repository.
//
// The labelling page reads `eval/gold_candidates.csv` and the freeze marker `eval/gold_v1.sha256` of the
// repository its code sits in. The stack (scripts/ui_e2e_stack.sh) runs a copy of the backend inside the state
// directory, so those two paths are `<state>/repo/eval/...`, a directory the stack made empty. The repository's
// own `eval/` is never read, written or named here: every path below is checked to be inside the state
// directory, and the first thing the labelling scenario asks the API is whether the set is frozen, which the
// real set is.

const CANDIDATES_FILE = "gold_candidates.csv";
const FREEZE_FILE = "gold_v1.sha256";

/** The scratch `eval/` directory of this run, checked to be inside the run's state directory. */
export function scratchEvalDir(): string {
  const state = realpathSync(stateDir());
  const labels = join(state, "repo", "backend", "app", "tier1", "labels.py");
  if (!existsSync(labels)) {
    throw new Error(
      "the stack has no scratch repository: refusing to guess another eval/ directory",
    );
  }
  const dir = realpathSync(join(state, "repo", "eval"));
  if (!dir.startsWith(state + sep)) {
    throw new Error("the scratch eval/ directory is outside the state directory");
  }
  return dir;
}

/** The columns of the real candidates file (eval/gold_candidates.csv), in its order. */
const CANDIDATE_COLUMNS = [
  "cluster_id",
  "gold_set",
  "alert_id",
  "category",
  "severity",
  "source",
  "stratum",
  "occurrence_count",
  "first_seen",
  "last_seen",
  "agent_name",
  "rule_id",
  "scenario_id",
  "kind",
  "truth_label",
] as const;

export type Candidate = {
  alertId: string;
  agent: string;
  rule: string;
  category: string;
  severity: string;
  /** What the file holds that a labeller must never see: `source`, `stratum`, `scenario_id`, `kind`, `truth_label`. */
  hidden: { source: string; stratum: string; scenario: string; kind: string; truth: string };
};

/** Writes the scratch candidates file: one G2 cluster for each alert (`cluster_id` is the head's `alert_id`). */
export function writeCandidates(candidates: readonly Candidate[]): void {
  const now = new Date().toISOString();
  const rows = candidates.map((c) =>
    [
      c.alertId,
      "G2",
      c.alertId,
      c.category,
      c.severity,
      c.hidden.source,
      c.hidden.stratum,
      "1",
      now,
      now,
      c.agent,
      c.rule,
      c.hidden.scenario,
      c.hidden.kind,
      c.hidden.truth,
    ].join(","),
  );
  writeFileSync(
    join(scratchEvalDir(), CANDIDATES_FILE),
    [CANDIDATE_COLUMNS.join(","), ...rows].join("\n") + "\n",
    "utf8",
  );
}

/** The scratch freeze marker exists (the page and the undo then say the set is frozen). */
export function freezeMarkerExists(): boolean {
  return existsSync(join(scratchEvalDir(), FREEZE_FILE));
}

/** Freezes the scratch set the way the real freeze does: a marker holding the candidates file's sha256. */
export function writeFreezeMarker(): void {
  const dir = scratchEvalDir();
  const digest = createHash("sha256")
    .update(readFileSync(join(dir, CANDIDATES_FILE)))
    .digest("hex");
  writeFileSync(join(dir, FREEZE_FILE), `${digest}  ${CANDIDATES_FILE}\n`, "utf8");
}

// ---------------------------------------------------------------------------------------------------------
// A lock on the active admins' rows.
//
// The last-admin rule has to be met by a request that started as an admin's and finds, when it gets the locks
// (`update_user` locks every active admin row, then the target), that its actor is gone and the target is the
// only admin left. Through the page that is a request held at the lock while the actor stops being an admin.
// `holdAdminLocks` opens a transaction of its own, locks the active admin rows as `update_user` does, and keeps it
// open until `commit`. Given a username it also demotes that user in it, without ending their sessions: the
// page's request then finds its own actor gone. Given none it changes nothing, and the requests that wait on it
// (two admins demoting each other) go on in the order the database gives them the lock.

export type Held = {
  /** Commits the transaction: the held request goes on, and finds the admins as the transaction left them. */
  commit: () => Promise<void>;
  /** Ends the transaction without committing, and is safe to call after `commit` (a `finally` calls it). */
  abandon: () => Promise<void>;
};

const USERNAME = /^[a-z0-9._-]{3,32}$/;

export async function holdAdminLocks(demoteUsername?: string): Promise<Held> {
  if (demoteUsername !== undefined && !USERNAME.test(demoteUsername)) {
    throw new Error(`not a username: ${demoteUsername}`);
  }
  const child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
    env: psqlEnv(),
    stdio: ["pipe", "pipe", "ignore"],
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    output += chunk;
  });
  const closed = new Promise<number | null>((resolve) => {
    child.on("close", resolve);
    child.on("error", () => resolve(null));
  });
  let finished = false;
  const finish = async (statement: "COMMIT" | "ROLLBACK"): Promise<number | null> => {
    if (finished) return 0;
    finished = true;
    child.stdin.write(`${statement};\n\\q\n`);
    child.stdin.end();
    return closed;
  };

  child.stdin.write(
    "BEGIN;\n" +
      "SELECT user_id FROM users WHERE role = 'admin' AND is_active ORDER BY user_id FOR UPDATE;\n" +
      (demoteUsername === undefined
        ? ""
        : `UPDATE users SET role = 'tier2' WHERE username = '${demoteUsername}';\n`) +
      "SELECT 'held';\n",
  );
  try {
    await expect
      .poll(() => output.includes("held"), {
        message: "the admin rows are locked",
        timeout: 15_000,
      })
      .toBe(true);
  } catch (error) {
    await finish("ROLLBACK");
    throw error;
  }
  return {
    commit: async () => {
      expect(await finish("COMMIT"), "the lock holder committed").toBe(0);
    },
    abandon: async () => {
      await finish("ROLLBACK");
    },
  };
}

/** Waits until `count` requests of the API are waiting for a row lock (`FOR UPDATE`): they have started and are held. */
export async function waitForLockWaiters(count = 1): Promise<void> {
  await expect
    .poll(
      () =>
        Number(
          sql(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() " +
              "AND wait_event_type = 'Lock' AND query LIKE '%FOR UPDATE%'",
          ),
        ),
      { message: `${count} request(s) wait for the admin rows`, timeout: 15_000 },
    )
    .toBeGreaterThanOrEqual(count);
}

// ---------------------------------------------------------------------------------------------------------
// Seeds only the database can take.

/**
 * A month's spend of `usd`: one `llm_runs` row of this month with that cost (the table is append-only, so a
 * seed stays). The prices of the stack are 0, so no run of the stub costs anything; this is the only way to
 * have spent money against the cap.
 */
export function seedMonthSpend(usd: number): void {
  if (!Number.isFinite(usd) || usd <= 0 || usd >= 100_000) throw new Error("not an amount");
  sql(
    "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message, cost_usd) " +
      `VALUES (gen_random_uuid(), 'triage', 'alert', 'e2e-seeded-spend', 'proposer', 'e2e seed', 'e2e seed', ${usd})`,
  );
}

/** How many audit events of a type the database holds (a subject narrows it). */
export function eventCount(type: string, subject?: string): number {
  if (!/^[a-z_.]+$/.test(type)) throw new Error(`not an event type: ${type}`);
  const where = subject === undefined ? "" : ` AND subject_id = '${subject.replace(/'/g, "''")}'`;
  return Number(sql(`SELECT count(*) FROM audit_events WHERE event_type = '${type}'${where}`));
}

// ---------------------------------------------------------------------------------------------------------
// What the browser did.

/**
 * The API calls a page makes from now on, as `METHOD /path` with the query left out (a query may name a user).
 * A websocket's handshake is not a request of the page for Playwright; the socket is `trackSockets`'s.
 */
export function recordApiCalls(page: Page): () => string[] {
  const seen: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) seen.push(`${request.method()} ${url.pathname}`);
  });
  return () => [...seen];
}

type SocketWindow = Window & { __e2eSockets?: { opened: number; closed: number[] } };

/**
 * Records, in the page, how many sockets it opened and the close code of each that closed. An init script, so
 * it is in place before the app's own scripts and the app's CSP does not apply to it. Call it before `goto`.
 */
export async function trackSockets(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as SocketWindow;
    w.__e2eSockets = { opened: 0, closed: [] };
    const Native = window.WebSocket;
    window.WebSocket = class extends Native {
      constructor(url: string | URL, protocols?: string | string[]) {
        super(url, protocols);
        if (w.__e2eSockets) w.__e2eSockets.opened += 1;
        this.addEventListener("close", (event) => w.__e2eSockets?.closed.push(event.code));
      }
    };
  });
}

/** What `trackSockets` has seen so far. */
export async function socketsSeen(page: Page): Promise<{ opened: number; closed: number[] }> {
  const seen = await page.evaluate(() => (window as SocketWindow).__e2eSockets);
  return seen ?? { opened: 0, closed: [] };
}
