// src/features/tier1/aiState.test.ts — the one place the ① state is decided, for a queue row and for the alert view.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AlertView, QueueRow } from "../../api/tier1";
import { DECIDED, aiStateOfRow, aiStateOfView, conclusionOf, heldOf } from "./aiState";

/** A visible-arm row of the queue with a ① result: every key the server sends. */
const row = (over: Partial<QueueRow> = {}): QueueRow => ({
  alert_id: "a1",
  rule_id: "5760",
  description: "sshd: authentication failed",
  category: "ssh_brute_force",
  severity: "high",
  agent_name: "lab-ubuntu-01",
  occurrence_count: 3,
  triaged_count: 1,
  first_seen_at: "2026-09-30T01:00:00Z",
  last_seen_at: "2026-09-30T02:00:00Z",
  alert_time: "2026-09-30T01:00:00Z",
  suggestion_visible: true,
  status: "queued_tier1",
  needs_retriage: false,
  risk_band: "Cao",
  triage_status: "ready",
  run_id: "r1",
  suggested_action: "true_positive",
  confidence: "medium",
  gate_forced: false,
  proposed_action: "true_positive",
  held_by: [],
  ...over,
});

/** The row the server sends for a blind, undecided head: the ① keys are not there at all. */
function blindRow(over: Partial<QueueRow> = {}): QueueRow {
  const stripped = row({ suggestion_visible: false });
  delete stripped.suggested_action;
  delete stripped.confidence;
  delete stripped.gate_forced;
  delete stripped.proposed_action;
  delete stripped.held_by;
  delete stripped.triage_status;
  delete stripped.run_id;
  return { ...stripped, ...over };
}

describe("aiStateOfRow", () => {
  it("is ready with the action and confidence when the row carries a suggestion", () => {
    expect(aiStateOfRow(row())).toEqual({
      kind: "ready",
      action: "true_positive",
      confidence: "medium",
      forced: false,
      proposed: "true_positive",
      heldBy: [],
    });
  });

  // P14-T03 (DEC-213): the row carries the model's own answer and the reasons the system held it.
  it("carries the model's own answer and the reasons the system held it back", () => {
    const held = row({
      suggested_action: "needs_review",
      gate_forced: true,
      proposed_action: "false_positive",
      held_by: ["fp_policy:asset_criticality", "verifier_disagrees"],
    });
    expect(aiStateOfRow(held)).toEqual({
      kind: "ready",
      action: "needs_review",
      confidence: "medium",
      forced: true,
      proposed: "false_positive",
      heldBy: ["fp_policy:asset_criticality", "verifier_disagrees"],
    });
  });

  it("reads a missing, null or garbled proposed_action and held_by as none", () => {
    const bare = row();
    delete bare.proposed_action;
    delete bare.held_by;
    expect(aiStateOfRow(bare)).toMatchObject({ proposed: null, heldBy: [] });
    expect(aiStateOfRow(row({ proposed_action: null }))).toMatchObject({ proposed: null });
    const odd = row({
      proposed_action: 7 as unknown as string,
      held_by: "verifier_disagrees" as unknown as string[],
    });
    expect(aiStateOfRow(odd)).toMatchObject({ proposed: null, heldBy: [] });
    const mixed = row({ held_by: ["facts_mismatch", 3, null, ""] as unknown as string[] });
    expect(aiStateOfRow(mixed)).toMatchObject({ heldBy: ["facts_mismatch"] });
  });

  it("is forced only when gate_forced is true", () => {
    expect(aiStateOfRow(row({ gate_forced: true }))).toMatchObject({ kind: "ready", forced: true });
    expect(aiStateOfRow(row({ gate_forced: null }))).toMatchObject({
      kind: "ready",
      forced: false,
    });
    expect(aiStateOfRow(row({ gate_forced: undefined }))).toMatchObject({ forced: false });
  });

  it("keeps a missing confidence as null", () => {
    expect(aiStateOfRow(row({ confidence: null }))).toMatchObject({
      kind: "ready",
      confidence: null,
    });
  });

  it("is hidden for a blind row that says suggestion_visible false and has no keys", () => {
    const blind = blindRow();
    expect("suggested_action" in blind).toBe(false);
    expect(blind.suggestion_visible).toBe(false);
    expect(aiStateOfRow(blind)).toEqual({ kind: "hidden" });
  });

  it("is never pending for a blind row, whatever the status of the queue", () => {
    for (const status of ["queued_tier1", "tier1_active"]) {
      expect(aiStateOfRow(blindRow({ status })).kind).toBe("hidden");
    }
  });

  it("is not hidden once the alert is decided: the keys are back and it is ready", () => {
    for (const status of DECIDED) {
      expect(aiStateOfRow(row({ status, suggestion_visible: false })).kind).toBe("ready");
    }
  });

  it("is pending when the keys are absent on a decided, blind-flagged row that has no result", () => {
    // The server never strips a decided row, so this row has no result yet: pending, not hidden.
    expect(aiStateOfRow(blindRow({ status: "closed_fp" })).kind).toBe("pending");
  });

  it("is unavailable when ① gave up (triage_status unavailable, no action), with no reason: the queue row carries none (INT-T02)", () => {
    expect(
      aiStateOfRow(row({ suggested_action: null, confidence: null, triage_status: "unavailable" })),
    ).toEqual({ kind: "unavailable", stoppedBy: null });
  });

  it("is pending on the visible arm with no result yet", () => {
    expect(
      aiStateOfRow(row({ suggested_action: null, confidence: null, triage_status: "pending" })),
    ).toEqual({ kind: "pending" });
  });

  it("is pending when the visible arm has no key and no flag either", () => {
    const bare = blindRow({ suggestion_visible: true });
    expect(aiStateOfRow(bare)).toEqual({ kind: "pending" });
  });

  it("does not take a non-string action for a suggestion", () => {
    expect(aiStateOfRow(row({ suggested_action: null, triage_status: null })).kind).toBe("pending");
  });
});

/** A view of the alert page; `suggestion` is the key the blind arm strips. */
const view = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  triage_status: "ready",
  suggestion: { suggested_action: "false_positive", confidence: "high", gate: { forced: false } },
  proposed_action: "false_positive",
  held_by: [],
  ...over,
});

describe("aiStateOfView", () => {
  it("is ready from the suggestion of the view", () => {
    expect(aiStateOfView(view())).toEqual({
      kind: "ready",
      action: "false_positive",
      confidence: "high",
      forced: false,
      proposed: "false_positive",
      heldBy: [],
    });
  });

  it("carries the model's own answer and the reasons the system held it back", () => {
    const held = view({
      suggestion: {
        suggested_action: "needs_review",
        confidence: "medium",
        gate: { forced: true },
      },
      proposed_action: "true_positive",
      held_by: ["facts_mismatch", "no_verified_quote"],
    });
    expect(aiStateOfView(held)).toEqual({
      kind: "ready",
      action: "needs_review",
      confidence: "medium",
      forced: true,
      proposed: "true_positive",
      heldBy: ["facts_mismatch", "no_verified_quote"],
    });
  });

  it("reads a view without proposed_action and held_by as none", () => {
    const bare = view();
    delete bare.proposed_action;
    delete bare.held_by;
    expect(aiStateOfView(bare)).toMatchObject({ kind: "ready", proposed: null, heldBy: [] });
  });

  it("is hidden on the blind arm even when the view carries the two keys: they are read after the arm", () => {
    const blind = view({
      suggestion_visible: false,
      proposed_action: "false_positive",
      held_by: ["verifier_disagrees"],
    });
    delete blind.suggestion;
    delete blind.triage_status;
    expect(aiStateOfView(blind)).toEqual({ kind: "hidden" });
  });

  it("reads the gate flag of the suggestion", () => {
    const forced = view({
      suggestion: { suggested_action: "needs_review", confidence: "low", gate: { forced: true } },
    });
    expect(aiStateOfView(forced)).toMatchObject({ kind: "ready", forced: true });
  });

  it("is hidden when the suggestion key is absent, the flag is false and the alert is undecided", () => {
    const blind = view({ suggestion_visible: false });
    delete blind.suggestion;
    delete blind.triage_status;
    expect("suggestion" in blind).toBe(false);
    expect(aiStateOfView(blind)).toEqual({ kind: "hidden" });
  });

  it("is decided, with what ① said, once the status is one of DECIDED", () => {
    for (const status of DECIDED) {
      expect(aiStateOfView(view({ status }))).toEqual({
        kind: "decided",
        action: "false_positive",
        confidence: "high",
      });
    }
  });

  it("is decided with no action when ① never produced one", () => {
    expect(aiStateOfView(view({ status: "closed_benign", suggestion: null }))).toEqual({
      kind: "decided",
      action: null,
      confidence: null,
    });
  });

  it("is unavailable when ① gave up and there is no suggestion", () => {
    expect(aiStateOfView(view({ suggestion: null, triage_status: "unavailable" }))).toEqual({
      kind: "unavailable",
      stoppedBy: null,
    });
  });

  it("is pending on the visible arm with no result", () => {
    expect(aiStateOfView(view({ suggestion: null, triage_status: "pending" }))).toEqual({
      kind: "pending",
    });
  });

  // INT-T02 / DEC-211 R6: the alert view carries `llm_stopped_by`, the `stopped_by` of the newest ① run.
  describe("the reason ① stopped (llm_stopped_by)", () => {
    const gaveUp = (over: Partial<AlertView> = {}) =>
      view({ suggestion: null, triage_status: "unavailable", ...over });

    it("is passed to unavailable, so a provider 402 can be worded", () => {
      expect(aiStateOfView(gaveUp({ llm_stopped_by: "unavailable" }))).toEqual({
        kind: "unavailable",
        stoppedBy: "unavailable",
      });
      expect(aiStateOfView(gaveUp({ llm_stopped_by: "cap" }))).toEqual({
        kind: "unavailable",
        stoppedBy: "cap",
      });
    });

    it("is null when the view says none, null, or not a string", () => {
      expect(aiStateOfView(gaveUp())).toEqual({ kind: "unavailable", stoppedBy: null });
      expect(aiStateOfView(gaveUp({ llm_stopped_by: null }))).toEqual({
        kind: "unavailable",
        stoppedBy: null,
      });
      const odd = gaveUp({ llm_stopped_by: 402 as unknown as string });
      expect(aiStateOfView(odd)).toEqual({ kind: "unavailable", stoppedBy: null });
    });

    it("is read only where the state is unavailable: not by a pending, ready or decided view", () => {
      expect(
        aiStateOfView(view({ suggestion: null, triage_status: "pending", llm_stopped_by: "cap" })),
      ).toEqual({ kind: "pending" });
      expect(aiStateOfView(view({ llm_stopped_by: "cap" }))).toMatchObject({ kind: "ready" });
      expect(aiStateOfView(view({ status: "closed_fp", llm_stopped_by: "cap" }))).toEqual({
        kind: "decided",
        action: "false_positive",
        confidence: "high",
      });
    });

    it("never turns a blind, undecided head into anything but hidden, whatever the view carries", () => {
      // The server drops the key (visibility.ANALYST_HIDE) and the arm is read first: a view that did carry
      // it, with a triage status of unavailable besides, is still hidden and shows no reason.
      const blind = view({
        suggestion_visible: false,
        triage_status: "unavailable",
        llm_stopped_by: "unavailable",
      });
      delete blind.suggestion;
      expect(aiStateOfView(blind)).toEqual({ kind: "hidden" });
    });
  });
});

it("does not count an archived alert as decided: the blind arm stays hidden (DEC-212)", () => {
  expect(DECIDED.has("archived")).toBe(false);
  const blindRow = {
    alert_id: "a-1",
    status: "archived",
    suggestion_visible: false,
  } as unknown as Parameters<typeof aiStateOfRow>[0];
  expect(aiStateOfRow(blindRow)).toEqual({ kind: "hidden" });
  const blindView = {
    alert_id: "a-1",
    status: "archived",
    suggestion_visible: false,
  } as unknown as Parameters<typeof aiStateOfView>[0];
  expect(aiStateOfView(blindView)).toEqual({ kind: "hidden" });
});

// Review of INT-T03, Nit 7. The `triage` job of an archived alert is skipped (DEC-212), so its triage_status stays
// 'pending' for good, and "Đang phân tích…" would be a promise nobody keeps (the alert page polls while the state
// is pending). An archived alert with no result and no failure has no ① to wait for: the state is `none`.
describe("an archived alert never waits for a ① that will not come (DEC-212)", () => {
  const waitingRow = (over: Partial<QueueRow> = {}): QueueRow =>
    row({
      status: "archived",
      suggested_action: null,
      confidence: null,
      triage_status: "pending",
      ...over,
    });
  const waitingView = (over: Partial<AlertView> = {}): AlertView =>
    view({ status: "archived", suggestion: null, triage_status: "pending", ...over });

  it("is none, not pending, in the queue row", () => {
    expect(aiStateOfRow(waitingRow())).toEqual({ kind: "none" });
  });

  it("is none, not pending, in the alert view", () => {
    expect(aiStateOfView(waitingView())).toEqual({ kind: "none" });
  });

  it("keeps the blind-arm rule first: a blind archived head is hidden, whatever its triage status", () => {
    const blind = blindRow({ status: "archived", triage_status: "pending" });
    expect("suggested_action" in blind).toBe(false);
    expect(aiStateOfRow(blind)).toEqual({ kind: "hidden" });
    const blindView = waitingView({ suggestion_visible: false });
    delete blindView.suggestion;
    expect(aiStateOfView(blindView)).toEqual({ kind: "hidden" });
  });

  it("still shows a ① result the visible arm has, and still says ① gave up when it did", () => {
    expect(aiStateOfRow(row({ status: "archived" }))).toMatchObject({ kind: "ready" });
    expect(aiStateOfView(view({ status: "archived" }))).toMatchObject({ kind: "ready" });
    expect(aiStateOfRow(waitingRow({ triage_status: "unavailable" }))).toEqual({
      kind: "unavailable",
      stoppedBy: null,
    });
    expect(aiStateOfView(waitingView({ triage_status: "unavailable" }))).toEqual({
      kind: "unavailable",
      stoppedBy: null,
    });
  });

  it("is never decided, and the status of no other alert turns pending into none", () => {
    expect(aiStateOfView(waitingView()).kind).not.toBe("decided");
    for (const status of ["received", "enriching", "queued_tier1", "tier1_active"]) {
      expect(aiStateOfRow(waitingRow({ status })).kind, status).toBe("pending");
      expect(aiStateOfView(waitingView({ status })).kind, status).toBe("pending");
    }
  });
});

it("lists exactly the five statuses the server shows the suggestion in", () => {
  // visibility.SHOW_STATES of the backend.
  expect([...DECIDED].sort()).toEqual([
    "auto_closed",
    "closed_benign",
    "closed_confirmed",
    "closed_fp",
    "escalated_tier2",
  ]);
});

// DECIDED is a copy of the backend's SHOW_STATES, and a copy drifts: a status the server shows and this file
// does not know would draw "hidden" over a verdict the analyst may see, and the reverse would draw a verdict the
// server has withheld. So the Python source is read and the two sets are compared (the parity pattern of
// strings.test.ts: no file is named, the test finds the one that *defines* the set).
const BACKEND_APP = join("..", "backend", "app");

const pyFiles = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? pyFiles(path) : path.endsWith(".py") ? [path] : [];
  });

/**
 * The strings of a module-level `SHOW_STATES: frozenset[str] = frozenset({...})` under `root`. A line that
 * only imports the name, or a commented-out copy, is not a definition; none or two definitions are errors.
 */
function pyShowStates(root = BACKEND_APP): string[] {
  const pattern = /^SHOW_STATES(?::\s*frozenset\[str\])?\s*=\s*frozenset\(\s*\{([^}]*)\}\s*\)/m;
  const found = pyFiles(root).flatMap((path) => {
    const body = pattern.exec(readFileSync(path, "utf8"))?.[1];
    return body === undefined ? [] : [{ path, body }];
  });
  const [only] = found;
  if (found.length !== 1 || !only) {
    const where = found.map((f) => f.path).join(", ") || "no file";
    throw new Error(
      `expected exactly one definition of SHOW_STATES under ${root}, found ${found.length} (${where})`,
    );
  }
  return [...only.body.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "").sort();
}

describe("finding SHOW_STATES in the backend", () => {
  const root = mkdtempSync(join(tmpdir(), "p10t17-py-"));
  const put = (file: string, text: string): void => {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), text);
  };
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("reads the set from the one file that defines it, and ignores importers and comments", () => {
    put(
      "a/vis.py",
      '#: doc\nSHOW_STATES: frozenset[str] = frozenset(\n    {"closed_fp", "auto_closed"}\n)\n',
    );
    put("b/user.py", 'from a.vis import SHOW_STATES\n# SHOW_STATES = frozenset({"nope"})\n');
    expect(pyShowStates(root)).toEqual(["auto_closed", "closed_fp"]);
  });

  it("refuses a set defined twice or nowhere, so a stale copy cannot pass for the real one", () => {
    put("c/again.py", 'SHOW_STATES = frozenset({"closed_fp"})\n');
    expect(() => pyShowStates(root)).toThrow(/exactly one definition of SHOW_STATES.*found 2/);
    expect(() => pyShowStates(join(root, "b"))).toThrow(/found 0/);
  });

  it("reports a status added on the Python side only", () => {
    // What the parity test below would say if the backend grew a status and this file did not.
    const backend = mkdtempSync(join(tmpdir(), "p10t17-py2-"));
    try {
      mkdirSync(join(backend, "tier1"), { recursive: true });
      writeFileSync(
        join(backend, "tier1", "visibility.py"),
        `SHOW_STATES: frozenset[str] = frozenset(\n    {${[...DECIDED, "closed_dupe"].map((x) => `"${x}"`).join(", ")}}\n)\n`,
      );
      expect(pyShowStates(backend)).not.toEqual([...DECIDED].sort());
      expect(pyShowStates(backend)).toContain("closed_dupe");
    } finally {
      rmSync(backend, { recursive: true, force: true });
    }
  });
});

it("DECIDED is the backend's visibility.SHOW_STATES, status for status", () => {
  const backend = pyShowStates();
  expect(backend.length).toBeGreaterThan(0); // a parse that finds nothing would compare nothing
  expect([...DECIDED].sort()).toEqual(backend);
});

// P14-T03 (DEC-213): what the model concluded, and whether the system held it back. Two readings of a `ready`
// state, kept here so the column and the cell do not each decide them.
describe("conclusionOf and heldOf", () => {
  type Ready = Extract<ReturnType<typeof aiStateOfRow>, { kind: "ready" }>;
  const ready = (over: Partial<Ready> = {}): Ready => ({
    kind: "ready",
    action: "true_positive",
    confidence: "high",
    forced: false,
    proposed: "true_positive",
    heldBy: [],
    ...over,
  });

  it("takes the model's own answer first", () => {
    expect(conclusionOf(ready({ action: "needs_review", proposed: "false_positive" }))).toBe(
      "false_positive",
    );
    expect(conclusionOf(ready({ action: "true_positive", proposed: "true_positive" }))).toBe(
      "true_positive",
    );
  });

  it("falls back on the final action when the server sent no proposed_action and the action is the model's", () => {
    expect(conclusionOf(ready({ proposed: null, action: "true_positive" }))).toBe("true_positive");
    expect(conclusionOf(ready({ proposed: null, action: "false_positive" }))).toBe(
      "false_positive",
    );
  });

  it("is null when there is nothing to say the model concluded: needs_review alone, or a word it may not give", () => {
    expect(conclusionOf(ready({ proposed: null, action: "needs_review" }))).toBeNull();
    expect(conclusionOf(ready({ proposed: null, action: "escalate" }))).toBeNull();
    expect(conclusionOf(ready({ proposed: "needs_review", action: "needs_review" }))).toBeNull();
  });

  it("holds when the system's action is needs_review or reasons are given, and not otherwise", () => {
    expect(heldOf(ready())).toBe(false);
    expect(heldOf(ready({ action: "needs_review", proposed: "false_positive" }))).toBe(true);
    expect(heldOf(ready({ heldBy: ["verifier_disagrees"] }))).toBe(true);
    expect(heldOf(ready({ action: "false_positive", proposed: "false_positive" }))).toBe(false);
  });
});
