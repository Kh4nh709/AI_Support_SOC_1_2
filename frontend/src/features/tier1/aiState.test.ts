// src/features/tier1/aiState.test.ts — the one place the ① state is decided, for a queue row and for the alert view.
import type { AlertView, QueueRow } from "../../api/tier1";
import { DECIDED, aiStateOfRow, aiStateOfView } from "./aiState";

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
  suggested_action: "escalate",
  confidence: "medium",
  gate_forced: false,
  ...over,
});

/** The row the server sends for a blind, undecided head: the ① keys are not there at all. */
function blindRow(over: Partial<QueueRow> = {}): QueueRow {
  const stripped = row({ suggestion_visible: false });
  delete stripped.suggested_action;
  delete stripped.confidence;
  delete stripped.gate_forced;
  delete stripped.triage_status;
  delete stripped.run_id;
  return { ...stripped, ...over };
}

describe("aiStateOfRow", () => {
  it("is ready with the action and confidence when the row carries a suggestion", () => {
    expect(aiStateOfRow(row())).toEqual({
      kind: "ready",
      action: "escalate",
      confidence: "medium",
      forced: false,
    });
  });

  it("is forced only when gate_forced is true", () => {
    expect(aiStateOfRow(row({ gate_forced: true }))).toMatchObject({ kind: "ready", forced: true });
    expect(aiStateOfRow(row({ gate_forced: null }))).toMatchObject({ kind: "ready", forced: false });
    expect(aiStateOfRow(row({ gate_forced: undefined }))).toMatchObject({ forced: false });
  });

  it("keeps a missing confidence as null", () => {
    expect(aiStateOfRow(row({ confidence: null }))).toMatchObject({ kind: "ready", confidence: null });
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

  it("is unavailable when ① gave up (triage_status unavailable, no action)", () => {
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
  ...over,
});

describe("aiStateOfView", () => {
  it("is ready from the suggestion of the view", () => {
    expect(aiStateOfView(view())).toEqual({
      kind: "ready",
      action: "false_positive",
      confidence: "high",
      forced: false,
    });
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
