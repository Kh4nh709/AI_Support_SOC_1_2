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
import type { AlertView, QueueRow, RagRule } from "../../api/tier1";
import {
  DECIDED,
  MODEL_ACTIONS,
  aiStateOfRow,
  aiStateOfView,
  conclusionOf,
  heldOf,
} from "./aiState";

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

  // DEC-217: a verdict with warnings is the model's verdict (the server serves FP or TP), with the checks that
  // raised a warning in `held_by`; nothing is forced for a new run.
  it("keeps the verdict and carries the warnings beside it, forced false, for a new run", () => {
    const warned = row({
      suggested_action: "false_positive",
      gate_forced: false,
      proposed_action: "false_positive",
      held_by: ["fp_policy:asset_criticality", "verifier_disagrees"],
    });
    expect(aiStateOfRow(warned)).toEqual({
      kind: "ready",
      action: "false_positive",
      confidence: "medium",
      forced: false,
      proposed: "false_positive",
      heldBy: ["fp_policy:asset_criticality", "verifier_disagrees"],
    });
  });

  it("keeps forced true for a version 1 row the gate forced (gate_forced true), served as the model's verdict", () => {
    const v1 = row({
      suggested_action: "false_positive",
      gate_forced: true,
      proposed_action: "false_positive",
      held_by: ["fp_policy:playbook_rule"],
    });
    expect(aiStateOfRow(v1)).toEqual({
      kind: "ready",
      action: "false_positive",
      confidence: "medium",
      forced: true,
      proposed: "false_positive",
      heldBy: ["fp_policy:playbook_rule"],
    });
  });

  // P14-T03 (DEC-213), now only a guard: a stored `needs_review` that still arrives (an old client cache, a server
  // that predates DEC-217) is read as it came, with the model's own answer and the reasons beside it.
  it("carries the model's own answer and the reasons beside a stored needs_review that still arrives", () => {
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

  it("keeps the verdict and carries the warnings beside it, forced false, for a new run", () => {
    const warned = view({
      suggestion: {
        suggested_action: "true_positive",
        confidence: "medium",
        gate: { forced: false },
      },
      proposed_action: "true_positive",
      held_by: ["facts_mismatch", "no_verified_quote"],
    });
    expect(aiStateOfView(warned)).toEqual({
      kind: "ready",
      action: "true_positive",
      confidence: "medium",
      forced: false,
      proposed: "true_positive",
      heldBy: ["facts_mismatch", "no_verified_quote"],
    });
  });

  // DEC-219: for a run the RAG default applied to, the server leaves out of `held_by` the two reasons that would tell
  // what the model answered (the verifier's disagreement, the playbook rule it cited). The state leaves them out too, once,
  // so every consumer of `heldBy` (the line of a decided page, the flat column, the panel) gets the filtered list.
  describe("for a run the RAG default applied to (DEC-219), whatever arrives", () => {
    const applied = (over: Partial<AlertView> = {}, gate: Record<string, unknown> = {}) =>
      view({
        suggestion: {
          suggested_action: "false_positive",
          confidence: null,
          gate: {
            forced: false,
            rag_rule: { threshold: 80, best_pct: 62, applied: true },
            ...gate,
          },
        },
        proposed_action: "false_positive",
        ...over,
      });
    const STRAY = [
      "fp_policy:asset_criticality",
      "verifier_disagrees",
      "fp_policy:playbook_rule",
      "verifier_invalid",
      "facts_mismatch",
    ];

    it("leaves out the verifier's disagreement and the playbook rule, and keeps every other reason, in order", () => {
      expect(aiStateOfView(applied({ held_by: STRAY }))).toMatchObject({
        kind: "ready",
        heldBy: ["fp_policy:asset_criticality", "verifier_invalid", "facts_mismatch"],
      });
    });

    it("does the same for a decided page, whose line reads the same list", () => {
      const decided = applied({ status: "closed_fp", held_by: STRAY });
      expect(aiStateOfView(decided)).toMatchObject({
        kind: "decided",
        heldBy: ["fp_policy:asset_criticality", "verifier_invalid", "facts_mismatch"],
      });
    });

    it("is never forced, whatever the gate's record says", () => {
      expect(aiStateOfView(applied({}, { forced: true, forced_by: ["step4"] }))).toMatchObject({
        kind: "ready",
        forced: false,
      });
    });

    it("leaves a run the rule did not apply to as it was: both reasons stay", () => {
      const notApplied = applied(
        { held_by: STRAY },
        { rag_rule: { threshold: 80, applied: false } },
      );
      expect(aiStateOfView(notApplied)).toMatchObject({ heldBy: STRAY });
      const noRule = view({ held_by: STRAY });
      expect(aiStateOfView(noRule)).toMatchObject({ heldBy: STRAY });
    });

    it("reads `applied` as the server wrote it: only the JSON true", () => {
      for (const odd of ["true", 1, "yes", null, undefined, {}]) {
        const state = aiStateOfView(
          applied({ held_by: STRAY }, { rag_rule: { threshold: 80, applied: odd } }),
        );
        expect(state, String(odd)).toMatchObject({ heldBy: STRAY });
      }
    });
  });

  it("keeps forced true for a version 1 row the gate forced, served as the model's verdict", () => {
    const v1 = view({
      suggestion: {
        suggested_action: "true_positive",
        confidence: "medium",
        gate: { forced: true, forced_by: ["step4"] },
      },
      proposed_action: "true_positive",
      held_by: ["facts_mismatch"],
    });
    expect(aiStateOfView(v1)).toMatchObject({
      kind: "ready",
      action: "true_positive",
      forced: true,
      heldBy: ["facts_mismatch"],
    });
  });

  it("carries the model's own answer and the reasons beside a stored needs_review that still arrives (the guard)", () => {
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
        proposed: "false_positive",
        heldBy: [],
      });
    }
  });

  // Fix round 1 (I1): a decided alert still says what the AI concluded and which checks warned (DEC-217).
  it("carries the verdict and the warnings into the decided state", () => {
    const warned = view({
      status: "closed_fp",
      suggestion: {
        suggested_action: "true_positive",
        confidence: "medium",
        gate: { forced: false },
      },
      proposed_action: "true_positive",
      held_by: ["facts_mismatch", "verifier_invalid"],
    });
    expect(aiStateOfView(warned)).toEqual({
      kind: "decided",
      action: "true_positive",
      confidence: "medium",
      proposed: "true_positive",
      heldBy: ["facts_mismatch", "verifier_invalid"],
    });
  });

  it("carries the model's own answer and the reasons into the decided state beside a stored needs_review (the guard)", () => {
    const held = view({
      status: "closed_fp",
      suggestion: {
        suggested_action: "needs_review",
        confidence: "medium",
        gate: { forced: true },
      },
      proposed_action: "true_positive",
      held_by: ["facts_mismatch", "verifier_invalid"],
    });
    expect(aiStateOfView(held)).toEqual({
      kind: "decided",
      action: "needs_review",
      confidence: "medium",
      proposed: "true_positive",
      heldBy: ["facts_mismatch", "verifier_invalid"],
    });
  });

  it("reads a decided view without the two keys as none, and a blind head the decision revealed as decided", () => {
    const bare = view({ status: "closed_benign" });
    delete bare.proposed_action;
    delete bare.held_by;
    expect(aiStateOfView(bare)).toMatchObject({ kind: "decided", proposed: null, heldBy: [] });
    // the decision lifts the blind arm: the keys the server sent back are read
    const revealed = view({
      status: "closed_benign",
      suggestion_visible: false,
      proposed_action: "false_positive",
      held_by: ["verifier_disagrees"],
    });
    expect(aiStateOfView(revealed)).toMatchObject({
      kind: "decided",
      proposed: "false_positive",
      heldBy: ["verifier_disagrees"],
    });
  });

  it("is decided with no action when ① never produced one", () => {
    const silent = view({
      status: "closed_benign",
      suggestion: null,
      proposed_action: null,
      held_by: [],
    });
    expect(aiStateOfView(silent)).toEqual({
      kind: "decided",
      action: null,
      confidence: null,
      proposed: null,
      heldBy: [],
    });
  });

  // DEC-219 (amended): below the threshold `false_positive` is ①'s default answer. The alert view's
  // `suggestion.gate.rag_rule` says the rule applied (`applied` true, whether or not the model had said FP itself); the
  // state keeps the threshold of that rule, and only then (a rule that did not apply, a run with no `rag_rule`, and a
  // version 1 row have no such key). Only `applied` and `threshold` are read: the page never says what the model answered.
  describe("the RAG default below the threshold (DEC-219)", () => {
    const RULE: RagRule = { threshold: 80, best_pct: 62, applied: true };
    /**
     * A run the rule applied to as the server serves it: ① ended with FP, nothing of the model's own answer is served
     * (`proposed_action` and `gate.proposed_verdict` are the verdict ① ended with, the verifier's verdict and the
     * confidence are null), and nothing is forced. `held_by` never carries `verifier_disagrees`.
     */
    const applied = (over: Partial<AlertView> = {}, rule: unknown = RULE): AlertView =>
      view({
        suggestion: {
          suggested_action: "false_positive",
          confidence: null,
          gate: {
            forced: false,
            forced_by: [],
            proposed_verdict: "false_positive",
            final_verdict: "false_positive",
            verifier_verdict: null,
            rag_rule: rule as RagRule | null | undefined,
          },
        },
        proposed_action: "false_positive",
        held_by: [],
        ...over,
      });

    it("is carried by a ready state, beside the verdict, with nothing forced", () => {
      expect(aiStateOfView(applied())).toEqual({
        kind: "ready",
        action: "false_positive",
        confidence: null,
        forced: false,
        proposed: "false_positive",
        heldBy: [],
        ragDefaultBelow: 80,
      });
    });

    it("reads only applied and threshold: a key of the rule it does not read (a `changed` an older server sent) alters nothing", () => {
      const plain = aiStateOfView(applied());
      expect(plain).toMatchObject({ kind: "ready", ragDefaultBelow: 80 });
      for (const changed of [true, false]) {
        expect(aiStateOfView(applied({}, { ...RULE, changed }))).toEqual(plain);
      }
      expect(aiStateOfView(applied({}, { ...RULE, note: "x" }))).toEqual(plain);
    });

    it("is carried by a decided state too, the decision lifting the blind arm", () => {
      for (const status of DECIDED) {
        expect(aiStateOfView(applied({ status }))).toEqual({
          kind: "decided",
          action: "false_positive",
          confidence: null,
          proposed: "false_positive",
          heldBy: [],
          ragDefaultBelow: 80,
        });
      }
      expect(
        aiStateOfView(applied({ status: "closed_fp", suggestion_visible: false })),
      ).toMatchObject({ kind: "decided", ragDefaultBelow: 80 });
    });

    it("takes the threshold from the stored rule, whatever it was", () => {
      const rule = { ...RULE, threshold: 65, best_pct: 40 };
      expect(aiStateOfView(applied({}, rule))).toMatchObject({ ragDefaultBelow: 65 });
    });

    it("keeps the warnings beside it", () => {
      // a reason about a fact of the alert is the system's own and stays (the playbook rule is the model's and goes)
      expect(aiStateOfView(applied({ held_by: ["fp_policy:asset_criticality"] }))).toMatchObject({
        heldBy: ["fp_policy:asset_criticality"],
        ragDefaultBelow: 80,
      });
    });

    it.each([
      ["a rule that did not apply", { threshold: 80, best_pct: 91, applied: false }],
      ["a rule switched off", { threshold: 0, best_pct: null, applied: false }],
      ["a run with no rag_rule (null)", null],
      ["a run with no rag_rule (not a key)", undefined],
      ["a rag_rule that is not an object", "applied"],
      ["an applied rule with no threshold", { applied: true }],
      ["an applied rule whose threshold is not a number", { ...RULE, threshold: "80" }],
      [
        "an applied rule whose threshold is 0 (switched off: nothing is below it)",
        { ...RULE, threshold: 0 },
      ],
      ["a rule whose applied is not true", { ...RULE, applied: "yes" }],
      [
        "a rule with no applied key (a `changed` alone is not read)",
        { threshold: 80, best_pct: 62, changed: true },
      ],
    ])("has no threshold for %s", (_name, rule) => {
      const v = applied({}, rule);
      if (rule === undefined) delete v.suggestion?.gate?.rag_rule;
      const state = aiStateOfView(v);
      expect(state).toMatchObject({ kind: "ready" });
      expect("ragDefaultBelow" in state).toBe(false);
    });

    // A server that says the rule applied while the verdict it serves is not `false_positive` is inconsistent: the
    // state then has no default to announce, and the line is today's.
    it.each([
      ["true_positive", "ready"],
      ["needs_review", "ready"],
      ["true_positive", "decided"],
    ])(
      "has no threshold when the rule applied but the action is %s (an inconsistent server): %s",
      (action, kind) => {
        const v = applied(kind === "decided" ? { status: "closed_fp" } : {});
        v.suggestion = { ...v.suggestion!, suggested_action: action };
        const state = aiStateOfView(v);
        expect(state).toMatchObject({ kind, action });
        expect("ragDefaultBelow" in state).toBe(false);
      },
    );

    it("is never in the state of a queue row, which carries no rag_rule", () => {
      const queued = aiStateOfRow(
        row({
          suggested_action: "false_positive",
          proposed_action: "false_positive",
          gate_forced: false,
        }),
      );
      expect(queued).toEqual({
        kind: "ready",
        action: "false_positive",
        confidence: "medium",
        forced: false,
        proposed: "false_positive",
        heldBy: [],
      });
    });

    it("is not in a blind, undecided head, which has no suggestion to read it from", () => {
      const blind = applied({ suggestion_visible: false });
      delete blind.suggestion;
      delete blind.triage_status;
      expect(aiStateOfView(blind)).toEqual({ kind: "hidden" });
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
        proposed: "false_positive",
        heldBy: [],
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

// P14-T03 (DEC-213): what the model concluded, and whether the checks raised a warning beside it (DEC-217: the
// gate holds nothing back). Two readings of a `ready` state, kept here so the column and the cell do not each
// decide them.
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

  // DEC-219: the conclusion is the verdict ① ended with. For every run before the RAG rule the action and the
  // model's answer are the same word, or the action is a stored `needs_review`, so only a run below the RAG threshold can read differently.
  it("takes the verdict ① ended with first, the model's own answer when it is the same", () => {
    expect(conclusionOf(ready({ action: "true_positive", proposed: "true_positive" }))).toBe(
      "true_positive",
    );
    expect(conclusionOf(ready({ action: "false_positive", proposed: "false_positive" }))).toBe(
      "false_positive",
    );
  });

  it("is the verdict ① ended with, not the model's answer, whenever the two differ (the RAG default, DEC-219)", () => {
    expect(conclusionOf(ready({ action: "false_positive", proposed: "true_positive" }))).toBe(
      "false_positive",
    );
    expect(conclusionOf({ action: "false_positive", proposed: "true_positive", heldBy: [] })).toBe(
      "false_positive",
    );
  });

  it("falls back on proposed for an action that is none of the two, whatever the word: an unknown one too", () => {
    expect(conclusionOf(ready({ action: "escalate", proposed: "true_positive" }))).toBe(
      "true_positive",
    );
    expect(conclusionOf(ready({ action: "quarantine_host", proposed: "false_positive" }))).toBe(
      "false_positive",
    );
    expect(conclusionOf(ready({ action: "escalate", proposed: "needs_review" }))).toBeNull();
  });

  it("takes the model's own answer only when the action is not one of the two: the guard for a stored needs_review", () => {
    expect(conclusionOf(ready({ action: "needs_review", proposed: "false_positive" }))).toBe(
      "false_positive",
    );
    expect(conclusionOf(ready({ action: "needs_review", proposed: "true_positive" }))).toBe(
      "true_positive",
    );
    expect(conclusionOf({ action: null, proposed: "true_positive", heldBy: [] })).toBe(
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

  it("reads a decided state the same way, whose action may be null", () => {
    const decided = { action: null, proposed: "false_positive", heldBy: ["verifier_invalid"] };
    expect(conclusionOf(decided)).toBe("false_positive");
    expect(heldOf(decided)).toBe(true);
    expect(conclusionOf({ action: null, proposed: null, heldBy: [] })).toBeNull();
    expect(conclusionOf({ action: "true_positive", proposed: null, heldBy: [] })).toBe(
      "true_positive",
    );
    expect(heldOf({ action: null, proposed: null, heldBy: [] })).toBe(false);
  });

  it("warns when reasons are given beside a verdict, and not otherwise (DEC-217)", () => {
    expect(heldOf(ready())).toBe(false);
    expect(heldOf(ready({ heldBy: ["verifier_disagrees"] }))).toBe(true);
    expect(heldOf(ready({ action: "false_positive", proposed: "false_positive" }))).toBe(false);
    expect(
      heldOf(
        ready({ action: "false_positive", proposed: "false_positive", heldBy: ["facts_mismatch"] }),
      ),
    ).toBe(true);
    expect(heldOf(ready({ action: "true_positive", heldBy: ["fp_policy:severity"] }))).toBe(true);
  });

  it("still warns for a stored needs_review that arrives with no reason: the guard half", () => {
    expect(heldOf(ready({ action: "needs_review", proposed: "false_positive" }))).toBe(true);
    expect(heldOf(ready({ action: "needs_review", proposed: null }))).toBe(true);
  });
});

// MODEL_ACTIONS is a copy of the backend's `llm.verdicts.MODEL_ACTIONS` (the two answers the model may give), and a
// copy drifts: a third answer added there and not here would show as the system's `Cần xem xét` instead of the
// AI's conclusion. So the Python source is read and the two are compared, like DECIDED above.
function pyModelActions(root = BACKEND_APP): string[] {
  const pattern = /^MODEL_ACTIONS(?::\s*tuple\[str,\s*\.\.\.\])?\s*=\s*\(([^)]*)\)/m;
  const found = pyFiles(root).flatMap((path) => {
    const body = pattern.exec(readFileSync(path, "utf8"))?.[1];
    return body === undefined ? [] : [{ path, body }];
  });
  const [only] = found;
  if (found.length !== 1 || !only) {
    throw new Error(`expected exactly one definition of MODEL_ACTIONS, found ${found.length}`);
  }
  return [...only.body.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
}

describe("MODEL_ACTIONS", () => {
  it("is the backend's llm.verdicts.MODEL_ACTIONS, value for value", () => {
    const backend = pyModelActions();
    expect(backend).toEqual(["false_positive", "true_positive"]); // a parse that finds nothing compares nothing
    expect([...MODEL_ACTIONS].sort()).toEqual([...backend].sort());
  });

  it("reports a value added on the Python side only", () => {
    const root = mkdtempSync(join(tmpdir(), "p14t03-py-"));
    try {
      mkdirSync(join(root, "llm"), { recursive: true });
      writeFileSync(
        join(root, "llm", "verdicts.py"),
        'MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive", "quarantine")\n',
      );
      expect([...MODEL_ACTIONS].sort()).not.toEqual([...pyModelActions(root)].sort());
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
