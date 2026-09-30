// src/features/tier1/AiColumn.test.tsx — the ① column of the alert page, one test per state of `AiState`:
// ready, hidden (the blind arm, DEC-101), pending, unavailable and decided. What the column says is decided
// by `aiStateOfView`; these tests also inject a state, to pin what each state shows and, above all, what the
// hidden one never does.
import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { AlertView, Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { AiColumn } from "./AiColumn";
import { aiStateOfView, type AiState } from "./aiState";

const suggestion = (over: Partial<Suggestion> = {}): Suggestion => ({
  run_id: "r1",
  suggested_action: "escalate",
  confidence: "medium",
  reasons: [
    {
      claim: "37 lần xác thực thất bại từ cùng một IP ngoài",
      quote: "Failed password for invalid user admin from 203.0.113.45 port 51522 ssh2",
      source: "wazuh_raw_log",
    },
    { claim: "Chưa thấy đăng nhập thành công trong ±2 giờ", quote: null, source: "correlation" },
  ],
  gate: {
    forced: false,
    forced_by: null,
    proposed_verdict: "escalate",
    final_verdict: "escalate",
    verifier_verdict: "agree",
    warnings: [],
  },
  correlated_at_analysis: 4,
  created_at: "2026-09-30T02:31:02Z",
  ...over,
});

/** A visible-arm view with a ① result. */
const view = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  triage_status: "ready",
  suggestion: suggestion(),
  correlated_now: 4,
  ...over,
});

/** What the server sends for a blind, undecided head: no `suggestion`, no `triage_status`, no `run_id`. */
function blindView(over: Partial<AlertView> = {}): AlertView {
  const stripped = view({ suggestion_visible: false });
  delete stripped.suggestion;
  delete stripped.triage_status;
  return { ...stripped, ...over };
}

const column = () => screen.getByRole("region", { name: S.alert.aiHeading });
const renderColumn = (v: AlertView, state?: AiState) =>
  render(
    <main>
      <AiColumn view={v} state={state} />
    </main>,
  );

/** Every word of a verdict that must not reach a column that is hidden. */
const VERDICT_WORDS = [
  "Chuyển tier 2",
  "escalate",
  "Cần xem xét",
  "Dương tính giả",
  "trung bình",
  "37 lần xác thực",
  "Failed password",
];

describe("ready", () => {
  it("shows the verdict with its code, the confidence, and no flag when the gate forced nothing", () => {
    renderColumn(view());
    const col = within(column());
    expect(col.getByRole("heading", { name: S.alert.aiHeading })).toBeInTheDocument();
    expect(col.getByText(S.ai1.verdict).parentElement).toHaveTextContent(S.ai1.action.escalate);
    expect(col.getAllByText("escalate").length).toBeGreaterThan(0);
    expect(
      col.getByText(new RegExp(`${S.ai1.confidence}.*${S.confidence.medium}`)),
    ).toBeInTheDocument();
    expect(col.queryByRole("img", { name: S.ai1.forcedLabel })).not.toBeInTheDocument();
    expect(col.getByText(S.ai1.gateNotForced)).toBeInTheDocument();
  });

  it("shows ⚑ and the gate rules that forced the verdict", () => {
    renderColumn(
      view({
        suggestion: suggestion({
          suggested_action: "needs_review",
          gate: {
            forced: true,
            forced_by: ["quote_not_in_log", "privileged_account"],
            proposed_verdict: "false_positive",
            final_verdict: "needs_review",
            verifier_verdict: "disagree",
            warnings: [],
          },
        }),
      }),
    );
    const col = within(column());
    expect(col.getByRole("img", { name: S.ai1.forcedLabel })).toHaveTextContent(S.ai1.forced);
    expect(col.getByText(S.ai1.gateForced)).toBeInTheDocument();
    expect(col.getByText("quote_not_in_log, privileged_account")).toBeInTheDocument();
    // the verdict ① proposed before the gate, and the one after it
    const steps = within(col.getByRole("region", { name: S.ai1.gateSteps }));
    expect(steps.getByText(S.ai1.action.false_positive)).toBeInTheDocument();
    expect(steps.getByText(S.ai1.action.needs_review)).toBeInTheDocument();
  });

  it("lists each reason with its quote and its source, and a reason with no quote has none", () => {
    renderColumn(view());
    const reasons = within(within(column()).getByRole("region", { name: S.ai1.reasons }));
    const items = reasons.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("37 lần xác thực thất bại từ cùng một IP ngoài");
    expect(within(items[0]).getByText(/Failed password for invalid user admin/).tagName).toBe(
      "BLOCKQUOTE",
    );
    expect(items[0]).toHaveTextContent(`${S.ai1.source}: wazuh_raw_log`);
    expect(items[1]).toHaveTextContent("Chưa thấy đăng nhập thành công");
    expect(items[1].querySelector("blockquote")).toBeNull();
    expect(items[1]).toHaveTextContent(`${S.ai1.source}: correlation`);
  });

  it("shows the gate steps, the verifier, the facts ① used, and when it ran (+07)", () => {
    renderColumn(
      view({
        suggestion: suggestion({
          gate: {
            forced: false,
            forced_by: null,
            proposed_verdict: "escalate",
            final_verdict: "escalate",
            verifier_verdict: "agree",
            warnings: ["reason 3 cites no log"],
          },
        }),
      }),
    );
    const col = within(column());
    expect(col.getByText(S.ai1.verifier).parentElement).toHaveTextContent("agree");
    const steps = within(col.getByRole("region", { name: S.ai1.gateSteps }));
    expect(steps.getByText(S.ai1.gateProposed)).toBeInTheDocument();
    expect(steps.getByText(S.ai1.gateFinal)).toBeInTheDocument();
    expect(steps.getByText("reason 3 cites no log")).toBeInTheDocument();
    const facts = within(col.getByRole("region", { name: S.ai1.facts }));
    expect(facts.getByText(S.ai1.correlatedThen).parentElement).toHaveTextContent("4");
    // 02:31:02Z is 09:31:02 in Asia/Ho_Chi_Minh, whatever the zone of the machine
    expect(
      col.getByText(new RegExp(`${S.ai1.analysedAt}.*30/09/2026 09:31:02`)),
    ).toBeInTheDocument();
  });

  it("says that the clusters have changed since ① ran, and only then", () => {
    const { rerender } = renderColumn(view({ correlated_now: 6 }));
    expect(within(column()).getByText(S.ai1.correlatedChanged(4, 6))).toBeInTheDocument();
    rerender(
      <main>
        <AiColumn view={view({ correlated_now: 4 })} />
      </main>,
    );
    expect(within(column()).queryByText(/gợi ý dựa trên/)).not.toBeInTheDocument();
    rerender(
      <main>
        <AiColumn view={view({ suggestion: suggestion({ correlated_at_analysis: null }) })} />
      </main>,
    );
    expect(within(column()).queryByText(/gợi ý dựa trên/)).not.toBeInTheDocument();
  });

  it("unknown enum renders raw code: an action, a confidence and a verifier verdict without a label", () => {
    renderColumn(
      view({
        suggestion: suggestion({
          suggested_action: "quarantine_host",
          confidence: "very_high",
          gate: { forced: false, proposed_verdict: "isolate", verifier_verdict: "maybe" },
        }),
      }),
    );
    const col = within(column());
    expect(col.getAllByText("quarantine_host").length).toBeGreaterThan(0);
    expect(col.getByText(new RegExp("very_high"))).toBeInTheDocument();
    expect(col.getByText("isolate")).toBeInTheDocument();
    expect(col.getByText("maybe")).toBeInTheDocument();
  });

  it("renders hostile model text as text", () => {
    const hostile = '<img src=x onerror="window.__ai=1"> ‮evil \u001b[31m</script>';
    const { container } = renderColumn(
      view({
        suggestion: suggestion({
          reasons: [{ claim: hostile, quote: hostile, source: hostile }],
        }),
      }),
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect((window as unknown as { __ai?: number }).__ai).toBeUndefined();
    expect(container.textContent).toContain("<img src=x onerror=");
  });
});

describe("hidden (the blind arm)", () => {
  it("says S.ai1.hidden for a view the server stripped, and names no verdict anywhere in the column", () => {
    renderColumn(blindView());
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    for (const word of VERDICT_WORDS) expect(col.textContent, word).not.toContain(word);
    // it does not say that ① is working, or has failed, or has nothing to say
    expect(col.textContent).not.toContain(S.ai1.pending);
    expect(col.textContent).not.toContain(S.ai1.unavailable);
    expect(col.textContent).not.toContain(S.ai1.none);
  });

  it("shows no verdict text even when the state is hidden and the view holds a result", () => {
    // The state is the server's word, read once by aiStateOfView; a column that is told `hidden` shows none of
    // ①, whatever else the object it was handed happens to carry.
    renderColumn(view(), { kind: "hidden" });
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    for (const word of VERDICT_WORDS) expect(col.textContent, word).not.toContain(word);
    expect(within(col).queryByRole("img", { name: S.ai1.forcedLabel })).not.toBeInTheDocument();
  });

  it("is what aiStateOfView says of a blind view, which is where the column reads it", () => {
    expect(aiStateOfView(blindView()).kind).toBe("hidden");
    renderColumn(blindView());
    expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
  });
});

describe("pending", () => {
  it("says ① is working, and names no verdict", () => {
    renderColumn(view({ suggestion: null, triage_status: "pending" }));
    const col = column();
    expect(within(col).getByText(S.ai1.pending)).toBeInTheDocument();
    expect(col.textContent).toContain(S.ai1.pendingBody);
    expect(col.textContent).not.toContain(S.ai1.hidden);
    for (const word of VERDICT_WORDS) expect(col.textContent, word).not.toContain(word);
  });
});

describe("unavailable", () => {
  it("shows stopped_by with its label, and the code beside it", () => {
    renderColumn(view({ suggestion: null, triage_status: "unavailable" }), {
      kind: "unavailable",
      stoppedBy: "schema",
    });
    const col = within(column());
    expect(col.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(col.getByText(S.ai1.stoppedBy.schema)).toBeInTheDocument();
    expect(col.getByText("schema").tagName).toBe("CODE");
  });

  it("unknown enum renders raw code: a stopped_by without a label is shown as it came", () => {
    renderColumn(view({ suggestion: null }), { kind: "unavailable", stoppedBy: "cosmic_ray" });
    const col = within(column());
    expect(col.getAllByText("cosmic_ray").length).toBeGreaterThan(0);
  });

  it("says nothing of a reason it was not told (the view carries none)", () => {
    renderColumn(view({ suggestion: null, triage_status: "unavailable" }));
    const col = within(column());
    expect(col.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(col.queryByText(S.ai1.stoppedByLabel)).not.toBeInTheDocument();
  });
});

describe("decided", () => {
  const decided = (over: Partial<AlertView> = {}) =>
    view({
      status: "closed_fp",
      acknowledged_by: "u1",
      acknowledged_by_name: "An",
      ...over,
    });

  it("puts the decision beside what ① said", () => {
    renderColumn(decided());
    const col = within(column());
    expect(col.getByText(S.ai1.decidedHeading)).toBeInTheDocument();
    const mine = col.getByText(S.decision.heading).closest("div")!;
    expect(mine).toHaveTextContent(S.status.closed_fp);
    expect(mine).toHaveTextContent("An");
    const ai = col.getByText(S.ai1.decidedAi).closest("div")!;
    expect(ai).toHaveTextContent(S.ai1.action.escalate);
    expect(ai).toHaveTextContent(S.confidence.medium);
  });

  it("says ① had nothing to say when the view carries no result", () => {
    renderColumn(decided({ suggestion: null }));
    const ai = within(column()).getByText(S.ai1.decidedAi).closest("div")!;
    expect(ai).toHaveTextContent(S.ai1.none);
  });

  it("unknown enum renders raw code: a status and an action without a label", () => {
    // A status the UI does not know is not one of `DECIDED`, so the state is handed in: this pins how the
    // comparison words a status and an action it has no label for.
    renderColumn(
      decided({
        status: "closed_mystery",
        suggestion: suggestion({ suggested_action: "quarantine_host" }),
      }),
      { kind: "decided", action: "quarantine_host", confidence: "medium" },
    );
    const col = within(column());
    expect(col.getByText("closed_mystery")).toBeInTheDocument();
    expect(col.getByText("quarantine_host")).toBeInTheDocument();
  });
});

describe("accessibility", () => {
  const states: [string, AlertView, AiState | undefined][] = [
    ["ready", view(), undefined],
    [
      "ready and forced",
      view({
        suggestion: suggestion({
          gate: { forced: true, forced_by: ["x"], warnings: ["w"], verifier_verdict: "agree" },
        }),
        correlated_now: 9,
      }),
      undefined,
    ],
    ["hidden", blindView(), undefined],
    ["pending", view({ suggestion: null, triage_status: "pending" }), undefined],
    [
      "unavailable",
      view({ suggestion: null, triage_status: "unavailable" }),
      { kind: "unavailable", stoppedBy: "schema" },
    ],
    ["decided", view({ status: "closed_benign", acknowledged_by_name: "An" }), undefined],
  ];

  it.each(states)("has no axe violation in the %s state", async (_name, v, state) => {
    const { container } = renderColumn(v, state);
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(
      result.violations.map((x) => `${x.id}: ${x.nodes.map((n) => n.html).join(" | ")}`),
    ).toEqual([]);
  });
});
