// src/features/tier1/AiColumn.test.tsx — the ① column of the alert page, one test per state of `AiState`:
// ready, hidden (the blind arm, DEC-101), pending, unavailable and decided. What the column says is decided
// by `aiStateOfView` and by nothing else: the column takes no state, so every test here reaches a state the
// only way the page does, with a view the server could have sent.
import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { AlertView, Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { AiColumn, Unavailable } from "./AiColumn";
import { aiStateOfView } from "./aiState";

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
const renderColumn = (v: AlertView) =>
  render(
    <main>
      <AiColumn view={v} />
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
    const [first, second] = items as [HTMLElement, HTMLElement];
    expect(first).toHaveTextContent("37 lần xác thực thất bại từ cùng một IP ngoài");
    expect(within(first).getByText(/Failed password for invalid user admin/).tagName).toBe(
      "BLOCKQUOTE",
    );
    expect(first).toHaveTextContent(`${S.ai1.source}: wazuh_raw_log`);
    expect(second).toHaveTextContent("Chưa thấy đăng nhập thành công");
    expect(second.querySelector("blockquote")).toBeNull();
    expect(second).toHaveTextContent(`${S.ai1.source}: correlation`);
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

  it("shows no verdict text for a blind view that still carries the other ① keys", () => {
    // Hidden is the server's word (no `suggestion` key, `suggestion_visible` false), read once by aiStateOfView;
    // the column shows none of ① whatever else the view happens to carry: a ready triage status, a fresh count.
    const stray = blindView({ triage_status: "ready", correlated_now: 9, close_reason: null });
    expect(aiStateOfView(stray).kind).toBe("hidden");
    renderColumn(stray);
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    for (const word of VERDICT_WORDS) expect(col.textContent, word).not.toContain(word);
    expect(col.textContent).not.toContain(S.ai1.correlatedThen);
    expect(within(col).queryByRole("img", { name: S.ai1.forcedLabel })).not.toBeInTheDocument();
  });

  it("is what aiStateOfView says of a blind view, which is where the column reads it", () => {
    expect(aiStateOfView(blindView()).kind).toBe("hidden");
    renderColumn(blindView());
    expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
  });

  it("cannot be told a state: a view that holds a result is ready, whatever the caller would say", () => {
    // The column read a `state` prop once, for tests. It takes none now, so a state cannot come from anywhere
    // but the view: the type refuses the prop, and were it passed, it is not what the column shows.
    function Told() {
      return AiColumn({
        view: view(),
        // @ts-expect-error the column takes no state
        state: { kind: "hidden" },
      });
    }
    render(
      <main>
        <Told />
      </main>,
    );
    const col = column();
    expect(within(col).queryByText(S.ai1.hidden)).not.toBeInTheDocument();
    expect(col.textContent).toContain(S.ai1.action.escalate);
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
  it("says ① gave up, from the view's own triage status, and says nothing of a reason it was not told", () => {
    // Neither the queue nor the alert view carries `stopped_by`, so from a view the reason is never known.
    const gaveUp = view({ suggestion: null, triage_status: "unavailable" });
    expect(aiStateOfView(gaveUp)).toEqual({ kind: "unavailable", stoppedBy: null });
    renderColumn(gaveUp);
    const col = within(column());
    expect(col.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(col.getByText(S.ai1.unavailableBody)).toBeInTheDocument();
    expect(col.queryByText(S.ai1.stoppedByLabel)).not.toBeInTheDocument();
  });

  // The wording of a reason is kept for the day the view carries one: the part is drawn on its own.
  it("shows stopped_by with its label, and the code beside it", () => {
    render(<Unavailable stoppedBy="schema" />);
    expect(screen.getByText(S.ai1.stoppedBy.schema)).toBeInTheDocument();
    expect(screen.getByText("schema").tagName).toBe("CODE");
  });

  it("words a provider 402: stopped_by unavailable has a label, and the code beside it", () => {
    render(<Unavailable stoppedBy="unavailable" />);
    expect(screen.getByText(S.ai1.stoppedBy.unavailable)).toBeInTheDocument();
    expect(S.ai1.stoppedBy.unavailable).toBe("nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)");
    expect(screen.getByText("unavailable", { selector: "code" })).toBeInTheDocument();
  });

  it("unknown enum renders raw code: a stopped_by without a label is shown as it came", () => {
    render(<Unavailable stoppedBy="cosmic_ray" />);
    expect(screen.getByText("cosmic_ray")).toBeInTheDocument();
    expect(screen.queryByText("cosmic_ray", { selector: "code" })).not.toBeInTheDocument();
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
  /** The row that says whether ① and the person agree: its label's own container. */
  const match = () => within(column()).queryByText(S.ai1.match)?.parentElement ?? null;
  const labelOfStatus = (status: string) => (S.status as Record<string, string>)[status] ?? status;

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

  it("says ① had nothing to say when the view carries no result, and compares nothing", () => {
    renderColumn(decided({ suggestion: null }));
    const ai = within(column()).getByText(S.ai1.decidedAi).closest("div")!;
    expect(ai).toHaveTextContent(S.ai1.none);
    expect(match()).toHaveTextContent(S.ai1.matchNoVerdict);
  });

  it("unknown enum renders raw code: an action without a label", () => {
    // A status the UI does not know is not one of `DECIDED`, so it is not a decided view (the page tests
    // word an unknown status); the action is what a decided view can carry that the UI has no label for.
    renderColumn(decided({ suggestion: suggestion({ suggested_action: "quarantine_host" }) }));
    expect(within(column()).getByText("quarantine_host")).toBeInTheDocument();
    // the pilot report counts an action that is none of the three as no result: nothing is compared
    expect(match()).toHaveTextContent(S.ai1.matchNoVerdict);
  });

  describe("the Khớp row, by the pilot report's mapping (P10-T06, eval/ops_export.py)", () => {
    it.each([
      // agreement: ① escalate with a human escalation, ① false_positive with a human closed_fp
      ["escalated_tier2", "escalate", S.ai1.matchAgree],
      ["closed_fp", "false_positive", S.ai1.matchAgree],
      // any other pair of a verdict and a human decision disagrees
      ["escalated_tier2", "false_positive", S.ai1.matchDisagree],
      ["closed_fp", "escalate", S.ai1.matchDisagree],
      ["closed_benign", "escalate", S.ai1.matchDisagree],
      // ① has no benign verdict: a human closed_benign after ① false_positive is a disagreement
      ["closed_benign", "false_positive", S.ai1.matchDisagree],
      // ① needs_review is no verdict
      ["escalated_tier2", "needs_review", S.ai1.matchNoVerdict],
      ["closed_fp", "needs_review", S.ai1.matchNoVerdict],
      ["closed_benign", "needs_review", S.ai1.matchNoVerdict],
    ])("%s after ① %s says '%s'", (status, action, said) => {
      renderColumn(decided({ status, suggestion: suggestion({ suggested_action: action }) }));
      expect(match()).toHaveTextContent(said);
      expect(match()).toHaveTextContent(S.ai1.match);
    });

    it("has no row when the view is not decided", () => {
      renderColumn(view());
      expect(within(column()).queryByText(S.ai1.match)).not.toBeInTheDocument();
    });
  });

  describe("an alert that no Tier 1 person decided", () => {
    it.each(["auto_closed", "closed_confirmed"])(
      "%s names nobody as the decider and compares nothing",
      (status) => {
        renderColumn(decided({ status, acknowledged_by_name: "Nguyễn Văn Ân" }));
        const col = within(column());
        // the status is said; the person who once acknowledged the alert is not named as who decided it
        expect(col.getByText(S.decision.heading).closest("div")).toHaveTextContent(
          labelOfStatus(status),
        );
        expect(column().textContent).not.toContain("Nguyễn Văn Ân");
        expect(col.getByText(S.ai1.notTier1Decision)).toBeInTheDocument();
        expect(col.queryByText(S.ai1.match)).not.toBeInTheDocument();
        // what ① said is still shown beside it
        expect(col.getByText(S.ai1.decidedAi).closest("div")).toHaveTextContent(
          S.ai1.action.escalate,
        );
      },
    );

    it.each(["closed_fp", "closed_benign", "escalated_tier2"])(
      "%s names who decided it, and says nothing of a Tier 2 or system close",
      (status) => {
        renderColumn(decided({ status, acknowledged_by_name: "Nguyễn Văn Ân" }));
        expect(column().textContent).toContain("Nguyễn Văn Ân");
        expect(within(column()).queryByText(S.ai1.notTier1Decision)).not.toBeInTheDocument();
      },
    );

    it("names nobody, and keeps the note, for a close with no case even when case_id is null", () => {
      renderColumn(
        decided({ status: "closed_confirmed", case_id: null, acknowledged_by_name: "Trần Bình" }),
      );
      expect(within(column()).getByText(S.ai1.notTier1Decision)).toBeInTheDocument();
      expect(column().textContent).not.toContain("Trần Bình");
    });
  });

  // A Tier 2 conclusion rewrites the status of an alert Tier 1 escalated (concluded_fp → closed_fp,
  // concluded_policy_violation → closed_benign, confirmed_incident → closed_confirmed); the pilot report
  // still counts the Tier 1 decision an escalation (the `tier1.escalated` event), and only an escalation
  // writes the alert's `case_id`. The column follows the report, not the status.
  describe("an alert Tier 1 escalated and Tier 2 then concluded", () => {
    const CONCLUDED = ["closed_fp", "closed_benign", "closed_confirmed"] as const;
    const concluded = (status: string, action: string, over: Partial<AlertView> = {}) =>
      decided({
        status,
        case_id: 9,
        acknowledged_by_name: "Nguyễn Văn Ân",
        suggestion: suggestion({ suggested_action: action }),
        ...over,
      });

    it.each([
      ...CONCLUDED.map((status) => [status, "escalate", S.ai1.matchAgree] as const),
      ...CONCLUDED.map((status) => [status, "false_positive", S.ai1.matchDisagree] as const),
      ...CONCLUDED.map((status) => [status, "needs_review", S.ai1.matchNoVerdict] as const),
    ])(
      "%s with a case, after ① %s, says '%s' (the report counts an escalation)",
      (status, action, said) => {
        renderColumn(concluded(status, action));
        expect(match()).toHaveTextContent(said);
        expect(match()).toHaveTextContent(S.ai1.match);
        // it is a Tier 1 decision: the column does not say it was none
        expect(within(column()).queryByText(S.ai1.notTier1Decision)).not.toBeInTheDocument();
      },
    );

    it.each(CONCLUDED)(
      "%s: says Tier 1 escalated it, names the acknowledger there, and gives the conclusion as Tier 2's",
      (status) => {
        renderColumn(concluded(status, "escalate"));
        const col = within(column());
        // the decision is what Tier 1 did: the escalation, with the person who did it
        const escalation = col.getByText(S.status.escalated_tier2).closest("p")!;
        expect(escalation).toHaveTextContent("Nguyễn Văn Ân");
        // and not the close: the acknowledger did not close it
        expect(escalation).not.toHaveTextContent(labelOfStatus(status));
        // the conclusion is context, worded as Tier 2's, and carries no name
        const conclusion = col.getByText(S.ai1.tier2Concluded(labelOfStatus(status)));
        expect(conclusion).not.toHaveTextContent("Nguyễn Văn Ân");
        expect(col.getByText(S.decision.heading).closest("div")).toContainElement(conclusion);
        // the name is said once, on the escalation
        expect(column().textContent?.split("Nguyễn Văn Ân")).toHaveLength(2);
      },
    );

    it("says the escalation and no Tier 2 conclusion while the case is still open (escalated_tier2)", () => {
      renderColumn(concluded("escalated_tier2", "escalate"));
      const col = within(column());
      expect(col.getByText(S.status.escalated_tier2).closest("p")).toHaveTextContent(
        "Nguyễn Văn Ân",
      );
      expect(
        col.queryByText(S.ai1.tier2Concluded(labelOfStatus("closed_fp"))),
      ).not.toBeInTheDocument();
      expect(column().textContent).not.toContain(S.ai1.tier2Concluded(""));
      expect(match()).toHaveTextContent(S.ai1.matchAgree);
    });

    it("keeps what ① said beside it", () => {
      renderColumn(concluded("closed_fp", "false_positive"));
      expect(within(column()).getByText(S.ai1.decidedAi).closest("div")).toHaveTextContent(
        S.ai1.action.false_positive,
      );
    });
  });
});

describe("accessibility", () => {
  const states: [string, AlertView][] = [
    ["ready", view()],
    [
      "ready and forced",
      view({
        suggestion: suggestion({
          gate: { forced: true, forced_by: ["x"], warnings: ["w"], verifier_verdict: "agree" },
        }),
        correlated_now: 9,
      }),
    ],
    ["hidden", blindView()],
    ["pending", view({ suggestion: null, triage_status: "pending" })],
    ["unavailable", view({ suggestion: null, triage_status: "unavailable" })],
    ["decided, with the Khớp row", view({ status: "closed_benign", acknowledged_by_name: "An" })],
    ["decided by the system", view({ status: "auto_closed" })],
    [
      "escalated, then concluded by Tier 2",
      view({ status: "closed_confirmed", case_id: 9, acknowledged_by_name: "An" }),
    ],
  ];

  it.each(states)("has no axe violation in the %s state", async (_name, v) => {
    const { container } = renderColumn(v);
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(
      result.violations.map((x) => `${x.id}: ${x.nodes.map((n) => n.html).join(" | ")}`),
    ).toEqual([]);
  });
});
