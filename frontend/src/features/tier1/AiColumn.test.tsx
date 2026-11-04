// src/features/tier1/AiColumn.test.tsx — the ① column of the alert page, one test per state of `AiState`:
// ready, hidden (the blind arm, DEC-101), pending, none (an archived alert), unavailable and decided. What the column says is decided
// by `aiStateOfView` and by nothing else: the column takes no state, so every test here reaches a state the
// only way the page does, with a view the server could have sent.
import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { AlertView, Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { wordsFound } from "../../testing/containsWord";
import { AiColumn, Unavailable } from "./AiColumn";
import { aiStateOfView } from "./aiState";

const suggestion = (over: Partial<Suggestion> = {}): Suggestion => ({
  run_id: "r1",
  suggested_action: "true_positive",
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
    proposed_verdict: "true_positive",
    final_verdict: "true_positive",
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
  proposed_action: "true_positive",
  held_by: [],
  ...over,
});

/**
 * What the server sends for a blind, undecided head: no `suggestion`, no `triage_status`, no `run_id`, and
 * (P14-T03) no `proposed_action` and no `held_by`.
 */
function blindView(over: Partial<AlertView> = {}): AlertView {
  const stripped = view({ suggestion_visible: false });
  delete stripped.suggestion;
  delete stripped.triage_status;
  delete stripped.proposed_action;
  delete stripped.held_by;
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
  "TP",
  "FP",
  "true_positive",
  "false_positive",
  "Cần xem xét",
  "AI kết luận",
  "giữ lại",
  "độ tin cậy",
  "trung bình",
  "37 lần xác thực",
  "Failed password",
];

describe("ready", () => {
  it("shows what the AI concluded with its confidence, and no flag when the gate forced nothing", () => {
    renderColumn(view());
    const col = within(column());
    expect(col.getByRole("heading", { name: S.alert.aiHeading })).toBeInTheDocument();
    expect(col.getByText(/AI kết luận/)).toHaveTextContent(
      "AI kết luận: TP (độ tin cậy trung bình)",
    );
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
            proposed_verdict: "true_positive",
            final_verdict: "true_positive",
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
        proposed_action: null, // nothing the AI may have concluded: the old block, with the code
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

// P14-T03 (DEC-213): ① always concludes `false_positive | true_positive`. The alert page says what the AI
// concluded, with its confidence, and when the gate held it back for a person, says so and why.
describe("AI kết luận", () => {
  /** A verdict the gate held: the model said false_positive, the system stored needs_review. */
  const held = (reasons: string[], over: Partial<AlertView> = {}) =>
    view({
      suggestion: suggestion({
        suggested_action: "needs_review",
        confidence: "medium",
        gate: {
          forced: true,
          forced_by: ["step4"],
          proposed_verdict: "false_positive",
          final_verdict: "needs_review",
          verifier_verdict: "needs_review",
          warnings: [],
        },
      }),
      proposed_action: "false_positive",
      held_by: reasons,
      ...over,
    });
  /** The sentence itself: the one element whose own text starts it. */
  const line = () => within(column()).getByText(/AI kết luận/);

  it("says TP with the confidence of a true_positive the gate kept, and holds nothing back", () => {
    renderColumn(view({ suggestion: suggestion({ confidence: "high" }) }));
    expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy cao\)$/);
    expect(within(line()).getByText("TP").tagName).toBe("STRONG");
    expect(line().textContent).not.toContain("giữ lại");
  });

  it("says FP for a false_positive the gate kept", () => {
    renderColumn(
      view({
        suggestion: suggestion({ suggested_action: "false_positive", confidence: "low" }),
        proposed_action: "false_positive",
      }),
    );
    expect(line()).toHaveTextContent(/^AI kết luận: FP \(độ tin cậy thấp\)$/);
  });

  it("says what the AI concluded and that the system held it for a person, with both reasons", () => {
    renderColumn(held(["fp_policy:asset_criticality", "verifier_disagrees"]));
    expect(line()).toHaveTextContent(
      "AI kết luận: FP (độ tin cậy trung bình) — hệ thống giữ lại cho người xem vì: " +
        "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý",
    );
    // the AI's own answer, not the system's `Cần xem xét`, is the conclusion
    expect(within(line()).getByText("FP").tagName).toBe("STRONG");
    // and the phrase "hệ thống giữ lại cho người xem" is bold too, as spec 4.3 has it (M1)
    expect(within(line()).getByText("hệ thống giữ lại cho người xem").tagName).toBe("STRONG");
    expect(line().textContent).not.toContain("Cần xem xét");
  });

  it.each([
    ["facts_mismatch", "AI khai dữ kiện lệch với hệ thống"],
    ["no_verified_quote", "không có dẫn chứng kiểm chứng được"],
    ["fp_policy:severity", "alert mức critical"],
    ["fp_policy:ioc_reputation", "IOC độc hại hoặc đáng ngờ"],
    ["fp_policy:asset_criticality", "tài sản quan trọng hoặc chưa rõ"],
    ["fp_policy:identity_privileged", "tài khoản đặc quyền"],
    ["fp_policy:playbook_rule", "không khớp bảng quyết định đã duyệt"],
    ["verifier_disagrees", "bộ kiểm tra không đồng ý"],
  ])("words the reason %s as '%s'", (reason, label) => {
    renderColumn(held([reason]));
    expect(line()).toHaveTextContent(`hệ thống giữ lại cho người xem vì: ${label}`);
    expect(line().textContent).not.toContain(reason);
  });

  it("joins the reasons with a comma, in the order the server gave them", () => {
    renderColumn(held(["facts_mismatch", "no_verified_quote", "fp_policy:severity"]));
    expect(line()).toHaveTextContent(
      "vì: AI khai dữ kiện lệch với hệ thống, không có dẫn chứng kiểm chứng được, alert mức critical",
    );
  });

  it("shows a reason it has no label for as the code, as text", () => {
    const markup = "<img src=x onerror=alert(1)>";
    const { container } = renderColumn(held(["fp_policy:new_field", markup]));
    expect(line()).toHaveTextContent(`vì: fp_policy:new_field, ${markup}`);
    expect(container.querySelector("img")).toBeNull();
  });

  it("says it was held without a 'because' when the server names no reason", () => {
    renderColumn(held([]));
    expect(line()).toHaveTextContent(
      /^AI kết luận: FP \(độ tin cậy trung bình\) — hệ thống giữ lại cho người xem(⚑)?$/,
    );
    expect(line().textContent).not.toContain("vì:");
  });

  it("leaves the confidence out when the result has none", () => {
    renderColumn(view({ suggestion: suggestion({ confidence: null }) }));
    expect(line()).toHaveTextContent(/^AI kết luận: TP$/);
  });

  it("flags the held verdict and still shows the gate's own account of it", () => {
    renderColumn(held(["fp_policy:playbook_rule"]));
    const col = within(column());
    expect(col.getByRole("img", { name: S.ai1.forcedLabel })).toBeInTheDocument();
    expect(col.getByText(S.ai1.gateForced)).toBeInTheDocument();
    expect(col.getByText("step4")).toBeInTheDocument();
    const steps = within(col.getByRole("region", { name: S.ai1.gateSteps }));
    expect(steps.getByText(S.ai1.action.false_positive)).toBeInTheDocument();
    expect(steps.getByText(S.ai1.action.needs_review)).toBeInTheDocument();
  });

  it("falls back on the final action when the server sent no proposed_action", () => {
    const bare = view();
    delete bare.proposed_action;
    delete bare.held_by;
    renderColumn(bare);
    expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy trung bình\)$/);
  });

  it("makes no claim for a needs_review the server did not explain: the system's own word, as before", () => {
    const bare = held([]);
    delete bare.proposed_action;
    delete bare.held_by;
    renderColumn(bare);
    const col = within(column());
    expect(col.queryByText(/AI kết luận/)).not.toBeInTheDocument();
    expect(col.getByText(S.ai1.verdict).parentElement).toHaveTextContent("Cần xem xét");
  });

  it("names the ninth reason, an unusable verifier answer, in its own words (M3)", () => {
    renderColumn(held(["verifier_invalid"]));
    expect(line()).toHaveTextContent("vì: bộ kiểm tra không trả lời hợp lệ");
    expect(line().textContent).not.toContain("không đồng ý");
  });

  // Fix round 1 (I1): a decided page still says what the AI concluded and why the gate held it - in the
  // "Gợi ý ①" box, by the very component the undecided column uses. "Khớp" is still the stored verdict's.
  describe("on a decided page", () => {
    const decidedHeld = (over: Partial<AlertView> = {}) =>
      held(["fp_policy:asset_criticality", "verifier_disagrees"], {
        status: "closed_fp",
        acknowledged_by: "u1",
        acknowledged_by_name: "An",
        ...over,
      });
    const box = () => within(column()).getByText(S.ai1.decidedAi).closest("div")!;
    const khop = () => within(column()).getByText(S.ai1.match).parentElement!;

    it("says TP with the confidence in the box, and Khớp stays the stored verdict's", () => {
      renderColumn(view({ status: "escalated_tier2", case_id: 9, acknowledged_by_name: "An" }));
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        /^AI kết luận: TP \(độ tin cậy trung bình\)$/,
      );
      expect(khop()).toHaveTextContent(S.ai1.matchAgree);
    });

    it("says what the AI concluded and why the system held it, two reasons, and Khớp has no verdict to compare", () => {
      renderColumn(decidedHeld());
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        "AI kết luận: FP (độ tin cậy trung bình) — hệ thống giữ lại cho người xem vì: " +
          "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý",
      );
      expect(within(box()).getByText("hệ thống giữ lại cho người xem").tagName).toBe("STRONG");
      // the stored verdict is `needs_review`: the pilot report leaves it out, so does Khớp
      expect(khop()).toHaveTextContent(S.ai1.matchNoVerdict);
    });

    it("is one line in the column, not two", () => {
      renderColumn(decidedHeld());
      expect(within(column()).getAllByText(/AI kết luận/)).toHaveLength(1);
    });

    it("is the same line the undecided column draws for the same suggestion", () => {
      const undecided = renderColumn(held(["fp_policy:playbook_rule", "verifier_invalid"]));
      const before = within(column()).getByText(/AI kết luận/).textContent;
      undecided.unmount();
      renderColumn(
        held(["fp_policy:playbook_rule", "verifier_invalid"], { status: "closed_benign" }),
      );
      const after = within(box()).getByText(/AI kết luận/).textContent;
      // the gate's ⚑ belongs to the undecided column only (the decided state has no gate flag)
      expect(after).toBe((before ?? "").replace("⚑", ""));
    });

    it.each([
      ["a visible head", true],
      ["a blind head, now decided", false],
    ])("shows it for %s", (_name, visible) => {
      renderColumn(decidedHeld({ suggestion_visible: visible }));
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        /^AI kết luận: FP .* vì: tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý$/,
      );
      expect(within(column()).queryByText(S.ai1.hidden)).not.toBeInTheDocument();
    });

    it("is not there before the decision on the blind arm, and is after it (the same head)", () => {
      const before = renderColumn(blindView({ status: "tier1_active" }));
      expect(within(column()).queryByText(/AI kết luận/)).not.toBeInTheDocument();
      expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
      before.unmount();
      renderColumn(decidedHeld({ suggestion_visible: false }));
      expect(within(column()).getByText(/AI kết luận/)).toBeInTheDocument();
    });

    it("falls back on the stored verdict when the server sent neither key", () => {
      const bare = decidedHeld();
      delete bare.proposed_action;
      delete bare.held_by;
      renderColumn(bare);
      expect(within(column()).queryByText(/AI kết luận/)).not.toBeInTheDocument();
      expect(box()).toHaveTextContent("Cần xem xét");
    });

    it("says nothing for a decided alert ① never answered", () => {
      renderColumn(
        view({
          status: "closed_fp",
          suggestion: null,
          proposed_action: null,
          held_by: [],
          acknowledged_by_name: "An",
        }),
      );
      expect(within(column()).queryByText(/AI kết luận/)).not.toBeInTheDocument();
      expect(box()).toHaveTextContent(S.ai1.none);
    });
  });

  it("is not in a blind column, and nothing of it is: not the AI's answer, not a reason", () => {
    const stray = blindView({
      proposed_action: "false_positive",
      held_by: ["fp_policy:asset_criticality"],
    });
    expect(aiStateOfView(stray)).toEqual({ kind: "hidden" });
    renderColumn(stray);
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    // whole words: "FP" is a marker, "SFTP" in an unrelated line would not be one
    expect(
      wordsFound(col.textContent ?? "", [
        "AI kết luận",
        "giữ lại",
        "tài sản quan trọng hoặc chưa rõ",
        "FP",
        "TP",
      ]),
    ).toEqual([]);
  });
});

describe("hidden (the blind arm)", () => {
  it("says S.ai1.hidden for a view the server stripped, and names no verdict anywhere in the column", () => {
    renderColumn(blindView());
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(wordsFound(col.textContent ?? "", VERDICT_WORDS), "verdict words in the column").toEqual(
      [],
    );
    // it does not say that ① is working, or has failed, or has nothing to say
    expect(col.textContent).not.toContain(S.ai1.pending);
    expect(col.textContent).not.toContain(S.ai1.unavailable);
    expect(col.textContent).not.toContain(S.ai1.none);
  });

  it("shows no reason ① stopped for a blind view, even one that (wrongly) carries llm_stopped_by", () => {
    // The server drops the key from a blind, undecided head (visibility.ANALYST_HIDE); the column reads the
    // arm first, so a stray reason is neither worded nor named: "gave up, because the provider refused" says ① ran.
    const stray = blindView({ triage_status: "unavailable", llm_stopped_by: "unavailable" });
    expect(aiStateOfView(stray)).toEqual({ kind: "hidden" });
    renderColumn(stray);
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(col.textContent).not.toContain(S.ai1.unavailable);
    expect(col.textContent).not.toContain(S.ai1.stoppedByLabel);
    expect(col.textContent).not.toContain(S.ai1.stoppedBy.unavailable);
    expect(col.textContent).not.toContain("402");
    expect(within(col).queryByText("unavailable", { selector: "code" })).not.toBeInTheDocument();
  });

  it("shows no verdict text for a blind view that still carries the other ① keys", () => {
    // Hidden is the server's word (no `suggestion` key, `suggestion_visible` false), read once by aiStateOfView;
    // the column shows none of ① whatever else the view happens to carry: a ready triage status, a fresh count.
    const stray = blindView({ triage_status: "ready", correlated_now: 9, close_reason: null });
    expect(aiStateOfView(stray).kind).toBe("hidden");
    renderColumn(stray);
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(wordsFound(col.textContent ?? "", VERDICT_WORDS), "verdict words in the column").toEqual(
      [],
    );
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
    expect(col.textContent).toContain(S.ai1.action.true_positive);
  });
});

describe("pending", () => {
  it("says ① is working, and names no verdict", () => {
    renderColumn(view({ suggestion: null, triage_status: "pending" }));
    const col = column();
    expect(within(col).getByText(S.ai1.pending)).toBeInTheDocument();
    expect(col.textContent).toContain(S.ai1.pendingBody);
    expect(col.textContent).not.toContain(S.ai1.hidden);
    expect(wordsFound(col.textContent ?? "", VERDICT_WORDS), "verdict words in the column").toEqual(
      [],
    );
  });
});

describe("none (an archived alert with no ①)", () => {
  it("says there is no ① and never 'Đang phân tích…', and names no verdict", () => {
    renderColumn(view({ status: "archived", suggestion: null, triage_status: "pending" }));
    const col = column();
    expect(within(col).getByText(S.ai1.none)).toBeInTheDocument();
    expect(col.textContent).toContain(S.ai1.noneBody);
    expect(col.textContent).not.toContain(S.ai1.pending);
    expect(col.textContent).not.toContain(S.ai1.pendingBody);
    expect(col.textContent).not.toContain(S.ai1.hidden);
    expect(wordsFound(col.textContent ?? "", VERDICT_WORDS), "verdict words in the column").toEqual(
      [],
    );
  });

  it("is not what a blind archived head shows: that one stays 'ẩn — nhánh mù'", () => {
    renderColumn(blindView({ status: "archived", triage_status: "pending" }));
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(col.textContent).not.toContain(S.ai1.none);
    expect(col.textContent).not.toContain(S.ai1.pending);
  });
});

describe("unavailable", () => {
  it("says ① gave up, from the view's own triage status, and says nothing of a reason it was not told", () => {
    // A view with no `llm_stopped_by` (the run left none, or there was no run) names no reason.
    const gaveUp = view({ suggestion: null, triage_status: "unavailable" });
    expect(aiStateOfView(gaveUp)).toEqual({ kind: "unavailable", stoppedBy: null });
    renderColumn(gaveUp);
    const col = within(column());
    expect(col.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(col.getByText(S.ai1.unavailableBody)).toBeInTheDocument();
    expect(col.queryByText(S.ai1.stoppedByLabel)).not.toBeInTheDocument();
  });

  // INT-T02: the alert view carries the reason (`llm_stopped_by`), so the column words it.
  it("words a provider 402 on the alert page: the F6 label and the code, from the view", () => {
    const refused = view({
      suggestion: null,
      triage_status: "unavailable",
      llm_stopped_by: "unavailable",
    });
    expect(aiStateOfView(refused)).toEqual({ kind: "unavailable", stoppedBy: "unavailable" });
    renderColumn(refused);
    const col = within(column());
    expect(col.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(col.getByText(S.ai1.stoppedByLabel)).toBeInTheDocument();
    expect(
      col.getByText("nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)"),
    ).toBeInTheDocument();
    expect(col.getByText("unavailable", { selector: "code" })).toBeInTheDocument();
  });

  it("words the other reasons a run stops on, from the view", () => {
    for (const code of ["cap", "schema", "transient", "linter"] as const) {
      const { unmount } = renderColumn(
        view({ suggestion: null, triage_status: "unavailable", llm_stopped_by: code }),
      );
      expect(within(column()).getByText(S.ai1.stoppedBy[code])).toBeInTheDocument();
      unmount();
    }
  });

  it("shows a code with no label as it came", () => {
    renderColumn(
      view({ suggestion: null, triage_status: "unavailable", llm_stopped_by: "cosmic_ray" }),
    );
    expect(within(column()).getByText("cosmic_ray")).toBeInTheDocument();
  });

  // The wording of a reason, drawn on its own.
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
    expect(ai).toHaveTextContent(S.ai1.action.true_positive);
    expect(ai).toHaveTextContent(S.confidence.medium);
  });

  it("says ① had nothing to say when the view carries no result, and compares nothing", () => {
    // no result, so the server sends no conclusion and no reason either
    renderColumn(decided({ suggestion: null, proposed_action: null, held_by: [] }));
    const ai = within(column()).getByText(S.ai1.decidedAi).closest("div")!;
    expect(ai).toHaveTextContent(S.ai1.none);
    expect(match()).toHaveTextContent(S.ai1.matchNoVerdict);
  });

  it("unknown enum renders raw code: an action without a label", () => {
    // A status the UI does not know is not one of `DECIDED`, so it is not a decided view (the page tests
    // word an unknown status); the action is what a decided view can carry that the UI has no label for.
    renderColumn(
      decided({
        suggestion: suggestion({ suggested_action: "quarantine_host" }),
        proposed_action: null, // nothing the AI may have concluded: the stored word, as it came
      }),
    );
    expect(within(column()).getByText("quarantine_host")).toBeInTheDocument();
    // the pilot report counts an action that is none of the three as no result: nothing is compared
    expect(match()).toHaveTextContent(S.ai1.matchNoVerdict);
  });

  describe("the Khớp row, by the pilot report's mapping (P10-T06, eval/ops_export.py)", () => {
    it.each([
      // agreement: ① escalate with a human escalation, ① false_positive with a human closed_fp
      ["escalated_tier2", "true_positive", S.ai1.matchAgree],
      ["closed_fp", "false_positive", S.ai1.matchAgree],
      // any other pair of a verdict and a human decision disagrees
      ["escalated_tier2", "false_positive", S.ai1.matchDisagree],
      ["closed_fp", "true_positive", S.ai1.matchDisagree],
      ["closed_benign", "true_positive", S.ai1.matchDisagree],
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
          S.ai1.action.true_positive,
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
        // the AI concluded what it stored, unless the gate held it (`needs_review`)
        proposed_action: action === "needs_review" ? "false_positive" : action,
        ...over,
      });

    it.each([
      ...CONCLUDED.map((status) => [status, "true_positive", S.ai1.matchAgree] as const),
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
        renderColumn(concluded(status, "true_positive"));
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
      renderColumn(concluded("escalated_tier2", "true_positive"));
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
    [
      "ready and held for a person (P14-T03)",
      view({
        suggestion: suggestion({
          suggested_action: "needs_review",
          gate: { forced: true, forced_by: ["step4"], proposed_verdict: "false_positive" },
        }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality", "verifier_disagrees"],
      }),
    ],
    ["hidden", blindView()],
    ["pending", view({ suggestion: null, triage_status: "pending" })],
    [
      "none, an archived alert",
      view({ status: "archived", suggestion: null, triage_status: "pending" }),
    ],
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
