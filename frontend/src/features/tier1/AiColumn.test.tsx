// src/features/tier1/AiColumn.test.tsx — the ① column of the alert page, one test per state of `AiState`:
// ready, hidden (the blind arm, DEC-101), pending, none (an archived alert), unavailable and decided. What the column says is decided
// by `aiStateOfView` and by nothing else: the column takes no state, so every test here reaches a state the
// only way the page does, with a view the server could have sent.
import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { AlertView, RagRule, Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { phrasesFound, textOf, wordsFound } from "../../testing/containsWord";
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
 * A run with warnings (DEC-217): the model said `verdict`, ① stored and served it as it is, and the gate (version 2)
 * forced nothing; `held_by` lists the checks that raised a warning. The gate document is the one the version 2 server
 * writes: `proposed_verdict` and `final_verdict` are both the model's answer, and the verifier's verdict is the
 * model's too unless `held_by` carries `verifier_disagrees` (step 6 flags exactly a verifier that differs, and then
 * it said `needs_review`) or `verifier_invalid` (an unusable answer, so none).
 */
const warned = (
  reasons: string[],
  over: Partial<AlertView> = {},
  { verdict = "false_positive", confidence = "medium" } = {},
): AlertView => {
  let verifier: string | null = verdict;
  if (reasons.includes("verifier_disagrees")) verifier = "needs_review";
  else if (reasons.includes("verifier_invalid")) verifier = null;
  return view({
    suggestion: suggestion({
      suggested_action: verdict,
      confidence,
      gate: {
        forced: false,
        forced_by: [],
        proposed_verdict: verdict,
        final_verdict: verdict,
        verifier_verdict: verifier,
        warnings: [],
      },
    }),
    proposed_action: verdict,
    held_by: reasons,
    ...over,
  });
};

/** What the Khớp row says, whole: its label and its word. The words are substrings of each other ("có" is in "không có đề xuất để so"), so a check on the word alone is vacuous. */
const KHOP = (word: string): string => `${S.ai1.match} ${word}`;

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

/** The two-letter labels of a verdict: found as WORDS, so "SFTP" in an unrelated line is not a leak. */
const LABEL_MARKERS = ["TP", "FP"];

/**
 * What the RAG default of DEC-219 adds to ①'s account of itself, and only there: the parenthesis of the line,
 * "(dưới 80%: mặc định FP)", found as plain substrings.
 */
const RULE_MARKERS = ["dưới 80%", "mặc định FP"];

/** Everything else of a verdict that must not reach a column that is hidden: found as plain substrings. */
const VERDICT_WORDS = [
  "true_positive",
  "false_positive",
  "Cần xem xét",
  "AI kết luận",
  "cảnh báo kiểm chứng",
  "độ tin cậy",
  "trung bình",
  "37 lần xác thực",
  "Failed password",
  ...RULE_MARKERS,
];

/**
 * What of a verdict is in `el`. The text is read per text node: `textContent` glues the text of neighbouring
 * elements ("Đề xuất" + "Cần xem xét" read "Đề xuấtCần xem xét"), and a whole-word search would lose a marker at
 * the seam. The labels are looked for as words, the phrases as substrings.
 */
const leaksIn = (el: Element, phrases: readonly string[] = VERDICT_WORDS): string[] => {
  const text = textOf(el);
  return [...wordsFound(text, LABEL_MARKERS), ...phrasesFound(text, phrases)];
};

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

  it("shows ⚑ and the gate rules that forced the verdict of a version 1 row (gate_forced true)", () => {
    // DEC-217: the server serves the model's own verdict for a row the gate forced (version 1); the gate's
    // own record of it, `forced`, `forced_by` and `final_verdict`, is what was stored and is shown as it is.
    renderColumn(
      view({
        suggestion: suggestion({
          suggested_action: "false_positive",
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
// concluded, with its confidence, and, DEC-217, when the gate's checks raised warnings, says so and which: the
// verdict is the model's own, and the gate holds nothing back for a person.
describe("AI kết luận", () => {
  /**
   * A version 1 row: the gate forced `needs_review` then. The server serves the model's own verdict for it; the
   * gate's record (`forced`, `forced_by`, `final_verdict`) is what was stored, and `held_by` its reasons.
   */
  const forcedV1 = (reasons: string[], over: Partial<AlertView> = {}) =>
    view({
      suggestion: suggestion({
        suggested_action: "false_positive",
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

  it("says TP with the confidence of a true_positive, and raises no warning", () => {
    renderColumn(view({ suggestion: suggestion({ confidence: "high" }) }));
    expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy cao\)$/);
    expect(within(line()).getByText("TP").tagName).toBe("STRONG");
    expect(line().textContent).not.toContain("cảnh báo");
  });

  it("has no warning clause for a row with no warnings", () => {
    renderColumn(warned([]));
    expect(line()).toHaveTextContent(/^AI kết luận: FP \(độ tin cậy trung bình\)$/);
    expect(line().textContent).not.toContain("cảnh báo");
    expect(line().textContent).not.toContain("—");
    expect(within(line()).queryByText(S.ai1.held)).not.toBeInTheDocument();
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

  it("says FP and the warning, with one reason: the line of the spec (DEC-217 section 8)", () => {
    renderColumn(warned(["fp_policy:playbook_rule"], {}, { confidence: "high" }));
    expect(line().textContent).toBe(
      "AI kết luận: FP (độ tin cậy cao) — có cảnh báo kiểm chứng: không khớp bảng quyết định đã duyệt",
    );
  });

  it("says FP and the warning, with several reasons, joined by a comma", () => {
    renderColumn(
      warned(
        ["facts_mismatch", "fp_policy:asset_criticality", "verifier_disagrees"],
        {},
        { confidence: "high" },
      ),
    );
    expect(line().textContent).toBe(
      "AI kết luận: FP (độ tin cậy cao) — có cảnh báo kiểm chứng: AI khai dữ kiện lệch với hệ thống, " +
        "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý",
    );
  });

  it("shows the verdict, not Cần xem xét, for a false_positive with warnings", () => {
    renderColumn(warned(["fp_policy:asset_criticality", "verifier_disagrees"]));
    expect(line()).toHaveTextContent(
      "AI kết luận: FP (độ tin cậy trung bình) — có cảnh báo kiểm chứng: " +
        "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý",
    );
    // the model's own verdict is the conclusion, bold, and so is the phrase of the warning (spec section 8)
    expect(within(line()).getByText("FP").tagName).toBe("STRONG");
    expect(within(line()).getByText("có cảnh báo kiểm chứng").tagName).toBe("STRONG");
    expect(column().textContent).not.toContain("Cần xem xét");
    expect(line().textContent).not.toContain("giữ lại");
  });

  it("shows the verdict, with the warning, for a true_positive with warnings", () => {
    renderColumn(
      warned(["verifier_disagrees"], {}, { verdict: "true_positive", confidence: "high" }),
    );
    expect(line().textContent).toBe(
      "AI kết luận: TP (độ tin cậy cao) — có cảnh báo kiểm chứng: bộ kiểm tra không đồng ý",
    );
    expect(column().textContent).not.toContain("Cần xem xét");
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
    renderColumn(warned([reason]));
    expect(line()).toHaveTextContent(`có cảnh báo kiểm chứng: ${label}`);
    expect(line().textContent).not.toContain(reason);
  });

  it("joins the reasons with a comma, in the order the server gave them", () => {
    renderColumn(warned(["facts_mismatch", "no_verified_quote", "fp_policy:severity"]));
    expect(line()).toHaveTextContent(
      "có cảnh báo kiểm chứng: AI khai dữ kiện lệch với hệ thống, không có dẫn chứng kiểm chứng được, alert mức critical",
    );
  });

  it("shows a reason it has no label for as the code, as text", () => {
    const markup = "<img src=x onerror=alert(1)>";
    const { container } = renderColumn(warned(["fp_policy:new_field", markup]));
    expect(line()).toHaveTextContent(`có cảnh báo kiểm chứng: fp_policy:new_field, ${markup}`);
    expect(container.querySelector("img")).toBeNull();
  });

  it("has no warning clause for a version 1 row that names no reason, and keeps its flag", () => {
    renderColumn(forcedV1([]));
    expect(line()).toHaveTextContent(/^AI kết luận: FP \(độ tin cậy trung bình\)⚑$/);
    expect(line().textContent).not.toContain("cảnh báo");
  });

  it("says there is a warning, with no list, for a stored needs_review that names no reason (the guard)", () => {
    // `heldOf` keeps its second half for an old client cache: the stored word, with the model's answer beside it
    renderColumn(
      view({
        suggestion: suggestion({ suggested_action: "needs_review", confidence: "medium" }),
        proposed_action: "false_positive",
        held_by: [],
      }),
    );
    expect(line()).toHaveTextContent(
      /^AI kết luận: FP \(độ tin cậy trung bình\) — có cảnh báo kiểm chứng$/,
    );
  });

  it("leaves the confidence out when the result has none", () => {
    renderColumn(view({ suggestion: suggestion({ confidence: null }) }));
    expect(line()).toHaveTextContent(/^AI kết luận: TP$/);
  });

  it("still flags a version 1 row the gate forced (gate_forced true) and shows the gate's own account of it", () => {
    renderColumn(forcedV1(["fp_policy:playbook_rule"]));
    const col = within(column());
    expect(col.getByRole("img", { name: S.ai1.forcedLabel })).toBeInTheDocument();
    expect(col.getByText(S.ai1.gateForced)).toBeInTheDocument();
    expect(col.getByText("step4")).toBeInTheDocument();
    const steps = within(col.getByRole("region", { name: S.ai1.gateSteps }));
    expect(steps.getByText(S.ai1.action.false_positive)).toBeInTheDocument();
    expect(steps.getByText(S.ai1.action.needs_review)).toBeInTheDocument();
    // the head line of that row says the model's verdict and the warning, never the stored Cần xem xét
    expect(line()).toHaveTextContent(
      "AI kết luận: FP (độ tin cậy trung bình) — có cảnh báo kiểm chứng: không khớp bảng quyết định đã duyệt",
    );
  });

  it("shows no forced flag for a new run, with or without warnings", () => {
    for (const reasons of [["fp_policy:playbook_rule", "verifier_disagrees"], []]) {
      const { unmount } = renderColumn(warned(reasons));
      const col = within(column());
      expect(col.queryByRole("img", { name: S.ai1.forcedLabel })).not.toBeInTheDocument();
      expect(col.queryByText(S.ai1.forced)).not.toBeInTheDocument();
      expect(col.getByText(S.ai1.gateNotForced)).toBeInTheDocument();
      expect(col.queryByText(S.ai1.gateForced)).not.toBeInTheDocument();
      expect(col.queryByText(S.ai1.gateForcedBy)).not.toBeInTheDocument();
      unmount();
    }
  });

  it("lists the gate's own warnings of a run with warnings, as before", () => {
    const v = warned(["fp_policy:playbook_rule"]);
    v.suggestion = suggestion({
      ...v.suggestion,
      gate: { ...v.suggestion?.gate, warnings: ["fp_policy:playbook_rule: no rule cited"] },
    });
    renderColumn(v);
    const steps = within(within(column()).getByRole("region", { name: S.ai1.gateSteps }));
    expect(steps.getByText(S.ai1.gateWarnings)).toBeInTheDocument();
    expect(steps.getByText("fp_policy:playbook_rule: no rule cited")).toBeInTheDocument();
  });

  it("falls back on the final action when the server sent no proposed_action", () => {
    const bare = view();
    delete bare.proposed_action;
    delete bare.held_by;
    renderColumn(bare);
    expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy trung bình\)$/);
  });

  it("makes no claim for a stored needs_review the server did not explain: the guard, the stored word as it came", () => {
    // DEC-217: the server serves one of the two. A `needs_review` that still arrives (an old cache, a server that
    // predates the decision) with no `proposed_action` is shown as the stored word, never as a conclusion.
    const bare = view({
      suggestion: suggestion({ suggested_action: "needs_review", confidence: "medium" }),
    });
    delete bare.proposed_action;
    delete bare.held_by;
    renderColumn(bare);
    const col = within(column());
    expect(col.queryByText(/AI kết luận/)).not.toBeInTheDocument();
    expect(col.getByText(S.ai1.verdict).parentElement).toHaveTextContent("Cần xem xét");
  });

  it("names the ninth reason, an unusable verifier answer, in its own words (M3)", () => {
    renderColumn(warned(["verifier_invalid"]));
    expect(line()).toHaveTextContent("có cảnh báo kiểm chứng: bộ kiểm tra không trả lời hợp lệ");
    expect(line().textContent).not.toContain("không đồng ý");
  });

  // Fix round 1 (I1): a decided page still says what the AI concluded and which checks warned - in the
  // "Gợi ý ①" box, by the very component the undecided column uses. "Khớp" is still the stored verdict's.
  describe("on a decided page", () => {
    const decidedHeld = (over: Partial<AlertView> = {}) =>
      warned(["fp_policy:asset_criticality", "verifier_disagrees"], {
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
      expect(khop().textContent).toBe(KHOP(S.ai1.matchAgree));
    });

    it("says what the AI concluded and which checks warned, two reasons, and Khớp compares the verdict", () => {
      renderColumn(decidedHeld());
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        "AI kết luận: FP (độ tin cậy trung bình) — có cảnh báo kiểm chứng: " +
          "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý",
      );
      expect(within(box()).getByText("có cảnh báo kiểm chứng").tagName).toBe("STRONG");
      // the stored verdict is `false_positive` (DEC-217), a closed_fp agrees with it, warnings or none
      expect(khop().textContent).toBe(KHOP(S.ai1.matchAgree));
    });

    it("leaves Khớp with no verdict for a stored needs_review that still arrives (the guard)", () => {
      renderColumn(decidedHeld({ suggestion: suggestion({ suggested_action: "needs_review" }) }));
      expect(khop().textContent).toBe(KHOP(S.ai1.matchNoVerdict));
    });

    it("is one line in the column, not two", () => {
      renderColumn(decidedHeld());
      expect(within(column()).getAllByText(/AI kết luận/)).toHaveLength(1);
    });

    it.each([
      ["a run with warnings", warned],
      ["a version 1 row the gate forced", forcedV1],
    ])("is the same line the undecided column draws for the same suggestion: %s", (_name, make) => {
      const undecided = renderColumn(make(["fp_policy:playbook_rule", "verifier_invalid"]));
      const before = within(column()).getByText(/AI kết luận/).textContent;
      undecided.unmount();
      renderColumn(
        make(["fp_policy:playbook_rule", "verifier_invalid"], { status: "closed_benign" }),
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
        /^AI kết luận: FP .* có cảnh báo kiểm chứng: tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý$/,
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
      // a stored needs_review (the guard): with no `proposed_action` it is the stored word, as it came
      const bare = decidedHeld({ suggestion: suggestion({ suggested_action: "needs_review" }) });
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
    expect(
      leaksIn(col, [
        "AI kết luận",
        "cảnh báo kiểm chứng",
        "tài sản quan trọng hoặc chưa rõ",
        ...RULE_MARKERS,
      ]),
    ).toEqual([]);
  });
});

// Fix round 2 (Minor): the markers must still be found where a leaked verdict's text is glued to the text of the
// element beside it. A ready column that says `needs_review` with nothing the AI concluded draws "Đề xuất" and
// "Cần xem xét" in two elements: `textContent` reads them as "Đề xuấtCần xem xét".
describe("the leak markers of the blind tests", () => {
  it("find a verdict whose text is glued to its neighbour's", () => {
    const leaked = view({
      suggestion: suggestion({ suggested_action: "needs_review", confidence: null }),
      proposed_action: null,
      held_by: [],
    });
    renderColumn(leaked);
    const col = column();
    expect(col.textContent).toContain("Đề xuấtCần xem xét"); // the seam
    expect(leaksIn(col)).toContain("Cần xem xét");
  });

  it("find a leaked conclusion line, its label and its warnings", () => {
    renderColumn(
      view({
        suggestion: suggestion({ suggested_action: "false_positive" }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality"],
      }),
    );
    expect(leaksIn(column())).toEqual(
      expect.arrayContaining(["FP", "AI kết luận", "cảnh báo kiểm chứng"]),
    );
  });
});

describe("hidden (the blind arm)", () => {
  it("says S.ai1.hidden for a view the server stripped, and names no verdict anywhere in the column", () => {
    renderColumn(blindView());
    const col = column();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(leaksIn(col), "verdict markers in the column").toEqual([]);
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
    expect(leaksIn(col), "verdict markers in the column").toEqual([]);
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
    expect(leaksIn(col), "verdict markers in the column").toEqual([]);
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
    expect(leaksIn(col), "verdict markers in the column").toEqual([]);
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
    expect(match()?.textContent).toBe(KHOP(S.ai1.matchNoVerdict));
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
    expect(match()?.textContent).toBe(KHOP(S.ai1.matchNoVerdict));
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
      expect(match()?.textContent).toBe(KHOP(said));
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
        expect(match()?.textContent).toBe(KHOP(said));
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
      expect(match()?.textContent).toBe(KHOP(S.ai1.matchAgree));
    });

    it("keeps what ① said beside it", () => {
      renderColumn(concluded("closed_fp", "false_positive"));
      expect(within(column()).getByText(S.ai1.decidedAi).closest("div")).toHaveTextContent(
        S.ai1.action.false_positive,
      );
    });
  });
});

// P14-T07 (DEC-213, spec 4.3): beside the conclusion the column says how strongly the alert matched approved
// knowledge ("— trùng 87% với tri thức đã duyệt", in the conclusion line) and, when the lookup failed, the notice
// that the RAG was not applied. The sentences are written out in full: a label edited in strings.ts alone fails here.
describe("the RAG beside the conclusion", () => {
  const MATCH = "trùng 87% với tri thức đã duyệt";
  const withRag = (best_pct: number | null, not_applied: string | null = null) => ({
    rag: { best_pct, not_applied },
  });
  const line = () => within(column()).getByText(/AI kết luận/);
  const notice = () => within(column()).queryByRole("note");

  describe("the percentage", () => {
    it("follows the conclusion line, in the same sentence", () => {
      renderColumn(view({ suggestion: suggestion({ confidence: "high" }), ...withRag(87) }));
      expect(line()).toHaveTextContent(
        /^AI kết luận: TP \(độ tin cậy cao\) — trùng 87% với tri thức đã duyệt$/,
      );
      // only the verdict is bold: the percentage is not shouted
      expect(within(line()).getByText("TP").tagName).toBe("STRONG");
      expect(line().textContent).toContain(MATCH);
    });

    it("says what the server said, whatever the number", () => {
      renderColumn(view({ ...withRag(50) }));
      expect(line()).toHaveTextContent("— trùng 50% với tri thức đã duyệt");
    });

    it("says 0% when the best match is 0%", () => {
      renderColumn(view({ ...withRag(0) }));
      expect(line()).toHaveTextContent("— trùng 0% với tri thức đã duyệt");
    });

    it("says nothing when there is no match", () => {
      renderColumn(view({ ...withRag(null) }));
      expect(line().textContent).not.toContain("trùng");
      expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy trung bình\)$/);
    });

    it("says nothing when the server sent no rag at all (an older server)", () => {
      renderColumn(view());
      expect(line().textContent).not.toContain("trùng");
      expect(within(column()).queryByText(/trùng/)).not.toBeInTheDocument();
    });

    it("puts the percentage after the confidence note", () => {
      renderColumn(view({ ...withRag(87) }));
      expect(line().textContent).toBe(
        "AI kết luận: TP (độ tin cậy trung bình) — trùng 87% với tri thức đã duyệt",
      );
    });

    it("is in the same line when the checks warned, before the warning clause", () => {
      renderColumn(warned(["fp_policy:asset_criticality"], { ...withRag(87) }));
      expect(line()).toHaveTextContent(
        "AI kết luận: FP (độ tin cậy trung bình) — trùng 87% với tri thức đã duyệt — " +
          "có cảnh báo kiểm chứng: tài sản quan trọng hoặc chưa rõ",
      );
      expect(within(line()).getByText("có cảnh báo kiểm chứng").tagName).toBe("STRONG");
    });

    it("is one line in the column, not two", () => {
      renderColumn(view({ ...withRag(87) }));
      expect(within(column()).getAllByText(/AI kết luận/)).toHaveLength(1);
    });
  });

  describe("the notice that the RAG was not applied", () => {
    const TAIL = "AI đã phân tích không có tri thức tham khảo.";
    const KINDS = [
      ["rate_limit", "Voyage vượt giới hạn tốc độ"],
      ["timeout", "Voyage quá thời gian chờ"],
      ["auth", "thiếu hoặc sai API key Voyage"],
      ["quota", "Voyage hết hạn mức"],
      ["provider_error", "lỗi phía Voyage"],
      ["vectordb_unreachable", "không kết nối được vector DB"],
    ] as const;

    it.each(KINDS)("says it for %s, in the alert's words", (kind, label) => {
      renderColumn(view({ ...withRag(null, kind) }));
      expect(notice()).toHaveTextContent(`⚠ Không áp dụng RAG cho alert này: ${label} — ${TAIL}`);
    });

    it("is beside the conclusion, not instead of it", () => {
      renderColumn(view({ ...withRag(null, "auth") }));
      expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy trung bình\)$/);
      expect(notice()).toBeInTheDocument();
      expect(notice()?.textContent).not.toContain("AI kết luận");
    });

    it("never says 'case' on the alert page", () => {
      renderColumn(view({ ...withRag(null, "timeout") }));
      expect(notice()?.textContent).not.toContain("case");
    });

    it("is not there when the lookup did not fail", () => {
      renderColumn(view({ ...withRag(87, null) }));
      expect(notice()).not.toBeInTheDocument();
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
    });

    it("is not there when the server sent no rag at all", () => {
      renderColumn(view());
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
    });

    it("is beside a conclusion with warnings too", () => {
      renderColumn(warned(["verifier_disagrees"], { ...withRag(null, "quota") }));
      expect(line()).toHaveTextContent("có cảnh báo kiểm chứng: bộ kiểm tra không đồng ý");
      expect(notice()).toHaveTextContent("Voyage hết hạn mức");
    });

    it("is also drawn for a verdict with no conclusion line (a needs_review nobody explained)", () => {
      renderColumn(
        view({
          suggestion: suggestion({ suggested_action: "needs_review", confidence: null }),
          proposed_action: null,
          held_by: [],
          ...withRag(null, "auth"),
        }),
      );
      expect(within(column()).queryByText(/AI kết luận/)).not.toBeInTheDocument();
      expect(notice()).toHaveTextContent("thiếu hoặc sai API key Voyage");
    });

    it("draws nothing for a kind it has no words for, and never the code", () => {
      renderColumn(view({ ...withRag(null, "<b>cosmic_ray</b>") }));
      expect(notice()).not.toBeInTheDocument();
      expect(column().textContent).not.toContain("cosmic_ray");
      expect(column().querySelector("b")).toBeNull();
      // the conclusion beside it is untouched
      expect(line()).toHaveTextContent(/^AI kết luận: TP \(độ tin cậy trung bình\)$/);
    });

    it("draws nothing for a kind it has no words for on a decided page either", () => {
      renderColumn(
        view({
          status: "closed_fp",
          acknowledged_by_name: "An",
          ...withRag(64, "cosmic_ray"),
        }),
      );
      expect(notice()).not.toBeInTheDocument();
      expect(column().textContent).not.toContain("cosmic_ray");
      // the percentage is a different fact and still stands
      expect(line()).toHaveTextContent("— trùng 64% với tri thức đã duyệt");
    });

    it("can stand beside the percentage", () => {
      renderColumn(view({ ...withRag(64, "timeout") }));
      expect(line()).toHaveTextContent("— trùng 64% với tri thức đã duyệt");
      expect(notice()).toHaveTextContent("Voyage quá thời gian chờ");
    });

    it("is not drawn when ① gave up: no analysis was made without references", () => {
      renderColumn(
        view({
          suggestion: null,
          triage_status: "unavailable",
          llm_stopped_by: "unavailable",
          ...withRag(null, "quota"),
        }),
      );
      expect(notice()).not.toBeInTheDocument();
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
    });

    it("is not drawn while ① is still working", () => {
      renderColumn(view({ suggestion: null, triage_status: "pending", ...withRag(null, "auth") }));
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
    });
  });

  describe("on a decided page", () => {
    const decided = (over: Partial<AlertView> = {}) =>
      view({ status: "closed_fp", acknowledged_by: "u1", acknowledged_by_name: "An", ...over });
    const box = () => within(column()).getByText(S.ai1.decidedAi).closest("div")!;

    it("says the percentage in the box, in the same line as the undecided column", () => {
      renderColumn(decided({ ...withRag(87) }));
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        /^AI kết luận: TP \(độ tin cậy trung bình\) — trùng 87% với tri thức đã duyệt$/,
      );
    });

    it("says the percentage with the warning clause when the checks warned", () => {
      renderColumn(
        decided({
          ...warned(["fp_policy:asset_criticality"], { ...withRag(72) }),
          status: "closed_fp",
          acknowledged_by_name: "An",
        }),
      );
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(
        "AI kết luận: FP (độ tin cậy trung bình) — trùng 72% với tri thức đã duyệt — " +
          "có cảnh báo kiểm chứng: tài sản quan trọng hoặc chưa rõ",
      );
    });

    it("says the notice in the box, for the alert", () => {
      renderColumn(decided({ ...withRag(null, "rate_limit") }));
      expect(within(box()).getByRole("note")).toHaveTextContent(
        "⚠ Không áp dụng RAG cho alert này: Voyage vượt giới hạn tốc độ — " +
          "AI đã phân tích không có tri thức tham khảo.",
      );
    });

    it("is the same line the undecided column draws for the same view", () => {
      const rag = withRag(87, "timeout");
      const undecided = renderColumn(view(rag));
      const before = line().textContent;
      const noteBefore = notice()?.textContent;
      undecided.unmount();
      renderColumn(decided(rag));
      expect(within(box()).getByText(/AI kết luận/).textContent).toBe(before);
      expect(within(box()).getByRole("note").textContent).toBe(noteBefore);
    });

    it("says nothing for a decided alert with no match and no failure", () => {
      renderColumn(decided({ ...withRag(null, null) }));
      expect(within(box()).getByText(/AI kết luận/).textContent).not.toContain("trùng");
      expect(within(column()).queryByRole("note")).not.toBeInTheDocument();
    });

    it("is not there before the decision on the blind arm, and is after it (the same head)", () => {
      const before = renderColumn(blindView({ status: "tier1_active" }));
      expect(within(column()).queryByText(/trùng/)).not.toBeInTheDocument();
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
      before.unmount();
      renderColumn(decided({ suggestion_visible: false, ...withRag(87, "auth") }));
      expect(within(box()).getByText(/AI kết luận/)).toHaveTextContent(MATCH);
      expect(within(box()).getByRole("note")).toHaveTextContent("Không áp dụng RAG");
    });
  });

  describe("on the blind arm, before the decision", () => {
    it("shows neither, even for a view that (wrongly) still carries rag", () => {
      const stray = blindView({ ...withRag(87, "auth") });
      expect(aiStateOfView(stray)).toEqual({ kind: "hidden" });
      renderColumn(stray);
      const col = column();
      expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
      expect(
        leaksIn(col, ["trùng", "tri thức đã duyệt", "Không áp dụng RAG", "Voyage", "87%"]),
      ).toEqual([]);
      expect(within(col).queryByRole("note")).not.toBeInTheDocument();
    });

    it("shows neither for a blind head the server stripped", () => {
      renderColumn(blindView());
      expect(within(column()).queryByText(/trùng/)).not.toBeInTheDocument();
      expect(within(column()).queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
    });
  });
});

// DEC-219 (trial, amended by the Owner): below the threshold `false_positive` is ①'s DEFAULT answer. For a run the rule
// applied to, the alert page says so after the percentage; it never says what the model itself answered, shows no
// confidence note and no forced flag. The sentences are written out in full: a label edited in strings.ts alone fails
// here.
describe("the RAG default below the threshold (DEC-219)", () => {
  const RULE: RagRule = { threshold: 80, best_pct: 62, applied: true };
  /**
   * A visible-arm run the rule applied to, as the server serves it: ① ended FP, the gate forced nothing, and nothing
   * of the model's own answer is served: `proposed_action` and `gate.proposed_verdict` are the verdict ① ended with,
   * the verifier's verdict is `null` (it would give the model's answer away), the confidence is `null` (it is the
   * model's), and `held_by` never carries `verifier_disagrees` (the other warning codes can be there).
   */
  const ragDefault = (
    reasons: string[] = [],
    over: Partial<AlertView> = {},
    rule: RagRule | null | undefined = RULE,
  ): AlertView => {
    const gate: NonNullable<Suggestion["gate"]> = {
      forced: false,
      forced_by: [],
      proposed_verdict: "false_positive",
      final_verdict: "false_positive",
      verifier_verdict: null,
      warnings: [],
    };
    if (rule !== undefined) gate.rag_rule = rule;
    return view({
      suggestion: suggestion({ suggested_action: "false_positive", confidence: null, gate }),
      proposed_action: "false_positive",
      held_by: reasons,
      rag: { best_pct: 62, not_applied: null },
      ...over,
    });
  };
  /** A run the rule did not apply to: the model said FP, there is a 62 % match, and `rule` says what the gate stored. */
  const noRule = (
    reasons: string[],
    rule: RagRule | null | undefined,
    over: Partial<AlertView> = {},
  ): AlertView => {
    const base = warned(
      reasons,
      { rag: { best_pct: 62, not_applied: null }, ...over },
      { verdict: "false_positive", confidence: "high" },
    );
    if (rule === undefined) return base;
    return {
      ...base,
      suggestion: { ...base.suggestion!, gate: { ...base.suggestion!.gate, rag_rule: rule } },
    };
  };
  const line = () => within(column()).getByText(/AI kết luận/);
  const PERCENT = "trùng 62% với tri thức đã duyệt";
  const DEFAULT = "(dưới 80%: mặc định FP)";
  // The warnings of a run the rule applied to: the server never lists `verifier_disagrees` there.
  const REASONS = ["fp_policy:asset_criticality", "fp_policy:playbook_rule"];
  const REASONS_TEXT = "tài sản quan trọng hoặc chưa rõ, không khớp bảng quyết định đã duyệt";
  // The warnings of a run the rule did not apply to, where the verifier's answer is served and may disagree.
  const NO_RULE_REASONS = ["fp_policy:asset_criticality", "verifier_disagrees"];
  const NO_RULE_REASONS_TEXT = "tài sản quan trọng hoặc chưa rõ, bộ kiểm tra không đồng ý";

  describe("the line", () => {
    it("says the verdict is the default below the threshold, after the percentage, with no note and no flag", () => {
      renderColumn(ragDefault());
      expect(line().textContent).toBe(`AI kết luận: FP — ${PERCENT} ${DEFAULT}`);
      expect(line().textContent).toBe(
        "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP)",
      );
    });

    it("keeps the warning clause after it, with the reasons", () => {
      renderColumn(ragDefault(REASONS));
      expect(line().textContent).toBe(
        "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — " +
          `có cảnh báo kiểm chứng: ${REASONS_TEXT}`,
      );
    });

    // The server serves `rag_rule` as `{ threshold, best_pct, applied }` and nothing about what the model answered; the
    // line reads `applied` and `threshold` only, so a key it does not read (a `changed` an older server might send)
    // cannot alter it, whatever its value.
    it.each([true, false])(
      "is the same text when the rule carries an extra `changed` key an older server might send (%s)",
      (changed) => {
        renderColumn(ragDefault(REASONS, {}, { ...RULE, changed } as RagRule));
        expect(line().textContent).toBe(
          "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — " +
            `có cảnh báo kiểm chứng: ${REASONS_TEXT}`,
        );
      },
    );

    it("puts the parenthesis after the verdict when the page has no percentage, with and without warnings", () => {
      // The percentage of the line is the page's own, the `rag` pair every conclusion line reads; the backend gives
      // `rag_rule.best_pct` the same number, so with the pair empty there is no percentage clause, whatever the rule
      // stored (here `best_pct` 62), and the parenthesis (which needs only the threshold) still follows the verdict.
      const none = { rag: { best_pct: null, not_applied: null } };
      const { unmount } = renderColumn(ragDefault([], none));
      expect(line().textContent).toBe("AI kết luận: FP (dưới 80%: mặc định FP)");
      unmount();
      renderColumn(ragDefault(REASONS, none));
      expect(line().textContent).toBe(
        `AI kết luận: FP (dưới 80%: mặc định FP) — có cảnh báo kiểm chứng: ${REASONS_TEXT}`,
      );
    });

    it("does the same when the server sent no rag at all", () => {
      const noRag = ragDefault();
      delete noRag.rag;
      renderColumn(noRag);
      expect(line().textContent).toBe("AI kết luận: FP (dưới 80%: mặc định FP)");
    });

    it("says the threshold the rule had, whatever it was", () => {
      renderColumn(ragDefault([], {}, { ...RULE, threshold: 65, best_pct: 40 }));
      expect(line().textContent).toBe(
        "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 65%: mặc định FP)",
      );
    });

    it("says no confidence, which is the model's own, whatever the run holds", () => {
      for (const confidence of ["high", "medium", "low", null]) {
        const v = ragDefault();
        v.suggestion = { ...v.suggestion!, confidence };
        const { unmount } = renderColumn(v);
        expect(line().textContent).toBe(`AI kết luận: FP — ${PERCENT} ${DEFAULT}`);
        unmount();
      }
    });

    it("bolds the verdict and the warning phrase, and nothing else", () => {
      renderColumn(ragDefault(REASONS));
      const strong = Array.from(line().querySelectorAll("strong")).map((el) => el.textContent);
      expect(strong).toEqual(["FP", "có cảnh báo kiểm chứng"]);
    });

    it("never says what the model answered, even when the server serves its answer as TP", () => {
      const v = ragDefault(REASONS, { proposed_action: "true_positive" });
      v.suggestion = {
        ...v.suggestion!,
        gate: { ...v.suggestion!.gate, proposed_verdict: "true_positive" },
      };
      renderColumn(v);
      const text = line().textContent ?? "";
      expect(text).toBe(
        "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — " +
          `có cảnh báo kiểm chứng: ${REASONS_TEXT}`,
      );
      expect(wordsFound(text, ["TP"])).toEqual([]);
      expect(text).not.toContain("model kết luận");
      expect(text).not.toContain("true_positive");
    });

    it("is one line in the column, and the model's reasons stay under it", () => {
      renderColumn(ragDefault());
      expect(within(column()).getAllByText(/AI kết luận/)).toHaveLength(1);
      const reasons = within(within(column()).getByRole("region", { name: S.ai1.reasons }));
      expect(reasons.getAllByRole("listitem")).toHaveLength(2);
    });

    it.each([
      ["a rag_rule that is null", null],
      ["no rag_rule key (a run stored before DEC-219)", undefined],
      ["a rule that is switched off", { threshold: 0, best_pct: null, applied: false } as RagRule],
      [
        "a rule the match did not fall under",
        { threshold: 80, best_pct: 91, applied: false } as RagRule,
      ],
    ])("is today's line when the rule did not apply: %s", (_name, rule) => {
      renderColumn(noRule(NO_RULE_REASONS, rule));
      expect(line().textContent).toBe(
        "AI kết luận: FP (độ tin cậy cao) — trùng 62% với tri thức đã duyệt — " +
          `có cảnh báo kiểm chứng: ${NO_RULE_REASONS_TEXT}`,
      );
      expect(column().textContent).not.toContain("mặc định");
    });

    it("is today's line when the server says the rule applied but serves a verdict that is not FP (inconsistent)", () => {
      const v = ragDefault();
      v.suggestion = { ...v.suggestion!, suggested_action: "true_positive", confidence: "medium" };
      renderColumn(v);
      expect(line().textContent).toBe(
        "AI kết luận: TP (độ tin cậy trung bình) — trùng 62% với tri thức đã duyệt",
      );
      expect(column().textContent).not.toContain("mặc định");
    });

    it("is today's line, without a warning clause, when the rule did not apply and the checks did not warn", () => {
      renderColumn(noRule([], { threshold: 80, best_pct: 91, applied: false }));
      expect(line().textContent).toBe(
        "AI kết luận: FP (độ tin cậy cao) — trùng 62% với tri thức đã duyệt",
      );
    });
  });

  describe("the forced flag and the gate block", () => {
    it("shows no flag, in the line or anywhere in the column", () => {
      renderColumn(ragDefault(REASONS));
      const col = within(column());
      expect(col.queryByRole("img", { name: S.ai1.forcedLabel })).not.toBeInTheDocument();
      expect(col.queryByText(S.ai1.forced)).not.toBeInTheDocument();
      expect(column().textContent).not.toContain(S.ai1.forced);
    });

    it("says the gate forced nothing, and names no rule", () => {
      renderColumn(ragDefault());
      const col = within(column());
      expect(col.getByText(S.ai1.gateNotForced)).toBeInTheDocument();
      expect(col.queryByText(S.ai1.gateForced)).not.toBeInTheDocument();
      expect(col.queryByText(S.ai1.gateForcedBy)).not.toBeInTheDocument();
      expect(column().textContent).not.toContain("rag_rule");
      expect(column().textContent).not.toContain("quy tắc RAG");
    });

    // The gate block of a run the rule applied to is pinned whole: the verdict ① ended with twice, and no verifier row
    // (the server sends `verifier_verdict` null, and `GateSteps` draws a row only for a verdict it was given), so
    // nothing in it can give the model's own answer away. A label edited in strings.ts alone fails here.
    it("pins the gate block of a run the rule applied to: the verdict ① ended with twice, no verifier row", () => {
      renderColumn(ragDefault());
      const steps = within(column()).getByRole("region", { name: S.ai1.gateSteps });
      expect(steps.textContent).toBe("Các bước của cổngĐề xuất gốcFPKết luận sau cổngFP");
      expect(steps.textContent).not.toContain(S.ai1.verifier);
    });

    it("pins the gate block of such a run that also carries a gate warning of its own", () => {
      const v = ragDefault(REASONS);
      v.suggestion = {
        ...v.suggestion!,
        gate: { ...v.suggestion!.gate, warnings: ["fp_policy:playbook_rule: no rule cited"] },
      };
      renderColumn(v);
      const steps = within(column()).getByRole("region", { name: S.ai1.gateSteps });
      expect(steps.textContent).toBe(
        "Các bước của cổngĐề xuất gốcFPKết luận sau cổngFPCảnh báo của cổngfp_policy:playbook_rule: no rule cited",
      );
    });

    it("pins the gate line of such a run: the gate forced nothing", () => {
      renderColumn(ragDefault(REASONS));
      expect(within(column()).getByText(S.ai1.gate).parentElement?.textContent).toBe(
        "Cổng kiểm soátKhông bị ép",
      );
    });
  });

  describe("on a decided page", () => {
    const decided = (over: Partial<AlertView> = {}) =>
      ragDefault(REASONS, { status: "closed_fp", acknowledged_by_name: "An", ...over });
    const box = () => within(column()).getByText(S.ai1.decidedAi).closest("div")!;
    const khop = () => within(column()).getByText(S.ai1.match).parentElement!;

    it("says the same line in the box as the undecided column", () => {
      const undecided = renderColumn(ragDefault(REASONS));
      const before = line().textContent;
      undecided.unmount();
      renderColumn(decided());
      const after = within(box()).getByText(/AI kết luận/).textContent;
      expect(after).toBe(
        "AI kết luận: FP — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — " +
          `có cảnh báo kiểm chứng: ${REASONS_TEXT}`,
      );
      expect(after).toBe(before);
      expect(within(column()).getAllByText(/AI kết luận/)).toHaveLength(1);
    });

    it("says Khớp 'có' when the alert was closed as a false positive: ① ended with FP", () => {
      renderColumn(decided({ status: "closed_fp" }));
      expect(khop().textContent).toBe("Khớp có");
    });

    it("says Khớp 'không' when the alert was escalated", () => {
      renderColumn(decided({ status: "escalated_tier2", case_id: 9 }));
      expect(khop().textContent).toBe("Khớp không");
    });

    it("says Khớp 'không' for an alert Tier 2 has since concluded as a confirmed incident (an escalation)", () => {
      renderColumn(decided({ status: "closed_confirmed", case_id: 9 }));
      expect(khop().textContent).toBe("Khớp không");
    });

    it("says Khớp 'không' when the alert was closed as benign (① has no benign verdict)", () => {
      renderColumn(decided({ status: "closed_benign" }));
      expect(khop().textContent).toBe("Khớp không");
    });

    it("is today's line in the box when the rule did not apply", () => {
      renderColumn(
        noRule(
          NO_RULE_REASONS,
          { threshold: 80, best_pct: 91, applied: false },
          { status: "closed_fp", acknowledged_by_name: "An" },
        ),
      );
      expect(within(box()).getByText(/AI kết luận/).textContent).toBe(
        "AI kết luận: FP (độ tin cậy cao) — trùng 62% với tri thức đã duyệt — " +
          `có cảnh báo kiểm chứng: ${NO_RULE_REASONS_TEXT}`,
      );
    });
  });

  describe("on the blind arm", () => {
    it("draws nothing of the rule before the decision, and the markers find it where it is drawn", () => {
      const blind = blindView({ status: "tier1_active" });
      expect(aiStateOfView(blind)).toEqual({ kind: "hidden" });
      const hidden = renderColumn(blind);
      expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
      expect(leaksIn(column())).toEqual([]);
      expect(leaksIn(column(), RULE_MARKERS)).toEqual([]);
      hidden.unmount();
      renderColumn(ragDefault(REASONS));
      expect(phrasesFound(textOf(column()), RULE_MARKERS)).toEqual(RULE_MARKERS);
      expect(leaksIn(column())).toEqual(
        expect.arrayContaining(["FP", "AI kết luận", "dưới 80%", "mặc định FP"]),
      );
    });

    it("draws nothing of the rule for a blind head with the keys the server drops: no suggestion, no gate", () => {
      const stray = blindView({
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality"],
        rag: { best_pct: 62, not_applied: null },
      });
      renderColumn(stray);
      expect(leaksIn(column(), [...RULE_MARKERS, "trùng 62%", "62%"])).toEqual([]);
    });

    it("shows the line once the head is decided: the decision lifts the blind arm", () => {
      renderColumn(
        ragDefault(REASONS, {
          status: "closed_fp",
          suggestion_visible: false,
          acknowledged_by_name: "An",
        }),
      );
      expect(within(column()).getByText(/AI kết luận/).textContent).toContain(DEFAULT);
    });
  });
});

describe("accessibility", () => {
  const states: [string, AlertView][] = [
    ["ready", view()],
    [
      "ready with the percentage and the RAG notice (P14-T07)",
      view({ rag: { best_pct: 87, not_applied: "timeout" } }),
    ],
    [
      "decided with the percentage and the RAG notice (P14-T07)",
      view({
        status: "closed_benign",
        acknowledged_by_name: "An",
        rag: { best_pct: 87, not_applied: "auth" },
      }),
    ],
    [
      "ready, the RAG default below the threshold (DEC-219)",
      view({
        suggestion: suggestion({
          suggested_action: "false_positive",
          confidence: null,
          gate: {
            forced: false,
            forced_by: [],
            proposed_verdict: "false_positive",
            final_verdict: "false_positive",
            verifier_verdict: null,
            rag_rule: { threshold: 80, best_pct: 62, applied: true },
          },
        }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality"],
        rag: { best_pct: 62, not_applied: null },
      }),
    ],
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
      "ready with warnings beside the verdict (DEC-217)",
      view({
        suggestion: suggestion({
          suggested_action: "false_positive",
          gate: { forced: false, forced_by: [], proposed_verdict: "false_positive" },
        }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality", "verifier_disagrees"],
      }),
    ],
    [
      "ready, a version 1 row the gate forced",
      view({
        suggestion: suggestion({
          suggested_action: "false_positive",
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
