// src/features/tier1/AiColumn.test.tsx — the ① column of the alert page as the scorecard (DEC-221, AP-T4): four score tiles
// over five tabs for a view that has an `analysis`, and every state the column had before kept inside the same frame
// (the blind arm, pending, none, unavailable, decided with its Khớp row, the clusters-changed note, the RAG notice, a
// version 1 row's forced flag), and the flat rendering (`FlatAiColumn.test.tsx`) for a view that has no `analysis`.
// What the column says is decided by `aiStateOfView` and by nothing else; the scorecard is drawn only for a state that has
// a conclusion. The model's name appears nowhere (G5), and the blind arm draws nothing of ① (DEC-101).
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import type { AlertView, Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { phrasesFound, textOf, wordsFound } from "../../testing/containsWord";
import { modelNamesIn } from "../../testing/modelName";
import { AiColumn } from "./AiColumn";
import { analysis, olderAnalysis, ruleDecidedAnalysis, ruleDecidedKeys } from "./analysisFixtures";

const P = S.ai1.panel;

const suggestion = (over: Partial<Suggestion> = {}): Suggestion => ({
  run_id: "r1",
  suggested_action: "true_positive",
  confidence: "medium",
  reasons: [],
  gate: {
    forced: false,
    forced_by: [],
    proposed_verdict: "true_positive",
    final_verdict: "true_positive",
    verifier_verdict: "needs_review",
    warnings: [],
  },
  correlated_at_analysis: 3,
  created_at: "2026-11-15T11:35:56Z",
  ...over,
});

/** A visible-arm view with a ① result and the server's `analysis` of it. */
const view = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  triage_status: "ready",
  suggestion: suggestion(),
  correlated_now: 3,
  proposed_action: "true_positive",
  held_by: ["facts_mismatch", "verifier_disagrees"],
  rag: { best_pct: null, not_applied: null, below_floor_pct: 47, floor_pct: 50 },
  analysis: analysis(),
  ...over,
});

/**
 * What the server sends for a run the RAG rule decided (DEC-219, DEC-225): the verdict ① ended with, and nothing else of
 * the model's; the page is not told that a rule exists.
 */
const ruleDecided = (over: Partial<AlertView> = {}): AlertView =>
  view({
    ...ruleDecidedKeys(62),
    analysis: ruleDecidedAnalysis(),
    ...over,
  });

/** A blind, undecided head: the server drops every key of ①, the `analysis` among them (`visibility.ANALYST_HIDE`). */
function blindView(over: Partial<AlertView> = {}): AlertView {
  const stripped = view({ suggestion_visible: false });
  for (const key of [
    "suggestion",
    "triage_status",
    "proposed_action",
    "held_by",
    "rag",
    "analysis",
  ] as const) {
    delete stripped[key];
  }
  return { ...stripped, ...over };
}

const column = () => screen.getByRole("region", { name: S.alert.aiHeading });

/** All the blind column says: its heading, the advisory line and the notice with its explanation. */
const BLIND_TEXT = [S.alert.aiHeading, S.alert.aiHint, S.ai1.hidden, S.ai1.hiddenBody];
const renderColumn = (v: AlertView) =>
  render(
    <main>
      <AiColumn view={v} />
    </main>,
  );

const tile = (name: string) => within(column()).getByRole("group", { name });
/** What an element says, text node by text node, with the blanks between them left out. */
const said = (el: Element): string[] =>
  textOf(el)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");

const user = userEvent.setup();
const openTab = async (name: string) => {
  await user.click(within(column()).getByRole("tab", { name }));
  return within(column()).getByRole("tabpanel");
};

/** The two-letter labels of a verdict, found as WORDS ("SFTP" is not "TP"). */
const LABEL_MARKERS = ["TP", "FP"];
/** What the scorecard adds to the page, and only there: its captions and tabs, found as plain substrings. */
const PANEL_WORDS = [
  P.tile.confidence,
  P.tile.rag,
  P.tile.verdict,
  P.tile.checks,
  P.tabs.overview,
  P.tabs.evidence,
  P.tabs.knowledge,
  P.tabs.tech,
  P.overview.highlights,
  P.overview.attack,
  P.overview.benign,
  P.overview.nextChecks,
  P.tile.verdictNote.true_positive,
  P.tile.verdictNote.false_positive,
  S.analysis.knowledge.heading,
  P.history.heading,
  P.playbook.heading,
];
const VERDICT_WORDS = [
  "true_positive",
  "false_positive",
  "Cần xem xét",
  "AI kết luận",
  "cảnh báo kiểm chứng",
  "độ tin cậy",
  "dưới 80%",
  "mặc định FP",
  "trùng cao nhất",
  "dưới mức tối thiểu",
  "amsi.dll",
  "splwow64",
  ...PANEL_WORDS,
];
const leaksIn = (el: Element): string[] => {
  const text = textOf(el);
  return [...wordsFound(text, LABEL_MARKERS), ...phrasesFound(text, VERDICT_WORDS)];
};

describe("the frame", () => {
  it("is a region named by the heading 'PHÂN TÍCH AI · TIER 1', with the advisory line at the right", () => {
    renderColumn(view());
    expect(column()).toBeInTheDocument();
    expect(within(column()).getByRole("heading", { level: 2 })).toHaveTextContent(
      "PHÂN TÍCH AI · TIER 1",
    );
    expect(within(column()).getByText("Gợi ý tham khảo — bạn là người quyết định")).toBeVisible();
  });
});

describe("the four tiles", () => {
  it("are Kết luận, Độ tin cậy, Tri thức (RAG) and Kiểm chứng, in that order, above the tabs", () => {
    renderColumn(view());
    const groups = within(column()).getAllByRole("group");
    expect(groups.map((group) => group.getAttribute("aria-labelledby"))).toHaveLength(4);
    expect(
      groups.map(
        (group) =>
          within(group).getByText(/^(Kết luận|Độ tin cậy|Tri thức \(RAG\)|Kiểm chứng)$/)
            .textContent,
      ),
    ).toEqual(["Kết luận", "Độ tin cậy", "Tri thức (RAG)", "Kiểm chứng"]);
    const tablist = within(column()).getByRole("tablist");
    expect(
      groups.every(
        (group) => group.compareDocumentPosition(tablist) & Node.DOCUMENT_POSITION_FOLLOWING,
      ),
    ).toBe(true);
  });

  it("show a TP in the high-severity orange with 'tấn công thật' under it", () => {
    renderColumn(view());
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "TP", "tấn công thật"]);
    expect(tile("Kết luận")).toHaveAttribute("data-tone", "high");
  });

  it("show an FP in the calm blue with 'dương tính giả' under it", () => {
    renderColumn(
      view({
        suggestion: suggestion({ suggested_action: "false_positive" }),
        proposed_action: "false_positive",
      }),
    );
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "FP", "dương tính giả"]);
    expect(tile("Kết luận")).toHaveAttribute("data-tone", "low");
  });

  it("show the confidence as a word over a three-segment meter", () => {
    renderColumn(view());
    expect(said(tile("Độ tin cậy"))).toEqual(["Độ tin cậy", "Trung bình"]);
    expect(within(tile("Độ tin cậy")).getByRole("img", { name: "2 trên 3" })).toBeInTheDocument();
  });

  it("show the number of the lookup that scored under the floor, and the floor", () => {
    renderColumn(view());
    expect(said(tile("Tri thức (RAG)"))).toEqual(["Tri thức (RAG)", "47%", "dưới mức 50%"]);
  });

  it.each([
    [
      "a match",
      { state: "matched", best_pct: 62, floor_pct: 50 },
      ["Tri thức (RAG)", "62%", "trùng sự cố cũ"],
    ],
    [
      "no candidate",
      { state: "no_candidate", best_pct: null, candidates: [] },
      ["Tri thức (RAG)", "—", "không có mục nào trùng"],
    ],
    [
      "no lookup",
      { state: "no_lookup", best_pct: null, candidates: [] },
      ["Tri thức (RAG)", "—", "không có tra cứu"],
    ],
    [
      "a failure of a known kind",
      { state: "failed", failure: "rate_limit", best_pct: null, candidates: [] },
      ["Tri thức (RAG)", "—", "vượt giới hạn tốc độ"],
    ],
    [
      "a failure of a kind it has no words for",
      { state: "failed", failure: "cosmic_ray", best_pct: null, candidates: [] },
      ["Tri thức (RAG)", "—", "tra cứu bị lỗi"],
    ],
  ])("show the RAG tile for %s", (_name, rag, expected) => {
    renderColumn(view({ analysis: analysis({ rag: { ...analysis().rag, ...rag } as never }) }));
    expect(said(tile("Tri thức (RAG)"))).toEqual(expected);
  });

  it("show the checks passed over the checks that apply, and the warnings in the warning colour", () => {
    renderColumn(view());
    expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "3/5", "2 cảnh báo"]);
    expect(within(tile("Kiểm chứng")).getByText("2 cảnh báo")).toHaveAttribute("data-tone", "warn");
  });

  it("say there is no warning when there is none", () => {
    renderColumn(
      view({ analysis: analysis({ check_totals: { passed: 6, applicable: 6, warnings: 0 } }) }),
    );
    expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "6/6", "không có cảnh báo"]);
    expect(within(tile("Kiểm chứng")).getByText("không có cảnh báo")).toHaveAttribute(
      "data-tone",
      "muted",
    );
  });
});

describe("the five tabs", () => {
  it("are Tổng quan, Bằng chứng, Tri thức, Kiểm chứng and Kỹ thuật, with the first one open", () => {
    renderColumn(view());
    const tabs = within(column()).getAllByRole("tab");
    expect(tabs.map((tab) => tab.textContent)).toEqual([
      "Tổng quan",
      "Bằng chứng",
      "Tri thức",
      "Kiểm chứng",
      "Kỹ thuật",
    ]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(within(column()).getByRole("tablist")).toHaveAccessibleName(
      "Chi tiết phân tích AI Tier 1",
    );
  });

  it("are one tab stop: the arrow keys, Home and End move between them (the shared Tabs)", async () => {
    renderColumn(view());
    const tab = (name: string) => within(column()).getByRole("tab", { name });
    tab("Tổng quan").focus();
    await user.keyboard("{ArrowRight}");
    expect(tab("Bằng chứng")).toHaveFocus();
    expect(tab("Bằng chứng")).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(tab("Kỹ thuật")).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(tab("Tổng quan")).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(tab("Kỹ thuật")).toHaveFocus();
    await user.keyboard("{Home}");
    expect(tab("Tổng quan")).toHaveFocus();
    expect(
      within(column())
        .getAllByRole("tab")
        .filter((t) => t.tabIndex === 0),
    ).toHaveLength(1);
  });

  it("start on the first tab again for a new page load (the open tab is not kept)", async () => {
    const first = renderColumn(view());
    await openTab("Kỹ thuật");
    first.unmount();
    renderColumn(view());
    expect(within(column()).getByRole("tab", { name: "Tổng quan" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});

describe("Tổng quan, a version 4 run", () => {
  it("has the summary, the highlights with the mark of their direction, the two readings, what would change it and what to check", () => {
    renderColumn(view());
    const panel = within(column()).getByRole("tabpanel");
    expect(within(panel).getByText(/^amsi\.dll bị nạp bởi splwow64\.exe/)).toBeInTheDocument();
    const highlights = within(panel).getByRole("region", { name: "Điều nổi bật" });
    expect(
      within(highlights)
        .getAllByRole("img")
        .map((mark) => mark.getAttribute("aria-label")),
    ).toEqual([
      S.analysis.status.up,
      S.analysis.status.up,
      S.analysis.status.warn,
      S.analysis.status.warn,
      S.analysis.status.warn,
    ]);
    expect(said(highlights).slice(1)).toEqual([
      "Lịch sử: 15 trên 15 alert cùng kịch bản và cùng máy từng là sự cố thật.",
      "Tài khoản liên quan là tài khoản đặc quyền.",
      "Không có tri thức đã duyệt nào trùng từ 50% trở lên (cao nhất 47%).",
      "Bộ kiểm chứng độc lập không đồng ý.",
      // the held reasons of the view in the words of the flat column (spec G2), less the verifier's disagreement, which
      // the highlight above says already
      "Cảnh báo kiểm chứng: AI khai dữ kiện lệch với hệ thống",
    ]);
    const attack = within(panel).getByRole("region", { name: "Nếu là tấn công" });
    expect(attack).toHaveTextContent(
      "Mã độc nạp amsi.dll để dò hoặc vô hiệu hoá AMSI trước khi chạy PowerShell.",
    );
    const benign = within(panel).getByRole("region", { name: "Nếu lành tính" });
    expect(benign).toHaveTextContent(/^Nếu lành tính\s*splwow64\.exe là trình in của Windows/);
    expect(panel).toHaveTextContent(
      "Điều sẽ làm đổi kết luận: tiến trình cha là ứng dụng văn phòng đang in, không có lệnh PowerShell nào theo sau.",
    );
    const next = within(panel).getByRole("region", { name: "Nên kiểm tra tiếp" });
    expect(
      within(next)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      "Xem tiến trình cha và dòng lệnh của splwow64.exe (PID 728).",
      "Tìm lệnh PowerShell hoặc kết nối ra ngoài trong 30 phút sau đó.",
      "Đối chiếu job BITS của alert 112438: tải gì, từ đâu.",
    ]);
  });
});

describe("Tổng quan, an older run (stored before version 4)", () => {
  it("shows the highlights and nothing else, with no empty heading", () => {
    renderColumn(view({ analysis: olderAnalysis() }));
    const panel = within(column()).getByRole("tabpanel");
    expect(within(panel).getByRole("region", { name: "Điều nổi bật" })).toBeInTheDocument();
    for (const absent of ["Nếu là tấn công", "Nếu lành tính", "Nên kiểm tra tiếp"]) {
      expect(within(panel).queryByRole("region", { name: absent })).not.toBeInTheDocument();
      expect(within(panel).queryByText(absent)).not.toBeInTheDocument();
    }
    expect(within(panel).queryByText(/Điều sẽ làm đổi kết luận/)).not.toBeInTheDocument();
    expect(within(panel).queryByText(P.overview.none)).not.toBeInTheDocument();
  });

  it("says plainly that there is nothing to show when there is not even a highlight", () => {
    renderColumn(view({ analysis: olderAnalysis({ highlights: [] }), held_by: [] }));
    const panel = within(column()).getByRole("tabpanel");
    expect(panel).toHaveTextContent("Lượt phân tích này không có phần tóm tắt.");
    expect(within(panel).queryByRole("region")).not.toBeInTheDocument();
  });

  it("shows only the reading it has, and the rest of the tiles and tabs are there as ever", async () => {
    renderColumn(view({ analysis: olderAnalysis({ reading_attack: "Chỉ một cách đọc." }) }));
    const panel = within(column()).getByRole("tabpanel");
    expect(within(panel).getByRole("region", { name: "Nếu là tấn công" })).toBeInTheDocument();
    expect(within(panel).queryByRole("region", { name: "Nếu lành tính" })).not.toBeInTheDocument();
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "TP", "tấn công thật"]);
    expect(within(await openTab("Bằng chứng")).getAllByRole("listitem")).toHaveLength(4);
  });
});

describe("Bằng chứng", () => {
  it("lists every reason in its order, with its quote, its source in words and whether the server found the quote", async () => {
    renderColumn(view());
    const panel = await openTab("Bằng chứng");
    expect(
      within(panel).getByText("2 trên 4 dẫn chứng khớp nguyên văn với dữ liệu alert."),
    ).toBeVisible();
    const rows = within(panel).getAllByRole("listitem");
    expect(rows).toHaveLength(4);
    expect(
      rows.map((row) => row.querySelector("[data-verified]")?.getAttribute("data-verified")),
    ).toEqual(["true", "true", "false", "false"]);
    expect(said(rows[0]!)).toEqual([
      "amsi.dll được nạp bởi tiến trình bất thường splwow64.exe.",
      "Image: C:\\Windows\\splwow64.exe · ImageLoaded: C:\\Windows\\System32\\amsi.dll",
      "Log gốc của alert · khớp nguyên văn",
    ]);
    expect(within(rows[0]!).getByRole("img", { name: "Đã kiểm chứng" })).toBeInTheDocument();
    expect(said(rows[1]!)[2]).toBe("Ngữ cảnh tài khoản và tài sản · khớp nguyên văn");
    expect(said(rows[2]!)[2]).toBe(
      "Mẫu tương quan · AI ghép hoặc diễn giải, không tìm thấy nguyên văn",
    );
    expect(
      within(rows[2]!).getByRole("img", { name: "Không kiểm chứng được" }),
    ).toBeInTheDocument();
    // a reason that quotes nothing has no quote box, and names no source
    expect(said(rows[3]!)).toEqual([
      "15 trên 15 case cùng kịch bản và cùng máy đã được xác nhận là sự cố thật.",
      "AI diễn giải, không trích nguyên văn",
    ]);
  });

  it("says 'Không kiểm chứng được', the words of the mark beside it, for a quote the server gave no reason for", async () => {
    renderColumn(
      view({
        analysis: analysis({
          reasons: [
            { claim: "c", quote: "q", source: "wazuh_raw_log", verified: false, why: null },
          ],
        }),
      }),
    );
    const row = within(await openTab("Bằng chứng")).getByRole("listitem");
    expect(said(row)[2]).toBe("Log gốc của alert · không kiểm chứng được");
    expect(within(row).getByRole("img")).toHaveAccessibleName("Không kiểm chứng được");
  });

  it("starts 'Không kiểm chứng được' with a capital when it stands alone: a reason that names no source", async () => {
    renderColumn(
      view({
        analysis: analysis({
          reasons: [{ claim: "c", quote: "q", source: null, verified: false, why: null }],
        }),
      }),
    );
    const row = within(await openTab("Bằng chứng")).getByRole("listitem");
    expect(said(row)[2]).toBe("Không kiểm chứng được");
  });

  it("shows a source it has no words for as the code, and says plainly when the model cited nothing", async () => {
    const odd = renderColumn(
      view({
        analysis: analysis({
          reasons: [
            { claim: "c", quote: "q", source: "brand_new_source", verified: true, why: null },
          ],
        }),
      }),
    );
    expect(said(within(await openTab("Bằng chứng")).getByRole("listitem"))[2]).toBe(
      "brand_new_source · khớp nguyên văn",
    );
    odd.unmount();
    renderColumn(view({ analysis: analysis({ reasons: [] }) }));
    expect(await openTab("Bằng chứng")).toHaveTextContent("AI không nêu dẫn chứng nào.");
  });
});

describe("Tri thức", () => {
  it("shows the candidates, the sentence of the state and that the default rule did not apply", async () => {
    renderColumn(view());
    const panel = await openTab("Tri thức");
    const lookup = within(panel).getByRole("region", { name: "Tri thức đã duyệt" });
    expect(said(lookup)).toEqual([
      "Tri thức đã duyệt",
      "23 mục được chấm điểm",
      "47%",
      "PowerShell mã hoá Base64 từ wazuh-agent",
      "·",
      "sự cố thật",
      "43%",
      "Shell quyền SYSTEM do agent giám sát sinh ra",
      "·",
      "đã đóng FP",
      "41%",
      "Tác vụ cập nhật định kỳ của Windows",
      "·",
      "lành tính",
      "Không mục nào đạt mức tối thiểu 50%, nên AI không được cung cấp tri thức tham khảo.",
    ]);
  });

  it("says the decision history: the scope, the total, the incidents and the last time", async () => {
    renderColumn(view());
    const panel = await openTab("Tri thức");
    expect(within(panel).getByRole("region", { name: "Lịch sử quyết định" })).toHaveTextContent(
      "Cùng kịch bản và cùng máy: 15 quyết định, 15 là sự cố thật · gần nhất 06/11 16:00",
    );
  });

  it("says the playbook and the decision-table rule that matched", async () => {
    renderColumn(view());
    const panel = await openTab("Tri thức");
    const card = within(panel).getByRole("region", { name: "Playbook và bảng quyết định" });
    expect(card).toHaveTextContent(
      "Playbook ransomware_v1. Theo bảng quyết định, rule ran-1 khớp: cần người xem.",
    );
    expect(within(card).queryByText(P.playbook.unsigned)).not.toBeInTheDocument();
  });

  it("says that the decision table is not signed yet when it is not", async () => {
    renderColumn(
      view({
        analysis: analysis({
          playbook: {
            name: "ransomware_v1",
            rule_id: "ran-1",
            rule_action: "needs_review",
            rule_table_reviewed: false,
          },
        }),
      }),
    );
    const panel = await openTab("Tri thức");
    expect(within(panel).getByText("Bảng quyết định này chưa được ký duyệt.")).toBeVisible();
  });

  it.each([
    [
      "no rule matched",
      { name: "ssh_v1", rule_id: null, rule_action: null, rule_table_reviewed: true },
      "Playbook ssh_v1. Theo bảng quyết định, không có rule nào khớp.",
    ],
    [
      "no table for the category",
      { name: null, rule_id: null, rule_action: null, rule_table_reviewed: null },
      "Không có playbook hay bảng quyết định cho loại alert này.",
    ],
  ])("says %s", async (_name, playbook, expected) => {
    renderColumn(view({ analysis: analysis({ playbook: playbook as never }) }));
    const panel = await openTab("Tri thức");
    expect(
      within(panel).getByRole("region", { name: "Playbook và bảng quyết định" }),
    ).toHaveTextContent(expected);
  });

  it("says there is no history when the server found none", async () => {
    renderColumn(view({ analysis: analysis({ history: null }) }));
    const panel = await openTab("Tri thức");
    expect(within(panel).getByRole("region", { name: "Lịch sử quyết định" })).toHaveTextContent(
      "Chưa có quyết định nào trước đây cho alert tương tự.",
    );
  });

  it.each([
    [
      "matched",
      { state: "matched", best_pct: 62, floor_pct: 50 },
      "Mục trùng cao nhất đạt 62%, qua mức tối thiểu 50%, nên AI được cung cấp tri thức tham khảo.",
    ],
    [
      "no_candidate",
      { state: "no_candidate", best_pct: null, candidates: [] },
      "Không có mục tri thức đã duyệt nào được chấm điểm cho alert này.",
    ],
    [
      "no_lookup",
      { state: "no_lookup", best_pct: null, candidates: [] },
      "Lượt phân tích này không tra cứu tri thức đã duyệt.",
    ],
    [
      "failed",
      { state: "failed", failure: "timeout", best_pct: null, candidates: [] },
      "Không tra cứu được tri thức đã duyệt: Voyage quá thời gian chờ.",
    ],
    [
      "a state it has no words for (shown as the code)",
      { state: "future_state", best_pct: null, candidates: [] },
      "future_state",
    ],
  ])("explains the state %s", async (_name, rag, expected) => {
    renderColumn(view({ analysis: analysis({ rag: { ...analysis().rag, ...rag } as never }) }));
    const panel = await openTab("Tri thức");
    const lookup = within(panel).getByRole("region", { name: "Tri thức đã duyệt" });
    expect(said(lookup).at(-1)).toBe(expected);
  });
});

describe("Kiểm chứng", () => {
  it("has one line for each gate step with its mark, its name and its closed explanation", async () => {
    renderColumn(view());
    const panel = await openTab("Kiểm chứng");
    const lines = within(panel)
      .getAllByRole("img")
      .map((mark) => mark.getAttribute("aria-label"));
    expect(lines.slice(0, 6)).toEqual([
      "Đạt",
      "Cảnh báo",
      "Đạt",
      "Không áp dụng",
      "Đạt",
      "Cảnh báo",
    ]);
    const card = within(panel).getByRole("list", { name: "Các bước kiểm chứng" });
    expect(said(card)).toEqual([
      "Đúng định dạng",
      "— hợp lệ ngay lần đầu",
      "Dữ kiện",
      "— AI khai mức nghiêm trọng high, hệ thống ghi medium",
      "Dẫn chứng",
      "— 2 trên 4 khớp nguyên văn",
      "Chính sách FP",
      "— không xét, vì kết luận là TP",
      "Chèn lệnh",
      "— không phát hiện",
      "Bộ kiểm chứng độc lập",
      "— không đồng ý (trả lời: Cần xem xét)",
    ]);
    // the two held reasons of this run (the facts differ, the verifier disagreed) are said by their own lines: no
    // note repeats them in vaguer words, and neither is said twice on the tab
    const text = textOf(panel);
    expect(text).not.toContain("AI khai dữ kiện lệch với hệ thống");
    expect(text).not.toContain("bộ kiểm chứng không đồng ý");
  });

  it("has the facts table: the system's value beside what the model declared, and whether they agree", async () => {
    renderColumn(view());
    const panel = await openTab("Kiểm chứng");
    const table = within(panel).getByRole("table", { name: "Dữ kiện đã dùng" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Dữ kiện", "Hệ thống", "AI khai", "Khớp"]);
    expect(
      within(table)
        .getAllByRole("row")
        .slice(1)
        .map((row) => [...row.children].map((cell) => cell.textContent)),
    ).toEqual([
      ["Mức nghiêm trọng", "medium", "high", "lệch"],
      ["Danh tiếng IOC", "chưa tra", "chưa tra", "khớp"],
      ["Độ quan trọng tài sản", "medium", "medium", "khớp"],
      ["Tài khoản đặc quyền", "có", "có", "khớp"],
      ["Số lần xuất hiện", "2", "2", "khớp"],
    ]);
    expect(within(table).getByText("lệch")).toHaveAttribute("data-tone", "warn");
  });

  it("says that nothing was checked when no row came", async () => {
    renderColumn(view({ analysis: analysis({ checks: [], check_totals: undefined }) }));
    expect(await openTab("Kiểm chứng")).toHaveTextContent("chưa có kiểm chứng");
  });
});

/** What the column says on each of its five tabs, one text each: the page as a whole, for comparing two pages. */
async function everyTab(): Promise<string[]> {
  const pages: string[] = [];
  for (const tab of ["Tổng quan", "Bằng chứng", "Tri thức", "Kiểm chứng", "Kỹ thuật"]) {
    await openTab(tab);
    pages.push(textOf(column()));
  }
  return pages;
}

/** The gate of a view, with what is said of it (`held_by`, the gate's own keys) changed. */
const withGate = (
  gate: Record<string, unknown>,
  held: string[] = [],
  over: Partial<AlertView> = {},
) =>
  view({
    held_by: held,
    suggestion: suggestion({
      gate: {
        forced: false,
        forced_by: [],
        proposed_verdict: "true_positive",
        final_verdict: "true_positive",
        verifier_verdict: null,
        warnings: [],
        ...gate,
      },
    }),
    ...over,
  });

describe("the gate's own account of the run, on the page (spec G2)", () => {
  // step 4 saw a fact and the playbook fail; the model cited no rule; the verifier answered needs_review
  const HELD = [
    "fp_policy:ioc_reputation",
    "fp_policy:playbook_rule",
    "facts_mismatch",
    "verifier_disagrees",
  ];
  const fpFacts = analysis({
    checks: [
      { id: "2", outcome: "warn", detail: "facts_mismatch" },
      { id: "4", outcome: "warn", detail: "fp_policy_facts" },
      { id: "6", outcome: "warn", detail: "verifier_disagrees" },
    ],
    check_totals: { passed: 0, applicable: 3, warnings: 3 },
  });
  const both = () =>
    withGate({ warnings: ["no_rule_cited"], verifier_verdict: "needs_review" }, HELD, {
      analysis: fpFacts,
    });

  it("names, under step 4, the fact that failed and the playbook that failed with it, and what the rule check wrote", async () => {
    renderColumn(both());
    const panel = await openTab("Kiểm chứng");
    const card = within(panel).getByRole("list", { name: "Các bước kiểm chứng" });
    // steps 2 and 6 say their own held reasons (the facts differ, the verifier disagreed): no note; step 4 adds what its
    // line cannot, the fact and the playbook that failed with it, and what the rule check wrote
    expect(said(card)).toEqual([
      "Dữ kiện",
      "— AI khai mức nghiêm trọng high, hệ thống ghi medium",
      "Chính sách FP",
      "— một dữ kiện của alert không cho phép kết luận FP",
      "IOC độc hại hoặc đáng ngờ",
      "không khớp bảng quyết định đã duyệt",
      "AI không dẫn rule nào của bảng quyết định",
      "Bộ kiểm chứng độc lập",
      "— không đồng ý (trả lời: Cần xem xét)",
    ]);
  });

  it("puts the held reasons on the default tab too: the IOC reputation has no highlight, and is said there", () => {
    renderColumn(both());
    const panel = within(column()).getByRole("tabpanel");
    const highlights = within(panel).getByRole("region", { name: "Điều nổi bật" });
    // the verifier's disagreement is a highlight already ("Bộ kiểm chứng độc lập không đồng ý."): not said twice
    expect(said(highlights).at(-1)).toBe(
      "Cảnh báo kiểm chứng: IOC độc hại hoặc đáng ngờ, không khớp bảng quyết định đã duyệt, AI khai dữ kiện lệch với hệ thống",
    );
    expect(said(highlights)).toContain("Bộ kiểm chứng độc lập không đồng ý.");
    expect(
      said(highlights)
        .join(" ")
        .match(/không đồng ý/g),
    ).toHaveLength(1);
    expect(within(highlights).getAllByRole("img").at(-1)).toHaveAccessibleName("Cảnh báo");
  });

  it("says no warning line on the default tab for a run no check warned about", () => {
    renderColumn(withGate({}, [], { analysis: analysis({ highlights: [] }) }));
    const panel = within(column()).getByRole("tabpanel");
    expect(within(panel).queryByText(/^Cảnh báo kiểm chứng:/)).not.toBeInTheDocument();
  });

  it("draws the highlights card for a run whose only highlight is the held line", () => {
    renderColumn(
      withGate({}, ["fp_policy:severity"], {
        analysis: olderAnalysis({ highlights: [] }),
      }),
    );
    const panel = within(column()).getByRole("tabpanel");
    expect(said(within(panel).getByRole("region", { name: "Điều nổi bật" }))).toEqual([
      "Điều nổi bật",
      "Cảnh báo kiểm chứng: alert mức critical",
    ]);
    expect(within(panel).queryByText(P.overview.none)).not.toBeInTheDocument();
  });

  // The page used to read none of these keys: a change to any of them left it as it was.
  it.each([
    [
      "held_by",
      () => withGate({}, [], { analysis: fpFacts }),
      () => withGate({}, ["fp_policy:severity"], { analysis: fpFacts }),
    ],
    [
      "the gate's warnings",
      () => withGate({}, HELD, { analysis: fpFacts }),
      () => withGate({ warnings: ["unknown_rule"] }, HELD, { analysis: fpFacts }),
    ],
    [
      "the verifier's verdict",
      () => withGate({ verifier_verdict: "needs_review" }, HELD, { analysis: fpFacts }),
      () => withGate({ verifier_verdict: "true_positive" }, HELD, { analysis: fpFacts }),
    ],
  ])("is a different page when %s change", async (_name, before, after) => {
    const first = renderColumn(before());
    const pagesBefore = await everyTab();
    first.unmount();
    renderColumn(after());
    const pagesAfter = await everyTab();
    expect(pagesAfter).not.toEqual(pagesBefore);
  });

  it("says the verdict before and after the gate beside the gate line of a run the gate forced (a version 1 row)", async () => {
    renderColumn(
      withGate({
        forced: true,
        forced_by: ["step4"],
        proposed_verdict: "true_positive",
        final_verdict: "needs_review",
      }),
    );
    const panel = await openTab("Kiểm chứng");
    const gate = within(panel).getByRole("group", { name: S.ai1.gate });
    expect(said(gate)).toEqual([
      S.ai1.gate,
      S.ai1.gateForced,
      S.ai1.gateForcedBy,
      "step4",
      S.ai1.gateProposed,
      "TP",
      S.ai1.gateFinal,
      "Cần xem xét",
    ]);
  });

  it("lists a held reason that names no step under the tab, as the code, in a card of its own", async () => {
    renderColumn(withGate({}, ["brand_new_reason", "fp_policy:severity"]));
    const panel = await openTab("Kiểm chứng");
    const card = within(panel).getByRole("region", {
      name: "Cảnh báo khác, không có dòng kiểm chứng riêng",
    });
    expect(said(card)).toEqual([
      "Cảnh báo khác, không có dòng kiểm chứng riêng",
      "brand_new_reason",
    ]);
  });

  it("has no card of loose reasons when every reason stands under its step", async () => {
    renderColumn(both());
    const panel = await openTab("Kiểm chứng");
    expect(
      within(panel).queryByRole("region", {
        name: "Cảnh báo khác, không có dòng kiểm chứng riêng",
      }),
    ).not.toBeInTheDocument();
  });

  // No reason vanishes and none is said twice: the line of its step says it, or a note under the line does (step 4's facts,
  // a line that says something else). `once` is what the page must say exactly once for the code.
  const RULE_FACTS = { "4": "fp_policy_facts" };
  it.each([
    ["facts_mismatch", { "2": "facts_mismatch" }, "AI khai dữ kiện lệch với hệ thống"],
    ["no_verified_quote", { "3": "no_verified_quote" }, "không có dẫn chứng nào khớp nguyên văn"],
    ["fp_policy:severity", RULE_FACTS, "alert mức critical"],
    ["fp_policy:ioc_reputation", RULE_FACTS, "IOC độc hại hoặc đáng ngờ"],
    ["fp_policy:asset_criticality", RULE_FACTS, "tài sản quan trọng hoặc chưa rõ"],
    ["fp_policy:identity_privileged", RULE_FACTS, "tài khoản đặc quyền"],
    [
      "fp_policy:playbook_rule",
      { "4": "fp_policy_playbook" },
      "không khớp bảng quyết định đã duyệt",
    ],
    ["verifier_disagrees", { "6": "verifier_disagrees" }, "không đồng ý"],
    ["verifier_invalid", { "6": "verifier_invalid" }, "không trả lời hợp lệ"],
  ])("says the held reason %s once on the Kiểm chứng tab", async (code, details, once) => {
    expect(Object.keys(S.ai1.heldReason)).toContain(code);
    const rows = ["1", "2", "3", "4", "5", "6"].map((id) => ({
      id,
      outcome: id in details ? "warn" : "na",
      detail: (details as Record<string, string>)[id] ?? "not_run",
    }));
    renderColumn(
      withGate({}, [code], {
        analysis: analysis({
          facts: analysis().facts.map((fact) => ({ ...fact, model: fact.system, match: true })),
          checks: rows as never,
          check_totals: { passed: 0, applicable: 1, warnings: 1 },
        }),
      }),
    );
    const panel = await openTab("Kiểm chứng");
    const text = textOf(panel);
    expect(text.split(once).length - 1, `"${once}" on the tab`).toBe(1);
    expect(
      within(panel).queryByRole("region", {
        name: "Cảnh báo khác, không có dòng kiểm chứng riêng",
      }),
    ).not.toBeInTheDocument();
  });

  it("names a held reason in a note when the line of its step says something else (a reason must not vanish)", async () => {
    renderColumn(
      withGate({}, ["verifier_disagrees"], {
        analysis: analysis({ checks: [{ id: "6", outcome: "warn", detail: "verifier_invalid" }] }),
      }),
    );
    const panel = await openTab("Kiểm chứng");
    expect(said(within(panel).getByRole("list", { name: "Các bước kiểm chứng" }))).toEqual([
      "Bộ kiểm chứng độc lập",
      "— không trả lời hợp lệ",
      "bộ kiểm chứng không đồng ý",
    ]);
  });

  it("leaves the overview's warning line out when every held reason is a highlight already", () => {
    renderColumn(withGate({}, ["verifier_disagrees"]));
    const panel = within(column()).getByRole("tabpanel");
    const highlights = within(panel).getByRole("region", { name: "Điều nổi bật" });
    expect(said(highlights)).toContain("Bộ kiểm chứng độc lập không đồng ý.");
    expect(within(highlights).queryByText(/^Cảnh báo kiểm chứng:/)).not.toBeInTheDocument();
  });

  it("still names a reason on the overview when the cap of four highlights cut the one that would say it", () => {
    renderColumn(
      withGate({}, ["verifier_disagrees"], {
        analysis: analysis({ highlights: analysis().highlights.slice(0, 3) }),
      }),
    );
    const panel = within(column()).getByRole("tabpanel");
    expect(panel).toHaveTextContent("Cảnh báo kiểm chứng: bộ kiểm chứng không đồng ý");
  });

  describe("for a run the RAG rule decided (DEC-225)", () => {
    /**
     * What the server serves for such a run, whatever the model answered (`served_held_reasons`, `served_warnings`,
     * `served_verifier_verdict`, `served_action` of llm/verdicts.py): the verdict ① ended with, no verifier verdict, no
     * warning, no disagreement of the verifier and no playbook rule. Identical served JSON for two runs that differ in
     * the model's answer is the server's job (backend tests): the page does not know that a rule decided the run, so it
     * cannot filter anything itself, and draws what it is sent.
     */
    const servedRun = (over: Partial<AlertView> = {}) =>
      ruleDecided({
        held_by: ["fp_policy:asset_criticality"],
        // step 4 warned about the asset, as the server then builds it (from the system facts only); no row 6
        analysis: ruleDecidedAnalysis({
          checks: ruleDecidedAnalysis().checks.map((row) =>
            row.id === "4" ? { ...row, outcome: "warn", detail: "fp_policy_facts" } : row,
          ) as never,
          check_totals: { passed: 4, applicable: 5, warnings: 1 },
        }),
        ...over,
      });

    it("counts the verifier's unusable answer on the tile and names it in a card of its own: no row 6 is drawn for such a run", async () => {
      renderColumn(servedRun({ held_by: ["fp_policy:asset_criticality", "verifier_invalid"] }));
      // the figure is the server's (4 of 5 passed); the note counts the warning step 4 raised and the reason no row has
      expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "4/5", "2 cảnh báo"]);
      expect(tile("Kiểm chứng").querySelector("[data-tone='warn']")).not.toBeNull();
      // the default tab lists both reasons (no highlight says either)
      expect(within(column()).getByRole("tabpanel")).toHaveTextContent(
        "Cảnh báo kiểm chứng: tài sản quan trọng hoặc chưa rõ, bộ kiểm chứng không trả lời hợp lệ",
      );
      const panel = await openTab("Kiểm chứng");
      const card = within(panel).getByRole("region", {
        name: "Cảnh báo khác, không có dòng kiểm chứng riêng",
      });
      expect(said(card)).toEqual([
        "Cảnh báo khác, không có dòng kiểm chứng riêng",
        "bộ kiểm chứng không trả lời hợp lệ",
      ]);
    });

    it("says there is no warning only when the page lists none", () => {
      renderColumn(servedRun({ held_by: [] }));
      expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "4/5", "1 cảnh báo"]);
      document.body.replaceChildren();
      renderColumn(ruleDecided());
      expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "5/5", "không có cảnh báo"]);
      expect(within(column()).getByRole("tabpanel")).not.toHaveTextContent("Cảnh báo kiểm chứng:");
    });

    it("says only what the system itself checked: a fact that failed, and none of the rule the model cited", async () => {
      renderColumn(servedRun());
      const overview = textOf(within(column()).getByRole("tabpanel"));
      expect(overview).not.toContain("không đồng ý");
      await openTab("Kiểm chứng");
      const text = textOf(column());
      for (const word of [
        "không khớp bảng quyết định đã duyệt",
        "rule AI dẫn",
        "bộ kiểm chứng không đồng ý",
        "trả lời:",
        S.ai1.gateProposed,
        S.ai1.gateFinal,
      ]) {
        expect(text, word).not.toContain(word);
      }
      expect(text).toContain("tài sản quan trọng hoặc chưa rõ");
    });
  });
});

// A name or an id the server sends has no spaces to break at: it must wrap inside the column, in a code span and in the
// cells of an auto-layout table (which `break-words` does not reach). jsdom has no layout, so the classes are pinned; the
// built CSS is checked by `make ui-build` carrying the utility.
describe("a long unbroken token stays inside the column", () => {
  const ANYWHERE = "[overflow-wrap:anywhere]";

  it("wraps a playbook name and a rule id", async () => {
    const long = "ransomware_v1_with_a_very_long_name_that_has_no_spaces_at_all_1234567890";
    renderColumn(
      view({
        analysis: analysis({
          playbook: {
            name: long,
            rule_id: `${long}-rule`,
            rule_action: "needs_review",
            rule_table_reviewed: true,
          },
        }),
      }),
    );
    const panel = await openTab("Tri thức");
    const codes = within(panel).getAllByText(/^ransomware_v1_with/, { selector: "code" });
    expect(codes).toHaveLength(2);
    for (const code of codes) expect(code).toHaveClass(ANYWHERE);
  });

  it("wraps the cells of the facts table, whichever value arrives", async () => {
    const long = "x".repeat(90);
    renderColumn(
      view({
        analysis: analysis({
          facts: [{ field: "severity", system: long, model: long, match: true }],
        }),
      }),
    );
    const panel = await openTab("Kiểm chứng");
    const table = within(panel).getByRole("table", { name: "Dữ kiện đã dùng" });
    const cells = [...table.querySelectorAll("tbody th, tbody td")];
    expect(cells).toHaveLength(4);
    for (const cell of cells) expect(cell, cell.textContent ?? "").toHaveClass(ANYWHERE);
  });
});

describe("a new run starts on the first tab again", () => {
  it("resets the open tab when the run changes, and keeps it while the same run is shown", async () => {
    const first = suggestion({ run_id: "run-1" });
    const view1 = view({ suggestion: first });
    const { rerender } = render(
      <main>
        <AiColumn view={view1} />
      </main>,
    );
    await openTab("Kỹ thuật");
    expect(within(column()).getByRole("tab", { name: "Kỹ thuật" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // the same run, drawn again (a poll that found nothing new): the open tab is kept
    rerender(
      <main>
        <AiColumn view={view({ suggestion: suggestion({ run_id: "run-1" }) })} />
      </main>,
    );
    expect(within(column()).getByRole("tab", { name: "Kỹ thuật" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // a new run: back to the first
    rerender(
      <main>
        <AiColumn view={view({ suggestion: suggestion({ run_id: "run-2" }) })} />
      </main>,
    );
    expect(within(column()).getByRole("tab", { name: "Tổng quan" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});

describe("Kỹ thuật", () => {
  it("has the six rows the Owner approved, and no model, no verifier row, no answer format", async () => {
    renderColumn(view());
    const panel = await openTab("Kỹ thuật");
    const labels = [...panel.querySelectorAll("dt")].map((dt) => dt.textContent);
    expect(labels).toEqual([
      "Token vào → ra",
      "Thời gian",
      "Chi phí",
      "Phân tích lúc",
      "Nhãn MITRE của alert",
      "Cụm tương quan lúc phân tích",
    ]);
    expect([...panel.querySelectorAll("dd")].map((dd) => dd.textContent)).toEqual([
      "13.637 → 981",
      "4,2 giây",
      "$0,0007",
      "15/11/2026 18:35:56",
      "T1490",
      "3",
    ]);
  });

  it("shows a dash for a figure the run does not carry", async () => {
    renderColumn(
      view({
        analysis: analysis({
          tech: {
            input_tokens: null,
            output_tokens: null,
            latency_ms: null,
            cost_usd: null,
            analysed_at: null,
            mitre_ids: [],
            correlated_at_analysis: null,
          },
        }),
      }),
    );
    const panel = await openTab("Kỹ thuật");
    expect([...panel.querySelectorAll("dd")].map((dd) => dd.textContent)).toEqual([
      "—",
      "—",
      "—",
      "—",
      "—",
      "—",
    ]);
  });
});

describe("a run the RAG rule decided (DEC-225)", () => {
  it("is an ordinary FP: the verdict and its words, no note of a rule, no confidence, no flag", () => {
    renderColumn(ruleDecided());
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "FP", "dương tính giả"]);
    expect(textOf(tile("Độ tin cậy"))).not.toContain("mặc định");
    expect(said(tile("Độ tin cậy"))).toEqual(["Độ tin cậy", "—"]);
    expect(within(tile("Kết luận")).queryByRole("img")).not.toBeInTheDocument();
    // the matched entry closed a false positive, and the line says so: not an old incident
    expect(said(tile("Tri thức (RAG)"))).toEqual(["Tri thức (RAG)", "62%", "trùng mục đã đóng FP"]);
    expect(tile("Tri thức (RAG)")).toHaveAttribute("data-tone", "neutral");
    expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "5/5", "không có cảnh báo"]);
  });

  it("is an ordinary TP when the verdict is the other one: the same tiles, the same words of a TP", () => {
    const keys = ruleDecidedKeys(85);
    renderColumn(
      ruleDecided({
        ...keys,
        suggestion: {
          ...keys.suggestion!,
          suggested_action: "true_positive",
          gate: {
            ...keys.suggestion!.gate!,
            proposed_verdict: "true_positive",
            final_verdict: "true_positive",
          },
        },
        proposed_action: "true_positive",
      }),
    );
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "TP", "tấn công thật"]);
    expect(said(tile("Độ tin cậy"))).toEqual(["Độ tin cậy", "—"]);
  });

  it("has no reading and no 'what would change it' in the overview, and no heading for them", () => {
    renderColumn(ruleDecided());
    const panel = within(column()).getByRole("tabpanel");
    expect(within(panel).getByText(/^amsi\.dll bị nạp/)).toBeInTheDocument();
    expect(within(panel).getByRole("region", { name: "Nên kiểm tra tiếp" })).toBeInTheDocument();
    for (const absent of ["Nếu là tấn công", "Nếu lành tính"]) {
      expect(within(panel).queryByRole("region", { name: absent })).not.toBeInTheDocument();
    }
    expect(within(panel).queryByText(/Điều sẽ làm đổi kết luận/)).not.toBeInTheDocument();
  });

  it("shows the facts table with the system column only, and no verifier line and no row for a rule", async () => {
    renderColumn(ruleDecided());
    const panel = await openTab("Kiểm chứng");
    const table = within(panel).getByRole("table", { name: "Dữ kiện đã dùng" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Dữ kiện", "Hệ thống"]);
    expect(
      within(table)
        .getAllByRole("row")
        .slice(1)
        .map((row) => [...row.children].map((cell) => cell.textContent)),
    ).toEqual([
      ["Mức nghiêm trọng", "medium"],
      ["Danh tiếng IOC", "chưa tra"],
      ["Độ quan trọng tài sản", "medium"],
      ["Tài khoản đặc quyền", "không"],
      ["Số lần xuất hiện", "2"],
    ]);
    expect(within(panel).queryByText("Bộ kiểm chứng độc lập")).not.toBeInTheDocument();
    expect(within(panel).queryByText("Quy tắc RAG")).not.toBeInTheDocument();
  });

  it("has no word of a rule in the lookup card: the state sentence and nothing after it", async () => {
    renderColumn(ruleDecided());
    const panel = await openTab("Tri thức");
    const lookup = within(panel).getByRole("region", { name: "Tri thức đã duyệt" });
    expect(said(lookup).at(-1)).toBe(
      "Mục trùng cao nhất đạt 62%, qua mức tối thiểu 50%, nên AI được cung cấp tri thức tham khảo.",
    );
  });

  it("has no word of a rule on any tab, and never names the model's own answer (no TP, no true_positive, no confidence)", async () => {
    renderColumn(ruleDecided());
    for (const tab of ["Tổng quan", "Bằng chứng", "Tri thức", "Kiểm chứng", "Kỹ thuật"]) {
      await openTab(tab);
      const text = textOf(column());
      expect(wordsFound(text, ["TP"]), tab).toEqual([]);
      expect(phrasesFound(text, ["true_positive", "độ tin cậy", "AI kết luận"]), tab).toEqual([]);
      expect(
        phrasesFound(text, ["mặc định", "Quy tắc", "quy tắc", "ngưỡng", "rag_rule"]),
        tab,
      ).toEqual([]);
    }
  });

  it("is the same page whether the model had answered FP itself or TP: the view the server sends is the same", () => {
    const first = renderColumn(ruleDecided());
    const once = textOf(column());
    first.unmount();
    renderColumn(ruleDecided({ proposed_action: "false_positive" }));
    expect(textOf(column())).toBe(once);
  });
});

describe("the states the column kept", () => {
  it("says the blind arm's notice and nothing of ① for a blind, undecided head", () => {
    renderColumn(blindView());
    expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(within(column()).getByText(S.ai1.hiddenBody)).toBeInTheDocument();
    expect(leaksIn(column())).toEqual([]);
    expect(within(column()).queryByRole("group")).not.toBeInTheDocument();
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
    expect(within(column()).queryByRole("tab")).not.toBeInTheDocument();
    // the WHOLE text of the column is the heading, the advisory line and the notice, and nothing else: a leak of a
    // number alone ("3/5", "47%") that no marker lists goes red here (review of AP-T4)
    expect(said(column())).toEqual(BLIND_TEXT);
  });

  it("draws nothing of the panel for a blind head even if an analysis reached the page: the state is the suggestion's", () => {
    renderColumn(blindView({ analysis: analysis() }));
    expect(within(column()).getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(leaksIn(column())).toEqual([]);
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
    expect(said(column())).toEqual(BLIND_TEXT);
  });

  it("says exactly the same whole text for a blind head whatever else the view carries", () => {
    const stray = blindView({
      analysis: analysis(),
      rag: { best_pct: 62, not_applied: "timeout" },
      held_by: ["facts_mismatch"],
      proposed_action: "true_positive",
    });
    renderColumn(stray);
    expect(said(column())).toEqual(BLIND_TEXT);
  });

  it("finds the new panel's words as leaks (so the blind tests catch a leak of the scorecard)", () => {
    renderColumn(view());
    const found = leaksIn(column());
    expect(found).toEqual(
      expect.arrayContaining([
        "TP",
        "Kết luận",
        "Độ tin cậy",
        "Tri thức (RAG)",
        "Kiểm chứng",
        "Tổng quan",
        "Điều nổi bật",
        "tấn công thật",
      ]),
    );
  });

  it("says pending, and draws no panel, for a visible head with no result yet", () => {
    renderColumn(view({ suggestion: null, triage_status: "pending", analysis: null }));
    expect(within(column()).getByText(S.ai1.pending)).toBeInTheDocument();
    expect(within(column()).getByText(S.ai1.pendingBody)).toBeInTheDocument();
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("says none for an archived alert whose ① never answered", () => {
    renderColumn(
      view({ status: "archived", suggestion: null, triage_status: "pending", analysis: null }),
    );
    expect(within(column()).getByText(S.ai1.none)).toBeInTheDocument();
    expect(within(column()).getByText(S.ai1.noneBody)).toBeInTheDocument();
    expect(within(column()).queryByText(S.ai1.pending)).not.toBeInTheDocument();
  });

  it("says unavailable with the stop reason when ① gave up", () => {
    renderColumn(
      view({
        suggestion: null,
        triage_status: "unavailable",
        llm_stopped_by: "unavailable",
        analysis: null,
      }),
    );
    expect(within(column()).getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(within(column()).getByText(S.ai1.unavailableBody)).toBeInTheDocument();
    expect(within(column()).getByText(S.ai1.stoppedBy.unavailable)).toBeInTheDocument();
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("does not draw the panel for a state that has no conclusion, whatever analysis is there", () => {
    renderColumn(view({ suggestion: null, triage_status: "pending" }));
    expect(within(column()).getByText(S.ai1.pending)).toBeInTheDocument();
    expect(within(column()).queryByRole("group")).not.toBeInTheDocument();
  });

  it("says the clusters have changed since the analysis, in the words it always used", () => {
    renderColumn(view({ correlated_now: 5 }));
    expect(within(column()).getByText(S.ai1.correlatedChanged(3, 5))).toBeInTheDocument();
  });

  it("does not say the clusters changed when they have not, or when the view does not say how many there are now", () => {
    const same = renderColumn(view({ correlated_now: 3 }));
    expect(within(column()).queryByText(/hiện có/)).not.toBeInTheDocument();
    same.unmount();
    renderColumn(view({ correlated_now: undefined }));
    expect(within(column()).queryByText(/hiện có/)).not.toBeInTheDocument();
  });

  it("says that the RAG was not applied, in the words of the alert, beside the tiles", () => {
    renderColumn(view({ rag: { best_pct: null, not_applied: "timeout" } }));
    expect(
      within(column()).getByText(S.rag.notApplied("alert", S.rag.failureKind.timeout)),
    ).toBeInTheDocument();
  });

  it("says nothing of an unknown failure kind of the RAG notice, and never its code", () => {
    renderColumn(view({ rag: { best_pct: null, not_applied: "cosmic_ray" } }));
    expect(within(column()).queryByText(/cosmic_ray/)).not.toBeInTheDocument();
    expect(within(column()).queryByRole("note")).not.toBeInTheDocument();
  });

  it("keeps the flag of a version 1 row the gate forced, beside the conclusion and in the gate line of the checks", async () => {
    renderColumn(
      view({
        suggestion: suggestion({
          gate: {
            forced: true,
            forced_by: ["step4"],
            proposed_verdict: "true_positive",
            final_verdict: "needs_review",
          },
        }),
      }),
    );
    expect(
      within(tile("Kết luận")).getByRole("img", { name: S.ai1.forcedLabel }),
    ).toHaveTextContent(S.ai1.forced);
    const panel = await openTab("Kiểm chứng");
    expect(within(panel).getByText(S.ai1.gate)).toBeInTheDocument();
    expect(within(panel).getByText(S.ai1.gateForced)).toBeInTheDocument();
    expect(within(panel).getByText("step4")).toBeInTheDocument();
  });

  it("has no flag and no gate line for a new run, which is never forced", async () => {
    renderColumn(view());
    expect(within(tile("Kết luận")).queryByRole("img")).not.toBeInTheDocument();
    const panel = await openTab("Kiểm chứng");
    expect(within(panel).queryByText(S.ai1.gate)).not.toBeInTheDocument();
  });
});

describe("a decided alert", () => {
  const decided = (over: Partial<AlertView> = {}): AlertView =>
    view({ status: "closed_fp", acknowledged_by_name: "An", ...over });

  it("says 'Đã quyết — so sánh', the person's decision, and the AI's line, with the scorecard under them", () => {
    renderColumn(decided());
    expect(
      within(column()).getByRole("heading", { name: S.ai1.decidedHeading }),
    ).toBeInTheDocument();
    expect(within(column()).getByText(S.status.closed_fp)).toBeInTheDocument();
    expect(within(column()).getByText(/· An/)).toBeInTheDocument();
    // the line is the flat column's own, whole: the view's RAG pair (a best candidate at 47%, under the floor) is in it
    expect(within(column()).getByText(/AI kết luận/)).toHaveTextContent(
      `AI kết luận: TP (độ tin cậy trung bình) — trùng cao nhất 47% với tri thức đã duyệt (dưới mức tối thiểu 50%) — có cảnh báo kiểm chứng: ${S.ai1.heldReason.facts_mismatch}, ${S.ai1.heldReason.verifier_disagrees}`,
    );
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "TP", "tấn công thật"]);
    expect(within(column()).getByRole("tablist")).toBeInTheDocument();
  });

  it.each([
    ["closed_fp", "true_positive", "không"],
    ["closed_fp", "false_positive", "có"],
    ["escalated_tier2", "true_positive", "có"],
    ["closed_benign", "false_positive", "không"],
  ])("compares the decision %s with the verdict %s: Khớp %s", (status, action, word) => {
    renderColumn(
      decided({
        status,
        suggestion: suggestion({ suggested_action: action }),
        proposed_action: action,
      }),
    );
    expect(
      within(column()).getByText(S.ai1.match, { exact: true }).parentElement,
    ).toHaveTextContent(`${S.ai1.match} ${word}`);
  });

  it("compares with the verdict ① ended with, not the model's own answer, for a run the RAG rule decided", () => {
    renderColumn(ruleDecided({ status: "closed_fp", acknowledged_by_name: "An" }));
    expect(
      within(column()).getByText(S.ai1.match, { exact: true }).parentElement,
    ).toHaveTextContent(`${S.ai1.match} ${S.ai1.matchAgree}`);
    expect(within(column()).getByText(/AI kết luận/)).toHaveTextContent(
      "AI kết luận: FP — trùng 62% với tri thức đã duyệt",
    );
    expect(within(column()).getByText(/AI kết luận/)).not.toHaveTextContent("độ tin cậy");
  });

  it("says that the RAG was not applied once, in the comparison's line: the scorecard under it does not say it again", () => {
    renderColumn(decided({ rag: { best_pct: null, not_applied: "auth" } }));
    const notes = within(column()).getAllByRole("note");
    expect(notes).toHaveLength(1);
    expect(notes[0]).toHaveTextContent(S.rag.notApplied("alert", S.rag.failureKind.auth));
  });

  it("says a decision that is not a Tier 1 person's is not compared", () => {
    renderColumn(decided({ status: "auto_closed" }));
    expect(within(column()).getByText(S.ai1.notTier1Decision)).toBeInTheDocument();
    expect(within(column()).queryByText(S.ai1.match, { exact: true })).not.toBeInTheDocument();
  });

  it("has the comparison alone, with no panel, for a decided alert that has no analysis", () => {
    renderColumn(decided({ analysis: null }));
    expect(
      within(column()).getByRole("heading", { name: S.ai1.decidedHeading }),
    ).toBeInTheDocument();
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
  });
});

describe("a view that has no analysis, or one that cannot be read", () => {
  it.each([
    ["absent", undefined],
    ["null", null],
    ["a string", "garbled"],
    ["a list", []],
  ])("falls back on today's flat rendering when analysis is %s", (_name, value) => {
    const v = view({ analysis: value as never });
    if (value === undefined) delete v.analysis;
    renderColumn(v);
    // the conclusion line of the flat column, not an empty panel
    expect(within(column()).getByText(/AI kết luận/)).toHaveTextContent(
      `AI kết luận: TP (độ tin cậy trung bình) — trùng cao nhất 47% với tri thức đã duyệt (dưới mức tối thiểu 50%) — có cảnh báo kiểm chứng: ${S.ai1.heldReason.facts_mismatch}, ${S.ai1.heldReason.verifier_disagrees}`,
    );
    expect(within(column()).queryByRole("tablist")).not.toBeInTheDocument();
    expect(within(column()).queryByRole("group")).not.toBeInTheDocument();
  });

  it("draws the scorecard with what it can read for an object whose keys are all of the wrong kind", () => {
    renderColumn(view({ analysis: { summary: 5, checks: "x", rag: [] } as never }));
    expect(said(tile("Kết luận"))).toEqual(["Kết luận", "TP", "tấn công thật"]);
    expect(said(tile("Tri thức (RAG)"))).toEqual(["Tri thức (RAG)", "—", "chưa có dữ liệu"]);
    // no row of the gate could be read, yet the view lists two held reasons: the tile counts what the page lists
    expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "—", "2 cảnh báo"]);
  });

  it("says no check was made when the view lists no warning either", () => {
    renderColumn(view({ held_by: [], analysis: { summary: 5, checks: "x", rag: [] } as never }));
    expect(said(tile("Kiểm chứng"))).toEqual(["Kiểm chứng", "—", "chưa có kiểm chứng"]);
  });
});

describe("text only", () => {
  it("renders everything the model and the alert wrote as text, never as markup", async () => {
    const hostile = "<img src=x onerror=alert(1)><b>đậm</b>";
    renderColumn(
      view({
        analysis: analysis({
          summary: hostile,
          reading_attack: hostile,
          reading_benign: hostile,
          would_change: hostile,
          next_checks: [hostile],
          reasons: [
            { claim: hostile, quote: hostile, source: hostile, verified: false, why: null },
          ],
          rag: {
            ...analysis().rag,
            candidates: [{ pct: 47, title: hostile, conclusion: hostile as never }],
          },
          playbook: {
            name: hostile,
            rule_id: hostile,
            rule_action: null,
            rule_table_reviewed: true,
          },
        }),
      }),
    );
    for (const tab of ["Tổng quan", "Bằng chứng", "Tri thức"]) {
      await openTab(tab);
      expect(column().querySelector("img[src='x']"), tab).toBeNull();
      expect(column().querySelector("b"), tab).toBeNull();
      expect(column()).toHaveTextContent(hostile);
    }
  });
});

describe("the model's name appears nowhere (G5)", () => {
  const TABS = ["Tổng quan", "Bằng chứng", "Tri thức", "Kiểm chứng", "Kỹ thuật"];
  const states: [string, AlertView][] = [
    ["a version 4 run", view()],
    ["an older run", view({ analysis: olderAnalysis() })],
    ["a run the RAG rule decided", ruleDecided()],
    [
      "a run with a lookup that failed",
      view({
        analysis: analysis({
          rag: { ...analysis().rag, state: "failed", failure: "auth" } as never,
        }),
        rag: { best_pct: null, not_applied: "auth" },
      }),
    ],
    ["a decided alert", view({ status: "closed_fp", acknowledged_by_name: "An" })],
    [
      "a version 1 row the gate forced",
      view({ suggestion: suggestion({ gate: { forced: true, forced_by: ["step4"] } }) }),
    ],
    ["no analysis (the flat column)", view({ analysis: null })],
    ["the blind arm", blindView()],
    ["pending", view({ suggestion: null, triage_status: "pending" })],
    [
      "unavailable",
      view({ suggestion: null, triage_status: "unavailable", llm_stopped_by: "schema" }),
    ],
  ];

  it.each(states)("names no model in %s, on any tab", async (_name, v) => {
    renderColumn(v);
    expect(modelNamesIn(column())).toEqual([]);
    if (within(column()).queryByRole("tablist") === null) return;
    for (const tab of TABS) {
      await openTab(tab);
      expect(modelNamesIn(column()), tab).toEqual([]);
    }
  });

  it("holds the guard against a model name in the data: the pattern catches it where it would show", () => {
    renderColumn(view({ analysis: analysis({ summary: "Trả lời của GLM 5.3" }) }));
    expect(modelNamesIn(column())).not.toEqual([]);
  });

  it("has exactly the technical tab's expected labels, and the facts table's declared column is a key name, not a model", async () => {
    renderColumn(view());
    const tech = await openTab("Kỹ thuật");
    expect([...tech.querySelectorAll("dt")].map((dt) => dt.textContent)).toEqual([
      S.analysis.tech.tokens,
      S.analysis.tech.time,
      S.analysis.tech.cost,
      S.analysis.tech.analysedAt,
      P.tech.mitre,
      P.tech.correlated,
    ]);
    const checks = await openTab("Kiểm chứng");
    expect(
      within(checks)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toContain("AI khai");
  });
});

describe("accessibility", () => {
  const TABS = ["Tổng quan", "Bằng chứng", "Tri thức", "Kiểm chứng", "Kỹ thuật"];
  const states: [string, AlertView][] = [
    ["a version 4 run", view()],
    ["an older run", view({ analysis: olderAnalysis() })],
    ["a run the RAG rule decided", ruleDecided()],
    ["a decided alert", view({ status: "closed_benign", acknowledged_by_name: "An" })],
    [
      "a version 1 row the gate forced, with the clusters changed",
      view({
        suggestion: suggestion({ gate: { forced: true, forced_by: ["step4"] } }),
        correlated_now: 8,
        rag: { best_pct: null, not_applied: "timeout" },
      }),
    ],
    ["the blind arm", blindView()],
    ["pending", view({ suggestion: null, triage_status: "pending" })],
    ["unavailable", view({ suggestion: null, triage_status: "unavailable" })],
  ];

  it.each(states)("has no axe violation in %s, on any tab", async (_name, v) => {
    const { container } = renderColumn(v);
    const run = async () =>
      // jsdom computes no colour, so the contrast rule cannot run here.
      (
        await axe.run(container, { rules: { "color-contrast": { enabled: false } } })
      ).violations.map((x) => `${x.id}: ${x.nodes.map((n) => n.html).join(" | ")}`);
    expect(await run()).toEqual([]);
    if (within(column()).queryByRole("tablist") === null) return;
    for (const tab of TABS) {
      await openTab(tab);
      expect(await run(), tab).toEqual([]);
    }
  });
});
