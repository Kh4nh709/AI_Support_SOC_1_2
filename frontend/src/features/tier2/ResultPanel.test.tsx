// src/features/tier2/ResultPanel.test.tsx — the Tier 2 panel of a run that has a result (DEC-221): four score tiles
// over five tabs. Each tile in each state, each tab's content for a version 4 run and for an older one, the keyboard
// on the tabs, the notices that stay above them, and G5: the model's name is on no tab.
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { modelNamesIn } from "../../testing/modelName";
import { ResultPanel } from "./ResultPanel";
import {
  asRun,
  evidenceRow,
  knowledgeOf,
  runOld,
  runV3,
  runV4,
  timelineRow,
  unverifiedRow,
} from "./runFixtures";

const CURRENT = { alert_count: 4, total_occurrences: 9, last_seen_at: "2026-11-15T11:52:00+00:00" };

function renderPanel(run: unknown, current: typeof CURRENT | null = CURRENT) {
  return render(
    <MemoryRouter>
      <ResultPanel run={asRun(run)} current={current} />
    </MemoryRouter>,
  );
}

const tile = (name: string) => screen.getByRole("group", { name });
const open = (name: string) => userEvent.setup().click(screen.getByRole("tab", { name }));
const panel = () => screen.getByRole("tabpanel");

// ── the four tiles ───────────────────────────────────────────────────────────────────────────────

// A: the tile shows one short word per conclusion, as the mock-up does ("Sự cố"). The server's whole label is read by a
// screen reader in its place (the short word is hidden from it) and is the first line of the overview.
describe("the Kết luận tile", () => {
  it.each([
    ["confirmed_incident", "Là sự cố thật", "Sự cố", "critical"],
    ["policy_violation", "Có vi phạm nội quy, không phải tấn công", "Vi phạm nội quy", "high"],
    ["false_positive", "Không phải sự cố", "Không phải sự cố", "low"],
    ["need_more_data", "Cần thêm dữ liệu", "Cần thêm dữ liệu", "medium"],
  ])(
    "shows %s as the short word %s in its colour, under the line that says it is a suggestion",
    (code, label, word, tone) => {
      renderPanel(runV4({ conclusion: code, conclusion_label: label, model_conclusion: null }));
      // the whole label is in the tile for a screen reader, unless the word already is the whole label
      const spoken = word === label ? "" : label;
      expect(tile("Kết luận").textContent).toBe(`Kết luận${word}${spoken}gợi ý của AI`);
      expect(tile("Kết luận")).toHaveAttribute("data-tone", tone);
      expect(within(tile("Kết luận")).getByText(word)).toBeInTheDocument();
    },
  );

  it.each([
    ["confirmed_incident", "Là sự cố thật", "Sự cố"],
    ["policy_violation", "Có vi phạm nội quy, không phải tấn công", "Vi phạm nội quy"],
  ])(
    "hides the short word %s from a screen reader and gives it the whole label %s instead",
    (code, label, word) => {
      renderPanel(runV4({ conclusion: code, conclusion_label: label, model_conclusion: null }));
      expect(within(tile("Kết luận")).getByText(word)).toHaveAttribute("aria-hidden", "true");
      expect(within(tile("Kết luận")).getByText(label)).toHaveClass("sr-only");
    },
  );

  it.each([
    ["false_positive", "Không phải sự cố"],
    ["need_more_data", "Cần thêm dữ liệu"],
  ])("does not hide a word that is the whole label (%s: %s), and says it once", (code, label) => {
    renderPanel(runV4({ conclusion: code, conclusion_label: label, model_conclusion: null }));
    expect(within(tile("Kết luận")).getByText(label)).not.toHaveAttribute("aria-hidden");
    expect(within(tile("Kết luận")).getAllByText(label)).toHaveLength(1);
  });

  it.each([
    ["confirmed_incident", "Là sự cố thật"],
    ["policy_violation", "Có vi phạm nội quy, không phải tấn công"],
    ["false_positive", "Không phải sự cố"],
    ["need_more_data", "Cần thêm dữ liệu"],
  ])("puts the whole label of %s as the first line of the overview: %s", (code, label) => {
    renderPanel(runV4({ conclusion: code, conclusion_label: label, model_conclusion: null }));
    const first = panel().querySelector("[data-part='verdict']");
    expect(first?.textContent).toBe(label);
    // it is the first thing in the overview, above the summary
    expect(panel().firstElementChild?.firstElementChild).toBe(first);
  });

  it("shows the server's label on the overview for a conclusion it has no words for", () => {
    renderPanel(
      runV4({ conclusion: "cosmic", conclusion_label: "Nhãn lạ", model_conclusion: null }),
    );
    expect(panel().querySelector("[data-part='verdict']")?.textContent).toBe("Nhãn lạ");
  });

  it("reads a conclusion the system held back as the system's own, and keeps the model's for the overview", () => {
    renderPanel(
      runV4({
        conclusion: "need_more_data",
        conclusion_label: "Cần thêm dữ liệu",
        model_conclusion: "confirmed_incident",
        held_by: ["no_verified_evidence"],
      }),
    );
    expect(tile("Kết luận").textContent).toBe("Kết luậnCần thêm dữ liệuhệ thống giữ lại");
    expect(tile("Kết luận")).toHaveAttribute("data-tone", "medium");
    expect(
      screen.getByText(
        "AI kết luận: Là sự cố thật — hệ thống giữ lại vì: không có bằng chứng kiểm chứng được",
      ),
    ).toBeInTheDocument();
  });

  it("reads a conclusion an older run had lowered as lowered, and keeps the server's sentence for the overview", () => {
    const sentence =
      "Mô hình đề xuất Là sự cố thật nhưng kết luận đã bị hạ xuống Cần thêm dữ liệu: không có bằng chứng nào kiểm chứng được với log của case.";
    renderPanel(
      runOld({
        conclusion: "need_more_data",
        conclusion_label: "Cần thêm dữ liệu",
        model_conclusion: null,
        held_by: [],
        overruled: sentence,
      }),
    );
    expect(tile("Kết luận").textContent).toBe("Kết luậnCần thêm dữ liệuđã bị hạ");
    expect(screen.getByText(sentence)).toBeInTheDocument();
  });

  it("shows a label it has no words for as the server sent it, in the neutral colour", () => {
    renderPanel(
      runV4({ conclusion: "cosmic", conclusion_label: "Nhãn lạ", model_conclusion: null }),
    );
    expect(tile("Kết luận").textContent).toBe("Kết luậnNhãn lạgợi ý của AI");
    expect(tile("Kết luận")).toHaveAttribute("data-tone", "neutral");
  });
});

describe("the Độ tin cậy tile", () => {
  it.each([
    ["low", "Thấp", "1 trên 3"],
    ["medium", "Trung bình", "2 trên 3"],
    ["high", "Cao", "3 trên 3"],
  ])("shows %s as %s over a meter of %s", (level, word, spoken) => {
    renderPanel(runV4({ confidence: level }));
    expect(tile("Độ tin cậy").textContent).toBe(`Độ tin cậy${word}`);
    expect(within(tile("Độ tin cậy")).getByRole("img", { name: spoken })).toBeInTheDocument();
  });

  it("shows a level it has no words for as it came, with no meter, and a missing one as a dash", () => {
    const { unmount } = renderPanel(runV4({ confidence: "rất cao" }));
    expect(tile("Độ tin cậy").textContent).toBe("Độ tin cậyrất cao");
    expect(within(tile("Độ tin cậy")).queryByRole("img")).not.toBeInTheDocument();
    unmount();
    renderPanel(runV4({ confidence: null }));
    expect(tile("Độ tin cậy").textContent).toBe("Độ tin cậy—");
  });
});

describe("the Tri thức (RAG) tile", () => {
  const rag = (k: unknown) => renderPanel(runV4({ knowledge: k }));

  it("is the best match for a lookup that kept one", () => {
    rag(knowledgeOf("matched", { best_pct: 84 }));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)84%trùng sự cố cũ");
  });

  it("is the best candidate and the floor it was under, for a lookup that kept none", () => {
    rag(knowledgeOf("below_floor", { best_pct: 47, floor_pct: 50 }));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)47%dưới mức 50%");
  });

  it("says no candidate was scored", () => {
    rag(knowledgeOf("no_candidate"));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)—không có mục nào trùng");
  });

  it("says no lookup was made", () => {
    rag(knowledgeOf("no_lookup"));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)—không có tra cứu");
  });

  it.each([
    ["rate_limit", "vượt giới hạn tốc độ"],
    ["timeout", "quá thời gian chờ"],
    ["auth", "thiếu hoặc sai API key"],
    ["quota", "hết hạn mức"],
    ["provider_error", "lỗi phía nhà cung cấp"],
    ["vectordb_unreachable", "không kết nối được vector DB"],
  ])("says a lookup that failed with %s", (kind, line) => {
    rag(knowledgeOf("failed", { failure: kind }));
    expect(tile("Tri thức (RAG)").textContent).toBe(`Tri thức (RAG)—${line}`);
  });

  it("says a lookup that failed in a way it has no words for, without the kind", () => {
    rag(knowledgeOf("failed", { failure: "cosmic_ray" }));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)—tra cứu bị lỗi");
  });

  it("falls back on the older rag pair when the server sends no knowledge", () => {
    renderPanel(runOld({ rag: { best_pct: 87, not_applied: null } }));
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)87%trùng sự cố cũ");
  });
});

describe("the Dẫn chứng tile", () => {
  it("is the quotes found over the quotes cited, and warns when one was not found", () => {
    renderPanel(runV4());
    expect(tile("Dẫn chứng").textContent).toBe("Dẫn chứng2/3khớp nguyên văn");
    expect(within(tile("Dẫn chứng")).getByText("khớp nguyên văn")).toHaveAttribute(
      "data-tone",
      "warn",
    );
  });

  it("is calm when every quote was found", () => {
    renderPanel(runV4({ evidence_summary: { cited: 5, verified: 5 } }));
    expect(tile("Dẫn chứng").textContent).toBe("Dẫn chứng5/5khớp nguyên văn");
    expect(within(tile("Dẫn chứng")).getByText("khớp nguyên văn")).toHaveAttribute(
      "data-tone",
      "muted",
    );
  });

  it("says there is none when the assistant cited nothing", () => {
    renderPanel(runV4({ evidence: [], evidence_summary: { cited: 0, verified: 0 } }));
    expect(tile("Dẫn chứng").textContent).toBe("Dẫn chứng—không có dẫn chứng");
  });
});

// ── the tabs ─────────────────────────────────────────────────────────────────────────────────────

describe("the tab strip", () => {
  it("has five tabs, in the order of the approved mock-up, and opens on Tổng quan", () => {
    renderPanel(runV4());
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([
      "Tổng quan",
      "Diễn biến",
      "Giả thuyết",
      "Bằng chứng",
      "Kỹ thuật",
    ]);
    expect(screen.getByRole("tab", { name: "Tổng quan" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tablist", { name: S.ai2.tabs.label })).toBeInTheDocument();
  });

  it("moves between the tabs with the arrow keys, Home and End", async () => {
    const user = userEvent.setup();
    renderPanel(runV4());
    screen.getByRole("tab", { name: "Tổng quan" }).focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Diễn biến" })).toHaveFocus();
    expect(screen.getByRole("list", { name: "Dòng thời gian" })).toBeInTheDocument();
    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Kỹ thuật" })).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Tổng quan" })).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Kỹ thuật" })).toHaveFocus();
    await user.keyboard("{Home}");
    expect(screen.getByRole("tab", { name: "Tổng quan" })).toHaveFocus();
  });

  it("has one tab stop", () => {
    renderPanel(runV4());
    expect(screen.getAllByRole("tab").filter((tab) => tab.tabIndex === 0)).toHaveLength(1);
  });

  it("keeps the tiles and the disclaimer on screen whichever tab is open", async () => {
    renderPanel(runV4());
    await open("Kỹ thuật");
    for (const name of ["Kết luận", "Độ tin cậy", "Tri thức (RAG)", "Dẫn chứng"]) {
      expect(tile(name)).toBeInTheDocument();
    }
    expect(screen.getByText(S.ai2.disclaimer)).toBeInTheDocument();
  });
});

describe("Tổng quan", () => {
  it("opens with the summary the model wrote", () => {
    renderPanel(runV4());
    expect(
      within(panel()).getByText(
        "Trong 24 phút, tài khoản Administrator trên một máy trạm đã nạp amsi.dll từ trình in, tạo job BITS, chạy PowerShell mã hoá và xoá shadow copy.",
      ),
    ).toBeInTheDocument();
  });

  it("sets the model's hosts and accounts beside what the system knows, and counts the MITRE steps", () => {
    renderPanel(runV4());
    expect(screen.getByRole("group", { name: "Phạm vi" }).textContent).toBe(
      "Máy" +
        "AI nêu: wazuh-win-01" +
        "Hệ thống ghi: Windows_Endpoint" +
        "Tài khoản" +
        "AI nêu: Administrator" +
        "Hệ thống ghi: Administrator" +
        "Chiến thuật" +
        "4 bước MITRE" +
        "kết thúc ở T1490",
    );
  });

  // D: the server can send a hundred hosts into a column a third of a panel wide: the first five, then what is left.
  describe("a scope with many hosts and accounts", () => {
    const names = (prefix: string, n: number) =>
      Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`);
    const scopeOf = (over: Record<string, unknown>) => {
      renderPanel(
        runV4({
          scope: {
            hosts: ["m1"],
            accounts: ["a1"],
            system: { hosts: ["s1"], accounts: ["u1"], alert_count: 4 },
            ...over,
          },
        }),
      );
      return [...screen.getByRole("group", { name: "Phạm vi" }).querySelectorAll("dd")].map(
        (dd) => dd.textContent,
      );
    };

    it("shows the first five hosts the system knows and counts the other ninety-five", () => {
      const system = { hosts: names("s", 100), accounts: ["u1"], alert_count: 4 };
      expect(scopeOf({ system })).toEqual([
        "AI nêu: m1",
        "Hệ thống ghi: s1, s2, s3, s4, s5 và 95 máy khác",
        "AI nêu: a1",
        "Hệ thống ghi: u1",
        "4 bước MITRE",
        "kết thúc ở T1490",
      ]);
    });

    it("cuts the model's hosts the same way", () => {
      expect(scopeOf({ hosts: names("m", 7) })[0]).toBe("AI nêu: m1, m2, m3, m4, m5 và 2 máy khác");
    });

    it("cuts the accounts of both sides, and words them as accounts", () => {
      const lines = scopeOf({
        accounts: names("a", 6),
        system: { hosts: ["s1"], accounts: names("u", 9), alert_count: 4 },
      });
      expect(lines[2]).toBe("AI nêu: a1, a2, a3, a4, a5 và 1 tài khoản khác");
      expect(lines[3]).toBe("Hệ thống ghi: u1, u2, u3, u4, u5 và 4 tài khoản khác");
    });

    it("keeps a list of exactly five whole, with no remainder", () => {
      expect(scopeOf({ hosts: names("m", 5) })[0]).toBe("AI nêu: m1, m2, m3, m4, m5");
    });
  });

  it("lists the next steps with their priority, in the model's order", () => {
    renderPanel(runV4());
    const items = within(screen.getByRole("region", { name: "Việc nên làm tiếp" })).getAllByRole(
      "listitem",
    );
    expect(items.map((item) => [...item.children].map((part) => part.textContent))).toEqual([
      ["ưu tiên cao", "Cô lập máy Windows_Endpoint khỏi mạng."],
      ["ưu tiên cao", "Thu danh sách job BITS và nội dung lệnh PowerShell đã giải mã."],
      ["trung bình", "Tìm cùng chuỗi hành vi trên các máy khác trong 24 giờ."],
      ["thấp", "Đặt lại mật khẩu tài khoản Administrator của máy."],
    ]);
    expect(within(items[0]!).getByText("ưu tiên cao")).toHaveAttribute("data-tone", "critical");
    expect(within(items[2]!).getByText("trung bình")).toHaveAttribute("data-tone", "medium");
    expect(within(items[3]!).getByText("thấp")).toHaveAttribute("data-tone", "muted");
  });

  it("draws no card of next steps when the run has none", () => {
    renderPanel(runV4({ next_steps_rows: [], next_steps: [] }));
    expect(screen.queryByRole("region", { name: "Việc nên làm tiếp" })).not.toBeInTheDocument();
  });

  it("flags the quotes that were not found, in one line that says how many", () => {
    renderPanel(runV4());
    const card = screen.getByRole("region", { name: "Cần lưu ý" });
    expect(
      within(card).getByText(
        "1 trên 3 dẫn chứng chưa kiểm chứng được — cần xác minh trước khi tin (xem tab Bằng chứng).",
      ),
    ).toBeInTheDocument();
  });

  it("draws no Cần lưu ý card when there is nothing to flag", () => {
    renderPanel(runV4({ evidence: [evidenceRow()], evidence_summary: { cited: 1, verified: 1 } }));
    expect(screen.queryByRole("region", { name: "Cần lưu ý" })).not.toBeInTheDocument();
  });

  it("says why the system held the conclusion, in one line", () => {
    renderPanel(
      runV4({
        conclusion: "need_more_data",
        conclusion_label: "Cần thêm dữ liệu",
        model_conclusion: "confirmed_incident",
        held_by: ["no_verified_evidence", "high_severity_injection_finding"],
      }),
    );
    expect(
      within(screen.getByRole("region", { name: "Cần lưu ý" })).getByText(
        "AI kết luận: Là sự cố thật — hệ thống giữ lại vì: không có bằng chứng kiểm chứng được, phát hiện dấu hiệu chèn lệnh mức cao",
      ),
    ).toBeInTheDocument();
  });

  it("shows a cause it has no label for as the code, as text", () => {
    renderPanel(
      runV4({
        conclusion: "need_more_data",
        model_conclusion: "false_positive",
        held_by: ["<b>mới</b>"],
      }),
    );
    expect(
      screen.getByText("AI kết luận: Không phải sự cố — hệ thống giữ lại vì: <b>mới</b>"),
    ).toBeInTheDocument();
  });

  it("keeps the server's overrule sentence for a held conclusion that names no cause", () => {
    const sentence = "Mô hình đề xuất A nhưng kết luận đã bị hạ xuống B: x.";
    renderPanel(
      runV4({
        conclusion: "need_more_data",
        model_conclusion: "confirmed_incident",
        held_by: [],
        overruled: sentence,
      }),
    );
    expect(screen.getByText("AI kết luận: Là sự cố thật — hệ thống giữ lại")).toBeInTheDocument();
    expect(screen.getByText(sentence)).toBeInTheDocument();
  });

  it("does not repeat the overrule sentence when the causes are named", () => {
    const sentence = "Mô hình đề xuất A nhưng kết luận đã bị hạ xuống B: x.";
    renderPanel(
      runV4({
        conclusion: "need_more_data",
        model_conclusion: "confirmed_incident",
        held_by: ["no_verified_evidence"],
        overruled: sentence,
      }),
    );
    expect(screen.queryByText(sentence)).not.toBeInTheDocument();
  });

  it("says nothing of an overrule for a conclusion that was not touched", () => {
    renderPanel(runV4({ evidence: [evidenceRow()], evidence_summary: { cited: 1, verified: 1 } }));
    expect(screen.queryByText(/giữ lại/)).not.toBeInTheDocument();
    expect(screen.queryByText(/bị hạ xuống/)).not.toBeInTheDocument();
  });
});

describe("Diễn biến", () => {
  it("lists the timeline with the times the server took from the alerts, and where each step comes from", async () => {
    renderPanel(runV4());
    await open("Diễn biến");
    const list = screen.getByRole("list", { name: "Dòng thời gian" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(4);
    const first = within(rows[0]!);
    expect(first.getByText("18:28")).toBeInTheDocument();
    expect(first.getByText("amsi.dll được nạp bởi splwow64.exe")).toBeInTheDocument();
    expect(rows[0]!.querySelector("[data-part='meta']")!.textContent).toBe(
      "Né tránh phòng thủ · T1562.001 · alert 112437",
    );
    expect(rows.map((row) => row.querySelector("time")!.textContent)).toEqual([
      "18:28",
      "18:31",
      "18:40",
      "18:52",
    ]);
  });

  it("links each step to its alert, the way the heads of the case are linked", async () => {
    renderPanel(runV4());
    await open("Diễn biến");
    const list = screen.getByRole("list", { name: "Dòng thời gian" });
    expect(
      within(list)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["112437", "/alerts/112437"],
      ["112438", "/alerts/112438"],
      ["111525", "/alerts/111525"],
      ["111976", "/alerts/111976"],
    ]);
  });

  it("encodes an alert id that is not a plain token in its link", async () => {
    renderPanel(runV4({ timeline: [timelineRow({ alert_id: "a/b c" })] }));
    await open("Diễn biến");
    expect(screen.getByRole("link", { name: "a/b c" })).toHaveAttribute(
      "href",
      "/alerts/a%2Fb%20c",
    );
  });

  it("says the tactic or the technique alone when the other is missing, and the alert alone when both are", async () => {
    renderPanel(
      runV4({
        timeline: [
          timelineRow({ technique: null }),
          timelineRow({ alert_id: "2", tactic: null }),
          timelineRow({ alert_id: "3", tactic: null, technique: null }),
        ],
      }),
    );
    await open("Diễn biến");
    const metas = [...document.querySelectorAll("[data-part='meta']")].map((m) => m.textContent);
    expect(metas).toEqual(["Né tránh phòng thủ · alert 112437", "T1562.001 · alert 2", "alert 3"]);
  });

  it("marks the last step, where the chain ends", async () => {
    renderPanel(runV4());
    await open("Diễn biến");
    const dots = [...document.querySelectorAll("[data-part='dot']")].map((d) =>
      d.getAttribute("data-tone"),
    );
    expect(dots).toEqual(["ai", "ai", "ai", "critical"]);
  });

  it("shows the day too when the steps are not all on one day, and a dash for a step with no time", async () => {
    renderPanel(
      runV4({
        timeline: [
          timelineRow({ time: "2026-11-15T11:28:00+00:00" }),
          timelineRow({ alert_id: "2", time: "2026-11-16T01:05:00+00:00" }),
          timelineRow({ alert_id: "3", time: null }),
        ],
      }),
    );
    await open("Diễn biến");
    expect([...document.querySelectorAll("li time")].map((t) => t.textContent)).toEqual([
      "15/11 18:28",
      "16/11 08:05",
      "—",
    ]);
  });

  it("opens with the narrative the model wrote, keeping its line breaks", async () => {
    renderPanel(runV4());
    await open("Diễn biến");
    const narrative = within(panel()).getByText(/18:28 amsi\.dll được nạp/);
    expect(narrative).toHaveClass("whitespace-pre-wrap");
    expect(narrative.textContent).toBe("18:28 amsi.dll được nạp\n18:52 shadow copy bị xoá");
  });
});

describe("Giả thuyết", () => {
  it("shows each hypothesis with how likely it is, what is for it and what is against it", async () => {
    renderPanel(runV4());
    await open("Giả thuyết");
    const [first, second] = [...screen.getByRole("list", { name: "Giả thuyết" }).children];
    expect(
      within(first as HTMLElement).getByText("Chuẩn bị triển khai ransomware"),
    ).toBeInTheDocument();
    expect(within(first as HTMLElement).getByText("khả dĩ cao")).toHaveAttribute(
      "data-tone",
      "critical",
    );
    expect(within(first as HTMLElement).getByRole("list", { name: "Ủng hộ:" }).textContent).toBe(
      "bốn bước nối tiếp trong 24 phút, cùng tài khoản",
    );
    expect(within(first as HTMLElement).getByRole("list", { name: "Chống lại:" }).textContent).toBe(
      "chưa có alert mã hoá tệp",
    );
    expect(within(second as HTMLElement).getByText("khả dĩ thấp")).toHaveAttribute(
      "data-tone",
      "muted",
    );
    expect(
      within(within(second as HTMLElement).getByRole("list", { name: "Chống lại:" })).getAllByRole(
        "listitem",
      ),
    ).toHaveLength(2);
  });

  it("says 'khả dĩ trung bình' for a medium likelihood", async () => {
    renderPanel(
      runV4({
        hypotheses: [
          { text: "h", evidence_for: ["a"], evidence_against: ["b"], likelihood: "medium" },
        ],
      }),
    );
    await open("Giả thuyết");
    expect(screen.getByText("khả dĩ trung bình")).toHaveAttribute("data-tone", "medium");
  });

  it("warns when a hypothesis has no evidence against it, and only then", async () => {
    renderPanel(
      runV4({
        hypotheses: [
          { text: "một", evidence_for: ["a"], evidence_against: [], likelihood: "low" },
          { text: "hai", evidence_for: ["a"], evidence_against: ["b"], likelihood: "low" },
        ],
      }),
    );
    await open("Giả thuyết");
    expect(screen.getAllByText(S.ai2.noCounterEvidence)).toHaveLength(1);
    expect(screen.getAllByRole("list", { name: "Chống lại:" })).toHaveLength(1);
  });

  it("lists the knowledge candidates under the hypotheses, with no bar", async () => {
    renderPanel(runV4());
    await open("Giả thuyết");
    const card = screen.getByRole("region", { name: "Tri thức đã duyệt" });
    expect(card).toHaveTextContent("23 mục được chấm điểm");
    expect(
      within(card)
        .getAllByRole("listitem")
        .map((row) => row.textContent),
    ).toEqual([
      "84%PowerShell mã hoá kèm xoá shadow copy · sự cố thật",
      "71%Job BITS tải công cụ từ máy chủ ngoài · sự cố thật",
      "58%Quản trị viên dọn shadow copy theo lịch · lành tính",
    ]);
    expect(card.querySelector("svg")).toBeNull();
  });

  it("says that nothing reached the floor, with the candidates that came closest", async () => {
    renderPanel(
      runV4({
        knowledge: knowledgeOf("below_floor", {
          best_pct: 47,
          floor_pct: 50,
          scored: 23,
          candidates: [
            { pct: 47, title: "PowerShell mã hoá Base64", conclusion: "confirmed_incident" },
          ],
        }),
      }),
    );
    await open("Giả thuyết");
    const card = screen.getByRole("region", { name: "Tri thức đã duyệt" });
    expect(
      within(card).getByText(
        "Không mục nào đạt mức tối thiểu 50%, nên không có tri thức tham khảo nào được đưa cho AI.",
      ),
    ).toBeInTheDocument();
    expect(
      within(card).getByText("PowerShell mã hoá Base64", { exact: false }),
    ).toBeInTheDocument();
  });

  it.each([
    ["no_candidate", {}, "Không có mục tri thức đã duyệt nào được chấm điểm cho case này."],
    ["no_lookup", {}, "Lượt phân tích này không tra cứu tri thức đã duyệt."],
    ["failed", { failure: "quota" }, "Không tra cứu được tri thức đã duyệt: Voyage hết hạn mức."],
    ["failed", { failure: "cosmic_ray" }, "Không tra cứu được tri thức đã duyệt."],
  ])("says a lookup that came to %s %j in one sentence", async (state, over, sentence) => {
    renderPanel(runV4({ knowledge: knowledgeOf(state, { scored: null, ...over }) }));
    await open("Giả thuyết");
    const card = screen.getByRole("region", { name: "Tri thức đã duyệt" });
    expect(within(card).getByText(sentence)).toBeInTheDocument();
    expect(within(card).queryAllByRole("listitem")).toEqual([]);
  });

  it("draws no knowledge card when the run says nothing of a lookup", async () => {
    renderPanel(
      runOld({
        rag: { best_pct: null, not_applied: null, below_floor_pct: null, floor_pct: null },
      }),
    );
    await open("Giả thuyết");
    expect(screen.queryByRole("region", { name: "Tri thức đã duyệt" })).not.toBeInTheDocument();
  });

  it("says so when the run has no hypothesis", async () => {
    renderPanel(runV4({ hypotheses: [] }));
    await open("Giả thuyết");
    expect(screen.getByText("Lượt phân tích này không nêu giả thuyết nào.")).toBeInTheDocument();
  });
});

describe("Bằng chứng", () => {
  it("says how many quotes were found, and lists each with its alert and what became of it", async () => {
    renderPanel(runV4());
    await open("Bằng chứng");
    expect(
      screen.getByText("2 trên 3 dẫn chứng khớp nguyên văn với log của alert trong case."),
    ).toBeInTheDocument();
    const blocks = [...document.querySelectorAll("[data-verified]")];
    expect(blocks.map((block) => block.getAttribute("data-verified"))).toEqual([
      "true",
      "true",
      "false",
    ]);
    const first = within(blocks[0] as HTMLElement);
    expect(first.getByRole("img", { name: "Đã kiểm chứng" })).toBeInTheDocument();
    expect(first.getByText("Lệnh xoá toàn bộ shadow copy, không hỏi lại.")).toBeInTheDocument();
    expect(first.getByText("CommandLine: vssadmin delete shadows /all /quiet")).toBeInTheDocument();
    expect(blocks[0]!.lastElementChild!.textContent).toBe("alert 111976 · khớp nguyên văn");
  });

  it("gives the server's reason for a quote it did not find", async () => {
    renderPanel(runV4());
    await open("Bằng chứng");
    const block = document.querySelector("[data-verified='false']") as HTMLElement;
    expect(within(block).getByRole("img", { name: "Không kiểm chứng được" })).toBeInTheDocument();
    expect(block.lastElementChild!.textContent).toBe(
      "alert 112438 · trích dẫn không có trong log hay mô tả của alert",
    );
  });

  it("links each evidence's alert", async () => {
    renderPanel(runV4());
    await open("Bằng chứng");
    expect(
      screen.getAllByRole("link").map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["111976", "/alerts/111976"],
      ["111525", "/alerts/111525"],
      ["112438", "/alerts/112438"],
    ]);
  });

  // One wording on both tiers' panels, the same as the mark's spoken name beside it: "Không kiểm chứng được".
  it("says 'Không kiểm chứng được' for an unverified quote the server gave no reason for, as the icon beside it does", async () => {
    renderPanel(runV4({ evidence: [unverifiedRow({ reason_text: null })] }));
    await open("Bằng chứng");
    const block = document.querySelector("[data-verified='false']")!;
    expect(block.lastElementChild!.textContent).toBe("alert 112438 · Không kiểm chứng được");
    expect(within(block as HTMLElement).getByRole("img")).toHaveAccessibleName(
      "Không kiểm chứng được",
    );
  });

  it("copes with an evidence row that names no alert and quotes nothing", async () => {
    renderPanel(
      runV4({
        evidence: [{ alert_id: null, quote: null, why: null, verified: false, reason_text: null }],
        evidence_summary: { cited: 1, verified: 0 },
      }),
    );
    await open("Bằng chứng");
    const block = document.querySelector("[data-verified='false']") as HTMLElement;
    expect(block.textContent).toBe("—Không kiểm chứng được");
    expect(within(block).queryByRole("link")).not.toBeInTheDocument();
  });

  it("says so when the assistant gave no evidence", async () => {
    renderPanel(runV4({ evidence: [], evidence_summary: { cited: 0, verified: 0 } }));
    await open("Bằng chứng");
    expect(screen.getByText(S.ai2.noEvidence)).toBeInTheDocument();
    expect(screen.queryByText(/dẫn chứng khớp nguyên văn với log/)).not.toBeInTheDocument();
  });

  it("marks every row by its own verdict, not by the first", async () => {
    renderPanel(
      runV4({
        evidence: [
          unverifiedRow({ alert_id: "1" }),
          evidenceRow({ alert_id: "2" }),
          unverifiedRow({ alert_id: "3" }),
          evidenceRow({ alert_id: "4" }),
        ],
        evidence_summary: { cited: 4, verified: 2 },
      }),
    );
    await open("Bằng chứng");
    expect(
      [...document.querySelectorAll("[data-verified]")].map((b) => b.getAttribute("data-verified")),
    ).toEqual(["false", "true", "false", "true"]);
  });
});

describe("Kỹ thuật", () => {
  const rows = () =>
    [...panel().querySelectorAll("dt")].map((dt) => [
      dt.textContent,
      dt.nextElementSibling!.textContent,
    ]);

  it("shows tokens, time, cost, when, the playbook and the alerts read, and no more", async () => {
    renderPanel(runV4());
    await open("Kỹ thuật");
    expect(rows()).toEqual([
      ["Token vào → ra", "21.480 → 1.612"],
      ["Thời gian", "9,8 giây"],
      ["Chi phí", "$0,0013"],
      ["Phân tích lúc", "15/11/2026 19:02:11"],
      ["Playbook", "ransomware_v1"],
      ["Alert AI đã đọc", "4 trên 4"],
    ]);
  });

  it("shows a dash for what an older run did not store", async () => {
    renderPanel(runV3(), null);
    await open("Kỹ thuật");
    expect(rows()).toEqual([
      ["Token vào → ra", "—"],
      ["Thời gian", "—"],
      ["Chi phí", "—"],
      ["Phân tích lúc", "15/11/2026 19:02:11"],
      ["Playbook", "ransomware_v1"],
      ["Alert AI đã đọc", "—"],
    ]);
  });

  it("says one of the two token counts when the run stored only one", async () => {
    renderPanel(runV4({ tech: { ...runV4().tech, output_tokens: null } }));
    await open("Kỹ thuật");
    expect(rows()[0]).toEqual(["Token vào → ra", "21.480 → —"]);
  });

  it("says the alerts read without a total when the case's total is not known", async () => {
    renderPanel(runOld(), null);
    await open("Kỹ thuật");
    expect(rows()[5]).toEqual(["Alert AI đã đọc", "4"]);
  });

  it("says the playbook is missing as a dash", async () => {
    renderPanel(runV4({ tech: { ...runV4().tech, playbook: null } }));
    await open("Kỹ thuật");
    expect(rows()[4]).toEqual(["Playbook", "—"]);
  });
});

// ── an older run ─────────────────────────────────────────────────────────────────────────────────

describe("a run stored before version 4", () => {
  it("still draws its four tiles and five tabs", () => {
    renderPanel(runV3());
    expect(tile("Kết luận").textContent).toBe("Kết luậnSự cốLà sự cố thậtgợi ý của AI");
    expect(tile("Độ tin cậy").textContent).toBe("Độ tin cậyTrung bình");
    expect(tile("Tri thức (RAG)").textContent).toBe("Tri thức (RAG)84%trùng sự cố cũ");
    expect(tile("Dẫn chứng").textContent).toBe("Dẫn chứng2/3khớp nguyên văn");
    expect(screen.getAllByRole("tab")).toHaveLength(5);
  });

  it("shows what the system knows of the scope, says the model said nothing, and has no MITRE steps", () => {
    renderPanel(runV3());
    expect(screen.getByRole("group", { name: "Phạm vi" }).textContent).toBe(
      "Máy" +
        "AI không nêu" +
        "Hệ thống ghi: Windows_Endpoint" +
        "Tài khoản" +
        "AI không nêu" +
        "Hệ thống ghi: Administrator" +
        "Chiến thuật" +
        "—" +
        "chưa có dòng thời gian",
    );
  });

  it("lists the next steps with no priority, and no gutter for it", () => {
    renderPanel(runV3());
    const items = within(screen.getByRole("region", { name: "Việc nên làm tiếp" })).getAllByRole(
      "listitem",
    );
    expect(items.map((item) => item.textContent)).toEqual([
      "Cô lập máy Windows_Endpoint khỏi mạng.",
      "Thu danh sách job BITS và nội dung lệnh PowerShell đã giải mã.",
      "Tìm cùng chuỗi hành vi trên các máy khác trong 24 giờ.",
      "Đặt lại mật khẩu tài khoản Administrator của máy.",
    ]);
  });

  it("says in the timeline tab that there is none, and still shows the narrative", async () => {
    renderPanel(runV3());
    await open("Diễn biến");
    expect(screen.getByText("Lượt phân tích này không có dòng thời gian.")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Dòng thời gian" })).not.toBeInTheDocument();
    expect(within(panel()).getByText(/18:28 amsi\.dll được nạp/)).toBeInTheDocument();
  });

  it("shows the hypotheses with no likelihood", async () => {
    renderPanel(runV3());
    await open("Giả thuyết");
    expect(screen.getByText("Chuẩn bị triển khai ransomware")).toBeInTheDocument();
    expect(panel().querySelector("[data-part='likelihood']")).toBeNull();
    expect(panel()).not.toHaveTextContent("khả dĩ");
  });

  it("copes with a server that sends none of the new keys at all", async () => {
    renderPanel(runOld(), null);
    expect(tile("Dẫn chứng").textContent).toBe("Dẫn chứng2/3khớp nguyên văn");
    expect(screen.getByRole("group", { name: "Phạm vi" })).toBeInTheDocument();
    for (const name of ["Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật", "Tổng quan"]) {
      await open(name);
      expect(panel().textContent).not.toBe("");
    }
  });

  it("copes with a run that is nothing but a result, with every other key null or missing", async () => {
    const bare = {
      run_id: "r",
      created_at: null,
      result: {},
      conclusion: null,
      confidence: null,
      summary: null,
      narrative: null,
      hypotheses: null,
      evidence: null,
      next_steps: null,
      playbook_used: null,
      overruled: null,
      snapshot: null,
      rag: null,
      timeline: null,
      scope: null,
      tech: null,
      knowledge: null,
      next_steps_rows: null,
      evidence_summary: null,
    };
    renderPanel(bare, null);
    expect(tile("Kết luận").textContent).toBe("Kết luận—gợi ý của AI");
    for (const name of ["Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật", "Tổng quan"]) {
      await open(name);
      expect(panel()).toBeInTheDocument();
    }
  });
});

// ── the notices above the tabs ───────────────────────────────────────────────────────────────────

describe("what stays above the tabs", () => {
  it("says the case has changed since the run, beside the numbers then and now", () => {
    renderPanel(
      runV4({
        changed: true,
        snapshot: {
          alert_count: 3,
          total_occurrences: 61,
          last_seen_at: "2026-11-15T04:12:00+00:00",
        },
      }),
      { alert_count: 5, total_occurrences: 80, last_seen_at: "2026-11-15T09:30:00+00:00" },
    );
    expect(screen.getByText(S.ai2.stale)).toBeInTheDocument();
    expect(
      screen.getByText("Lúc phân tích: 3 alert, 61 lần xuất hiện, alert mới nhất 15/11 11:12."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Hiện tại: 5 alert, 80 lần xuất hiện, alert mới nhất 15/11 16:30."),
    ).toBeInTheDocument();
  });

  it("says nothing of a change when the case is as it was", () => {
    renderPanel(runV4({ changed: false }));
    expect(screen.queryByText(S.ai2.stale)).not.toBeInTheDocument();
  });

  // E: a snapshot or a current that is not what the server sends is no numbers; the notice is said without them.
  it.each([
    ["a string", "snapshot"],
    ["a list", [3, 61]],
    ["an empty object", {}],
    ["half a snapshot", { alert_count: 3 }],
    ["counts that are text", { alert_count: "3", total_occurrences: "61" }],
  ])(
    "says the change without the numbers of a snapshot that is %s, never 'undefined'",
    (_what, snapshot) => {
      const { container } = renderPanel(runV4({ changed: true, snapshot }), null);
      expect(screen.getByText(S.ai2.stale)).toBeInTheDocument();
      expect(screen.queryByText(/Lúc phân tích/)).not.toBeInTheDocument();
      expect(container.textContent).not.toContain("undefined");
      expect(container.textContent).not.toContain("NaN");
    },
  );

  it("says the numbers it has and leaves out the ones it has not: a good snapshot with a current that is nothing", () => {
    const { container } = renderPanel(
      runV4({
        changed: true,
        snapshot: { alert_count: 3, total_occurrences: 61, last_seen_at: null },
      }),
      {} as unknown as typeof CURRENT,
    );
    expect(screen.getByText("Lúc phân tích: 3 alert, 61 lần xuất hiện.")).toBeInTheDocument();
    expect(screen.queryByText(/Hiện tại/)).not.toBeInTheDocument();
    expect(container.textContent).not.toContain("undefined");
  });

  it("says the stale notice on whichever tab is open", async () => {
    renderPanel(runV4({ changed: true }));
    await open("Bằng chứng");
    expect(screen.getByText(S.ai2.stale)).toBeInTheDocument();
  });

  it("says the RAG was not applied, as the case's notice, on whichever tab is open", async () => {
    renderPanel(
      runV4({
        rag: { best_pct: null, not_applied: "quota", below_floor_pct: null, floor_pct: null },
        knowledge: knowledgeOf("failed", { failure: "quota", scored: null }),
      }),
    );
    const notice =
      "⚠ Không áp dụng RAG cho case này: Voyage hết hạn mức — AI đã phân tích không có tri thức tham khảo.";
    expect(screen.getByRole("note")).toHaveTextContent(notice);
    await open("Kỹ thuật");
    expect(screen.getByRole("note")).toHaveTextContent(notice);
  });

  it("draws no notice when the lookup did not fail, or for a kind it has no words for", () => {
    const { unmount } = renderPanel(runV4());
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    unmount();
    renderPanel(
      runV4({
        rag: { best_pct: null, not_applied: "cosmic_ray", below_floor_pct: null, floor_pct: null },
      }),
    );
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("carries the advisory disclaimer under the tabs", () => {
    renderPanel(runV4());
    expect(screen.getByText(S.ai2.disclaimer)).toBeInTheDocument();
  });

  it("has no button or field of its own: the controls belong to the column", () => {
    renderPanel(runV4());
    expect(screen.queryAllByRole("button")).toEqual([]);
    expect(screen.queryAllByRole("textbox")).toEqual([]);
  });
});

// ── text only ────────────────────────────────────────────────────────────────────────────────────

describe("everything the model wrote is text", () => {
  const evil = "<img src=x onerror=alert(1)>";

  it("renders no element out of it, on any tab", async () => {
    renderPanel(
      runV4({
        summary: evil,
        narrative: evil,
        hypotheses: [
          { text: evil, evidence_for: [evil], evidence_against: [evil], likelihood: "high" },
        ],
        evidence: [evidenceRow({ quote: evil, why: evil })],
        evidence_summary: { cited: 1, verified: 1 },
        next_steps_rows: [{ step: evil, priority: "high" }],
        timeline: [timelineRow({ what: evil, tactic: evil, technique: evil })],
        scope: {
          hosts: [evil],
          accounts: [evil],
          system: { hosts: [evil], accounts: [evil], alert_count: 1 },
        },
        knowledge: knowledgeOf("matched", {
          best_pct: 84,
          candidates: [{ pct: 84, title: evil, conclusion: evil }],
        }),
      }),
    );
    for (const name of ["Tổng quan", "Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật"]) {
      await open(name);
      expect(document.querySelector("img")).toBeNull();
      expect(panel().innerHTML).not.toContain("<img");
    }
    await open("Bằng chứng");
    expect(panel()).toHaveTextContent(evil);
  });
});

// ── G5 ───────────────────────────────────────────────────────────────────────────────────────────

describe("G5: the model's name is on no tab", () => {
  const TABS = ["Tổng quan", "Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật"];
  const RUNS: [string, unknown][] = [
    ["a version 4 run", runV4()],
    ["an older run", runV3()],
    ["a run from a server that sends none of the new keys", runOld()],
    [
      "a held run",
      runV4({
        conclusion: "need_more_data",
        model_conclusion: "confirmed_incident",
        held_by: ["no_verified_evidence"],
      }),
    ],
    ["a run under the floor", runV4({ knowledge: knowledgeOf("below_floor", { best_pct: 47 }) })],
    ["a run whose lookup failed", runV4({ knowledge: knowledgeOf("failed", { failure: "auth" }) })],
  ];

  it.each(RUNS)(
    "names no model in %s, on any tab, in any text or attribute",
    async (_name, run) => {
      const { container } = renderPanel(run);
      for (const tab of TABS) {
        await open(tab);
        expect(modelNamesIn(container)).toEqual([]);
      }
    },
  );

  it("labels the technical tab with exactly the six rows, whatever the run", async () => {
    for (const run of [runV4(), runV3(), runOld()]) {
      const { unmount } = renderPanel(run);
      await open("Kỹ thuật");
      expect([...panel().querySelectorAll("dt")].map((dt) => dt.textContent)).toEqual([
        "Token vào → ra",
        "Thời gian",
        "Chi phí",
        "Phân tích lúc",
        "Playbook",
        "Alert AI đã đọc",
      ]);
      unmount();
    }
  });

  it("does not print a model the run happens to carry: the page reads no key that names one", async () => {
    const { container } = renderPanel(
      runV4({
        model: "GLM-5.3",
        model_id: "glm-5.3",
        tech: { ...runV4().tech, model: "GLM-5.3", model_id: "glm" },
      }),
    );
    for (const tab of TABS) {
      await open(tab);
      expect(modelNamesIn(container)).toEqual([]);
    }
  });
});

// ── accessibility ────────────────────────────────────────────────────────────────────────────────

describe("accessibility", () => {
  // jsdom computes no layout or colour, so the contrast rule cannot run here.
  const check = async (container: HTMLElement) => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  };

  it.each(["Tổng quan", "Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật"])(
    "has no axe violation on %s of a version 4 run",
    async (tab) => {
      const { container } = renderPanel(runV4({ changed: true }));
      await open(tab);
      await check(container);
    },
  );

  it.each(["Tổng quan", "Diễn biến", "Giả thuyết", "Bằng chứng", "Kỹ thuật"])(
    "has no axe violation on %s of an older run, held, with the RAG not applied",
    async (tab) => {
      const { container } = renderPanel(
        runV3({
          conclusion: "need_more_data",
          model_conclusion: "confirmed_incident",
          held_by: ["no_verified_evidence"],
          rag: { best_pct: null, not_applied: "timeout", below_floor_pct: null, floor_pct: null },
          knowledge: knowledgeOf("failed", { failure: "timeout" }),
        }),
        null,
      );
      await open(tab);
      await check(container);
    },
  );
});
