// src/features/analysis/analysis.test.tsx — the pieces the two AI panels share (DEC-221): the score tile, the
// confidence meter, the tab strip, the evidence block, the knowledge candidates, the status icon, the figures grid and
// the cards around them. Nothing here knows a tier; each piece gets its words from its props or from `S.analysis`.
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { S } from "../../strings";
import { Card, FactRows, Figures, IconLine } from "./Cards";
import { ConfidenceMeter } from "./ConfidenceMeter";
import { EvidenceBlock } from "./EvidenceBlock";
import { KnowledgeCandidates } from "./KnowledgeCandidates";
import { ScoreTile } from "./ScoreTile";
import { StatusIcon } from "./StatusIcon";
import { CAPTION, CAPTION_BASE } from "./styles";
import { Tabs } from "./Tabs";

describe("ScoreTile", () => {
  it("is a group named by its label, with the value and the line under it", () => {
    render(<ScoreTile label="Dẫn chứng" value="4/5" figure note="khớp nguyên văn" />);
    const tile = screen.getByRole("group", { name: "Dẫn chứng" });
    expect(within(tile).getByText("4/5")).toBeInTheDocument();
    expect(within(tile).getByText("khớp nguyên văn")).toBeInTheDocument();
  });

  it("says its tone so the page and the tests can tell the conclusion's colour", () => {
    render(<ScoreTile label="Kết luận" tone="critical" value="Là sự cố thật" />);
    expect(screen.getByRole("group", { name: "Kết luận" })).toHaveAttribute(
      "data-tone",
      "critical",
    );
  });

  // The cascade cannot be seen in jsdom, and in the built CSS `.text-muted` wins over a tint on the same element: so the
  // caption of a coloured tile must not carry both colour classes. It carries its tile's tint and no `text-muted`; a
  // quiet tile's carries `text-muted` and no tint. (Review of the Tier 2 panel: every coloured caption rendered grey.)
  it.each(["critical", "high", "medium", "low"] as const)(
    "tints the caption of a %s tile with its own colour, and not with the muted grey too",
    (tone) => {
      render(<ScoreTile label="Kết luận" tone={tone} value="TP" />);
      const caption = screen.getByText("Kết luận");
      expect(caption).toHaveClass(`text-${tone}`);
      expect(caption).not.toHaveClass("text-muted");
    },
  );

  it.each(["neutral", "ai"] as const)(
    "writes the caption of a %s tile in the muted grey and in no tint",
    (tone) => {
      render(<ScoreTile label="Độ tin cậy" tone={tone} value="x" />);
      const caption = screen.getByText("Độ tin cậy");
      expect(caption).toHaveClass("text-muted");
      for (const tint of ["critical", "high", "medium", "low"]) {
        expect(caption).not.toHaveClass(`text-${tint}`);
      }
    },
  );

  it("shares its caption style with the cards without the colour: the base has none, the card's has the grey", () => {
    expect(CAPTION_BASE).not.toMatch(/text-(muted|critical|high|medium|low|text|ok)\b/);
    expect(CAPTION).toBe(`${CAPTION_BASE} text-muted`);
  });

  it("is neutral when it is given no tone", () => {
    render(<ScoreTile label="Dẫn chứng" value="—" />);
    expect(screen.getByRole("group", { name: "Dẫn chứng" })).toHaveAttribute(
      "data-tone",
      "neutral",
    );
  });

  it("draws its children instead of a value and a note", () => {
    render(
      <ScoreTile label="Độ tin cậy" tone="ai">
        <span>trong tile</span>
      </ScoreTile>,
    );
    expect(within(screen.getByRole("group", { name: "Độ tin cậy" })).getByText("trong tile"));
  });

  it("marks a note as a warning when it is one", () => {
    render(<ScoreTile label="Kiểm chứng" value="4/6" figure note="2 cảnh báo" noteTone="warn" />);
    expect(screen.getByText("2 cảnh báo")).toHaveAttribute("data-tone", "warn");
  });

  it("renders text the server sent as text", () => {
    const { container } = render(
      <ScoreTile label="Kết luận" value="<img src=x onerror=alert(1)>" note="<b>x</b>" />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container).toHaveTextContent("<img src=x onerror=alert(1)>");
  });
});

describe("ConfidenceMeter", () => {
  it.each([
    ["low", "Thấp", "1 trên 3"],
    ["medium", "Trung bình", "2 trên 3"],
    ["high", "Cao", "3 trên 3"],
  ] as const)("says %s as the word %s over a meter that reads %s", (level, word, spoken) => {
    render(<ConfidenceMeter level={level} word={word} />);
    expect(screen.getByText(word)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: spoken })).toBeInTheDocument();
  });

  it("fills as many of the three segments as the level has", () => {
    render(<ConfidenceMeter level="medium" word="Trung bình" />);
    const segments = screen.getByRole("img", { name: "2 trên 3" }).children;
    expect(segments).toHaveLength(3);
    expect([...segments].map((segment) => segment.getAttribute("data-filled"))).toEqual([
      "true",
      "true",
      "false",
    ]);
  });

  it("draws the word alone, with no meter, for a level it does not know", () => {
    render(<ConfidenceMeter level={null} word="rất cao" />);
    expect(screen.getByText("rất cao")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});

describe("StatusIcon", () => {
  it.each(["pass", "warn", "na"] as const)(
    "draws the %s mark as an SVG, never as an emoji",
    (kind) => {
      const { container } = render(<StatusIcon kind={kind} />);
      const svg = container.querySelector("svg");
      expect(svg).not.toBeNull();
      expect(svg?.querySelector("path")).not.toBeNull();
      expect(container.textContent).toBe("");
    },
  );

  it("is hidden from a screen reader when it has no label, and spoken when it has one", () => {
    const { container, rerender } = render(<StatusIcon kind="pass" />);
    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    rerender(<StatusIcon kind="pass" label={S.analysis.evidence.verified} />);
    expect(screen.getByRole("img", { name: "Đã kiểm chứng" })).toBeInTheDocument();
  });

  it("gives each kind its own colour and its own shape", () => {
    const { container } = render(
      <>
        <StatusIcon kind="pass" />
        <StatusIcon kind="warn" />
        <StatusIcon kind="na" />
      </>,
    );
    const paths = [...container.querySelectorAll("path")].map((path) => path.getAttribute("d"));
    expect(new Set(paths).size).toBe(3);
    expect([...container.querySelectorAll("svg")].map((svg) => svg.dataset.kind)).toEqual([
      "pass",
      "warn",
      "na",
    ]);
  });

  // The Tier 1 panel's highlights point up (towards an attack) or down (towards a benign reading), as the approved
  // mock-up draws them: an arrow in the warning-orange or the calm blue. Added for Tier 1; the three marks above are
  // unchanged.
  it("draws an arrow up and an arrow down, each with its own shape and colour, and says them aloud", () => {
    const { container } = render(
      <>
        <StatusIcon kind="up" label={S.analysis.status.up} />
        <StatusIcon kind="down" label={S.analysis.status.down} />
      </>,
    );
    const svgs = [...container.querySelectorAll("svg")];
    expect(svgs.map((svg) => svg.dataset.kind)).toEqual(["up", "down"]);
    expect(new Set(svgs.map((svg) => svg.querySelector("path")?.getAttribute("d"))).size).toBe(2);
    expect(svgs[0]).toHaveClass("stroke-high");
    expect(svgs[1]).toHaveClass("stroke-low");
    expect(screen.getByRole("img", { name: "Nghiêng về tấn công" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Nghiêng về lành tính" })).toBeInTheDocument();
  });

  it("speaks the arrow of an icon line", () => {
    render(<IconLine kind="up">Tài khoản đặc quyền.</IconLine>);
    expect(screen.getByRole("img", { name: S.analysis.status.up })).toBeInTheDocument();
  });
});

describe("Tabs", () => {
  const TABS = [
    { id: "one", label: "Tổng quan", content: <p>nội dung một</p> },
    { id: "two", label: "Diễn biến", content: <p>nội dung hai</p> },
    { id: "three", label: "Giả thuyết", content: <p>nội dung ba</p> },
  ];
  const tab = (name: string) => screen.getByRole("tab", { name });

  // The five labels leave no slack in a 486 px column (review of AP-T4): the strip scrolls sideways inside the column
  // rather than clip a tab or widen the page, and a tab keeps its width (it is not squeezed, and does not wrap).
  it("scrolls sideways when the labels do not fit, so that it cannot clip or widen the column", () => {
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    const list = screen.getByRole("tablist", { name: "Chi tiết" });
    expect(list).toHaveClass("overflow-x-auto");
    expect(list).toHaveClass("max-w-full");
    for (const tab of within(list).getAllByRole("tab")) {
      expect(tab).toHaveClass("shrink-0");
      expect(tab).toHaveClass("whitespace-nowrap");
    }
  });

  it("is a tablist with a tab for each entry, and the first one open", () => {
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    const list = screen.getByRole("tablist", { name: "Chi tiết" });
    expect(
      within(list)
        .getAllByRole("tab")
        .map((t) => t.textContent),
    ).toEqual(["Tổng quan", "Diễn biến", "Giả thuyết"]);
    expect(tab("Tổng quan")).toHaveAttribute("aria-selected", "true");
    expect(tab("Diễn biến")).toHaveAttribute("aria-selected", "false");
  });

  it("draws only the open tab's panel, named by its tab", () => {
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveTextContent("nội dung một");
    expect(screen.queryByText("nội dung hai")).not.toBeInTheDocument();
    expect(panel).toHaveAttribute("aria-labelledby", tab("Tổng quan").id);
    expect(tab("Tổng quan")).toHaveAttribute("aria-controls", panel.id);
    expect(tab("Diễn biến")).not.toHaveAttribute("aria-controls");
  });

  it("opens a tab on a click", async () => {
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    await userEvent.setup().click(tab("Giả thuyết"));
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung ba");
    expect(tab("Giả thuyết")).toHaveAttribute("aria-selected", "true");
  });

  it("has one tab stop: only the open tab can be tabbed to", () => {
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    expect(screen.getAllByRole("tab").map((t) => t.tabIndex)).toEqual([0, -1, -1]);
  });

  it("moves between the tabs with the arrow keys, wrapping at both ends", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    tab("Tổng quan").focus();
    await user.keyboard("{ArrowRight}");
    expect(tab("Diễn biến")).toHaveFocus();
    expect(tab("Diễn biến")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung hai");
    await user.keyboard("{ArrowRight}{ArrowRight}");
    expect(tab("Tổng quan")).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(tab("Giả thuyết")).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung ba");
  });

  it("goes to the first and the last tab with Home and End", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    tab("Tổng quan").focus();
    await user.keyboard("{End}");
    expect(tab("Giả thuyết")).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung ba");
    await user.keyboard("{Home}");
    expect(tab("Tổng quan")).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung một");
  });

  it("follows the focus: the tab stop is the open tab", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    tab("Tổng quan").focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getAllByRole("tab").map((t) => t.tabIndex)).toEqual([-1, 0, -1]);
  });

  it("leaves the tablist for the panel on Tab", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    tab("Tổng quan").focus();
    await user.tab();
    expect(screen.getByRole("tabpanel")).toHaveFocus();
  });

  it("ignores a key it has no use for, and does not swallow it", async () => {
    const user = userEvent.setup();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    tab("Tổng quan").focus();
    await user.keyboard("a{ArrowDown}");
    expect(tab("Tổng quan")).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung một");
  });

  it("keeps the open tab in the component only: a new mount starts on the first tab", async () => {
    const { unmount } = render(<Tabs label="Chi tiết" tabs={TABS} />);
    await userEvent.setup().click(tab("Giả thuyết"));
    unmount();
    render(<Tabs label="Chi tiết" tabs={TABS} />);
    expect(tab("Tổng quan")).toHaveAttribute("aria-selected", "true");
  });

  it("falls back on the first tab when the open one is no longer in the list", async () => {
    const { rerender } = render(<Tabs label="Chi tiết" tabs={TABS} />);
    await userEvent.setup().click(tab("Giả thuyết"));
    rerender(<Tabs label="Chi tiết" tabs={TABS.slice(0, 2)} />);
    expect(tab("Tổng quan")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveTextContent("nội dung một");
  });

  it("has no axe violation", async () => {
    const { container } = render(<Tabs label="Chi tiết" tabs={TABS} />);
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("EvidenceBlock", () => {
  it("shows a verified quote: the claim, the quote in a box, and where it comes from", () => {
    render(
      <EvidenceBlock
        claim="Lệnh xoá toàn bộ shadow copy, không hỏi lại."
        quote="CommandLine: vssadmin delete shadows /all /quiet"
        source="alert 111976 · khớp nguyên văn"
        verified
      />,
    );
    expect(screen.getByRole("img", { name: "Đã kiểm chứng" })).toBeInTheDocument();
    expect(screen.getByText("Lệnh xoá toàn bộ shadow copy, không hỏi lại.")).toBeInTheDocument();
    const quote = screen.getByText("CommandLine: vssadmin delete shadows /all /quiet");
    expect(quote).toHaveClass("font-mono");
    expect(screen.getByText("alert 111976 · khớp nguyên văn")).toBeInTheDocument();
  });

  it("shows an unverified quote as one the server could not find, with a dashed box", () => {
    const { container } = render(
      <EvidenceBlock
        claim="Job BITS tải tệp từ một máy chủ bên ngoài."
        quote="RemoteName: hxxp://… /update.bin"
        source="alert 112438 · không tìm thấy nguyên văn trong log"
        verified={false}
      />,
    );
    expect(screen.getByRole("img", { name: "Không kiểm chứng được" })).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: "Đã kiểm chứng" })).not.toBeInTheDocument();
    expect(screen.getByText("RemoteName: hxxp://… /update.bin")).toHaveClass("border-dashed");
    expect(container.firstElementChild).toHaveAttribute("data-verified", "false");
  });

  it("marks a verified block for the page and the tests", () => {
    const { container } = render(<EvidenceBlock claim="c" quote="q q q q q" source="s" verified />);
    expect(container.firstElementChild).toHaveAttribute("data-verified", "true");
  });

  it("draws no quote box for a quote that is not there", () => {
    const { container } = render(
      <EvidenceBlock
        claim="Lịch sử quyết định."
        quote={null}
        source="AI diễn giải"
        verified={false}
      />,
    );
    expect(container.querySelector(".font-mono")).toBeNull();
  });

  it("keeps a quote's line breaks and renders it as text, never as markup", () => {
    const { container } = render(
      <EvidenceBlock
        claim="<b>claim</b>"
        quote={"line 1\n<img src=x onerror=alert(1)>"}
        source={<span>nguồn</span>}
        verified
      />,
    );
    expect(container.querySelector("img[src]")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText(/line 1/)).toHaveClass("whitespace-pre-wrap");
    expect(container).toHaveTextContent("<img src=x onerror=alert(1)>");
  });
});

describe("KnowledgeCandidates", () => {
  const ROWS = [
    { pct: 84, title: "PowerShell mã hoá kèm xoá shadow copy", conclusion: "confirmed_incident" },
    { pct: 58, title: "Quản trị viên dọn shadow copy theo lịch", conclusion: "closed_benign" },
  ];
  const rowTexts = () => screen.getAllByRole("listitem").map((row) => row.textContent);

  it("lists the percentage, the title and the conclusion's label of each candidate", () => {
    render(<KnowledgeCandidates rows={ROWS} />);
    expect(rowTexts()).toEqual([
      "84%PowerShell mã hoá kèm xoá shadow copy · sự cố thật",
      "58%Quản trị viên dọn shadow copy theo lịch · lành tính",
    ]);
  });

  it("draws a bar for each row, as wide as the percentage", () => {
    const { container } = render(<KnowledgeCandidates rows={ROWS} />);
    const fills = [...container.querySelectorAll("[data-bar-fill]")];
    expect(fills.map((fill) => fill.getAttribute("width"))).toEqual(["84%", "58%"]);
  });

  it("draws no bar when it is asked not to", () => {
    const { container } = render(<KnowledgeCandidates rows={ROWS} bar={false} />);
    expect(container.querySelector("svg")).toBeNull();
  });

  it("words each conclusion the knowledge base can hold, and colours it by its kind", () => {
    render(
      <KnowledgeCandidates
        rows={[
          { pct: 90, title: "a", conclusion: "confirmed_incident" },
          { pct: 80, title: "b", conclusion: "concluded_policy_violation" },
          { pct: 70, title: "c", conclusion: "concluded_fp" },
          { pct: 60, title: "d", conclusion: "closed_fp" },
          { pct: 50, title: "e", conclusion: "closed_benign" },
        ]}
      />,
    );
    expect(rowTexts()).toEqual([
      "90%a · sự cố thật",
      "80%b · vi phạm chính sách",
      "70%c · dương tính giả",
      "60%d · đã đóng FP",
      "50%e · lành tính",
    ]);
    expect(screen.getByText("sự cố thật")).toHaveAttribute("data-tone", "high");
    expect(screen.getByText("lành tính")).toHaveAttribute("data-tone", "low");
  });

  it("shows a conclusion it has no label for as it came, as text", () => {
    render(<KnowledgeCandidates rows={[{ pct: 40, title: "t", conclusion: "<b>lạ</b>" }]} />);
    expect(rowTexts()).toEqual(["40%t · <b>lạ</b>"]);
    expect(screen.getByText("<b>lạ</b>")).toHaveAttribute("data-tone", "muted");
  });

  it("names an entry with no title, and leaves out a conclusion that is not there", () => {
    render(<KnowledgeCandidates rows={[{ pct: 33, title: null, conclusion: null }]} />);
    expect(rowTexts()).toEqual(["33%Mục không có tiêu đề"]);
  });

  it("has no axe violation", async () => {
    const { container } = render(<KnowledgeCandidates rows={ROWS} />);
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("Figures", () => {
  it("is a grid of label over value over note", () => {
    render(
      <Figures
        label="Phạm vi"
        items={[
          { label: "Máy", value: "1 máy trạm", note: "phòng nhân sự" },
          { label: "Tài khoản", value: "Administrator" },
        ]}
      />,
    );
    const grid = screen.getByRole("group", { name: "Phạm vi" });
    expect(within(grid).getByText("Máy")).toBeInTheDocument();
    expect(within(grid).getByText("1 máy trạm")).toBeInTheDocument();
    expect(within(grid).getByText("phòng nhân sự")).toBeInTheDocument();
    expect(within(grid).getByText("Administrator")).toBeInTheDocument();
    expect(grid.querySelectorAll("dt")).toHaveLength(2);
    expect(grid.querySelectorAll("dd")).toHaveLength(3);
  });
});

describe("FactRows", () => {
  it("is a list of labels and values, one row each", () => {
    const { container } = render(
      <FactRows
        rows={[
          { label: "Token vào → ra", value: "21.480 → 1.612" },
          { label: "Thời gian", value: "9,8 giây" },
        ]}
      />,
    );
    expect([...container.querySelectorAll("dt")].map((dt) => dt.textContent)).toEqual([
      "Token vào → ra",
      "Thời gian",
    ]);
    expect([...container.querySelectorAll("dd")].map((dd) => dd.textContent)).toEqual([
      "21.480 → 1.612",
      "9,8 giây",
    ]);
  });
});

describe("Card and IconLine", () => {
  it("is a region named by its title", () => {
    render(
      <Card title="Cần lưu ý">
        <p>nội dung</p>
      </Card>,
    );
    const card = screen.getByRole("region", { name: "Cần lưu ý" });
    expect(card).toHaveTextContent("nội dung");
  });

  it("puts what it is given beside the title", () => {
    render(
      <Card title="Tri thức đã duyệt" aside="23 mục được chấm điểm">
        <p>x</p>
      </Card>,
    );
    expect(screen.getByRole("region", { name: "Tri thức đã duyệt" })).toHaveTextContent(
      "23 mục được chấm điểm",
    );
  });

  it("is a line of text beside a mark", () => {
    const { container } = render(<IconLine kind="warn">Một dẫn chứng không khớp.</IconLine>);
    expect(container).toHaveTextContent("Một dẫn chứng không khớp.");
    expect(container.querySelector("svg")).toHaveAttribute("data-kind", "warn");
    // the mark is spoken: a screen reader hears that this is a warning
    expect(screen.getByRole("img", { name: "Cảnh báo" })).toBeInTheDocument();
  });
});
