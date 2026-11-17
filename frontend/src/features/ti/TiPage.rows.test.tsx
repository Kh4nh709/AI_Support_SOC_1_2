// src/features/ti/TiPage.rows.test.tsx — the rows and the detail panel: what each cell prints (a value defanged by its type, a missing
// confidence as a dash), the copy button (the ORIGINAL value, and a fallback when the clipboard refuses), and the one link of the page.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import type { TiIoc } from "../../api/ti";
import { S } from "../../strings";
import { tiFixture } from "./fixtures";
import { fake, renderTi, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
});
afterAll(() => server.close());

const ready = () => screen.findByRole("table", { name: S.ti.tableLabel });
const rowOf = (id: number): HTMLElement =>
  screen.getByRole("button", { name: S.ti.detail.open(id) }).closest("tr") as HTMLElement;
const panel = (id: number) => screen.findByRole("region", { name: S.ti.detail.title(id) });

describe("the table", () => {
  it("has the columns, and one row per IOC in the order served", async () => {
    serve(server, fake());
    renderTi();
    const table = await ready();
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      S.ti.col.time,
      S.ti.col.source,
      S.ti.col.type,
      S.ti.col.value,
      S.ti.col.malware,
      S.ti.col.confidence,
      S.ti.col.tags,
      S.ti.col.copy,
    ]);
    const buttons = within(table).getAllByRole("button", { name: /^Xem chi tiết IOC / });
    expect(buttons.map((b) => b.getAttribute("aria-label"))).toEqual([
      S.ti.detail.open(1001),
      S.ti.detail.open(1002),
      S.ti.detail.open(1003),
      S.ti.detail.open(1004),
    ]);
  });

  it("prints each value defanged by its type, a hash as it is", async () => {
    serve(server, fake());
    renderTi();
    await ready();
    expect(within(rowOf(1001)).getByText("203.0.113[.]7:443")).toBeInTheDocument();
    expect(
      within(rowOf(1002)).getByText(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      ),
    ).toBeInTheDocument();
    expect(
      within(rowOf(1003)).getByText("hxxp://payload[.]example[.]com/bin/a.exe"),
    ).toBeInTheDocument();
    expect(within(rowOf(1004)).getByText("c2[.]example[.]net")).toBeInTheDocument();
    // the original is nowhere in the text of the table
    expect(screen.getByRole("table").textContent).not.toContain("http://payload.example.com");
    expect(screen.getByRole("table").textContent).not.toContain("203.0.113.7:443");
  });

  it("prints the time in GMT+7, the source and type, the malware and the confidence", async () => {
    serve(server, fake());
    renderTi();
    await ready();
    const row = within(rowOf(1001));
    // 02:15:30Z is 09:15 in GMT+7
    expect(row.getByText("17/11 09:15")).toBeInTheDocument();
    expect(row.getByText(S.ti.source.threatfox)).toBeInTheDocument();
    expect(row.getByText("ip:port")).toBeInTheDocument();
    expect(row.getByText("Example.Rat")).toBeInTheDocument();
    expect(row.getByText("90")).toBeInTheDocument();
  });

  it("prints a missing confidence as a dash, never as 0", async () => {
    serve(server, fake());
    renderTi();
    await ready();
    const cells = within(rowOf(1002)).getAllByRole("cell");
    const confidence = cells[5] as HTMLElement;
    expect(confidence.textContent).toBe(S.common.missing);
    expect(confidence.textContent).not.toMatch(/0/);
  });

  it("shows the first tags and counts the rest, each tag as text", async () => {
    const many = Array.from({ length: 32 }, (_, i) => `tag${i}`);
    serve(server, fake({ rows: [tiFixture.ioc({ tags: many })] }));
    renderTi();
    await ready();
    const row = within(rowOf(1001));
    expect(row.getByText("tag0")).toBeInTheDocument();
    expect(row.getByText("tag2")).toBeInTheDocument();
    expect(row.queryByText("tag3")).not.toBeInTheDocument();
    expect(row.getByText(S.ti.moreTags(29))).toBeInTheDocument();
  });

  it("wraps a value of 2 048 characters inside its cell and cuts it to a few lines, the table scrolls and the page does not break", async () => {
    const long = `http://long.example.com/${"a".repeat(2048 - 24)}`;
    expect(long).toHaveLength(2048);
    serve(server, fake({ rows: [tiFixture.url({ value: long })] }));
    renderTi();
    const table = await ready();
    const cell = screen
      .getByRole("button", { name: S.ti.detail.open(1003) })
      .closest("td") as HTMLElement;
    expect(cell.className).toMatch(/wrap-anywhere/);
    expect(cell.className).toMatch(/max-w-/);
    expect(within(cell).getByText(/^hxxp:\/\/long\[\.\]example\[\.\]com\/a+$/).className).toMatch(
      /line-clamp-/,
    );
    // inside the data table's own scroll box
    expect(table.parentElement?.className).toMatch(/overflow-x-auto/);
  });
});

describe("the copy button", () => {
  const copyButton = (id: number) =>
    within(rowOf(id)).getByRole("button", { name: S.ti.copy.label(id) });

  it("copies the ORIGINAL value, not the defanged text: a URL, an ip:port, a domain and a hash", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    const original: Array<[number, string]> = [
      [1003, "http://payload.example.com/bin/a.exe"],
      [1001, "203.0.113.7:443"],
      [1004, "c2.example.net"],
      [1002, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
    ];
    for (const [id, value] of original) {
      await user.click(copyButton(id));
      expect(await navigator.clipboard.readText(), String(id)).toBe(value);
    }
  });

  it("says it was copied", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(copyButton(1001));
    expect(await within(rowOf(1001)).findByText(S.ti.copy.copied)).toBeInTheDocument();
  });

  it("copies the original value exactly, a hidden character and a long value included", async () => {
    const odd = "evil\u202e.example.com\u200b/x";
    serve(server, fake({ rows: [tiFixture.url({ value: odd })] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(copyButton(1003));
    expect(await navigator.clipboard.readText()).toBe(odd);
  });

  it("falls back to selecting the original value when the clipboard refuses", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    await user.click(copyButton(1003));
    const box = (await within(rowOf(1003)).findByLabelText(S.ti.copy.boxLabel)) as HTMLInputElement;
    expect(box.value).toBe("http://payload.example.com/bin/a.exe");
    expect(box.readOnly).toBe(true);
    expect(box.selectionStart).toBe(0);
    expect(box.selectionEnd).toBe(box.value.length);
    expect(box).toHaveFocus();
    expect(within(rowOf(1003)).getByText(S.ti.copy.fallback)).toBeInTheDocument();
    expect(within(rowOf(1003)).queryByText(S.ti.copy.copied)).not.toBeInTheDocument();
  });

  it("falls back the same way when there is no clipboard API at all (a page served over plain http)", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    await user.click(copyButton(1001));
    const box = (await within(rowOf(1001)).findByLabelText(S.ti.copy.boxLabel)) as HTMLInputElement;
    expect(box.value).toBe("203.0.113.7:443");
    expect(box.selectionEnd).toBe(box.value.length);
  });

  it("closes the box when it loses the focus", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    await user.click(copyButton(1001));
    await within(rowOf(1001)).findByLabelText(S.ti.copy.boxLabel);
    await user.tab();
    await waitFor(() =>
      expect(within(rowOf(1001)).queryByLabelText(S.ti.copy.boxLabel)).not.toBeInTheDocument(),
    );
  });
});

describe("the detail panel", () => {
  it("opens from a row with every field, and the value defanged", async () => {
    const ioc = tiFixture.ioc({ tags: ["rat", "c2"], hit_count: 0, last_hit: null });
    serve(server, fake({ rows: [ioc] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1001) }));
    const box = await panel(1001);
    const F = S.ti.detail.field;
    const dd = (label: string): string => {
      const term = within(box).getByText(label, { selector: "dt" });
      return (term.nextElementSibling as HTMLElement).textContent ?? "";
    };
    expect(dd(F.id)).toBe("1001");
    expect(dd(F.value)).toContain("203.0.113[.]7:443");
    expect(dd(F.type)).toBe("ip:port");
    expect(dd(F.source)).toBe(S.ti.source.threatfox);
    expect(dd(F.malware)).toBe("Example.Rat");
    expect(dd(F.threat)).toBe("botnet_cc");
    expect(dd(F.confidence)).toBe("90");
    expect(dd(F.tags)).toBe("rat, c2");
    expect(dd(F.firstSeen)).toBe("17/11/2026 09:15:30");
    expect(dd(F.lastSeen)).toBe("17/11/2026 07:10:05");
    expect(dd(F.importedAt)).toBe("17/11/2026 07:10:05");
    expect(dd(F.expiresAt)).toBe("17/12/2026 07:10:05");
    expect(dd(F.hitCount)).toBe("0");
    expect(dd(F.lastHit)).toBe(S.common.missing);
    expect(dd(F.reference)).toContain(S.ti.detail.reference.open);
    // the original value is not in the panel's text: the copy button is the way to it
    expect(box.textContent).not.toContain("203.0.113.7:443");
  });

  it("shows a missing confidence, malware, threat, tags and reference as a dash or a word, never as 0 or blank", async () => {
    const bare = tiFixture.hash({
      malware: null,
      threat: null,
      confidence: null,
      tags: [],
      reference: null,
    });
    serve(server, fake({ rows: [bare] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1002) }));
    const box = await panel(1002);
    const F = S.ti.detail.field;
    const dd = (label: string): string =>
      (within(box).getByText(label, { selector: "dt" }).nextElementSibling as HTMLElement)
        .textContent ?? "";
    expect(dd(F.confidence)).toBe(S.common.missing);
    expect(dd(F.malware)).toBe(S.common.missing);
    expect(dd(F.threat)).toBe(S.common.missing);
    expect(dd(F.reference)).toBe(S.common.missing);
    expect(dd(F.tags)).toBe(S.ti.detail.noTags);
  });

  it("lists all thirty-two tags, each as text", async () => {
    const many = Array.from({ length: 32 }, (_, i) => `tag${i}`);
    serve(server, fake({ rows: [tiFixture.ioc({ tags: many })] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1001) }));
    const box = await panel(1001);
    expect(box.textContent).toContain("tag31");
    expect(box.textContent).toContain("tag0");
  });

  it("has a copy button of its own, which copies the original value", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1003) }));
    const box = await panel(1003);
    await user.click(within(box).getByRole("button", { name: S.ti.copy.label(1003) }));
    expect(await navigator.clipboard.readText()).toBe("http://payload.example.com/bin/a.exe");
  });

  it("closes with its button and with Escape, and gives the focus back to the row it came from", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    const opener = screen.getByRole("button", { name: S.ti.detail.open(1001) });
    await user.click(opener);
    const box = await panel(1001);
    await user.click(within(box).getByRole("button", { name: S.ti.detail.close }));
    expect(screen.queryByRole("region", { name: S.ti.detail.title(1001) })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    await user.click(opener);
    await panel(1001);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("region", { name: S.ti.detail.title(1001) })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("moves to another IOC when another row is pressed", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1001) }));
    await panel(1001);
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1004) }));
    await panel(1004);
    expect(screen.queryByRole("region", { name: S.ti.detail.title(1001) })).not.toBeInTheDocument();
  });

  it("stays open when the list moves to another page, and does not need the list to keep its IOC", async () => {
    const state = fake({ total: 120 });
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1001) }));
    await panel(1001);
    state.rows = [tiFixture.ioc({ id: 2001, value: "198.51.100.9:80" })];
    const nav = await screen.findByRole("navigation", { name: S.ti.pagination });
    await user.click(within(nav).getByRole("link", { name: S.ti.page(2) }));
    await screen.findByText("198.51.100[.]9:80");
    expect(screen.getByRole("region", { name: S.ti.detail.title(1001) })).toBeInTheDocument();
  });
});

describe("the reference", () => {
  const referenceOf = async (reference: string | null, over: Partial<TiIoc> = {}) => {
    serve(server, fake({ rows: [tiFixture.ioc({ reference, ...over })] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1001) }));
    return panel(1001);
  };

  it.each([
    "https://threatfox.abuse.ch/ioc/1000001/",
    "https://urlhaus.abuse.ch/url/2000001/",
    "https://bazaar.abuse.ch/sample/0123456789abcdef/",
  ])("is a link, opened in a new tab with rel noopener noreferrer, for %s", async (reference) => {
    const box = await referenceOf(reference);
    const link = within(box).getByRole("link", { name: new RegExp(S.ti.detail.reference.open) });
    expect(link).toHaveAttribute("href", reference);
    expect(link).toHaveAttribute("target", "_blank");
    const rel = (link.getAttribute("rel") ?? "").split(/\s+/);
    expect(rel).toContain("noopener");
    expect(rel).toContain("noreferrer");
    // no other link in the panel
    expect(within(box).getAllByRole("link")).toHaveLength(1);
  });

  it.each([
    [
      "a look-alike host",
      "https://threatfox.abuse.ch.evil.example/ioc/1/",
      "hxxps://threatfox[.]abuse[.]ch[.]evil[.]example/ioc/1/",
    ],
    [
      "the name in the path only",
      "https://evil.example/threatfox.abuse.ch",
      "hxxps://evil[.]example/threatfox.abuse.ch",
    ],
    ["http, not https", "http://threatfox.abuse.ch/ioc/1/", "hxxp://threatfox[.]abuse[.]ch/ioc/1/"],
    [
      "a user in front",
      "https://threatfox.abuse.ch@evil.example/",
      "hxxps://threatfox[.]abuse[.]ch@evil[.]example/",
    ],
    [
      "another port",
      "https://threatfox.abuse.ch:8443/ioc/1/",
      "hxxps://threatfox[.]abuse[.]ch:8443/ioc/1/",
    ],
    ["javascript:", "javascript:alert(1)", "javascript:alert(1)"],
    [
      "a markup value",
      "<a href=https://threatfox.abuse.ch/>x</a>",
      "<a href=hxxps://threatfox[.]abuse[.]ch/>x</a>",
    ],
  ])("is defanged text and no link for %s", async (_name, reference, shown) => {
    const box = await referenceOf(reference);
    expect(within(box).queryByRole("link")).not.toBeInTheDocument();
    expect(box.querySelector("a")).toBeNull();
    const dd = within(box).getByText(S.ti.detail.field.reference, { selector: "dt" })
      .nextElementSibling as HTMLElement;
    expect(dd.textContent).toContain(shown);
    expect(within(dd).getByText(S.ti.detail.reference.notLinked)).toBeInTheDocument();
  });
});
