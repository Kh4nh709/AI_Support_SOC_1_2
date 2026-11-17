// src/features/ti/TiPage.export.test.tsx — the export control: the admin's alone (hidden, not just disabled, for the other roles), a
// fetch through the API client with the Bearer header, the answer as a Blob handed to the browser as an object URL under the server's
// fixed file name, and what each refusal says. It is never a plain link to the route, and a file name never comes from data.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { S } from "../../strings";
import { busy, fake, renderTi, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

/** What the browser was asked to save: the object URLs made, the anchors clicked (with their href and download), the URLs revoked. */
const saved: {
  blobs: Blob[];
  clicks: Array<{ href: string; download: string }>;
  revoked: string[];
} = {
  blobs: [],
  clicks: [],
  revoked: [],
};

beforeEach(() => {
  saved.blobs = [];
  saved.clicks = [];
  saved.revoked = [];
  let n = 0;
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    writable: true,
    value: (blob: Blob) => {
      saved.blobs.push(blob);
      n += 1;
      return `blob:http://localhost/ti-${n}`;
    },
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    writable: true,
    value: (url: string) => {
      saved.revoked.push(url);
    },
  });
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    saved.clicks.push({
      href: this.getAttribute("href") ?? "",
      download: this.getAttribute("download") ?? "",
    });
  });
});
afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
});
afterAll(() => server.close());

const ready = () => screen.findByRole("table", { name: S.ti.tableLabel });
const control = () => screen.findByRole("group", { name: S.ti.export.label });
const bytesOf = async (blob: Blob): Promise<number[]> => [
  ...new Uint8Array(await blob.arrayBuffer()),
];

describe("who sees it", () => {
  it("shows the admin both buttons, and the note that a person reads a blocklist before it is used", async () => {
    serve(server, fake());
    renderTi({ role: "admin" });
    await ready();
    const box = await control();
    expect(within(box).getByRole("button", { name: S.ti.export.csv })).toBeEnabled();
    expect(within(box).getByRole("button", { name: S.ti.export.blocklist })).toBeEnabled();
    expect(within(box).getByText(S.ti.export.review)).toBeInTheDocument();
  });

  it.each(["tier1", "tier2"] as const)(
    "hides it from %s: no group, no button, no text, and no request",
    async (role) => {
      const state = fake();
      serve(server, state);
      renderTi({ role });
      await ready();
      expect(screen.queryByRole("group", { name: S.ti.export.label })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: S.ti.export.csv })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: S.ti.export.blocklist })).not.toBeInTheDocument();
      expect(screen.queryByText(S.ti.export.review)).not.toBeInTheDocument();
      expect(screen.queryByText(/xuất/i)).not.toBeInTheDocument();
      expect(state.exports).toHaveLength(0);
    },
  );
});

describe("the download", () => {
  it("fetches the CSV with the Bearer header, and gives the browser an object URL under the fixed file name", async () => {
    const state = fake();
    state.exportAnswer = () =>
      new HttpResponse(new Uint8Array([0xef, 0xbb, 0xbf, 0x69, 0x64, 0x0d, 0x0a]), {
        headers: {
          "content-type": "text/csv; charset=utf-8",
          // a name from the server's header is not the page's to use: the page names its own file
          "content-disposition": 'attachment; filename="../../evil.sh"',
        },
      });
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin" });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
    await waitFor(() => expect(saved.clicks).toHaveLength(1));
    expect(state.exports).toHaveLength(1);
    expect(state.exports[0]?.authorization).toBe("Bearer tok-1");
    expect(state.exports[0]?.url.pathname).toBe("/api/ti/export");
    expect(state.exports[0]?.url.searchParams.get("format")).toBe("csv");
    expect(saved.clicks[0]).toEqual({
      href: "blob:http://localhost/ti-1",
      download: "threat-intel-iocs.csv",
    });
    // the bytes are the server's, the byte order mark included
    expect(await bytesOf(saved.blobs[0] as Blob)).toEqual([
      0xef, 0xbb, 0xbf, 0x69, 0x64, 0x0d, 0x0a,
    ]);
    expect(await screen.findByText(S.ti.export.done("threat-intel-iocs.csv"))).toBeInTheDocument();
  });

  it("names the blocklist threat-intel-blocklist.txt", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin" });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.blocklist }));
    await waitFor(() => expect(saved.clicks).toHaveLength(1));
    expect(state.exports[0]?.url.searchParams.get("format")).toBe("blocklist");
    expect(saved.clicks[0]?.download).toBe("threat-intel-blocklist.txt");
  });

  it("is never a plain link to the route: no anchor to /api/ti/export is ever in the page, before or after", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    const view = renderTi({ role: "admin" });
    await ready();
    const none = () =>
      view.container.querySelectorAll("a[href*='/api/'], a[download], a[href^='blob:']");
    expect(none()).toHaveLength(0);
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
    await waitFor(() => expect(saved.clicks).toHaveLength(1));
    expect(none()).toHaveLength(0);
    // the click was on an anchor that was removed again, and its href was the object URL and nothing else
    expect(saved.clicks[0]?.href).toMatch(/^blob:/);
    expect(saved.clicks[0]?.href).not.toMatch(/api/);
  });

  it("revokes the object URL after the click", async () => {
    serve(server, fake());
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      renderTi({ role: "admin" });
      await ready();
      await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
      await waitFor(() => expect(saved.clicks).toHaveLength(1));
      await vi.advanceTimersByTimeAsync(60_000);
      expect(saved.revoked).toEqual(["blob:http://localhost/ti-1"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("asks for the filters of the list and nothing else: no page, no page_size, no min_confidence for any", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({
      role: "admin",
      entry: "/threat-intel?source=urlhaus&type=url&from=2026-11-01&q=abc&page=3&min_confidence=0",
    });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
    await waitFor(() => expect(state.exports).toHaveLength(1));
    expect(Object.fromEntries(state.exports[0]?.url.searchParams ?? [])).toEqual({
      source: "urlhaus",
      type: "url",
      from: "2026-11-01",
      q: "abc",
      format: "csv",
    });
  });

  it("takes the file name from the format alone, whatever the filters hold", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({
      role: "admin",
      entry: `/threat-intel?q=${encodeURIComponent("../../etc/passwd")}&malware=${encodeURIComponent('x".sh')}`,
    });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
    await waitFor(() => expect(saved.clicks).toHaveLength(1));
    expect(saved.clicks[0]?.download).toBe("threat-intel-iocs.csv");
  });

  it("is disabled and says it is working while the file comes, then is ready again", async () => {
    const state = fake();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    state.exportAnswer = async () => {
      await gate;
      return new HttpResponse("x", { headers: { "content-type": "text/csv" } });
    };
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin" });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
    const working = await within(await control()).findAllByRole("button", {
      name: S.ti.export.working,
    });
    expect(working.length).toBeGreaterThan(0);
    for (const button of within(await control()).getAllByRole("button"))
      expect(button).toBeDisabled();
    release();
    await waitFor(() => expect(saved.clicks).toHaveLength(1));
    await waitFor(() =>
      expect(
        within(screen.getByRole("group", { name: S.ti.export.label })).getByRole("button", {
          name: S.ti.export.csv,
        }),
      ).toBeEnabled(),
    );
  });
});

describe("what a refusal says", () => {
  const run = async (answer: () => Response) => {
    const state = fake();
    state.exportAnswer = answer;
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin" });
    await ready();
    await user.click(within(await control()).getByRole("button", { name: S.ti.export.csv }));
  };

  it("busy: a 503 timeout is 'busy, try again', and nothing is saved", async () => {
    await run(busy);
    expect(await screen.findByText(S.ti.busy)).toBeInTheDocument();
    expect(saved.clicks).toHaveLength(0);
    expect(saved.blobs).toHaveLength(0);
  });

  it("too many rows: a 422 says the cap and to narrow the filters", async () => {
    await run(() =>
      HttpResponse.json(
        { detail: { field: "filters", reason: "too_many_rows", limit: 20000 } },
        { status: 422 },
      ),
    );
    expect(await screen.findByText(S.ti.export.tooMany(20000))).toBeInTheDocument();
    expect(saved.clicks).toHaveLength(0);
  });

  it("forbidden: a 403 says only an admin exports", async () => {
    await run(() => HttpResponse.json({ detail: "forbidden" }, { status: 403 }));
    expect(await screen.findByText(S.ti.export.forbidden)).toBeInTheDocument();
  });

  it("any other failure is the generic words, and the buttons are back", async () => {
    await run(() => HttpResponse.json({ detail: "boom" }, { status: 500 }));
    expect(await screen.findByText(S.ti.export.failed)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.ti.export.csv })).toBeEnabled();
    expect(saved.clicks).toHaveLength(0);
  });
});

// TI12 M4: the export is for the filters that are APPLIED (the URL's), not for what is typed in the form. While the form says something
// else the buttons are shut with a hint, so a blocklist is never made for filters nobody applied.
describe("the export is for the applied filters", () => {
  const form = () => screen.getByRole("search", { name: S.ti.filters.label });
  const buttons = async () => {
    const box = await control();
    return {
      csv: within(box).getByRole("button", { name: S.ti.export.csv }),
      blocklist: within(box).getByRole("button", { name: S.ti.export.blocklist }),
    };
  };

  it("says in its label that it is for the applied filters", async () => {
    serve(server, fake());
    renderTi({ role: "admin" });
    await ready();
    const box = await control();
    expect(S.ti.export.scope(20000)).toMatch(/bộ lọc đã áp dụng/);
    expect(within(box).getByText(S.ti.export.scope(20000))).toBeInTheDocument();
    expect(within(box).queryByText(S.ti.export.unapplied)).not.toBeInTheDocument();
  });

  it("shuts both buttons, with a hint, while the form holds a filter that is not applied, and opens them when it is sent", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin", entry: "/threat-intel?source=urlhaus" });
    await ready();
    expect((await buttons()).csv).toBeEnabled();
    await user.selectOptions(
      within(form()).getByLabelText(S.ti.filters.source),
      S.ti.source.threatfox,
    );
    const shut = await buttons();
    expect(shut.csv).toBeDisabled();
    expect(shut.blocklist).toBeDisabled();
    const hint = within(await control()).getByText(S.ti.export.unapplied);
    expect(shut.csv).toHaveAccessibleDescription(S.ti.export.unapplied);
    expect(hint).toBeInTheDocument();
    // pressing a shut button asks for nothing
    await user.click(shut.csv);
    await user.click(shut.blocklist);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(state.exports).toHaveLength(0);
    // sent: the view is the form's, and the export is for it
    await user.click(within(form()).getByRole("button", { name: S.ti.filters.apply }));
    await waitFor(async () => expect((await buttons()).csv).toBeEnabled());
    expect(within(await control()).queryByText(S.ti.export.unapplied)).not.toBeInTheDocument();
    await user.click((await buttons()).csv);
    await waitFor(() => expect(state.exports).toHaveLength(1));
    expect(state.exports[0]?.url.searchParams.get("source")).toBe("threatfox");
  });

  it("shuts them for a typed search too, and for a date, a type, a malware and a confidence; and never exports what is typed", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ role: "admin" });
    await ready();
    await user.type(within(form()).getByLabelText(S.ti.filters.search), "typed but not sent");
    expect((await buttons()).blocklist).toBeDisabled();
    await user.clear(within(form()).getByLabelText(S.ti.filters.search));
    expect((await buttons()).blocklist).toBeEnabled();
    for (const [label, value] of [
      [S.ti.filters.type, "domain"],
      [S.ti.filters.malware, "Example.Rat"],
      [S.ti.filters.confidence, "75"],
    ] as const) {
      const field = within(form()).getByLabelText(label);
      await user.type(field, value);
      expect((await buttons()).csv, label).toBeDisabled();
      await user.clear(field);
      expect((await buttons()).csv, label).toBeEnabled();
    }
    expect(state.exports).toHaveLength(0);
  });

  it("is not shut by a difference that is no difference: white space, a 0 for any confidence, the same text again", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi({ role: "admin", entry: "/threat-intel?q=abc" });
    await ready();
    const search = within(form()).getByLabelText(S.ti.filters.search);
    await user.type(search, "  ");
    expect((await buttons()).csv).toBeEnabled();
    await user.clear(search);
    await user.type(search, "  abc  ");
    expect((await buttons()).csv).toBeEnabled();
    await user.type(within(form()).getByLabelText(S.ti.filters.confidence), "0");
    expect((await buttons()).csv).toBeEnabled();
  });

  it("opens again when the form is cleared with Xoá bộ lọc, and the form goes back to what is applied", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi({ role: "admin", entry: "/threat-intel?source=urlhaus" });
    await ready();
    await user.selectOptions(
      within(form()).getByLabelText(S.ti.filters.source),
      S.ti.source.malwarebazaar,
    );
    expect((await buttons()).csv).toBeDisabled();
    await user.click(within(form()).getByRole("button", { name: S.ti.filters.clear }));
    await waitFor(async () => expect((await buttons()).csv).toBeEnabled());
    expect((within(form()).getByLabelText(S.ti.filters.source) as HTMLSelectElement).value).toBe(
      "",
    );
  });

  it("is not shut for a tier that has no export at all (nothing is there to shut)", async () => {
    serve(server, fake());
    const user = userEvent.setup();
    renderTi({ role: "tier1" });
    await ready();
    await user.type(within(form()).getByLabelText(S.ti.filters.search), "x");
    expect(screen.queryByText(S.ti.export.unapplied)).not.toBeInTheDocument();
  });
});
