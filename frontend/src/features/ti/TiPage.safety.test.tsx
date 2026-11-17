// src/features/ti/TiPage.safety.test.tsx — the security rules of the page, against values made to hurt: no IOC field is ever markup, a link,
// a request or an attribute; a hidden character cannot reorder or hide what the analyst reads; the copy keeps the original; and
// nothing on the page reaches a host an IOC names. Every value here is made up (documentation ranges, example.* names).
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import type { TiIoc } from "../../api/ti";
import { S } from "../../strings";
import { tiFixture } from "./fixtures";
import { fake, renderTi, serve } from "./testkit";

const server = setupServer();
const requests: string[] = [];
beforeAll(() => {
  server.events.on("request:start", ({ request }) => {
    requests.push(request.url);
  });
  server.listen({ onUnhandledRequest: "error" });
});
beforeEach(() => {
  requests.length = 0;
});
afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
});
afterAll(() => server.close());

const ready = () => screen.findByRole("table", { name: S.ti.tableLabel });

/** An IOC whose every text field is made to hurt. */
const hostile = (id: number, over: Partial<TiIoc> = {}): TiIoc =>
  tiFixture.ioc({
    id,
    type: "url",
    value: "http://evil.example.com/<img src=x onerror=alert(1)>?q=<script>alert(2)</script>",
    malware: '<img src="http://evil.example.net/m.png" onerror=alert(3)>',
    threat: "<iframe src=http://evil.example.net/t></iframe>",
    tags: ["<b>bold</b>", "javascript:alert(4)", '"><svg onload=alert(5)>'],
    reference: "javascript:alert(6)",
    ...over,
  });

describe("an IOC field is text, never markup", () => {
  it("renders every field of a hostile IOC as characters: no element is made of them, the list and the panel alike", async () => {
    serve(server, fake({ rows: [hostile(1)] }));
    const user = userEvent.setup();
    const view = renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1) }));
    await screen.findByRole("region", { name: S.ti.detail.title(1) });
    for (const tag of [
      "img",
      "script",
      "iframe",
      "svg[onload]",
      "b",
      "object",
      "embed",
      "style",
      "link",
      "input[type=image]",
    ]) {
      // the only SVG elements are the charts' own; none has an onload
      expect(view.container.querySelectorAll(tag), tag).toHaveLength(0);
    }
    for (const attribute of [
      "onerror",
      "onload",
      "onclick",
      "srcset",
      "poster",
      "ping",
      "formaction",
    ]) {
      expect(view.container.querySelectorAll(`[${attribute}]`), attribute).toHaveLength(0);
    }
    const text = view.container.textContent ?? "";
    expect(text).toContain("<b>bold</b>");
    expect(text).toContain("javascript:alert(4)");
    expect(text).toContain('"><svg onload=alert(5)>');
    // the labels (malware, threat, tags) are text as they came: only a value and a reference are defanged
    expect(text).toContain("<iframe src=http://evil.example.net/t></iframe>");
    expect(text).toContain('<img src="http://evil.example.net/m.png" onerror=alert(3)>');
  });

  it("has no src anywhere (no image, no frame, no script, no favicon, nothing to prefetch), and no link but the allow-listed one", async () => {
    serve(
      server,
      fake({ rows: [hostile(1), hostile(2, { reference: "https://evil.example.org/x" })] }),
    );
    const user = userEvent.setup();
    const view = renderTi();
    await ready();
    await user.click(
      screen.getAllByRole("button", { name: /^Xem chi tiết IOC / })[0] as HTMLElement,
    );
    await screen.findByRole("region", { name: S.ti.detail.title(1) });
    expect(view.container.querySelectorAll("[src]")).toHaveLength(0);
    expect(view.container.querySelectorAll("a[href]:not([href^='/threat-intel'])")).toHaveLength(0);
    expect(
      document.querySelectorAll(
        "link[rel~=icon], link[rel~=prefetch], link[rel~=preload], link[rel~=dns-prefetch], link[rel~=preconnect]",
      ),
    ).toHaveLength(0);
  });

  it("does not put an IOC value in a title, an href, a class or any attribute at all", async () => {
    const value = "http://marker-value.example.com/marker-path";
    serve(
      server,
      fake({
        rows: [
          tiFixture.url({
            value,
            malware: "MarkerMalware",
            threat: "marker_threat",
            tags: ["marker-tag"],
            reference: "https://threatfox.abuse.ch/ioc/777/",
          }),
        ],
      }),
    );
    const user = userEvent.setup();
    const view = renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1003) }));
    await screen.findByRole("region", { name: S.ti.detail.title(1003) });
    const hits: string[] = [];
    for (const el of view.container.querySelectorAll("*")) {
      // the one reference link carries abuse.ch's address as its href: it is the allow-listed exception
      for (const attr of el.getAttributeNames()) {
        const val = el.getAttribute(attr) ?? "";
        if (/marker-value|marker-path|MarkerMalware|marker_threat|marker-tag/.test(val))
          hits.push(`${el.tagName}[${attr}]`);
      }
    }
    expect(hits).toEqual([]);
  });
});

describe("nothing reaches a host an IOC names", () => {
  it("makes no request but the API's own, for URLs, domains and addresses of every shape", async () => {
    const rows = [
      tiFixture.url({ id: 1, value: "http://evil.example.com/a.exe" }),
      tiFixture.url({
        id: 2,
        value: "https://evil.example.net/b",
        reference: "https://evil.example.org/ref",
      }),
      tiFixture.domain({ id: 3, value: "evil.example.com" }),
      tiFixture.ioc({ id: 4, value: "203.0.113.50:8080" }),
      tiFixture.ioc({ id: 5, value: "[2001:db8::50]:8080" }),
      hostile(6),
    ];
    serve(server, fake({ rows }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    for (const id of [1, 2, 3, 4, 5, 6]) {
      await user.click(screen.getByRole("button", { name: S.ti.detail.open(id) }));
      await screen.findByRole("region", { name: S.ti.detail.title(id) });
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(requests.length).toBeGreaterThan(0);
    for (const url of requests) {
      expect(new URL(url).pathname, url).toMatch(/^\/api\/ti\/(iocs|stats|status)$/);
      expect(url).not.toMatch(/evil|203\.0\.113\.50|2001:db8/);
    }
  });
});

describe("a hidden character cannot reorder or hide what the analyst reads", () => {
  const RLO = "\u202e";
  const ZWSP = "\u200b";
  const LRI = "\u2066";
  const TAG_A = "\u{e0041}";

  it("prints each one as a visible escape, in the value, the malware, the threat, the tags, the type, the reference and the source", async () => {
    const ioc = tiFixture.ioc({
      id: 1,
      type: `ip${ZWSP}:port`,
      value: `evil${RLO}moc.example.com${ZWSP}`,
      malware: `Ex${LRI}Rat`,
      threat: `bot${TAG_A}net`,
      tags: [`ta${RLO}g`],
      reference: `https://evil.example.org/${RLO}x`,
      source: `threat${ZWSP}fox` as never,
    });
    serve(server, fake({ rows: [ioc] }));
    const user = userEvent.setup();
    const view = renderTi();
    await ready();
    await user.click(screen.getByRole("button", { name: S.ti.detail.open(1) }));
    const box = await screen.findByRole("region", { name: S.ti.detail.title(1) });
    // none of the characters is in the text of the list or of the panel
    expect(view.container.textContent).not.toMatch(/[\u202e\u200b\u2066]|\u{e0041}/u);
    expect(box.textContent).toContain("evil\\u202emoc.example.com\\u200b");
    expect(box.textContent).toContain("Ex\\u2066Rat");
    expect(box.textContent).toContain("bot\\u{e0041}net");
    expect(box.textContent).toContain("ta\\u202eg");
    expect(box.textContent).toContain("ip\\u200b:port");
    expect(box.textContent).toContain("threat\\u200bfox");
    expect(box.textContent).toContain("\\u202ex");
  });

  it("keeps the original in the copy, the hidden characters included", async () => {
    const value = `evil${RLO}moc.example.com${ZWSP}`;
    serve(server, fake({ rows: [tiFixture.domain({ id: 1, value })] }));
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.click(
      within(screen.getByRole("table")).getByRole("button", { name: S.ti.copy.label(1) }),
    );
    expect(await navigator.clipboard.readText()).toBe(value);
  });

  it("shows a name with no hidden character as it is (nothing is stripped that is not hidden)", async () => {
    serve(server, fake({ rows: [tiFixture.ioc({ malware: "Ví dụ Rat — 木马" })] }));
    renderTi();
    await ready();
    expect(screen.getByText("Ví dụ Rat — 木马")).toBeInTheDocument();
  });
});

describe("a value that is already defanged is shown once defanged", () => {
  it("does not defang it twice", async () => {
    serve(
      server,
      fake({
        rows: [
          tiFixture.url({ id: 1, value: "hxxp://evil[.]example[.]com/a" }),
          tiFixture.ioc({ id: 2, value: "203.0.113[.]7:443" }),
        ],
      }),
    );
    renderTi();
    await ready();
    expect(screen.getByText("hxxp://evil[.]example[.]com/a")).toBeInTheDocument();
    expect(screen.getByText("203.0.113[.]7:443")).toBeInTheDocument();
  });
});
