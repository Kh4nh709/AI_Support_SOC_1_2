// src/live/socket.test.ts — the /api/ws client with a fake WebSocket class: auth as the first frame, ready
// makes it live, a close makes it offline and reconnects with a backoff, and the token is never in the URL.
import { BACKOFF_BASE_MS, BACKOFF_MAX_MS, connectLive, liveUrl } from "./socket";

/** The part of a browser WebSocket that socket.ts touches, driven from the test. */
class FakeSocket extends EventTarget {
  static all: FakeSocket[] = [];
  static failToConstruct = false;
  readonly url: string;
  readonly sent: string[] = [];
  closedWith: number | null = null;

  constructor(url: string | URL) {
    super();
    if (FakeSocket.failToConstruct) throw new DOMException("blocked", "SecurityError");
    this.url = String(url);
    FakeSocket.all.push(this);
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(code = 1000): void {
    this.closedWith = code;
  }
  // The server's side of the wire.
  open(): void {
    this.dispatchEvent(new Event("open"));
  }
  say(payload: unknown): void {
    const data = typeof payload === "string" ? payload : JSON.stringify(payload);
    this.dispatchEvent(new MessageEvent("message", { data }));
  }
  drop(code = 1006): void {
    this.dispatchEvent(new CloseEvent("close", { code }));
  }
}

const last = (): FakeSocket => {
  const socket = FakeSocket.all.at(-1);
  if (!socket) throw new Error("no socket was opened");
  return socket;
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal("WebSocket", FakeSocket);
  FakeSocket.all = [];
  FakeSocket.failToConstruct = false;
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function start(token: string | null | (() => string | null) = "t") {
  const changes: (string[] | "many")[] = [];
  const statuses: string[] = [];
  const unauthorized: string[] = [];
  const disconnect = connectLive({
    token: typeof token === "function" ? token : () => token,
    onChange: (ids) => changes.push(ids),
    onStatus: (s) => statuses.push(s),
    onUnauthorized: (sent) => unauthorized.push(sent),
  });
  return { changes, statuses, unauthorized, disconnect };
}

describe("the first frame", () => {
  it("sends {type:auth, token} once the socket is open, and nothing before", () => {
    start("t");
    expect(last().sent).toEqual([]);
    last().open();
    expect(last().sent).toEqual(['{"type":"auth","token":"t"}']);
  });

  it("reads the token when the socket opens, so a reconnect sends the newer one", () => {
    let token = "old";
    start(() => token);
    last().open();
    expect(JSON.parse(last().sent[0] ?? "null")).toEqual({ type: "auth", token: "old" });
    last().drop();
    token = "new";
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    last().open();
    expect(JSON.parse(last().sent[0] ?? "null")).toEqual({ type: "auth", token: "new" });
  });

  it("sends nothing and stays quiet when there is no token any more", () => {
    const { statuses } = start(null);
    last().open();
    expect(last().sent).toEqual([]);
    expect(last().closedWith).not.toBeNull();
    last().drop();
    vi.advanceTimersByTime(BACKOFF_MAX_MS * 2);
    expect(FakeSocket.all).toHaveLength(1); // no session, no reconnect
    expect(statuses).not.toContain("live");
  });
});

describe("the URL", () => {
  it("never contains the token, and carries no query at all", () => {
    start("s3cret-token-value");
    const url = last().url;
    expect(url).not.toContain("s3cret-token-value");
    expect(url).not.toContain("token");
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/api/ws");
    expect(parsed.search).toBe("");
    expect(parsed.hash).toBe("");
    expect(parsed.username).toBe("");
    expect(parsed.password).toBe("");
  });

  it("is on the page's own host, ws on http and wss on https", () => {
    expect(liveUrl({ protocol: "http:", host: "127.0.0.1:8080" })).toBe("ws://127.0.0.1:8080/api/ws");
    expect(liveUrl({ protocol: "https:", host: "soc.example" })).toBe("wss://soc.example/api/ws");
  });

  it("opens the URL it is given", () => {
    connectLive({
      token: () => "t",
      onChange: () => {},
      onStatus: () => {},
      url: "ws://elsewhere.test/api/ws",
    });
    expect(last().url).toBe("ws://elsewhere.test/api/ws");
  });
});

describe("the status", () => {
  it("becomes live on ready, not on open", () => {
    const { statuses } = start();
    last().open();
    expect(statuses).not.toContain("live");
    last().say({ type: "ready" });
    expect(statuses.at(-1)).toBe("live");
  });

  it("goes offline on a close, and reconnects after a backoff", () => {
    const { statuses } = start();
    last().open();
    last().say({ type: "ready" });
    last().drop(1006);
    expect(statuses).toEqual(["live", "offline"]);
    expect(FakeSocket.all).toHaveLength(1);
    vi.advanceTimersByTime(BACKOFF_BASE_MS - 1);
    expect(FakeSocket.all).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("does not repeat a status it has already given", () => {
    const { statuses } = start();
    last().open();
    last().say({ type: "ready" });
    last().say({ type: "ready" });
    last().drop();
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    last().drop(); // the second attempt fails before it was ever live
    expect(statuses).toEqual(["live", "offline"]);
  });

  it("doubles the wait after each failure, up to a ceiling, and starts over after a ready", () => {
    start();
    const waits: number[] = [];
    for (let i = 0; i < 8; i++) {
      const before = FakeSocket.all.length;
      last().drop();
      let waited = 0;
      while (FakeSocket.all.length === before) {
        vi.advanceTimersByTime(250);
        waited += 250;
      }
      waits.push(waited);
    }
    expect(waits).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
    last().open();
    last().say({ type: "ready" });
    last().drop();
    const before = FakeSocket.all.length;
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    expect(FakeSocket.all.length).toBe(before + 1);
  });

  it("treats a server outage (1011) like any other drop and reconnects", () => {
    const { statuses } = start();
    last().open();
    last().say({ type: "ready" });
    last().drop(1011);
    expect(statuses.at(-1)).toBe("offline");
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("keeps trying when the socket cannot even be built", () => {
    FakeSocket.failToConstruct = true;
    const { statuses } = start();
    expect(statuses).toEqual(["offline"]);
    FakeSocket.failToConstruct = false;
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    expect(FakeSocket.all).toHaveLength(1);
  });
});

describe("a refusal", () => {
  it("4401 ends the session: offline, reported with the token that was sent, and never retried", () => {
    const { statuses, unauthorized } = start("tok-9");
    last().open();
    last().drop(4401);
    expect(statuses.at(-1)).toBe("offline");
    expect(unauthorized).toEqual(["tok-9"]);
    vi.advanceTimersByTime(BACKOFF_MAX_MS * 3);
    expect(FakeSocket.all).toHaveLength(1);
  });

  it("4403 (role not allowed) is offline and is not retried either, but it is not a 401", () => {
    const { statuses, unauthorized } = start();
    last().open();
    last().drop(4403);
    expect(statuses.at(-1)).toBe("offline");
    expect(unauthorized).toEqual([]);
    vi.advanceTimersByTime(BACKOFF_MAX_MS * 3);
    expect(FakeSocket.all).toHaveLength(1);
  });
});

describe("the changes", () => {
  it("hands over the ids of an alerts.changed message", () => {
    const { changes } = start();
    last().open();
    last().say({ type: "ready" });
    last().say({ type: "alerts.changed", ids: ["a1", "a2"] });
    expect(changes).toEqual([["a1", "a2"]]);
  });

  it("hands over 'many' when the server says a burst was coalesced", () => {
    const { changes } = start();
    last().open();
    last().say({ type: "ready" });
    last().say({ type: "alerts.changed", many: true });
    expect(changes).toEqual(["many"]);
  });

  it("keeps only the string ids and drops a message that has none", () => {
    const { changes } = start();
    last().open();
    last().say({ type: "ready" });
    last().say({ type: "alerts.changed", ids: ["a1", 7, null, { x: 1 }, "a2"] });
    last().say({ type: "alerts.changed", ids: [] });
    last().say({ type: "alerts.changed", ids: [1, 2] });
    expect(changes).toEqual([["a1", "a2"]]);
  });

  it("ignores what it does not understand: bad JSON, other types, other shapes, a non-text frame", () => {
    const { changes, statuses } = start();
    last().open();
    last().say({ type: "ready" });
    last().say("{not json");
    last().say("null");
    last().say("[]");
    last().say('"alerts.changed"');
    last().say({ type: "alerts.changed" });
    last().say({ type: "alerts.changed", ids: "a1" });
    last().say({ type: "alerts.changed", many: "yes" });
    last().say({ type: "cases.changed", ids: ["c1"] });
    last().dispatchEvent(new MessageEvent("message", { data: new ArrayBuffer(4) }));
    expect(changes).toEqual([]);
    expect(statuses).toEqual(["live"]);
  });

  it("ignores a change that arrives before ready", () => {
    const { changes } = start();
    last().open();
    last().say({ type: "alerts.changed", ids: ["a1"] });
    expect(changes).toEqual([]);
  });
});

describe("disconnect", () => {
  it("closes the socket and calls nothing afterwards", () => {
    const { changes, statuses, disconnect } = start();
    const socket = last();
    socket.open();
    socket.say({ type: "ready" });
    disconnect();
    expect(socket.closedWith).toBe(1000);
    socket.say({ type: "alerts.changed", ids: ["a1"] });
    socket.drop(1006);
    expect(changes).toEqual([]);
    expect(statuses).toEqual(["live"]);
  });

  it("cancels a reconnect that was waiting", () => {
    const { disconnect } = start();
    last().drop();
    disconnect();
    vi.advanceTimersByTime(BACKOFF_MAX_MS * 2);
    expect(FakeSocket.all).toHaveLength(1);
  });

  it("is safe to call twice", () => {
    const { disconnect } = start();
    disconnect();
    expect(() => disconnect()).not.toThrow();
  });

  it("ignores the events of a socket it has already replaced", () => {
    const { statuses } = start();
    const first = last();
    first.drop();
    vi.advanceTimersByTime(BACKOFF_BASE_MS);
    const second = last();
    second.open();
    second.say({ type: "ready" });
    first.drop(1006); // a late close of the old socket
    expect(statuses.at(-1)).toBe("live");
  });
});
