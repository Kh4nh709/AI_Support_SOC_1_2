// src/auth/session.test.ts — the session lives in memory, sessionStorage and a BroadcastChannel; never in
// the persistent store (spec §3, §6). A second `BroadcastChannel` instance here plays the second tab.
import {
  clearSession,
  forgetSession,
  loadSession,
  requestSessionFromOtherTabs,
  saveSession,
  startSessionSharing,
  type Session,
} from "./session";

const KEY = "soc.session";
const CHANNEL = "soc-session";
const HOUR = 3_600_000;

const SESSION: Session = {
  token: "tok-1",
  role: "tier1",
  username: "an",
  expiresAt: new Date(Date.now() + 8 * HOUR).toISOString(),
};

let tabs: BroadcastChannel[] = [];
/** A second tab: its own channel instance, collecting what it hears. */
function otherTab(): { channel: BroadcastChannel; heard: unknown[] } {
  const channel = new BroadcastChannel(CHANNEL);
  const heard: unknown[] = [];
  channel.onmessage = (e) => heard.push(e.data);
  tabs.push(channel);
  return { channel, heard };
}

const settle = (ms = 60) => new Promise((resolve) => setTimeout(resolve, ms));

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});
afterEach(() => {
  for (const t of tabs) t.close();
  tabs = [];
});

describe("saveSession and loadSession", () => {
  it("writes the session to sessionStorage and to nothing persistent", () => {
    saveSession(SESSION);
    expect(JSON.parse(sessionStorage.getItem(KEY) ?? "null")).toEqual(SESSION);
    expect(localStorage.length).toBe(0);
    expect(loadSession()).toEqual(SESSION);
  });

  it("loads an expired session as null, and drops it", () => {
    saveSession({ ...SESSION, expiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(loadSession()).toBeNull();
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("loads nothing from a missing, unreadable or malformed entry", () => {
    expect(loadSession()).toBeNull();
    sessionStorage.setItem(KEY, "{not json");
    expect(loadSession()).toBeNull();
    for (const bad of [
      { ...SESSION, role: "root" },
      { ...SESSION, token: "" },
      { ...SESSION, token: 7 },
      { ...SESSION, expiresAt: "soon" },
      { role: "tier1" },
      "tok-1",
      null,
    ]) {
      sessionStorage.setItem(KEY, JSON.stringify(bad));
      expect(loadSession(), JSON.stringify(bad)).toBeNull();
    }
  });
});

describe("clearSession", () => {
  it("empties the storage and posts {type:'logout'} on the channel", async () => {
    const { heard } = otherTab();
    saveSession(SESSION);
    clearSession();
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(loadSession()).toBeNull();
    await vi.waitFor(() => expect(heard).toContainEqual({ type: "logout" }));
  });

  it("forgetSession empties this tab only and says nothing to the others", async () => {
    const { heard } = otherTab();
    saveSession(SESSION);
    forgetSession();
    expect(sessionStorage.getItem(KEY)).toBeNull();
    await settle();
    expect(heard).toEqual([]);
  });
});

describe("startSessionSharing", () => {
  it("answers {type:'session-request'} of a second tab with the stored session", async () => {
    const stop = startSessionSharing(() => {});
    const { channel, heard } = otherTab();
    saveSession(SESSION);
    channel.postMessage({ type: "session-request" });
    await vi.waitFor(() => expect(heard).toContainEqual({ type: "session", session: SESSION }));
    stop();
  });

  it("stays silent when this tab has no session, or an expired one", async () => {
    const stop = startSessionSharing(() => {});
    const { channel, heard } = otherTab();
    channel.postMessage({ type: "session-request" });
    await settle();
    sessionStorage.setItem(
      KEY,
      JSON.stringify({ ...SESSION, expiresAt: new Date(Date.now() - 1000).toISOString() }),
    );
    channel.postMessage({ type: "session-request" });
    await settle();
    expect(heard).toEqual([]);
    stop();
  });

  it("closes this tab's session on {type:'logout'} and does not broadcast it again", async () => {
    const onLogout = vi.fn();
    const stop = startSessionSharing(onLogout);
    const { channel, heard } = otherTab();
    saveSession(SESSION);
    channel.postMessage({ type: "logout" });
    await vi.waitFor(() => expect(onLogout).toHaveBeenCalledTimes(1));
    expect(sessionStorage.getItem(KEY)).toBeNull();
    await settle();
    expect(heard).toEqual([]); // a rebroadcast would ping-pong between the tabs
    stop();
  });

  it("ignores what is not a message of the protocol, and stops when told to", async () => {
    const onLogout = vi.fn();
    const stop = startSessionSharing(onLogout);
    const { channel, heard } = otherTab();
    saveSession(SESSION);
    for (const junk of [null, "logout", 7, { type: "nonsense" }, { kind: "logout" }]) {
      channel.postMessage(junk);
    }
    await settle();
    expect(onLogout).not.toHaveBeenCalled();
    expect(heard).toEqual([]);
    stop();
    channel.postMessage({ type: "logout" });
    await settle();
    expect(onLogout).not.toHaveBeenCalled();
    expect(loadSession()).toEqual(SESSION);
  });
});

describe("requestSessionFromOtherTabs", () => {
  it("returns the session another tab answers with", async () => {
    const { channel } = otherTab();
    channel.onmessage = (e) => {
      if ((e.data as { type?: string }).type === "session-request") {
        channel.postMessage({ type: "session", session: SESSION });
      }
    };
    await expect(requestSessionFromOtherTabs(1000)).resolves.toEqual(SESSION);
  });

  it("returns null when no tab answers within the timeout", async () => {
    const started = Date.now();
    await expect(requestSessionFromOtherTabs(80)).resolves.toBeNull();
    expect(Date.now() - started).toBeGreaterThanOrEqual(70);
  });

  it("does not take an expired or malformed answer for a session", async () => {
    const { channel } = otherTab();
    channel.onmessage = (e) => {
      if ((e.data as { type?: string }).type !== "session-request") return;
      channel.postMessage({
        type: "session",
        session: { ...SESSION, expiresAt: new Date(Date.now() - 1000).toISOString() },
      });
      channel.postMessage({ type: "session", session: { token: "x" } });
      channel.postMessage({ type: "session" });
    };
    await expect(requestSessionFromOtherTabs(150)).resolves.toBeNull();
  });

  it("stops waiting when its signal aborts", async () => {
    const ac = new AbortController();
    const pending = requestSessionFromOtherTabs(5000, ac.signal);
    ac.abort();
    await expect(pending).resolves.toBeNull();
  });

  it("two tabs, end to end: the new tab gets the open tab's session", async () => {
    saveSession(SESSION);
    const stop = startSessionSharing(() => {});
    await expect(requestSessionFromOtherTabs(1000)).resolves.toEqual(SESSION);
    stop();
  });
});
