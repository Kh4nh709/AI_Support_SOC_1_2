// src/auth/AuthProvider.test.tsx — restore on load, /me confirmation, expiry, logout broadcasts, login, logout.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { StrictMode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { api } from "../api/client";
import { AuthProvider, useAuth } from "./AuthProvider";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
let tabs: BroadcastChannel[] = [];
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
  for (const t of tabs) t.close();
  tabs = [];
});
afterAll(() => server.close());

const KEY = "soc.session";
const later = (ms: number) => new Date(Date.now() + ms).toISOString();
const stored = (over: Record<string, unknown> = {}) =>
  sessionStorage.setItem(
    KEY,
    JSON.stringify({
      token: "tok-1",
      role: "tier1",
      username: "stale",
      expiresAt: later(3_600_000),
      ...over,
    }),
  );
const meOk = (over: Record<string, unknown> = {}) =>
  http.get("/api/auth/me", () =>
    HttpResponse.json({
      user_id: 4,
      username: "bo",
      display_name: "Bo",
      role: "tier2",
      expires_at: later(3_600_000),
      ...over,
    }),
  );

function Probe() {
  const { session, ready, login, logout } = useAuth();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  return (
    <div>
      <p data-testid="state">
        {`${ready ? "ready" : "loading"} ${
          session ? `${session.username}/${session.role}/${session.token}` : "none"
        }`}
      </p>
      <p data-testid="where">{`${location.pathname} from ${from ?? "-"}`}</p>
      <button onClick={() => void login("an", "pw").catch(() => {})}>do login</button>
      <button onClick={() => void logout()}>do logout</button>
      <button onClick={() => void api("/ping").catch(() => {})}>call api</button>
    </div>
  );
}

function renderProvider(entry = "/alerts/5") {
  return render(
    <StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <AuthProvider>
          <Routes>
            <Route path="*" element={<Probe />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </StrictMode>,
  );
}

const state = () => screen.getByTestId("state").textContent;
const where = () => screen.getByTestId("where").textContent;

describe("on load", () => {
  it("reads /me instead of trusting the storage: the role and the name come from the server", async () => {
    let bearer: string | null = null;
    server.use(
      http.get("/api/auth/me", ({ request }) => {
        bearer = request.headers.get("authorization");
        return HttpResponse.json({
          user_id: 4,
          username: "bo",
          display_name: "Bo",
          role: "tier2",
          expires_at: later(3_600_000),
        });
      }),
    );
    stored();
    renderProvider();
    expect(state()).toBe("loading stale/tier1/tok-1"); // provisional until /me answers
    await waitFor(() => expect(state()).toBe("ready bo/tier2/tok-1"));
    expect(bearer).toBe("Bearer tok-1");
    expect(JSON.parse(sessionStorage.getItem(KEY) ?? "null")).toMatchObject({
      username: "bo",
      role: "tier2",
      token: "tok-1",
    });
  });

  it("clears the session when /me answers 401", async () => {
    server.use(http.get("/api/auth/me", () => HttpResponse.json({ detail: "x" }, { status: 401 })));
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready none"));
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  // A session with no usable end date would arm a timer of NaN milliseconds, which fires at once and
  // re-arms itself for ever. It is not a session.
  it.each<[string, Record<string, unknown>]>([
    ["has no expires_at", { expires_at: undefined }],
    ["has a null expires_at", { expires_at: null }],
    ["has an expires_at that is not a date", { expires_at: "soon" }],
    ["has an expires_at in the past", { expires_at: later(-60_000) }],
  ])("ends the session, and arms no timer of NaN, when /me %s", async (_name, over) => {
    const timers = vi.spyOn(globalThis, "setTimeout");
    try {
      server.use(meOk(over));
      stored();
      renderProvider();
      await waitFor(() => expect(state()).toBe("ready none"));
      expect(sessionStorage.getItem(KEY)).toBeNull();
      await new Promise((r) => setTimeout(r, 60)); // a loop would show in this time
      expect(state()).toBe("ready none");
      const nan = timers.mock.calls.filter(([, ms]) => typeof ms === "number" && Number.isNaN(ms));
      expect(nan).toHaveLength(0);
    } finally {
      timers.mockRestore();
    }
  });

  it("keeps the session when /me cannot be answered (the backend is down, not the login)", async () => {
    server.use(http.get("/api/auth/me", () => HttpResponse.json({}, { status: 503 })));
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
  });

  it("asks the other tabs when this tab has no session, and confirms what they send", async () => {
    server.use(meOk());
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    other.onmessage = (e) => {
      if ((e.data as { type?: string }).type === "session-request") {
        other.postMessage({
          type: "session",
          session: { token: "tok-2", role: "tier2", username: "bo", expiresAt: later(3_600_000) },
        });
      }
    };
    renderProvider();
    expect(state()).toBe("loading none");
    await waitFor(() => expect(state()).toBe("ready bo/tier2/tok-2"));
    expect(JSON.parse(sessionStorage.getItem(KEY) ?? "null")).toMatchObject({ token: "tok-2" });
  });

  it("is ready with no session when no tab answers", async () => {
    renderProvider();
    expect(state()).toBe("loading none");
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("answers the session request of a new tab", async () => {
    server.use(meOk({ username: "stale", role: "tier1" }));
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    const heard: unknown[] = [];
    other.onmessage = (e) => heard.push(e.data);
    other.postMessage({ type: "session-request" });
    await waitFor(() =>
      expect(heard).toContainEqual({
        type: "session",
        session: expect.objectContaining({ token: "tok-1" }) as unknown,
      }),
    );
  });
});

describe("while signed in", () => {
  it("clears the session at expiresAt", async () => {
    const expiresAt = later(400);
    server.use(meOk({ username: "stale", role: "tier1", expires_at: expiresAt }));
    stored({ expiresAt });
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("closes the session on a logout broadcast from another tab", async () => {
    server.use(meOk({ username: "stale", role: "tier1" }));
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    other.postMessage({ type: "logout" });
    await waitFor(() => expect(state()).toBe("ready none"));
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("ends the session when any call answers 401, once", async () => {
    let pings = 0;
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.get("/api/ping", () => {
        pings += 1;
        return HttpResponse.json({ detail: "expired" }, { status: 401 });
      }),
    );
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    await userEvent.setup().click(screen.getByText("call api"));
    await waitFor(() => expect(state()).toBe("ready none"));
    expect(pings).toBe(1);
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("does not tell the other tabs about a 401 of its own token", async () => {
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.get("/api/ping", () => HttpResponse.json({}, { status: 401 })),
    );
    stored();
    renderProvider();
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    const heard: unknown[] = [];
    other.onmessage = (e) => heard.push(e.data);
    await userEvent.setup().click(screen.getByText("call api"));
    await waitFor(() => expect(state()).toBe("ready none"));
    await new Promise((r) => setTimeout(r, 60));
    expect(heard).toEqual([]);
  });
});

describe("login and logout", () => {
  it("login posts the credentials, saves the session and goes to the role home", async () => {
    server.use(
      http.post("/api/auth/login", async ({ request }) => {
        expect(await request.json()).toEqual({ username: "an", password: "pw" });
        return HttpResponse.json({
          token: "tok-7",
          role: "tier2",
          user_id: 4,
          expires_at: later(3_600_000),
        });
      }),
    );
    renderProvider("/login");
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
    await userEvent.setup().click(screen.getByText("do login"));
    await waitFor(() => expect(state()).toBe("ready an/tier2/tok-7"));
    expect(where()).toBe("/cases from -");
    expect(JSON.parse(sessionStorage.getItem(KEY) ?? "null")).toMatchObject({
      token: "tok-7",
      username: "an",
      role: "tier2",
    });
  });

  it.each<[string, Record<string, unknown>]>([
    ["has no expires_at", { expires_at: undefined }],
    ["has an expires_at that is not a date", { expires_at: "soon" }],
    ["has no token", { token: "" }],
    ["has a role this UI does not know", { role: "auditor" }],
  ])(
    "login makes no session, and arms no timer of NaN, when the answer %s",
    async (_name, over) => {
      const timers = vi.spyOn(globalThis, "setTimeout");
      try {
        server.use(
          http.post("/api/auth/login", () =>
            HttpResponse.json({
              token: "tok-7",
              role: "tier2",
              user_id: 4,
              expires_at: later(3_600_000),
              ...over,
            }),
          ),
        );
        renderProvider("/login");
        await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
        await userEvent.setup().click(screen.getByText("do login"));
        await new Promise((r) => setTimeout(r, 80));
        expect(state()).toBe("ready none");
        expect(where()).toBe("/login from -");
        expect(sessionStorage.getItem(KEY)).toBeNull();
        const nan = timers.mock.calls.filter(
          ([, ms]) => typeof ms === "number" && Number.isNaN(ms),
        );
        expect(nan).toHaveLength(0);
      } finally {
        timers.mockRestore();
      }
    },
  );

  it("login leaves the session empty when the backend refuses", async () => {
    server.use(
      http.post("/api/auth/login", () => HttpResponse.json({ detail: "x" }, { status: 401 })),
    );
    renderProvider("/login");
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
    await userEvent.setup().click(screen.getByText("do login"));
    await new Promise((r) => setTimeout(r, 80));
    expect(state()).toBe("ready none");
    expect(where()).toBe("/login from -");
  });

  it("a wrong password on one tab does not sign out the other tabs", async () => {
    server.use(
      http.post("/api/auth/login", () => HttpResponse.json({ detail: "x" }, { status: 401 })),
    );
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    const heard: unknown[] = [];
    other.onmessage = (e) => heard.push(e.data);
    renderProvider("/login");
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 2000 });
    await userEvent.setup().click(screen.getByText("do login"));
    await new Promise((r) => setTimeout(r, 80));
    expect(heard).not.toContainEqual({ type: "logout" });
  });

  it("logout posts /auth/logout with the token, clears everything, tells the other tabs, goes to /login", async () => {
    let bearer: string | null = null;
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.post("/api/auth/logout", ({ request }) => {
        bearer = request.headers.get("authorization");
        return new HttpResponse(null, { status: 204 });
      }),
    );
    stored();
    renderProvider("/alerts/5");
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    const heard: unknown[] = [];
    other.onmessage = (e) => heard.push(e.data);
    await userEvent.setup().click(screen.getByText("do logout"));
    await waitFor(() => expect(state()).toBe("ready none"));
    expect(bearer).toBe("Bearer tok-1");
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(where()).toBe("/login from -");
    await waitFor(() => expect(heard).toContainEqual({ type: "logout" }));
  });

  it("logout does not wait for a stalled backend: it ends here at once, and the POST still carries the old token", async () => {
    let bearer: string | null = null;
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.post("/api/auth/logout", async ({ request }) => {
        bearer = request.headers.get("authorization");
        await delay("infinite"); // the backend never answers
        return new HttpResponse(null, { status: 204 });
      }),
    );
    stored();
    renderProvider("/alerts/5");
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const other = new BroadcastChannel("soc-session");
    tabs.push(other);
    const heard: unknown[] = [];
    other.onmessage = (e) => heard.push(e.data);
    await userEvent.setup().click(screen.getByText("do logout"));
    // Nothing below waits for the POST: the session, the storage, the other tabs and the page all
    // moved on while it is still open.
    await waitFor(() => expect(state()).toBe("ready none"), { timeout: 500 });
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(where()).toBe("/login from -");
    await waitFor(() => expect(heard).toContainEqual({ type: "logout" }), { timeout: 500 });
    // ... and the request was still sent, with the token that is no longer the session's.
    await waitFor(() => expect(bearer).toBe("Bearer tok-1"));
  });

  it("gives up on the logout POST after about five seconds", async () => {
    let aborted = false;
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.post("/api/auth/logout", async ({ request }) => {
        request.signal.addEventListener("abort", () => {
          aborted = true;
        });
        await delay("infinite");
        return new HttpResponse(null, { status: 204 });
      }),
    );
    stored();
    renderProvider("/alerts/5");
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    const timers = vi.spyOn(globalThis, "setTimeout");
    try {
      await userEvent.setup().click(screen.getByText("do logout"));
      await waitFor(() => expect(state()).toBe("ready none"));
      const fiveSeconds = timers.mock.calls.find(([, ms]) => ms === 5000);
      expect(fiveSeconds).toBeDefined();
      expect(aborted).toBe(false);
      (fiveSeconds?.[0] as () => void)(); // the five seconds are up
      await waitFor(() => expect(aborted).toBe(true));
    } finally {
      timers.mockRestore();
    }
  });

  it("logout clears the session even when the request fails", async () => {
    server.use(
      meOk({ username: "stale", role: "tier1" }),
      http.post("/api/auth/logout", () => HttpResponse.error()),
    );
    stored();
    renderProvider("/alerts/5");
    await waitFor(() => expect(state()).toBe("ready stale/tier1/tok-1"));
    await userEvent.setup().click(screen.getByText("do logout"));
    await waitFor(() => expect(state()).toBe("ready none"));
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(where()).toBe("/login from -");
  });
});
