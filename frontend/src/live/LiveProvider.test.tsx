// src/live/LiveProvider.test.tsx — the provider owns the socket of the session: one per token, closed with
// it, its status for the header, and what a change does to the cache. The socket itself is faked here.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import axe from "axe-core";
import type { ReactNode } from "react";
import type { MockInstance } from "vitest";
import { setTokenSource } from "../api/client";
import { AuthContext, type AuthState } from "../auth/AuthProvider";
import type { Session } from "../auth/session";
import { S } from "../strings";
import { LiveIndicator } from "./LiveIndicator";
import { LiveProvider, useLiveStatus } from "./LiveProvider";
import type { LiveOptions } from "./socket";

const fake = vi.hoisted(() => ({ opened: [] as unknown[], disconnects: [] as string[] }));
vi.mock("./socket", () => ({
  connectLive: (opts: LiveOptions) => {
    fake.opened.push(opts);
    const n = fake.opened.length;
    return () => fake.disconnects.push(`socket ${n}`);
  },
}));

const opened = () => fake.opened as LiveOptions[];
const newest = (): LiveOptions => {
  const opts = opened().at(-1);
  if (!opts) throw new Error("no socket was opened");
  return opts;
};

const session = (token: string): Session => ({
  token,
  role: "tier1",
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

let client: QueryClient;
let invalidate: MockInstance<QueryClient["invalidateQueries"]>;
beforeEach(() => {
  fake.opened = [];
  fake.disconnects = [];
  client = new QueryClient();
  invalidate = vi.spyOn(client, "invalidateQueries");
});
afterEach(() => {
  setTokenSource(
    () => null,
    () => {},
  );
});

function Status() {
  return <p data-testid="status">{useLiveStatus()}</p>;
}

function tree(s: Session | null, children: ReactNode = <Status />) {
  const auth: AuthState = {
    session: s,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  return (
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <LiveProvider>{children}</LiveProvider>
      </AuthContext.Provider>
    </QueryClientProvider>
  );
}

const status = () => screen.getByTestId("status").textContent;
const invalidated = () => invalidate.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));

describe("the socket of the session", () => {
  it("opens one for a signed-in session, giving it the token", () => {
    render(tree(session("tok-1")));
    expect(opened()).toHaveLength(1);
    expect(newest().token()).toBe("tok-1");
  });

  it("opens none while nobody is signed in", () => {
    render(tree(null));
    expect(opened()).toHaveLength(0);
    expect(status()).toBe("offline");
  });

  it("does not reconnect when the same token comes back in a new session object", () => {
    const { rerender } = render(tree(session("tok-1")));
    rerender(tree(session("tok-1"))); // /me confirmed the session: same token, new object
    expect(opened()).toHaveLength(1);
    expect(fake.disconnects).toEqual([]);
  });

  it("closes it when the session ends, and again on a new token opens another", () => {
    const { rerender } = render(tree(session("tok-1")));
    rerender(tree(null));
    expect(fake.disconnects).toEqual(["socket 1"]);
    rerender(tree(session("tok-2")));
    expect(opened()).toHaveLength(2);
    expect(newest().token()).toBe("tok-2");
  });

  it("closes it when the provider goes away", () => {
    const { unmount } = render(tree(session("tok-1")));
    unmount();
    expect(fake.disconnects).toEqual(["socket 1"]);
  });
});

describe("the status", () => {
  it("is offline until the socket says live, then follows it", () => {
    render(tree(session("tok-1")));
    expect(status()).toBe("offline");
    act(() => newest().onStatus("live"));
    expect(status()).toBe("live");
    act(() => newest().onStatus("offline"));
    expect(status()).toBe("offline");
  });

  it("is offline again for a new session, whatever the old socket last said", () => {
    const { rerender } = render(tree(session("tok-1")));
    act(() => newest().onStatus("live"));
    rerender(tree(session("tok-2")));
    expect(status()).toBe("offline");
  });

  it("is offline once the session has ended", () => {
    const { rerender } = render(tree(session("tok-1")));
    act(() => newest().onStatus("live"));
    rerender(tree(null));
    expect(status()).toBe("offline");
  });

  it("reads offline with no provider at all, so a page rendered alone polls", () => {
    render(<Status />);
    expect(status()).toBe("offline");
  });
});

describe("what a change does", () => {
  it("fetches the queue again, and the alerts it names", () => {
    render(tree(session("tok-1")));
    act(() => newest().onChange(["a1", "a2"]));
    expect(invalidated()).toEqual(['["queue"]', '["alert","a1"]', '["alert","a2"]']);
  });

  it("fetches everything again when the server folded a burst into 'many'", () => {
    render(tree(session("tok-1")));
    act(() => newest().onChange("many"));
    expect(invalidated()).toEqual(['["queue"]', '["alert"]']);
  });

  it("does not fetch on the first live after mount: the fetch of the page that just opened is fresh", () => {
    render(tree(session("tok-1")));
    act(() => newest().onStatus("live"));
    expect(invalidated()).toEqual([]);
  });

  it("fetches everything again when the socket is live again after a drop: what came meanwhile was missed", () => {
    render(tree(session("tok-1")));
    act(() => newest().onStatus("live"));
    act(() => newest().onStatus("offline"));
    expect(invalidated()).toEqual([]); // the drop itself fetches nothing (the page polls)
    act(() => newest().onStatus("live"));
    expect(invalidated()).toEqual(['["queue"]', '["alert"]']);
  });

  it("fetches when the first live comes after a first attempt that failed: the page polled, or waited, meanwhile", () => {
    render(tree(session("tok-1")));
    act(() => newest().onStatus("offline")); // the socket never came up at all
    act(() => newest().onStatus("live"));
    expect(invalidated()).toEqual(['["queue"]', '["alert"]']);
  });

  it("tells a new session's first live from a reconnect: the new socket has not dropped yet", () => {
    const { rerender } = render(tree(session("tok-1")));
    act(() => newest().onStatus("live"));
    act(() => newest().onStatus("offline"));
    rerender(tree(session("tok-2")));
    act(() => newest().onStatus("live"));
    expect(invalidated()).toEqual([]);
  });

  it("does not fetch again when the socket goes offline (the page polls instead)", () => {
    render(tree(session("tok-1")));
    act(() => newest().onStatus("offline"));
    expect(invalidated()).toEqual([]);
  });

  it("stops acting on a socket that was closed with its session", () => {
    const { rerender } = render(tree(session("tok-1")));
    const old = newest();
    rerender(tree(null));
    act(() => old.onChange(["a1"]));
    expect(invalidated()).toEqual([]);
  });
});

describe("the session and the cache", () => {
  it("forgets what it held when the session ends: the next person is not shown the last one's rows", () => {
    const { rerender } = render(tree(session("tok-1")));
    client.setQueryData(["queue", {}, 1], { rows: [{ alert_id: "a1" }] });
    expect(client.getQueryCache().getAll()).toHaveLength(1);
    rerender(tree(null));
    expect(client.getQueryCache().getAll()).toHaveLength(0);
  });

  it("forgets it on a new login too", () => {
    const { rerender } = render(tree(session("tok-1")));
    client.setQueryData(["queue", {}, 1], { rows: [] });
    rerender(tree(session("tok-2")));
    expect(client.getQueryCache().getAll()).toHaveLength(0);
  });

  it("keeps it while the session goes on", () => {
    const { rerender } = render(tree(session("tok-1")));
    client.setQueryData(["queue", {}, 1], { rows: [] });
    rerender(tree(session("tok-1")));
    expect(client.getQueryCache().getAll()).toHaveLength(1);
  });
});

describe("a 4401", () => {
  it("ends the session, through the client's hook, when the token sent is still the current one", () => {
    const onUnauthorized = vi.fn();
    setTokenSource(() => "tok-1", onUnauthorized);
    render(tree(session("tok-1")));
    newest().onUnauthorized?.("tok-1");
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("is about the old session only if the token has since changed", () => {
    const onUnauthorized = vi.fn();
    setTokenSource(() => "tok-2", onUnauthorized);
    render(tree(session("tok-1")));
    newest().onUnauthorized?.("tok-1");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe("LiveIndicator", () => {
  it("says Trực tiếp when live and Mất kết nối otherwise, in a status region", () => {
    render(tree(session("tok-1"), <LiveIndicator />));
    expect(screen.getByRole("status")).toHaveTextContent(S.live.off);
    act(() => newest().onStatus("live"));
    expect(screen.getByRole("status")).toHaveTextContent(S.live.on);
    expect(screen.getByRole("status")).not.toHaveTextContent(S.live.off);
  });

  it("has no axe violation, live or offline (the word says it, not the colour)", async () => {
    const { container } = render(tree(session("tok-1"), <LiveIndicator />));
    // jsdom computes no colour, so the contrast rule cannot run here.
    const scan = async () =>
      (
        await axe.run(container, { rules: { "color-contrast": { enabled: false } } })
      ).violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
    expect(screen.getByRole("status")).toHaveTextContent(S.live.off);
    expect(await scan()).toEqual([]);
    act(() => newest().onStatus("live"));
    expect(screen.getByRole("status")).toHaveTextContent(S.live.on);
    expect(await scan()).toEqual([]);
  });
});
