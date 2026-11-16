// src/features/soar/SoarNavBadge.test.tsx — the count of open tickets in the header's link, and the signal when a newer
// ticket arrives: silent on the first load, a tone and a notification on a later change, nothing with the switch off.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, vi } from "vitest";
import { setTokenSource } from "../../api/client";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import type { Session } from "../../auth/session";
import { AppHeader } from "../../components/AppHeader";
import { S } from "../../strings";
import { countOf } from "./fixtures";
import { SOAR_COUNT_POLL_MS, countQueryOptions, soarKeys } from "./soarQueries";
import { SoarNavBadge } from "./SoarNavBadge";
import { turnSignalOn } from "./signal";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const session: Session = {
  token: "tok-1",
  role: "tier1",
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
};

const tone = vi.hoisted(() => ({ started: 0 }));
class FakeAudioContext {
  state = "running";
  currentTime = 0;
  destination = {};
  resume = async () => {};
  close = async () => {};
  createGain() {
    return {
      gain: { setValueAtTime: () => {}, exponentialRampToValueAtTime: () => {} },
      connect: () => {},
    };
  }
  createOscillator() {
    return {
      type: "",
      frequency: { value: 0 },
      connect: () => {},
      start: () => {
        tone.started += 1;
      },
      stop: () => {},
      onended: null,
    };
  }
}
class FakeNotification {
  static permission = "granted";
  static shown: { title: string; body: string | undefined }[] = [];
  static requestPermission = async () => "granted";
  constructor(title: string, options?: NotificationOptions) {
    FakeNotification.shown.push({ title, body: options?.body });
  }
}

/** What `GET /api/soar/reviews/count` answers, one entry per call; the last entry repeats. */
function serveCounts(...answers: (ReturnType<typeof countOf> | number)[]) {
  let calls = 0;
  server.use(
    http.get("/api/soar/reviews/count", () => {
      const answer = answers[Math.min(calls, answers.length - 1)];
      calls += 1;
      return typeof answer === "number"
        ? HttpResponse.json({ detail: "boom" }, { status: answer })
        : HttpResponse.json(answer);
    }),
  );
  return () => calls;
}

const T1 = "2026-11-16T01:00:00+00:00";
const T2 = "2026-11-16T01:05:00+00:00";

let client: QueryClient;
function renderBadge() {
  const auth: AuthState = {
    session,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  return render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter>
          <AppHeader soarBadge={<SoarNavBadge />} />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}
const refetch = () => act(() => client.refetchQueries({ queryKey: soarKeys.count }));
const link = () => screen.getByRole("link", { name: new RegExp(S.nav.soar) });

beforeEach(() => {
  localStorage.clear();
  tone.started = 0;
  FakeNotification.shown = [];
  FakeNotification.permission = "granted";
  vi.stubGlobal("AudioContext", FakeAudioContext);
  vi.stubGlobal("Notification", FakeNotification);
  setTokenSource(
    () => session.token,
    () => {},
  );
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("the badge", () => {
  it("shows the number of open tickets in the nav link, and says it in words for a screen reader", async () => {
    serveCounts(countOf(3, T1));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("3"));
    expect(link()).toHaveAccessibleName(`${S.nav.soar} ${S.soar.badge.sr(3)}`);
    expect(S.soar.badge.sr(3)).toBe("3 phiếu đang mở");
    expect(link()).toHaveAttribute("href", "/soar");
  });

  it("shows no badge at 0: the link is its name alone", async () => {
    const calls = serveCounts(countOf(0, null));
    renderBadge();
    await waitFor(() => expect(calls()).toBe(1));
    await waitFor(() => expect(client.getQueryData(soarKeys.count)).toBeDefined());
    expect(link()).toHaveAccessibleName(S.nav.soar);
    expect(link()).toHaveTextContent(/^Phản hồi SOAR$/);
  });

  it("caps a long number as 99+", async () => {
    serveCounts(countOf(240, T1));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("99+"));
    expect(S.soar.badge.text(99)).toBe("99");
    expect(S.soar.badge.text(100)).toBe("99+");
  });

  it("leaves the header whole when the count fails, and shows the badge when the next ask works", async () => {
    serveCounts(500, countOf(2, T1));
    renderBadge();
    await waitFor(() => expect(client.getQueryState(soarKeys.count)?.status).toBe("error"));
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(link()).toHaveAccessibleName(S.nav.soar);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await refetch();
    await waitFor(() => expect(link()).toHaveTextContent("2"));
  });

  it("asks every 30 s, also from a tab in the background", () => {
    const options = countQueryOptions();
    expect(SOAR_COUNT_POLL_MS).toBe(30_000);
    expect(options.refetchInterval).toBe(30_000);
    expect(options.refetchIntervalInBackground).toBe(true);
    expect(options.queryKey).toEqual(["soar", "count"]);
  });

  it("really asks again 30 s later", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const calls = serveCounts(countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    expect(calls()).toBe(1);
    await act(() => vi.advanceTimersByTimeAsync(SOAR_COUNT_POLL_MS + 100));
    await waitFor(() => expect(link()).toHaveTextContent("2"));
    expect(calls()).toBe(2);
  });

  it("has no axe violation, with and without a badge", async () => {
    serveCounts(countOf(3, T1));
    const { container } = renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("3"));
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("the new-ticket signal", () => {
  it("is silent on the first load, whatever the switch says", async () => {
    turnSignalOn();
    serveCounts(countOf(2, T1));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("2"));
    expect(tone.started).toBe(0);
    expect(FakeNotification.shown).toEqual([]);
  });

  it("plays a tone and shows a notification, carrying only the count, when latest_created_at moves forward", async () => {
    turnSignalOn();
    serveCounts(countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    await refetch();
    await waitFor(() => expect(tone.started).toBe(1));
    expect(FakeNotification.shown).toEqual([
      { title: S.soar.signal.notification.title, body: S.soar.signal.notification.body(2) },
    ]);
  });

  it("does not signal when the newest ticket is the same, older, or gone, nor when only the count changes", async () => {
    turnSignalOn();
    serveCounts(countOf(2, T2), countOf(3, T2), countOf(1, T1), countOf(0, null));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("2"));
    for (let i = 0; i < 3; i++) await refetch();
    expect(client.getQueryData(soarKeys.count)).toEqual(countOf(0, null));
    expect(tone.started).toBe(0);
    expect(FakeNotification.shown).toEqual([]);
  });

  it("signals for a ticket that arrives after the list was empty", async () => {
    turnSignalOn();
    serveCounts(countOf(0, null), countOf(1, T1));
    renderBadge();
    await waitFor(() => expect(client.getQueryData(soarKeys.count)).toEqual(countOf(0, null)));
    await refetch();
    await waitFor(() => expect(tone.started).toBe(1));
  });

  it("stays silent for the first answer that arrives after a failed first ask", async () => {
    turnSignalOn();
    serveCounts(500, countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(client.getQueryState(soarKeys.count)?.status).toBe("error"));
    await refetch();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    expect(tone.started).toBe(0);
    await refetch();
    await waitFor(() => expect(tone.started).toBe(1));
  });

  it("is silent while the switch is off", async () => {
    serveCounts(countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    await refetch();
    await waitFor(() => expect(link()).toHaveTextContent("2"));
    expect(tone.started).toBe(0);
    expect(FakeNotification.shown).toEqual([]);
  });

  it("plays the tone alone when the browser refused notifications", async () => {
    turnSignalOn();
    FakeNotification.permission = "denied";
    serveCounts(countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    await refetch();
    await waitFor(() => expect(tone.started).toBe(1));
    expect(FakeNotification.shown).toEqual([]);
  });

  it("plays the tone alone, and does not throw, when the browser has no Notification API", async () => {
    turnSignalOn();
    vi.stubGlobal("Notification", undefined);
    serveCounts(countOf(1, T1), countOf(2, T2));
    renderBadge();
    await waitFor(() => expect(link()).toHaveTextContent("1"));
    await refetch();
    await waitFor(() => expect(tone.started).toBe(1));
  });
});
