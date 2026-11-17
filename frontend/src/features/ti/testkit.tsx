// What the tests of the Threat Intel page share: a fake API (msw handlers over a mutable state, recording every request), and the page
// rendered under the providers it has in the app. Not a test file itself.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configure, render } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import type { SetupServer } from "msw/node";
import { vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router";
import { setTokenSource } from "../../api/client";
import type { TiIoc, TiListResponse, TiStats, TiStatus } from "../../api/ti";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import type { Session } from "../../auth/session";
import { tiFixture } from "./fixtures";
import { TiPage } from "./TiPage";

// A step of these tests waits for what the mock server answers; the library's 1 s default is not enough on a machine running
// a hundred files at once (the SOAR page's tests learned this), and a passing test is no slower for a longer limit.
export const STEP_WAIT_MS = 8_000;
configure({ asyncUtilTimeout: STEP_WAIT_MS });
vi.setConfig({ testTimeout: 20_000 });

export type Fake = {
  /** What the list serves (the whole answer is built from it, `total` from `total` or the length). */
  rows: TiIoc[];
  total?: number;
  stats: TiStats;
  status: TiStatus;
  /** An answer of your own for a route (an error, a slow one); falls back to the fixtures. */
  list?: (
    url: URL,
  ) => TiListResponse | Response | undefined | Promise<TiListResponse | Response | undefined>;
  statsAnswer?: () => TiStats | Response | undefined;
  statusAnswer?: () => TiStatus | Response | undefined;
  exportAnswer?: (url: URL) => Response | Promise<Response>;
  /** What the server saw, in order. */
  lists: URL[];
  statsRequests: URL[];
  statusRequests: number;
  exports: Array<{ url: URL; authorization: string | null }>;
};

export function fake(over: Partial<Pick<Fake, "rows" | "total" | "stats" | "status">> = {}): Fake {
  return {
    rows: [tiFixture.ioc(), tiFixture.hash(), tiFixture.url(), tiFixture.domain()],
    stats: tiFixture.stats(),
    status: tiFixture.status(),
    lists: [],
    statsRequests: [],
    statusRequests: 0,
    exports: [],
    ...over,
  };
}

/** Installs the handlers of `state` on `server`. */
export function serve(server: SetupServer, state: Fake): void {
  server.use(
    http.get("/api/ti/iocs", async ({ request }) => {
      const url = new URL(request.url);
      state.lists.push(url);
      const own = await state.list?.(url);
      if (own instanceof Response) return own;
      if (own !== undefined) return HttpResponse.json(own);
      const page = Number(url.searchParams.get("page") ?? "1");
      return HttpResponse.json(
        tiFixture.list(state.rows, { total: state.total ?? state.rows.length, page }),
      );
    }),
    http.get("/api/ti/stats", ({ request }) => {
      state.statsRequests.push(new URL(request.url));
      const own = state.statsAnswer?.();
      if (own instanceof Response) return own;
      return HttpResponse.json(own ?? state.stats);
    }),
    http.get("/api/ti/status", () => {
      state.statusRequests += 1;
      const own = state.statusAnswer?.();
      if (own instanceof Response) return own;
      return HttpResponse.json(own ?? state.status);
    }),
    http.get("/api/ti/export", async ({ request }) => {
      const url = new URL(request.url);
      state.exports.push({ url, authorization: request.headers.get("authorization") });
      if (state.exportAnswer !== undefined) return state.exportAnswer(url);
      const csv = url.searchParams.get("format") !== "blocklist";
      return new HttpResponse(csv ? "\ufeffid,value\r\n" : "example.com\n", {
        headers: { "content-type": csv ? "text/csv; charset=utf-8" : "text/plain; charset=utf-8" },
      });
    }),
  );
}

export const busy = (): Response =>
  HttpResponse.json({ detail: { reason: "timeout" } }, { status: 503 });

export const sessionOf = (role: Session["role"] = "tier2", username = "an"): Session => ({
  token: "tok-1",
  role,
  username,
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

function Where() {
  const { pathname, search } = useLocation();
  return <p data-testid="where">{`${pathname}${search}`}</p>;
}

export function renderTi(
  options: {
    entry?: string;
    role?: Session["role"];
    client?: QueryClient;
    onUnauthorized?: () => void;
  } = {},
) {
  const session = sessionOf(options.role);
  setTokenSource(() => session.token, options.onUnauthorized ?? (() => {}));
  const auth: AuthState = {
    session,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const client =
    options.client ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[options.entry ?? "/threat-intel"]}>
          <main>
            <TiPage />
          </main>
          <Where />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
