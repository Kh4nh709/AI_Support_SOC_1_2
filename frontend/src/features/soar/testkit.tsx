// What the tests of the SOAR page share: a fake API (msw handlers over a mutable state, recording every request), and the
// page rendered under the providers it has in the app. Not a test file itself. The clock is a fixed instant, so a
// countdown reads the same in every run.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configure, render } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { vi } from "vitest";
import type { SetupServer } from "msw/node";
import { useEffect } from "react";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
import type {
  SoarDecision,
  SoarDecisionAnswer,
  SoarListResponse,
  SoarReview,
  SoarReviewDetail,
} from "../../api/soar";
import { setTokenSource } from "../../api/client";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import type { Session } from "../../auth/session";
import { detailOf, listOf } from "./fixtures";
import { SoarPage } from "./SoarPage";

/**
 * How long a step of these tests waits for what the page gets from the mock server (the first list, a tab's list, a detail, an
 * answer) before it says it is not there. The library's default is 1 s of wall clock for every `findBy*` and `waitFor`, which a
 * machine running a hundred test files at once spends between the render and the answer. With thirty-two busy loops beside it on
 * eight cores, five of seven runs of one test of followup.test.tsx failed at the first `findByRole` of the page, the first list
 * (not at a tab change, as it was first read): the same 1 s is under every list, detail and answer these tests wait for. Nothing
 * waited for is slower then, only the clock is, so a step waits on the state it needs and gives up only on a hang; the limit
 * costs a passing test nothing. The test itself gets room for the waits it holds (vitest's default of 5 s would end it before
 * the last one gave up).
 */
export const STEP_WAIT_MS = 8_000;
export const TEST_MS = 20_000;
configure({ asyncUtilTimeout: STEP_WAIT_MS });
vi.setConfig({ testTimeout: TEST_MS });

/** 14:41:05 UTC on the day of the fixtures: 21:41:05 in +07, 35 minutes after the ticket was made. */
export const NOW = Date.parse("2026-11-13T14:41:05+00:00");

export type DecisionCall = { id: string; body: { decision: SoarDecision; note?: string } };

export type Fake = {
  /** What the list serves for a review tab, and for `kind=notice`. */
  rows: SoarReview[];
  notices: SoarReview[];
  /** `GET /api/soar/reviews/{id}`; the default is the fixture's detail of that row. */
  detail?: (id: string) => SoarReviewDetail | Response | undefined;
  /** `POST /api/soar/reviews/{id}/decision`; the default answers `ok` with the row as it was. */
  decision?: (
    call: DecisionCall,
  ) => SoarDecisionAnswer | Response | Promise<SoarDecisionAnswer | Response>;
  /** A list answer of your own (a page of a bigger total, an error); falls back to the rows. */
  list?: (
    url: URL,
  ) => SoarListResponse | Response | undefined | Promise<SoarListResponse | Response | undefined>;
  /** What the server saw, in order. */
  lists: URL[];
  decisions: DecisionCall[];
  details: string[];
};

export function fake(over: Partial<Pick<Fake, "rows" | "notices">> = {}): Fake {
  return { rows: [], notices: [], lists: [], decisions: [], details: [], ...over };
}

/** Installs the handlers of `state` on `server`. */
export function serve(server: SetupServer, state: Fake): void {
  server.use(
    http.get("/api/soar/reviews/count", () =>
      HttpResponse.json({ count: 0, latest_received_at: null }),
    ),
    http.get("/api/soar/reviews", async ({ request }) => {
      const url = new URL(request.url);
      state.lists.push(url);
      const own = await state.list?.(url);
      if (own instanceof Response) return own;
      if (own !== undefined) return HttpResponse.json(own);
      return HttpResponse.json(
        listOf(url.searchParams.get("kind") === "notice" ? state.notices : state.rows),
      );
    }),
    http.get("/api/soar/reviews/:id", ({ params }) => {
      const id = String(params.id);
      state.details.push(id);
      const own = state.detail?.(id);
      if (own instanceof Response) return own;
      if (own !== undefined) return HttpResponse.json(own);
      const row = [...state.rows, ...state.notices].find((r) => r.id === id);
      if (row === undefined) return HttpResponse.json({ detail: "not found" }, { status: 404 });
      return HttpResponse.json(detailOf(row));
    }),
    http.post("/api/soar/reviews/:id/decision", async ({ params, request }) => {
      const call: DecisionCall = {
        id: String(params.id),
        body: (await request.json()) as DecisionCall["body"],
      };
      state.decisions.push(call);
      const own = await state.decision?.(call);
      if (own instanceof Response) return own;
      if (own !== undefined) return HttpResponse.json(own);
      const row = state.rows.find((r) => r.id === call.id);
      return HttpResponse.json({ outcome: "ok", message: null, review: row });
    }),
  );
}

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

/** Moves the router of the page rendered last, as the back and forward buttons of a browser would: `nav.go("/soar?tab=done")`. */
export const nav: { go: (to: string) => void } = {
  go: () => {
    throw new Error("no page is rendered");
  },
};

function Navigator() {
  const navigate = useNavigate();
  useEffect(() => {
    nav.go = (to) => void navigate(to);
  }, [navigate]);
  return null;
}

export function renderSoar(
  options: {
    entry?: string;
    role?: Session["role"];
    username?: string;
    now?: () => number;
    client?: QueryClient;
  } = {},
) {
  const session = sessionOf(options.role, options.username);
  setTokenSource(
    () => session.token,
    () => {},
  );
  const auth: AuthState = {
    session,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const client =
    options.client ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const now = options.now ?? (() => NOW);
  const view = render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[options.entry ?? "/soar"]}>
          <main>
            <SoarPage now={now} />
          </main>
          <Where />
          <Navigator />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
