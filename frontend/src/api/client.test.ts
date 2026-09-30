// src/api/client.test.ts — the one fetch wrapper: the Bearer header, the 401 hook, the server's `detail`.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { ApiError, api, reportUnauthorized, setTokenSource } from "./client";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  setTokenSource(
    () => null,
    () => {},
  );
});
afterAll(() => server.close());

/** A token source that hands out `t` and counts the times the client reports a 401. */
function withToken(token: string | null) {
  const onUnauthorized = vi.fn();
  setTokenSource(() => token, onUnauthorized);
  return onUnauthorized;
}

it("sends Authorization: Bearer <token>", async () => {
  let seen: string | null = "unset";
  server.use(
    http.get("/api/ping", ({ request }) => {
      seen = request.headers.get("authorization");
      return HttpResponse.json({ ok: true });
    }),
  );
  withToken("t");
  await expect(api<{ ok: boolean }>("/ping")).resolves.toEqual({ ok: true });
  expect(seen).toBe("Bearer t");
});

it("sends no Authorization header when there is no token", async () => {
  let seen: string | null = "unset";
  server.use(
    http.get("/api/ping", ({ request }) => {
      seen = request.headers.get("authorization");
      return HttpResponse.json({});
    }),
  );
  withToken(null);
  await api("/ping");
  expect(seen).toBeNull();
});

it("keeps the headers the caller set", async () => {
  let seen: string | null = null;
  server.use(
    http.get("/api/ping", ({ request }) => {
      seen = request.headers.get("x-probe");
      return HttpResponse.json({});
    }),
  );
  withToken("t");
  await api("/ping", { headers: { "x-probe": "1" } });
  expect(seen).toBe("1");
});

it("calls onUnauthorized exactly once on a 401 and throws ApiError(401)", async () => {
  server.use(
    http.get("/api/ping", () => HttpResponse.json({ detail: "expired" }, { status: 401 })),
  );
  const onUnauthorized = withToken("t");
  const error = await api("/ping").catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).status).toBe(401);
  expect(onUnauthorized).toHaveBeenCalledTimes(1);
});

it("does not report a 401 that answers a request which carried no token", async () => {
  // A wrong password at the login form is a 401 too; it is no sign that a session ended.
  server.use(http.post("/api/auth/login", () => HttpResponse.json({}, { status: 401 })));
  const onUnauthorized = withToken(null);
  await expect(api("/auth/login", { method: "POST", json: {} })).rejects.toMatchObject({
    status: 401,
  });
  expect(onUnauthorized).not.toHaveBeenCalled();
});

it("does not report a 401 for a token that is no longer the current one", async () => {
  // The user logged in again while the old request was in flight: the answer is about the old token.
  let current = "old";
  const onUnauthorized = vi.fn();
  setTokenSource(() => current, onUnauthorized);
  server.use(
    http.get("/api/ping", () => {
      current = "new";
      return HttpResponse.json({}, { status: 401 });
    }),
  );
  await expect(api("/ping")).rejects.toMatchObject({ status: 401 });
  expect(onUnauthorized).not.toHaveBeenCalled();
});

// The socket's 4401 is the same fact as a 401 (P10-T09): the same rule, through the same hook.
describe("reportUnauthorized (a 4401 from the socket)", () => {
  it("ends the session when the token the socket sent is still the current one", () => {
    const onUnauthorized = withToken("t");
    reportUnauthorized("t");
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does nothing for a token that is no longer current, or when nobody is signed in", () => {
    const onUnauthorized = withToken("new");
    reportUnauthorized("old");
    expect(onUnauthorized).not.toHaveBeenCalled();
    setTokenSource(() => null, onUnauthorized);
    reportUnauthorized("old");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

it("throws ApiError with the server's detail object intact on a 409", async () => {
  const detail = { code: "held_by_other", user: "bob", since: "2026-09-30T02:31:00Z" };
  server.use(http.post("/api/ping", () => HttpResponse.json({ detail }, { status: 409 })));
  const onUnauthorized = withToken("t");
  const error = await api("/ping", { method: "POST" }).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).status).toBe(409);
  expect((error as ApiError).detail).toEqual(detail);
  expect(onUnauthorized).not.toHaveBeenCalled();
});

it.each([422, 429, 503])("surfaces the detail of a %i unchanged", async (status) => {
  server.use(http.get("/api/ping", () => HttpResponse.json({ detail: `d${status}` }, { status })));
  withToken("t");
  await expect(api("/ping")).rejects.toMatchObject({ status, detail: `d${status}` });
});

it("keeps the whole body beside the detail, for a flat 423 with locked_until", async () => {
  const body = { detail: "locked", locked_until: "2026-09-30T08:15:00+00:00" };
  server.use(http.post("/api/ping", () => HttpResponse.json(body, { status: 423 })));
  withToken(null);
  const error = (await api("/ping", { method: "POST" }).catch((e: unknown) => e)) as ApiError;
  expect(error.detail).toBe("locked");
  expect(error.body).toEqual(body);
});

it("takes the body itself for the detail when the server sent no `detail` key", async () => {
  server.use(http.get("/api/ping", () => HttpResponse.json({ error: "x" }, { status: 400 })));
  withToken("t");
  await expect(api("/ping")).rejects.toMatchObject({ status: 400, detail: { error: "x" } });
});

it("throws ApiError with a null detail when an error body is not JSON", async () => {
  server.use(
    http.get("/api/ping", () => new HttpResponse("<html>Bad gateway</html>", { status: 502 })),
  );
  withToken("t");
  await expect(api("/ping")).rejects.toMatchObject({ status: 502, detail: null });
});

it("sends a JSON body with content-type: application/json", async () => {
  let type: string | null = null;
  let received: unknown = null;
  server.use(
    http.post("/api/ping", async ({ request }) => {
      type = request.headers.get("content-type");
      received = await request.json();
      return HttpResponse.json({ id: 1 }, { status: 201 });
    }),
  );
  withToken("t");
  await expect(api("/ping", { method: "POST", json: { reason: "ok", n: 2 } })).resolves.toEqual({
    id: 1,
  });
  expect(type).toBe("application/json");
  expect(received).toEqual({ reason: "ok", n: 2 });
});

it("sends no content-type when there is no JSON body", async () => {
  let type: string | null = "unset";
  server.use(
    http.post("/api/ping", ({ request }) => {
      type = request.headers.get("content-type");
      return new HttpResponse(null, { status: 204 });
    }),
  );
  withToken("t");
  await api("/ping", { method: "POST" });
  expect(type).toBeNull();
});

it("returns null for a 204", async () => {
  server.use(http.post("/api/ping", () => new HttpResponse(null, { status: 204 })));
  withToken("t");
  await expect(api("/ping", { method: "POST" })).resolves.toBeNull();
});

it("puts the query string and the base /api on the request", async () => {
  let url = "";
  server.use(
    http.get("/api/tier1/queue", ({ request }) => {
      url = new URL(request.url).pathname + new URL(request.url).search;
      return HttpResponse.json([]);
    }),
  );
  withToken("t");
  await api("/tier1/queue?band=high");
  expect(url).toBe("/api/tier1/queue?band=high");
});
