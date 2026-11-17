// src/api/clientBlob.test.ts — `apiBlob`, the one fetch wrapper's way to a file: the same Bearer header and the same 401 hook as `api`,
// the answer as a Blob with its bytes untouched (a UTF-8 byte order mark stays), an error status as the ApiError with the server's
// `detail`. The Threat Intel export is the user of it: a plain link to the route would carry no Authorization header.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { ApiError, apiBlob, setTokenSource } from "./client";

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

function withToken(token: string | null) {
  const onUnauthorized = vi.fn();
  setTokenSource(() => token, onUnauthorized);
  return onUnauthorized;
}

const bytesOf = async (blob: Blob): Promise<number[]> => [
  ...new Uint8Array(await blob.arrayBuffer()),
];

it("sends Authorization: Bearer <token> and returns the body as a Blob", async () => {
  let seen: string | null = "unset";
  server.use(
    http.get("/api/file", ({ request }) => {
      seen = request.headers.get("authorization");
      return new HttpResponse("a,b\r\n1,2\r\n", { headers: { "content-type": "text/csv" } });
    }),
  );
  withToken("t");
  const blob = await apiBlob("/file");
  expect(seen).toBe("Bearer t");
  expect(blob).toBeInstanceOf(Blob);
  expect(await blob.text()).toBe("a,b\r\n1,2\r\n");
});

it("keeps every byte: a UTF-8 byte order mark is still the first three bytes", async () => {
  server.use(
    http.get("/api/file", () => new HttpResponse(new Uint8Array([0xef, 0xbb, 0xbf, 0x69, 0x64]))),
  );
  withToken("t");
  expect(await bytesOf(await apiBlob("/file"))).toEqual([0xef, 0xbb, 0xbf, 0x69, 0x64]);
});

it("sends no Authorization header when there is no token", async () => {
  let seen: string | null = "unset";
  server.use(
    http.get("/api/file", ({ request }) => {
      seen = request.headers.get("authorization");
      return new HttpResponse("x");
    }),
  );
  withToken(null);
  await apiBlob("/file");
  expect(seen).toBeNull();
});

it("reports a 401 for the token it sent, and throws ApiError(401)", async () => {
  server.use(http.get("/api/file", () => HttpResponse.json({ detail: "no" }, { status: 401 })));
  const onUnauthorized = withToken("t");
  await expect(apiBlob("/file")).rejects.toMatchObject({ name: "ApiError", status: 401 });
  expect(onUnauthorized).toHaveBeenCalledTimes(1);
});

it("throws the server's detail unchanged for another error status, a 403 and a 422 and a 503 alike", async () => {
  server.use(
    http.get("/api/a", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })),
    http.get("/api/b", () =>
      HttpResponse.json(
        { detail: { field: "filters", reason: "too_many_rows", limit: 20000 } },
        { status: 422 },
      ),
    ),
    http.get("/api/c", () => HttpResponse.json({ detail: { reason: "timeout" } }, { status: 503 })),
    http.get("/api/d", () => new HttpResponse("not json", { status: 502 })),
  );
  withToken("t");
  const a = await apiBlob("/a").catch((e: unknown) => e);
  expect(a).toBeInstanceOf(ApiError);
  expect(a).toMatchObject({ status: 403, detail: "forbidden" });
  await expect(apiBlob("/b")).rejects.toMatchObject({
    status: 422,
    detail: { field: "filters", reason: "too_many_rows", limit: 20000 },
  });
  await expect(apiBlob("/c")).rejects.toMatchObject({ status: 503, detail: { reason: "timeout" } });
  await expect(apiBlob("/d")).rejects.toMatchObject({ status: 502, detail: null });
});

it("passes the abort signal to the request", async () => {
  server.use(http.get("/api/file", () => new HttpResponse("x")));
  withToken("t");
  const controller = new AbortController();
  controller.abort();
  await expect(apiBlob("/file", { signal: controller.signal })).rejects.toBeTruthy();
});
