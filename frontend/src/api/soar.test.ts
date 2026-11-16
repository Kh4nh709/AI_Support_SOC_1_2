// src/api/soar.test.ts — the request paths of the SOAR review routes (spec section 4): what is sent for a filter, a
// page, the count, one review and a decision. The transport is a fake fetch, so the test sees the URL and the body.
import { afterEach, vi } from "vitest";
import { ApiError } from "./client";
import {
  SOAR_PAGE_SIZE,
  fetchSoarCount,
  fetchSoarReview,
  fetchSoarReviews,
  postSoarDecision,
  soarListPath,
} from "./soar";

const params = (path: string) => new URL(path, "http://x").searchParams;

afterEach(() => vi.restoreAllMocks());

function fakeFetch(body: unknown, status = 200) {
  return vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(async () => new Response(JSON.stringify(body), { status }));
}

describe("soarListPath", () => {
  it("asks for the first page of fifty with nothing else by default", () => {
    const path = soarListPath({ page: 1 });
    expect(path.startsWith("/soar/reviews?")).toBe(true);
    expect(Object.fromEntries(params(path))).toEqual({
      page: "1",
      page_size: String(SOAR_PAGE_SIZE),
    });
    expect(SOAR_PAGE_SIZE).toBe(50);
  });

  it("repeats status, once per status", () => {
    const query = params(soarListPath({ status: ["open", "processing"], page: 2 }));
    expect(query.getAll("status")).toEqual(["open", "processing"]);
    expect(query.get("page")).toBe("2");
  });

  it("sends kind, q and a page size when they are set, and leaves out an empty q and an empty status list", () => {
    const set = params(soarListPath({ kind: "notice", q: "10.0.0.5", page: 3, pageSize: 20 }));
    expect(Object.fromEntries(set)).toEqual({
      kind: "notice",
      q: "10.0.0.5",
      page: "3",
      page_size: "20",
    });
    const empty = params(soarListPath({ status: [], q: "", page: 1 }));
    expect([...empty.keys()].sort()).toEqual(["page", "page_size"]);
  });

  it("encodes a q that holds characters of a URL", () => {
    const path = soarListPath({ q: "a&b=c#d%", page: 1 });
    expect(path).not.toContain("a&b");
    expect(params(path).get("q")).toBe("a&b=c#d%");
  });
});

describe("the routes", () => {
  it("fetches the list from /api/soar/reviews and returns the answer as it came", async () => {
    const answer = { rows: [], total: 0, page: 1, page_size: 50 };
    const spy = fakeFetch(answer);
    await expect(fetchSoarReviews({ status: ["kept"], page: 1 })).resolves.toEqual(answer);
    expect(String(spy.mock.calls[0]?.[0])).toBe(
      "/api/soar/reviews?page=1&page_size=50&status=kept",
    );
  });

  it("fetches the count from /api/soar/reviews/count", async () => {
    const spy = fakeFetch({ count: 3, latest_received_at: "2026-11-16T01:00:00+00:00" });
    await expect(fetchSoarCount()).resolves.toEqual({
      count: 3,
      latest_received_at: "2026-11-16T01:00:00+00:00",
    });
    expect(String(spy.mock.calls[0]?.[0])).toBe("/api/soar/reviews/count");
  });

  it("fetches one review by its id, encoded", async () => {
    const spy = fakeFetch({ id: "N-1/x" });
    await fetchSoarReview("N-1/x");
    expect(String(spy.mock.calls[0]?.[0])).toBe("/api/soar/reviews/N-1%2Fx");
  });

  it("posts a decision as JSON, with the note only when there is one", async () => {
    const spy = fakeFetch({ outcome: "ok", message: null, review: {} });
    await postSoarDecision("K7QM2XHP", { decision: "undo", note: "máy sạch" });
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/soar/reviews/K7QM2XHP/decision");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("content-type")).toBe("application/json");
    expect(JSON.parse(String(init.body))).toEqual({ decision: "undo", note: "máy sạch" });
    await postSoarDecision("K7QM2XHP", { decision: "keep" });
    const [, second] = spy.mock.calls[1] as [string, RequestInit];
    expect(JSON.parse(String(second.body))).toEqual({ decision: "keep" });
  });

  it("throws the ApiError of a local 409 with its detail unchanged", async () => {
    fakeFetch({ detail: { reason: "locked", review: { id: "K7QM2XHP" } } }, 409);
    const error = await postSoarDecision("K7QM2XHP", { decision: "keep" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(409);
    expect((error as ApiError).detail).toEqual({
      reason: "locked",
      review: { id: "K7QM2XHP" },
    });
  });
});
