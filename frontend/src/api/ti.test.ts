// src/api/ti.test.ts — api/ti.ts: the query each filter makes, and the three reads and the export over the fetch wrapper.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { tiFixture } from "../features/ti/fixtures";
import { ApiError, setTokenSource } from "./client";
import {
  TI_EXPORT_FILES,
  fetchTiExport,
  fetchTiIocs,
  fetchTiStats,
  fetchTiStatus,
  isTiBusy,
  tiExportPath,
  tiFilterParams,
  tiListPath,
} from "./ti";

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

describe("the query of the filters", () => {
  it("is empty when nothing is set, and a list is page and page_size only", () => {
    expect(tiFilterParams({}).toString()).toBe("");
    expect(tiListPath({ page: 1 })).toBe("/ti/iocs?page=1&page_size=50");
  });

  it("carries each filter under the router's own name", () => {
    const params = tiFilterParams({
      source: "urlhaus",
      type: "domain",
      malware: "Example.Rat",
      from: "2026-11-01",
      to: "2026-11-17",
      minConfidence: 75,
      q: "a b&c=d",
    });
    expect(Object.fromEntries(params)).toEqual({
      source: "urlhaus",
      type: "domain",
      malware: "Example.Rat",
      from: "2026-11-01",
      to: "2026-11-17",
      min_confidence: "75",
      q: "a b&c=d",
    });
  });

  it("encodes a hostile search as one parameter", () => {
    const path = tiListPath({ page: 2, q: "&page_size=200#x" });
    const url = new URL(path, "http://x");
    expect(url.searchParams.get("q")).toBe("&page_size=200#x");
    expect(url.searchParams.get("page_size")).toBe("50");
    expect(url.searchParams.get("page")).toBe("2");
  });

  it("sends NO min_confidence for 'any confidence': not 0, not undefined, not a number out of 1..100", () => {
    for (const minConfidence of [undefined, 0, -1, 101, 1.5, Number.NaN]) {
      expect(tiFilterParams({ minConfidence }).has("min_confidence"), String(minConfidence)).toBe(
        false,
      );
    }
    expect(tiFilterParams({ minConfidence: 1 }).get("min_confidence")).toBe("1");
    expect(tiFilterParams({ minConfidence: 100 }).get("min_confidence")).toBe("100");
  });

  it("leaves an empty text out", () => {
    expect(tiFilterParams({ type: "", malware: "", from: "", to: "", q: "" }).toString()).toBe("");
  });

  it("is the same filters in the export, with the format", () => {
    const path = tiExportPath("blocklist", { source: "threatfox", minConfidence: 50 });
    expect(new URL(path, "http://x").pathname).toBe("/ti/export");
    expect(Object.fromEntries(new URL(path, "http://x").searchParams)).toEqual({
      source: "threatfox",
      min_confidence: "50",
      format: "blocklist",
    });
  });
});

describe("the length of the series the page asks for", () => {
  it("is 30 by default and never more than the API's 30 (a longer series is a 422), nor less than 1", async () => {
    const seen: string[] = [];
    server.use(
      http.get("/api/ti/stats", ({ request }) => {
        seen.push(new URL(request.url).search);
        return HttpResponse.json(tiFixture.stats());
      }),
    );
    await fetchTiStats();
    await fetchTiStats(90);
    await fetchTiStats(31);
    await fetchTiStats(30);
    await fetchTiStats(7);
    await fetchTiStats(0);
    await fetchTiStats(-5);
    await fetchTiStats(7.9);
    await fetchTiStats(Number.NaN);
    expect(seen).toEqual([
      "?days=30",
      "?days=30",
      "?days=30",
      "?days=30",
      "?days=7",
      "?days=1",
      "?days=1",
      "?days=7",
      "?days=30",
    ]);
  });
});

describe("the reads", () => {
  it("fetches the list, the stats and the status with the Bearer header", async () => {
    const seen: Array<[string, string | null]> = [];
    server.use(
      http.get("/api/ti/iocs", ({ request }) => {
        seen.push([new URL(request.url).search, request.headers.get("authorization")]);
        return HttpResponse.json(tiFixture.list([tiFixture.ioc()]));
      }),
      http.get("/api/ti/stats", ({ request }) => {
        seen.push([new URL(request.url).search, request.headers.get("authorization")]);
        return HttpResponse.json(tiFixture.stats());
      }),
      http.get("/api/ti/status", ({ request }) => {
        seen.push(["", request.headers.get("authorization")]);
        return HttpResponse.json(tiFixture.status());
      }),
    );
    setTokenSource(
      () => "tok",
      () => {},
    );
    expect((await fetchTiIocs({ page: 3, source: "threatfox" })).rows).toHaveLength(1);
    expect((await fetchTiStats()).by_day).toHaveLength(30);
    expect((await fetchTiStatus()).stale).toBe(false);
    expect(seen).toEqual([
      ["?source=threatfox&page=3&page_size=50", "Bearer tok"],
      ["?days=30", "Bearer tok"],
      ["", "Bearer tok"],
    ]);
  });
});

describe("the export", () => {
  it("is fetched as a blob with the Bearer header, bytes untouched, the fixed file names are the page's own", async () => {
    let auth: string | null = null;
    let search = "";
    server.use(
      http.get("/api/ti/export", ({ request }) => {
        auth = request.headers.get("authorization");
        search = new URL(request.url).search;
        return new HttpResponse(new Uint8Array([0xef, 0xbb, 0xbf, 0x69, 0x64]), {
          headers: {
            "content-type": "text/csv; charset=utf-8",
            "content-disposition": 'attachment; filename="threat-intel-iocs.csv"',
          },
        });
      }),
    );
    setTokenSource(
      () => "tok",
      () => {},
    );
    const blob = await fetchTiExport("csv", { source: "threatfox" });
    expect([...new Uint8Array(await blob.arrayBuffer())]).toEqual([0xef, 0xbb, 0xbf, 0x69, 0x64]);
    expect(auth).toBe("Bearer tok");
    expect(search).toBe("?source=threatfox&format=csv");
    expect(TI_EXPORT_FILES).toEqual({
      csv: "threat-intel-iocs.csv",
      blocklist: "threat-intel-blocklist.txt",
    });
  });
});

describe("isTiBusy", () => {
  it("is true for 503 {reason: timeout} and nothing else", () => {
    expect(isTiBusy(new ApiError(503, { reason: "timeout" }))).toBe(true);
    expect(isTiBusy(new ApiError(503, { reason: "other" }))).toBe(false);
    expect(isTiBusy(new ApiError(503, "busy"))).toBe(false);
    expect(isTiBusy(new ApiError(503, null))).toBe(false);
    expect(isTiBusy(new ApiError(500, { reason: "timeout" }))).toBe(false);
    expect(isTiBusy(new ApiError(422, { reason: "timeout" }))).toBe(false);
    expect(isTiBusy(new Error("503"))).toBe(false);
    expect(isTiBusy(null)).toBe(false);
  });
});
