// src/api/tiContract.test.ts — api/ti.ts and what the Threat Intel page handles, against the backend that serves it
// (backend/app/web/routers/ti.py and backend/app/ti/queries.py), key by key, bound by bound. TypeScript types are erased, so nothing
// else compares them with the handler: a key the backend adds, a bound that moves or a file name it changes would be a page that
// quietly reads `undefined`. This reads the Python source (as soarContract.test.ts does) and holds the frontend to it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TI_DAYS,
  TI_DAYS_MAX,
  TI_EXPORT_FILES,
  TI_EXPORT_FORMATS,
  TI_EXPORT_MAX_ROWS,
  TI_HIGH_CONFIDENCE,
  TI_LOG_STATUSES,
  TI_MALWARE_MAX,
  TI_NEWEST_MALWARE,
  TI_PAGE_MAX,
  TI_PAGE_SIZE,
  TI_PAGE_SIZE_MAX,
  TI_Q_MAX,
  TI_SOURCES,
  TI_TOP_MALWARE,
  TI_TYPE_MAX,
  TI_VALUE_MAX,
} from "./ti";
import { tiFixture } from "../features/ti/fixtures";

const BACKEND = join("..", "backend", "app");
const queriesPy = readFileSync(join(BACKEND, "ti", "queries.py"), "utf8");
const importerPy = readFileSync(join(BACKEND, "ti", "importer.py"), "utf8");
const routerPy = readFileSync(join(BACKEND, "web", "routers", "ti.py"), "utf8");
const tsApi = readFileSync(join("src", "api", "ti.ts"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\/\/.*$/gm, "");

/** The quoted words of the Python tuple assigned to `name`. */
function pyWords(source: string, name: string): string[] {
  const found = new RegExp(`^${name}\\s*(?::[^=]+)?=\\s*[(\\[]([\\s\\S]*?)[)\\]]`, "m").exec(
    source,
  );
  if (found === null) throw new Error(`no ${name} in the source`);
  return [...(found[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);
}

/** The number a Python constant is assigned (`NAME = 200`, `NAME = 20_000`, `NAME = VALUE_MAX_BYTES`). */
function pyNumber(source: string, name: string): number {
  const found = new RegExp(`^${name}\\s*(?::[^=]+)?=\\s*([0-9_]+|[A-Z_]+)\\s*(?:#.*)?$`, "m").exec(
    source,
  );
  if (found === null) throw new Error(`no ${name} in the source`);
  const raw = found[1] as string;
  return /^[0-9_]+$/.test(raw) ? Number(raw.replaceAll("_", "")) : pyNumber(importerPy, raw);
}

/** The text of a Python constant assigned a string: `NAME = "text"`. */
function pyString(source: string, name: string): string {
  const found = new RegExp(`^${name}\\s*(?::[^=]+)?=\\s*"([^"]*)"`, "m").exec(source);
  if (found === null) throw new Error(`no ${name} in the source`);
  return found[1] as string;
}

/** The body of a Python function: from its `def` to the next top-level `def`, `class`, decorator or banner. */
function pyFunction(source: string, name: string): string {
  const start = source.indexOf(`def ${name}(`);
  if (start === -1) throw new Error(`no def ${name}`);
  const rest = source.slice(start + 1);
  const end = rest.search(/\n(?:def |class |@|# ═)/);
  return end === -1 ? rest : rest.slice(0, end);
}

/** The property names of the TypeScript type `name` of api/ti.ts (one level: a nested `{` is skipped). */
function tsKeys(name: string): string[] {
  const open = tsApi.indexOf("{", tsApi.indexOf(`export type ${name} =`));
  let depth = 0;
  let end = open;
  for (let i = open; i < tsApi.length; i += 1) {
    if (tsApi[i] === "{") depth += 1;
    if (tsApi[i] === "}" && --depth === 0) {
      end = i;
      break;
    }
  }
  const keys: string[] = [];
  let level = 0;
  for (const line of tsApi.slice(open + 1, end).split("\n")) {
    if (level === 0) {
      const found = /^\s*(\w+)\??:/.exec(line);
      if (found !== null) keys.push(found[1] as string);
    }
    level += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
  }
  return keys;
}

const sorted = (words: readonly string[]): string[] => [...words].sort();
const dictKeys = (body: string): string[] =>
  [...body.matchAll(/"(\w+)":/g)].map((m) => m[1] as string);

describe("the served IOC", () => {
  const served = pyWords(queriesPy, "IOC_KEYS");

  it("reads the backend (a guard over nothing would pass for nothing)", () => {
    expect(served.length).toBeGreaterThan(10);
    expect(served).toEqual(expect.arrayContaining(["id", "value", "type", "reference", "tags"]));
  });

  it("has exactly the keys of the TypeScript type TiIoc, and of the fixture the tests serve", () => {
    expect(sorted(tsKeys("TiIoc"))).toEqual(sorted(served));
    expect(sorted(Object.keys(tiFixture.ioc()))).toEqual(sorted(served));
  });

  it("is built by serve_ioc with the same keys", () => {
    expect(sorted(dictKeys(pyFunction(queriesPy, "serve_ioc")))).toEqual(sorted(served));
  });
});

describe("the list", () => {
  it("answers rows, total, page and page_size", () => {
    expect(sorted(tsKeys("TiListResponse"))).toEqual(["page", "page_size", "rows", "total"]);
    expect(pyFunction(routerPy, "api_list_iocs")).toContain(
      'return {"rows": rows, "total": total, "page": page, "page_size": page_size}',
    );
  });

  it("holds the bounds the page sends inside", () => {
    expect(TI_PAGE_SIZE).toBe(pyNumber(queriesPy, "PAGE_SIZE_DEFAULT"));
    expect(TI_PAGE_SIZE_MAX).toBe(pyNumber(queriesPy, "PAGE_SIZE_MAX"));
    expect(TI_PAGE_MAX).toBe(pyNumber(queriesPy, "PAGE_MAX"));
    expect(TI_Q_MAX).toBe(pyNumber(queriesPy, "Q_MAX"));
    expect(TI_TYPE_MAX).toBe(pyNumber(queriesPy, "TYPE_MAX"));
    expect(TI_MALWARE_MAX).toBe(pyNumber(queriesPy, "MALWARE_MAX"));
    expect(TI_VALUE_MAX).toBe(pyNumber(queriesPy, "VALUE_MAX"));
  });

  it("names the filters as the router's own query parameters", () => {
    const filters = pyFunction(routerPy, "filters");
    expect(filters).toContain("source: Source | None");
    expect(filters).toContain('alias="type"');
    expect(filters).toContain("malware: Annotated");
    expect(filters).toContain('alias="from"');
    expect(filters).toContain('alias="to"');
    expect(filters).toContain("min_confidence: Annotated[int | None, Query(ge=0, le=100)]");
    expect(filters).toContain("q: Annotated");
    expect(routerPy).toContain("page_size: Annotated[int, Query(ge=1, le=queries.PAGE_SIZE_MAX)]");
  });

  it("is on the path the page asks", () => {
    expect(routerPy).toContain('@router.get("/api/ti/iocs")');
    expect(tsApi).toContain("/ti/iocs?");
  });
});

describe("the sources", () => {
  it("are the three of the importer, the router's Literal and the page's", () => {
    expect(sorted(TI_SOURCES)).toEqual(sorted(pyWords(importerPy, "SOURCES")));
    const literal = /^Source = Literal\[([^\]]*)\]/m.exec(routerPy)?.[1] ?? "";
    expect(sorted([...literal.matchAll(/"(\w+)"/g)].map((m) => m[1] as string))).toEqual(
      sorted(TI_SOURCES),
    );
  });

  it("are the keys of a day of the series and of the stats' `sources`", () => {
    const day = tiFixture.stats().by_day[0] as Record<string, unknown>;
    expect(sorted(Object.keys(day))).toEqual(sorted(["day", ...TI_SOURCES, "total"]));
    expect(sorted(tsKeys("TiDay"))).toEqual(sorted(["day", ...TI_SOURCES, "total"]));
    const built = /by_day\.append\(\{([^}]*)\}\)/.exec(pyFunction(queriesPy, "stats"))?.[1] ?? "";
    expect(built).toContain('"day": day.isoformat()');
    expect(built).toContain("**counts");
    expect(built).toContain('"total": sum(counts.values())');
  });
});

describe("the stats", () => {
  const stats = pyFunction(queriesPy, "stats");
  const returned = /return \{([\s\S]*?)\n {4}\}/.exec(stats)?.[1] ?? "";

  it("has exactly the keys of the TypeScript type TiStats and of the fixture", () => {
    expect(returned).not.toBe("");
    expect(sorted(tsKeys("TiStats"))).toEqual(sorted(dictKeys(returned)));
    expect(sorted(Object.keys(tiFixture.stats()))).toEqual(sorted(dictKeys(returned)));
  });

  it("is the route the page asks, over days 1..90 with 30 as its own default", () => {
    expect(routerPy).toContain('@router.get("/api/ti/stats")');
    expect(pyNumber(queriesPy, "DAYS_DEFAULT")).toBe(TI_DAYS);
    expect(pyNumber(queriesPy, "DAYS_MAX")).toBe(TI_DAYS_MAX);
    expect(tsApi).toContain("/ti/stats?");
  });

  it("has the figures the cards name: a top of ten, a newest of three, 75 as high confidence", () => {
    expect(pyNumber(queriesPy, "TOP_MALWARE")).toBe(TI_TOP_MALWARE);
    expect(pyNumber(queriesPy, "NEWEST_MALWARE")).toBe(TI_NEWEST_MALWARE);
    expect(pyNumber(queriesPy, "HIGH_CONFIDENCE")).toBe(TI_HIGH_CONFIDENCE);
    expect(stats).toContain('"malware": name, "count": count');
    expect(sorted(tsKeys("TiMalwareCount"))).toEqual(["count", "malware"]);
  });
});

describe("the status", () => {
  it("has the keys of the TypeScript types and of the fixture", () => {
    const status = pyFunction(queriesPy, "status");
    const returned = /return \{([\s\S]*?)\n {4}\}/.exec(status)?.[1] ?? "";
    expect(sorted(tsKeys("TiStatus"))).toEqual(sorted(dictKeys(returned)));
    expect(sorted(Object.keys(tiFixture.status()))).toEqual(sorted(dictKeys(returned)));
    const log = /return \{([\s\S]*?)\n {4}\}/.exec(pyFunction(queriesPy, "_serve_log"))?.[1] ?? "";
    expect(sorted(tsKeys("TiLog"))).toEqual(sorted(dictKeys(log)));
    const logFixture = tiFixture.status().latest_success as Record<string, unknown>;
    expect(sorted(Object.keys(logFixture))).toEqual(sorted(dictKeys(log)));
  });

  it("knows the three statuses of a run, and the route", () => {
    expect(sorted(TI_LOG_STATUSES)).toEqual(sorted(pyWords(importerPy, "STATUSES")));
    expect(routerPy).toContain('@router.get("/api/ti/status")');
    expect(tsApi).toContain('"/ti/status"');
  });
});

describe("the export", () => {
  it("is the admin's alone, and every read is for the three roles", () => {
    expect(routerPy).toContain(
      'Reader = Annotated[Claims, Depends(require_role("tier1", "tier2", "admin"))]',
    );
    expect(routerPy).toContain('Admin = Annotated[Claims, Depends(require_role("admin"))]');
    expect(/def api_export\(\s*conn: Conn,\s*claims: Admin,/.test(routerPy)).toBe(true);
  });

  it("has two formats and fixed file names that are the router's own", () => {
    expect(TI_EXPORT_FORMATS).toEqual(["csv", "blocklist"]);
    expect(routerPy).toContain(
      'fmt: Annotated[Literal["csv", "blocklist"], Query(alias="format")]',
    );
    expect(TI_EXPORT_FILES.csv).toBe(pyString(routerPy, "CSV_FILE"));
    expect(TI_EXPORT_FILES.blocklist).toBe(pyString(routerPy, "BLOCKLIST_FILE"));
    expect(routerPy).toContain('@router.get("/api/ti/export")');
    expect(tsApi).toContain("/ti/export?");
  });

  it("refuses an export of more rows than the cap with a closed 422, and the page knows the cap", () => {
    expect(TI_EXPORT_MAX_ROWS).toBe(pyNumber(queriesPy, "EXPORT_MAX_ROWS"));
    expect(routerPy).toContain(
      'detail={"field": "filters", "reason": "too_many_rows", "limit": exc.limit}',
    );
  });
});

describe("the busy answer", () => {
  it("is a 503 whose detail is {reason: timeout}, on every read", () => {
    expect(routerPy).toContain(
      'raise HTTPException(status_code=503, detail={"reason": "timeout"})',
    );
    for (const name of ["api_list_iocs", "api_stats", "api_status", "api_export"]) {
      expect(pyFunction(routerPy, name), name).toContain("_bounded(conn)");
    }
  });
});
