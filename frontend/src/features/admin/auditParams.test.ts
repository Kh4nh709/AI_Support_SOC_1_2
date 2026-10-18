// src/features/admin/auditParams.test.ts — the audit page's view as URL search params (a reload and a shared
// link keep the filters, spec §3) and the reading of a failed read (what a 422, a 503 and a 403 each say).
import { ApiError } from "../../api/client";
import {
  DEFAULT_RANGE,
  PAGE_SIZE,
  auditFaultOf,
  isFiltered,
  readView,
  viewKey,
  viewToParams,
} from "./auditParams";

const params = (query: string) => new URLSearchParams(query);

describe("readView", () => {
  it("reads no filter as the default view: seven days, nothing else", () => {
    expect(readView(params(""))).toEqual({ range: "7d" });
    expect(DEFAULT_RANGE).toBe("7d");
  });

  it("reads each of the four filters", () => {
    expect(
      readView(params("range=30d&group=users&actor=lan.t1&subject=1759012345.1662100")),
    ).toEqual({ range: "30d", group: "users", actor: "lan.t1", subject: "1759012345.1662100" });
  });

  it("reads each range the server offers", () => {
    for (const range of ["24h", "7d", "30d"] as const) {
      expect(readView(params(`range=${range}`)).range).toBe(range);
    }
  });

  it("drops a range or a group that is not one the server offers, so it is never sent", () => {
    expect(readView(params("range=1y&group=nope"))).toEqual({ range: "7d" });
    expect(readView(params("range=&group="))).toEqual({ range: "7d" });
    expect(readView(params("group=USERS"))).toEqual({ range: "7d" });
    expect(readView(params("range=month"))).toEqual({ range: "7d" });
  });

  it("drops an empty or blank actor or subject: the server answers 422 to an empty text", () => {
    expect(readView(params("actor=&subject="))).toEqual({ range: "7d" });
    expect(readView(params("actor=%20%20&subject=%09"))).toEqual({ range: "7d" });
  });

  it("trims the text of an actor and of a subject", () => {
    expect(readView(params("actor=%20lan.t1%20&subject=%20abc%20"))).toEqual({
      range: "7d",
      actor: "lan.t1",
      subject: "abc",
    });
  });

  it("ignores a key it does not know, and a cursor in the URL (the cursor is the page's, not the link's)", () => {
    expect(readView(params("cursor=12&limit=5&page=3&x=1"))).toEqual({ range: "7d" });
  });

  it("keeps a hostile value as text, whole", () => {
    expect(readView(params("actor=%3Cscript%3E&subject=%00"))).toEqual({
      range: "7d",
      actor: "<script>",
      subject: "\u0000",
    });
  });
});

describe("viewToParams", () => {
  it("writes only what differs from the default", () => {
    expect(viewToParams({ range: "7d" }).toString()).toBe("");
    expect(viewToParams({ range: "24h" }).toString()).toBe("range=24h");
    expect(viewToParams({ range: "7d", group: "model" }).toString()).toBe("group=model");
  });

  it("writes the four filters in a fixed order", () => {
    expect(
      viewToParams({ range: "30d", group: "system", actor: "llm", subject: "x y" }).toString(),
    ).toBe("range=30d&group=system&actor=llm&subject=x+y");
  });

  it("round-trips through readView", () => {
    const view = {
      range: "24h",
      group: "alerts_cases",
      actor: "lan.t1",
      subject: "a&b=c#d",
    } as const;
    expect(readView(viewToParams(view))).toEqual(view);
    expect(readView(viewToParams({ range: "7d" }))).toEqual({ range: "7d" });
  });

  it("never writes an empty text", () => {
    expect(viewToParams({ range: "7d", actor: "", subject: "" }).toString()).toBe("");
  });
});

describe("viewKey and isFiltered", () => {
  it("keys the same view the same way, and a different one differently", () => {
    expect(viewKey({ range: "7d", actor: "a" })).toBe(viewKey({ actor: "a", range: "7d" }));
    expect(viewKey({ range: "7d", actor: "a" })).not.toBe(viewKey({ range: "7d", actor: "b" }));
    expect(viewKey({ range: "7d" })).not.toBe(viewKey({ range: "24h" }));
  });

  it("says a view is filtered when a filter is set, or the range is narrower than the default", () => {
    expect(isFiltered({ range: "7d" })).toBe(false);
    expect(isFiltered({ range: "30d" })).toBe(false);
    expect(isFiltered({ range: "24h" })).toBe(true);
    expect(isFiltered({ range: "7d", group: "users" })).toBe(true);
    expect(isFiltered({ range: "7d", actor: "a" })).toBe(true);
    expect(isFiltered({ range: "7d", subject: "a" })).toBe(true);
  });

  it("asks for 50 rows a page, the server's own page size", () => {
    expect(PAGE_SIZE).toBe(50);
  });
});

/** A 422 as FastAPI's validation writes it: a list of `{type, loc, msg}`. */
const validation = (name: string | null) =>
  new ApiError(422, [
    { type: "value_error", loc: name === null ? ["query"] : ["query", name], msg: "bad" },
  ]);

describe("auditFaultOf", () => {
  it.each(["range", "group", "actor", "subject"] as const)(
    "reads a 422 on `%s` as a fault of that filter",
    (name) => {
      expect(auditFaultOf(validation(name))).toEqual({ kind: "filter", field: name });
    },
  );

  it("reads a 422 on the cursor, the limit, or nothing that names a filter, as a fault of the filters", () => {
    expect(auditFaultOf(validation("cursor"))).toEqual({ kind: "filters" });
    expect(auditFaultOf(validation("limit"))).toEqual({ kind: "filters" });
    expect(auditFaultOf(validation(null))).toEqual({ kind: "filters" });
    expect(auditFaultOf(new ApiError(422, "something"))).toEqual({ kind: "filters" });
    expect(auditFaultOf(new ApiError(422, null))).toEqual({ kind: "filters" });
    expect(auditFaultOf(new ApiError(422, [null, 3, "x"]))).toEqual({ kind: "filters" });
  });

  it("takes the first entry that names one of the four filters", () => {
    const error = new ApiError(422, [
      { loc: ["query", "limit"], msg: "x" },
      { loc: ["query", "subject"], msg: "y" },
    ]);
    expect(auditFaultOf(error)).toEqual({ kind: "filter", field: "subject" });
  });

  it("reads the house shape of a 422 too: {field, reason}", () => {
    expect(auditFaultOf(new ApiError(422, { field: "actor", reason: "empty" }))).toEqual({
      kind: "filter",
      field: "actor",
    });
    expect(auditFaultOf(new ApiError(422, { field: "cursor", reason: "invalid" }))).toEqual({
      kind: "filters",
    });
  });

  it("does not read a `loc` of another place (a body or a path) as a filter", () => {
    expect(auditFaultOf(new ApiError(422, [{ loc: ["body", "actor"], msg: "x" }]))).toEqual({
      kind: "filters",
    });
  });

  it("reads the two 503 reasons", () => {
    expect(auditFaultOf(new ApiError(503, { reason: "timeout" }))).toEqual({ kind: "timeout" });
    expect(auditFaultOf(new ApiError(503, { reason: "query_failed" }))).toEqual({
      kind: "query_failed",
    });
  });

  it("reads any 403 as a refusal, whatever it says", () => {
    expect(auditFaultOf(new ApiError(403, "forbidden"))).toEqual({ kind: "forbidden" });
    expect(auditFaultOf(new ApiError(403, null))).toEqual({ kind: "forbidden" });
    expect(auditFaultOf(new ApiError(403, { reason: "unknown-thing" }))).toEqual({
      kind: "forbidden",
    });
  });

  it("reads everything else as a failed load, with the status", () => {
    expect(auditFaultOf(new ApiError(500, "Internal Server Error"))).toEqual({
      kind: "load",
      status: 500,
    });
    expect(auditFaultOf(new ApiError(503, "auth disabled"))).toEqual({ kind: "load", status: 503 });
    expect(auditFaultOf(new ApiError(404, null))).toEqual({ kind: "load", status: 404 });
    expect(auditFaultOf(new ApiError(401, null))).toEqual({ kind: "load", status: 401 });
  });

  it("reads a network failure as a failed load with no status, and never throws", () => {
    expect(auditFaultOf(new TypeError("Failed to fetch"))).toEqual({ kind: "load", status: 0 });
    expect(auditFaultOf(null)).toEqual({ kind: "load", status: 0 });
    expect(auditFaultOf(undefined)).toEqual({ kind: "load", status: 0 });
    expect(auditFaultOf("boom")).toEqual({ kind: "load", status: 0 });
  });
});
