// src/features/tier1/queueParams.test.ts — the filters, the sort and the page live in the URL search params,
// so a reload or a shared link keeps them. A value the UI does not know is ignored, never sent to the server.
import { nextSort, pageList, readView, viewSearch, viewToParams } from "./queueParams";

const read = (search: string) => readView(new URLSearchParams(search));

describe("readView", () => {
  it("is the waiting queue, first page, no filter, for an empty query", () => {
    expect(read("")).toEqual({ filters: { status: "queued" }, page: 1 });
  });

  it("reads every filter and the page", () => {
    expect(read("band=high&category=ssh_brute_force&agent=lab-01&status=mine&page=3")).toEqual({
      filters: { band: "high", category: "ssh_brute_force", agent: "lab-01", status: "mine" },
      page: 3,
    });
  });

  it("takes the band as a code only: a label, or a code it has no name for, is no filter", () => {
    for (const band of ["Cao", "urgent", "", "HIGH", "constructor"]) {
      expect(read(`band=${encodeURIComponent(band)}`).filters).toEqual({ status: "queued" });
    }
  });

  it("takes any status but 'mine' for the waiting queue", () => {
    for (const status of ["queued", "all", "", "tier1_active"]) {
      expect(read(`status=${status}`).filters.status).toBe("queued");
    }
  });

  it("trims the text filters, and leaves out an empty or blank one", () => {
    expect(read("category=%20%20x%20&agent=%20%20").filters).toEqual({
      category: "x",
      status: "queued",
    });
  });

  it("takes a page that is a whole number from 1, and any other for the first", () => {
    for (const page of ["0", "-2", "abc", "", "1.5", "2e3", "99999999999999999999"]) {
      expect(read(`page=${page}`).page).toBe(1);
    }
    expect(read("page=7").page).toBe(7);
  });
});

describe("viewToParams", () => {
  it("writes nothing for the default view, so the plain link stays plain", () => {
    expect(viewToParams({ filters: { status: "queued" }, page: 1 }).toString()).toBe("");
  });

  it("writes only what differs from the default", () => {
    const params = viewToParams({
      filters: { band: "critical", agent: "lab-01", status: "mine" },
      page: 2,
    });
    expect(Object.fromEntries(params)).toEqual({
      band: "critical",
      agent: "lab-01",
      status: "mine",
      page: "2",
    });
  });

  it("round-trips through readView", () => {
    const view = {
      filters: { band: "low" as const, category: "a b&c=d", status: "mine" as const },
      page: 4,
    };
    expect(readView(new URLSearchParams(viewToParams(view).toString()))).toEqual(view);
  });
});

// P10-T14 (DEC-164): the sort is `sort` and `dir` beside the filters. The default risk order is the absence
// of both; a sort is always written with its direction, so a link says what it shows.
describe("the sort in the URL", () => {
  it("is the risk order, with no sort, for an empty query", () => {
    expect(read("").sort).toBeUndefined();
    expect(read("band=high&page=2").sort).toBeUndefined();
  });

  it("reads each sort key with its direction", () => {
    expect(read("sort=time&dir=asc").sort).toEqual({ key: "time", dir: "asc" });
    expect(read("sort=time&dir=desc").sort).toEqual({ key: "time", dir: "desc" });
    expect(read("sort=occurrences&dir=asc").sort).toEqual({ key: "occurrences", dir: "asc" });
    expect(read("sort=agent&dir=desc").sort).toEqual({ key: "agent", dir: "desc" });
  });

  it("gives a key without a direction its default: newest, most, A to Z", () => {
    expect(read("sort=time").sort).toEqual({ key: "time", dir: "desc" });
    expect(read("sort=occurrences").sort).toEqual({ key: "occurrences", dir: "desc" });
    expect(read("sort=agent").sort).toEqual({ key: "agent", dir: "asc" });
  });

  it("gives a direction it does not know the default of the key", () => {
    for (const dir of ["up", "", "ASC", "descending", "constructor"]) {
      expect(read(`sort=agent&dir=${dir}`).sort).toEqual({ key: "agent", dir: "asc" });
      expect(read(`sort=time&dir=${dir}`).sort).toEqual({ key: "time", dir: "desc" });
    }
  });

  it("takes a sort key it does not know, or the risk order named, as no sort", () => {
    // The server refuses every one of these (422): the UI never sends them.
    for (const sort of [
      "risk",
      "",
      "Time",
      "risk_score",
      "triaged_count",
      "needs_retriage",
      "constructor",
      "time;drop",
    ]) {
      expect(read(`sort=${encodeURIComponent(sort)}&dir=asc`).sort).toBeUndefined();
    }
  });

  it("takes a direction with no sort as no sort", () => {
    expect(read("dir=asc").sort).toBeUndefined();
    expect(read("dir=desc&page=2").sort).toBeUndefined();
  });

  it("writes a sort with its direction, and the risk order as neither", () => {
    const filters = { status: "queued" as const };
    expect(
      Object.fromEntries(viewToParams({ filters, page: 1, sort: { key: "time", dir: "desc" } })),
    ).toEqual({ sort: "time", dir: "desc" });
    expect(
      Object.fromEntries(viewToParams({ filters, page: 1, sort: { key: "agent", dir: "desc" } })),
    ).toEqual({ sort: "agent", dir: "desc" });
    expect(viewToParams({ filters, page: 1 }).toString()).toBe("");
    expect(viewToParams({ filters, page: 1, sort: undefined }).toString()).toBe("");
  });

  it("round-trips the filters, the sort and the page together", () => {
    const view = {
      filters: {
        band: "high" as const,
        category: "a b&c=d",
        agent: "lab-01",
        status: "mine" as const,
      },
      page: 3,
      sort: { key: "occurrences" as const, dir: "asc" as const },
    };
    const search = viewToParams(view).toString();
    expect(readView(new URLSearchParams(search))).toEqual(view);
    expect(Object.fromEntries(new URLSearchParams(search))).toEqual({
      band: "high",
      category: "a b&c=d",
      agent: "lab-01",
      status: "mine",
      sort: "occurrences",
      dir: "asc",
      page: "3",
    });
  });

  it("keeps the sort in the search of a link to a view", () => {
    const filters = { band: "low" as const, status: "queued" as const };
    expect(viewSearch({ filters, page: 2, sort: { key: "time", dir: "asc" } })).toBe(
      "?band=low&sort=time&dir=asc&page=2",
    );
    expect(viewSearch({ filters, page: 2 })).toBe("?band=low&page=2");
  });
});

describe("nextSort (a click on a column header)", () => {
  it("sorts by the key in its default direction on the first click", () => {
    expect(nextSort(undefined, "time")).toEqual({ key: "time", dir: "desc" });
    expect(nextSort(undefined, "occurrences")).toEqual({ key: "occurrences", dir: "desc" });
    expect(nextSort(undefined, "agent")).toEqual({ key: "agent", dir: "asc" });
  });

  it("reverses the direction on a second click on the same key, and back on a third", () => {
    const first = nextSort(undefined, "agent");
    const second = nextSort(first, "agent");
    expect(second).toEqual({ key: "agent", dir: "desc" });
    expect(nextSort(second, "agent")).toEqual({ key: "agent", dir: "asc" });
    expect(nextSort({ key: "time", dir: "desc" }, "time")).toEqual({ key: "time", dir: "asc" });
  });

  it("starts another key in its own default direction, whatever the last key was", () => {
    expect(nextSort({ key: "time", dir: "asc" }, "agent")).toEqual({ key: "agent", dir: "asc" });
    expect(nextSort({ key: "agent", dir: "desc" }, "time")).toEqual({ key: "time", dir: "desc" });
  });
});

describe("pageList", () => {
  it("lists every page of a short queue", () => {
    expect(pageList(1, 1)).toEqual([1]);
    expect(pageList(2, 3)).toEqual([1, 2, 3]);
    expect(pageList(4, 7)).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it("keeps the ends and two pages each side of the current one, and marks what it leaves out", () => {
    expect(pageList(1, 20)).toEqual([1, 2, 3, "gap", 20]);
    expect(pageList(10, 20)).toEqual([1, "gap", 8, 9, 10, 11, 12, "gap", 20]);
    expect(pageList(20, 20)).toEqual([1, "gap", 18, 19, 20]);
  });

  it("shows a single page it would otherwise leave out, instead of a gap mark", () => {
    expect(pageList(5, 20)).toEqual([1, 2, 3, 4, 5, 6, 7, "gap", 20]);
    expect(pageList(6, 20)).toEqual([1, "gap", 4, 5, 6, 7, 8, "gap", 20]);
  });

  it("stays inside the queue for a page beyond its end", () => {
    expect(pageList(99, 3)).toEqual([1, 2, 3]);
    expect(pageList(3, 0)).toEqual([1]);
  });
});
