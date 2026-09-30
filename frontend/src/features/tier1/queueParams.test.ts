// src/features/tier1/queueParams.test.ts — the filters and the page live in the URL search params, so a
// reload or a shared link keeps them. A value the UI does not know is ignored, never sent to the server.
import { pageList, readView, viewToParams } from "./queueParams";

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
