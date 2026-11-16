// src/features/soar/soarParams.test.ts — the view of the page in the URL, and the request each view makes.
import { soarListPath } from "../../api/soar";
import { Q_MAX, cleanQuery, listQueryOf, readView, viewSearch, viewToParams } from "./soarParams";

const read = (search: string) => readView(new URLSearchParams(search));
const requestOf = (search: string) =>
  Object.fromEntries(new URL(soarListPath(listQueryOf(read(search))), "http://x").searchParams);
const statusesOf = (search: string) =>
  new URL(soarListPath(listQueryOf(read(search))), "http://x").searchParams.getAll("status");

describe("readView", () => {
  it("is the open tab, no search, the first page, for no params at all", () => {
    expect(read("")).toEqual({ tab: "open", q: "", page: 1 });
  });

  it("reads the four tabs, the search and the page", () => {
    expect(read("tab=done&q=10.0.0.5&page=3")).toEqual({ tab: "done", q: "10.0.0.5", page: 3 });
    for (const tab of ["open", "done", "expired", "notice"])
      expect(read(`tab=${tab}`).tab).toBe(tab);
  });

  it("drops a tab it does not know, a page that is not a whole number, and a search over 100 characters", () => {
    expect(read("tab=everything").tab).toBe("open");
    expect(read("tab=constructor").tab).toBe("open");
    for (const page of ["0", "-1", "2.5", "abc", "", "99999999"])
      expect(read(`page=${page}`).page).toBe(1);
    expect(read(`q=${"x".repeat(150)}`).q).toBe("x".repeat(Q_MAX));
    expect(read("q=%20%20").q).toBe("");
  });
});

describe("a leading # of the search is not part of it (#65 searches case 65)", () => {
  it("is stripped when the URL is read, with the spaces around it", () => {
    expect(read("q=%2365").q).toBe("65");
    expect(read("q=%23%2065%20").q).toBe("65");
    expect(read("q=%23%2365").q).toBe("65");
    expect(read("q=%23").q).toBe("");
    // only a LEADING one: a # inside the text is kept
    expect(read("q=a%2365").q).toBe("a#65");
  });

  it("is stripped from what the form sends, so the request and the URL carry 65", () => {
    expect(cleanQuery("#65")).toBe("65");
    expect(cleanQuery("  # 65  ")).toBe("65");
    expect(cleanQuery("#")).toBe("");
    expect(cleanQuery("x".repeat(150))).toBe("x".repeat(Q_MAX));
    expect(requestOf("q=%2365")).toMatchObject({ q: "65" });
  });
});

describe("viewToParams and viewSearch", () => {
  it("writes only what differs from the default", () => {
    expect(viewSearch({ tab: "open", q: "", page: 1 })).toBe("");
    expect(viewSearch({ tab: "expired", q: "", page: 1 })).toBe("?tab=expired");
    expect(viewSearch({ tab: "open", q: "AD-server", page: 2 })).toBe("?q=AD-server&page=2");
    expect(viewToParams({ tab: "notice", q: "", page: 1 }).toString()).toBe("tab=notice");
  });

  it("round-trips a view", () => {
    const view = { tab: "done" as const, q: "a b&c", page: 4 };
    expect(read(viewToParams(view).toString())).toEqual(view);
  });
});

describe("the request of each tab", () => {
  it("Đang mở asks for open and processing", () => {
    expect(statusesOf("")).toEqual(["open", "processing"]);
  });

  it("Đã xử lý asks for kept, undone and false_positive", () => {
    expect(statusesOf("tab=done")).toEqual(["kept", "undone", "false_positive"]);
  });

  it("Hết hạn asks for expired", () => {
    expect(statusesOf("tab=expired")).toEqual(["expired"]);
  });

  it("Thông báo asks for kind=notice and for no status", () => {
    expect(requestOf("tab=notice")).toEqual({ kind: "notice", page: "1", page_size: "50" });
  });

  it("sends kind=review on the three review tabs, so a notice never shows among tickets, and not on the notices tab's own", () => {
    for (const search of ["", "tab=done", "tab=expired"]) {
      expect(requestOf(search), search).toMatchObject({ kind: "review" });
    }
    expect(requestOf("tab=notice")).toMatchObject({ kind: "notice" });
  });

  it("sends the search and the page, and nothing for an empty search", () => {
    expect(requestOf("q=AD-server&page=2")).toMatchObject({ q: "AD-server", page: "2" });
    expect(requestOf("")).not.toHaveProperty("q");
  });
});
