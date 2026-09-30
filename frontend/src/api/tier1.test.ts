// src/api/tier1.test.ts — the request path of the queue (P10-T14, DEC-164): a sort is sent as `sort` and `dir`
// together; the default risk order is sent as neither, for the server refuses a `dir` with `sort=risk`.
import { queuePath } from "./tier1";

const params = (path: string) => new URL(path, "http://x").searchParams;
const filters = { status: "queued" as const };

describe("queuePath", () => {
  it("asks for the first page of the waiting queue, with no sort, by default", () => {
    const query = params(queuePath(filters, 1));
    expect([...query.keys()].sort()).toEqual(["page", "page_size"]);
  });

  it("sends no sort and no dir for the risk order", () => {
    const query = params(queuePath(filters, 2, undefined));
    expect(query.has("sort")).toBe(false);
    expect(query.has("dir")).toBe(false);
  });

  it("sends the sort and its direction together", () => {
    const time = params(queuePath(filters, 1, { key: "time", dir: "desc" }));
    expect(time.get("sort")).toBe("time");
    expect(time.get("dir")).toBe("desc");
    const agent = params(queuePath(filters, 3, { key: "agent", dir: "asc" }));
    expect(agent.get("sort")).toBe("agent");
    expect(agent.get("dir")).toBe("asc");
    expect(agent.get("page")).toBe("3");
  });

  it("sends the sort beside the filters and the page size", () => {
    const query = params(
      queuePath({ band: "high", agent: "lab-01", status: "mine" }, 2, {
        key: "occurrences",
        dir: "asc",
      }),
    );
    expect(Object.fromEntries(query)).toEqual({
      page: "2",
      page_size: "50",
      band: "high",
      agent: "lab-01",
      status: "mine",
      sort: "occurrences",
      dir: "asc",
    });
  });
});
