// src/api/adminLab.test.ts — the lab calls of api/admin.ts (P14-T10): one typed function per route of
// backend/app/web/routers/admin_lab.py, each sending the method, the path and the JSON body the handler reads,
// and the reader of the refusals that page shows in words (`labErrorOf`). The constants the page's form checks
// are held equal to the backend's here.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { ApiError, setTokenSource } from "./client";
import {
  LAB_FIELDS,
  LAB_FIELD_REASONS,
  LAB_LABELS,
  LAB_LIMITS,
  LAB_PURPOSES,
  createLabRun,
  deleteLabLabel,
  getLabRunAlerts,
  labErrorOf,
  listLabRuns,
  putLabLabel,
  type LabError,
} from "./admin";

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

type Seen = {
  method: string;
  path: string;
  search: string;
  raw: string;
  body: unknown;
  contentType: string | null;
  authorization: string | null;
};

/** Answers every /api call with `answer` (a 204 has no body) and records what each call carried. */
function record(answer: JsonBodyType = {}, status = 200): Seen[] {
  const seen: Seen[] = [];
  server.use(
    http.all("/api/*", async ({ request }) => {
      const url = new URL(request.url);
      const raw = await request.text();
      seen.push({
        method: request.method,
        path: url.pathname,
        search: url.search,
        raw,
        body: raw === "" ? undefined : (JSON.parse(raw) as unknown),
        contentType: request.headers.get("content-type"),
        authorization: request.headers.get("authorization"),
      });
      return status === 204
        ? new HttpResponse(null, { status })
        : HttpResponse.json(answer, { status });
    }),
  );
  return seen;
}

const RUN = "5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab";

describe("the lab functions send the method, path and body of their routes", () => {
  it("listLabRuns is GET /api/admin/lab/runs, with no body and no content type", async () => {
    const seen = record({ runs: [] });
    await expect(listLabRuns()).resolves.toEqual({ runs: [] });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      method: "GET",
      path: "/api/admin/lab/runs",
      raw: "",
      contentType: null,
    });
  });

  it("createLabRun is POST /api/admin/lab/runs with exactly the four fields, as JSON", async () => {
    const body = {
      name: "Lần 1",
      purpose: "test",
      starts_at: "2026-11-04T09:00:00+07:00",
      ends_at: "2026-11-04T11:00:00+07:00",
    } as const;
    const seen = record({ run_id: RUN });
    await createLabRun(body);
    expect(seen[0]).toMatchObject({ method: "POST", path: "/api/admin/lab/runs", body });
    expect(seen[0]?.contentType).toMatch(/^application\/json/);
  });

  it("getLabRunAlerts is GET .../runs/{id}/alerts, with no query until it is given one", async () => {
    const seen = record({ run: {}, alerts: [], next_after: null });
    await getLabRunAlerts(RUN);
    expect(seen[0]).toMatchObject({
      method: "GET",
      path: `/api/admin/lab/runs/${RUN}/alerts`,
      search: "",
      raw: "",
    });
  });

  it("getLabRunAlerts sends `after` and `limit` when they are given, and `after` encoded", async () => {
    const seen = record({ run: {}, alerts: [], next_after: null });
    await getLabRunAlerts(RUN, { after: "1766.5&x=1", limit: 50 });
    expect(seen[0]?.search).toBe("?after=1766.5%26x%3D1&limit=50");
    await getLabRunAlerts(RUN, { after: null });
    expect(seen[1]?.search).toBe("");
  });

  it("encodes a run id that is not a uuid, rather than letting it change the path", async () => {
    const seen = record({});
    await getLabRunAlerts("a/b?c");
    expect(seen[0]?.path).toBe("/api/admin/lab/runs/a%2Fb%3Fc/alerts");
  });

  it("putLabLabel is PUT .../labels/{alert_id} with {label} and nothing else", async () => {
    const seen = record({ alert_id: "1766.5", run_id: RUN, label: "true_positive" });
    await expect(putLabLabel("1766.5", "true_positive")).resolves.toEqual({
      alert_id: "1766.5",
      run_id: RUN,
      label: "true_positive",
    });
    expect(seen[0]).toMatchObject({
      method: "PUT",
      path: "/api/admin/lab/labels/1766.5",
      body: { label: "true_positive" },
    });
    expect(seen[0]?.contentType).toMatch(/^application\/json/);
  });

  it("encodes an alert id in a path", async () => {
    const seen = record({});
    await putLabLabel("a/b%c", "false_positive");
    await deleteLabLabel("a/b%c");
    expect(seen.map((s) => s.path)).toEqual([
      "/api/admin/lab/labels/a%2Fb%25c",
      "/api/admin/lab/labels/a%2Fb%25c",
    ]);
  });

  // The route asks DELETE only for the JSON content type (`deps.require_json_type`), and the client's wrapper
  // sets it only when it has a body to send: so the call sends `{}`, as the undo of the gold labels does.
  it("deleteLabLabel is DELETE .../labels/{alert_id} with the JSON content type, and resolves to nothing on 204", async () => {
    const seen = record({}, 204);
    await expect(deleteLabLabel("1766.5")).resolves.toBeUndefined();
    expect(seen[0]).toMatchObject({
      method: "DELETE",
      path: "/api/admin/lab/labels/1766.5",
      raw: "{}",
      contentType: "application/json",
    });
  });

  it("sends the Bearer token of the session, as every call of the app does", async () => {
    setTokenSource(
      () => "tok-admin",
      () => {},
    );
    const seen = record({ runs: [] });
    await listLabRuns();
    expect(seen[0]?.authorization).toBe("Bearer tok-admin");
  });
});

describe("the vocabularies of the page are the backend's", () => {
  const BACKEND = join("..", "backend", "app");
  const py = (...path: string[]) => readFileSync(join(BACKEND, ...path), "utf8");
  const quoted = (text: string | undefined) =>
    [...(text ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);

  it("purposes are PURPOSES of lab/runs.py, labels are LABELS of lab/labels.py", () => {
    const purposes = /^PURPOSES: tuple\[str, \.\.\.\] = \(([^)]*)\)/m.exec(py("lab", "runs.py"));
    const labels = /^LABELS: tuple\[str, \.\.\.\] = \(([^)]*)\)/m.exec(py("lab", "labels.py"));
    expect([...LAB_PURPOSES]).toEqual(quoted(purposes?.[1]));
    expect([...LAB_LABELS]).toEqual(quoted(labels?.[1]));
  });

  it("the longest name is NAME_MAX_CHARS of lab/runs.py", () => {
    const max = /^NAME_MAX_CHARS = (\d+)/m.exec(py("lab", "runs.py"));
    expect(LAB_LIMITS.nameMax).toBe(Number(max?.[1]));
  });

  it("the years of an instant are YEAR_MIN and YEAR_MAX of lab/runs.py", () => {
    const min = /^YEAR_MIN = (\d+)/m.exec(py("lab", "runs.py"));
    const max = /^YEAR_MAX = (\d+)/m.exec(py("lab", "runs.py"));
    expect([LAB_LIMITS.yearMin, LAB_LIMITS.yearMax]).toEqual([Number(min?.[1]), Number(max?.[1])]);
  });

  // The reasons and fields the router writes, read from its source: a code it started to use and the reader
  // below does not know would reach the page as `other`, in the generic words.
  it("every 422 field and reason, and every 409 and 404 reason, the router writes is one the reader knows", () => {
    const router = py("web", "routers", "admin_lab.py");
    const runs = py("lab", "runs.py");
    const bad = [...router.matchAll(/_bad\(\s*"([a-z_]+)",\s*"([a-z_]+)"\)/g)].map(
      (m) => [m[1], m[2]] as const,
    );
    expect(bad.length).toBeGreaterThan(3);
    for (const [field, reason] of bad) {
      expect(LAB_FIELDS as readonly string[]).toContain(field);
      expect(LAB_FIELD_REASONS as readonly string[]).toContain(reason);
    }
    // `InvalidRun("name", "empty")` of lab/runs.py is a 422 too (the router passes exc.field, exc.reason on).
    const raised = [...runs.matchAll(/InvalidRun\(\s*"([a-z_]+)",\s*"([a-z_]+)"\)/g)].map(
      (m) => [m[1], m[2]] as const,
    );
    expect(raised.length).toBeGreaterThan(5);
    for (const [field, reason] of raised) {
      expect(LAB_FIELDS as readonly string[]).toContain(field);
      expect(LAB_FIELD_REASONS as readonly string[]).toContain(reason);
    }
    const refusals = [...router.matchAll(/_refuse\(\s*(\d+),\s*"([a-z_]+)"\)/g)].map(
      (m) => `${m[1]} ${m[2]}`,
    );
    expect([...new Set(refusals)].sort()).toEqual([
      "404 not_found",
      "409 not_a_queue_head",
      "409 outside_every_run",
      "409 overlap",
    ]);
  });
});

describe("labErrorOf", () => {
  const fail = (status: number, detail: unknown) => new ApiError(status, detail, { detail });

  it("reads 409 overlap", () => {
    expect(labErrorOf(fail(409, { reason: "overlap" }))).toEqual<LabError>({
      kind: "overlap",
      status: 409,
    });
  });

  it.each(["not_a_queue_head", "outside_every_run"] as const)("reads 409 %s", (reason) => {
    expect(labErrorOf(fail(409, { reason }))).toEqual({ kind: reason, status: 409 });
  });

  it("reads a 404 of the route's own reason, and the plain text of a bad id in a path, as not_found", () => {
    expect(labErrorOf(fail(404, { reason: "not_found" }))).toEqual({
      kind: "not_found",
      status: 404,
    });
    expect(labErrorOf(fail(404, "not found"))).toEqual({ kind: "not_found", status: 404 });
  });

  it("does not take FastAPI's own `Not Found` for a refusal of the route", () => {
    expect(labErrorOf(fail(404, "Not Found"))).toEqual({ kind: "other", status: 404 });
  });

  it.each([
    ["name", "empty"],
    ["name", "too_long"],
    ["name", "invalid"],
    ["name", "taken"],
    ["name", "required"],
    ["purpose", "invalid"],
    ["purpose", "required"],
    ["starts_at", "invalid"],
    ["starts_at", "required"],
    ["ends_at", "invalid"],
    ["ends_at", "not_after_starts"],
    ["ends_at", "required"],
    ["body", "invalid"],
    ["label", "invalid"],
  ] as const)("reads the 422 of %s / %s as a field error", (field, reason) => {
    expect(labErrorOf(fail(422, { field, reason }))).toEqual({
      kind: "field",
      status: 422,
      field,
      reason,
    });
  });

  it.each([
    ["a field it does not know", { field: "colour", reason: "invalid" }],
    ["a reason it does not know", { field: "name", reason: "poetic" }],
    ["a field that is not text", { field: 7, reason: "invalid" }],
    ["a reason that is not text", { field: "name", reason: ["empty"] }],
    ["no reason", { field: "name" }],
    ["FastAPI's own list-shaped 422", [{ type: "missing", loc: ["body"], msg: "x" }]],
    ["a text", "boom"],
  ])("reads a 422 with %s as other", (_name, detail) => {
    expect(labErrorOf(fail(422, detail))).toEqual({ kind: "other", status: 422 });
  });

  it("reads a reason at the wrong status as other: only 409 carries the conflicts, only 404 not_found", () => {
    expect(labErrorOf(fail(500, { reason: "overlap" }))).toEqual({ kind: "other", status: 500 });
    expect(labErrorOf(fail(422, { reason: "overlap" }))).toEqual({ kind: "other", status: 422 });
    expect(labErrorOf(fail(409, { reason: "not_found" }))).toEqual({ kind: "other", status: 409 });
    expect(labErrorOf(fail(409, { reason: "something_new" }))).toEqual({
      kind: "other",
      status: 409,
    });
  });

  it("reads a hostile reason such as constructor or __proto__ as other", () => {
    expect(labErrorOf(fail(409, { reason: "constructor" }))).toEqual({
      kind: "other",
      status: 409,
    });
    expect(labErrorOf(fail(422, { field: "__proto__", reason: "invalid" }))).toEqual({
      kind: "other",
      status: 422,
    });
  });

  it("reads a 403 and a 401 as other, with their status", () => {
    expect(labErrorOf(fail(403, "forbidden"))).toEqual({ kind: "other", status: 403 });
    expect(labErrorOf(fail(401, null))).toEqual({ kind: "other", status: 401 });
  });

  it("reads anything that is not an ApiError (a network failure) as other, status 0", () => {
    expect(labErrorOf(new TypeError("Failed to fetch"))).toEqual({ kind: "other", status: 0 });
    expect(labErrorOf(undefined)).toEqual({ kind: "other", status: 0 });
    expect(labErrorOf("boom")).toEqual({ kind: "other", status: 0 });
  });

  it("reads the refusal of a real call of the client", async () => {
    server.use(
      http.post("/api/admin/lab/runs", () =>
        HttpResponse.json({ detail: { reason: "overlap" } }, { status: 409 }),
      ),
    );
    const error = await createLabRun({
      name: "x",
      purpose: "kb",
      starts_at: "2026-11-04T09:00:00+07:00",
      ends_at: "2026-11-04T10:00:00+07:00",
    }).catch((e: unknown) => e);
    expect(labErrorOf(error)).toEqual({ kind: "overlap", status: 409 });
  });
});
