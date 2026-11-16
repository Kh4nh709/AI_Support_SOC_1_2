// src/api/soarContract.test.ts — api/soar.ts, the fixtures and what the SOAR page handles, against the backend that serves them
// (backend/app/soar/reviews.py and web/routers/soar_reviews.py), key by key and status code by status code. TypeScript types are
// erased, so nothing else compares them to the handler: a key the backend adds, a status it answers with, a closed set that grows,
// or a limit that moves would be a page that quietly reads `undefined`. This reads the Python source (as adminTypes.test.ts does)
// and holds the frontend to it. The first run of it found: the history's `actor` is null for the system (the page read the string
// "system"), and `503 busy` shares its status with `503 soar approval not configured`.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ApiError } from "./client";
import {
  SOAR_ACTION_TYPES,
  SOAR_KINDS,
  SOAR_PAGE_SIZE,
  SOAR_SEVERITIES,
  SOAR_STATUSES,
} from "./soar";
import { detailOf, review } from "../features/soar/fixtures";
import { NOTE_MAX } from "../features/soar/model";
import { failureOf } from "../features/soar/outcome";
import { Q_MAX } from "../features/soar/soarParams";
import { S } from "../strings";

const BACKEND = join("..", "backend", "app");
const reviewsPy = readFileSync(join(BACKEND, "soar", "reviews.py"), "utf8");
const routerPy = readFileSync(join(BACKEND, "web", "routers", "soar_reviews.py"), "utf8");
const noticePy = readFileSync(join(BACKEND, "soar", "review_notice.py"), "utf8");
const tsApi = readFileSync(join("src", "api", "soar.ts"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\/\/.*$/gm, "");

/** The quoted words of a Python tuple or list assigned to `name`. */
function pyWords(source: string, name: string): string[] {
  const found = new RegExp(`^${name}\\s*(?::[^=]+)?=\\s*[(\\[]([\\s\\S]*?)[)\\]]`, "m").exec(
    source,
  );
  if (found === null) throw new Error(`no ${name} in the source`);
  return [...(found[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);
}

/** The number a Python constant is assigned (`NAME = 200`, `NAME = 8 * 1024`). */
function pyNumber(source: string, name: string): number {
  const found = new RegExp(`^${name}\\s*(?::[^=]+)?=\\s*([0-9 *]+)`, "m").exec(source);
  if (found === null) throw new Error(`no ${name} in the source`);
  return (found[1] ?? "").split("*").reduce((product, part) => product * Number(part.trim()), 1);
}

/** The body of a Python function: from its `def` to the next top-level `def`, `class` or comment banner. */
function pyFunction(source: string, name: string): string {
  const start = source.indexOf(`def ${name}(`);
  if (start === -1) throw new Error(`no def ${name}`);
  const rest = source.slice(start + 1);
  const end = rest.search(/\n(?:def |class |@|# ──)/);
  return end === -1 ? rest : rest.slice(0, end);
}

/** Python code with its comments and string literals blanked, in one pass so a `#` or a quote inside the other is not mistaken. */
function pyCode(source: string): string {
  return source.replace(
    /"""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|#[^\n]*/g,
    (found) => (found.startsWith("#") ? "" : '""'),
  );
}

/**
 * The ways Python code can add keys to a dict that the readers of this file (`review["name"] =` in serve, `review["name"]` in
 * get_detail) cannot see. The guard over the served keys reads those two forms only; a key added in any of these would be served
 * and held against nothing, so the forms themselves are refused where the keys are built.
 */
const KEYS_THE_READERS_CANNOT_SEE: ReadonlyArray<readonly [string, RegExp]> = [
  [".update(", /\.update\s*\(/],
  ["setdefault(", /\bsetdefault\s*\(/],
  ["** unpacking", /\*\*/],
  ["|= merge", /\|=/],
];

/** The forms of KEYS_THE_READERS_CANNOT_SEE that the code of `body` (comments and strings aside) uses. */
function unreadableKeyForms(body: string): string[] {
  const code = pyCode(body);
  return KEYS_THE_READERS_CANNOT_SEE.filter(([, form]) => form.test(code)).map(([name]) => name);
}

/** The property names of the TypeScript type `name` of api/soar.ts (one level: a nested `{` is skipped). */
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

describe("the served review", () => {
  const served = [
    ...pyWords(reviewsPy, "_SERVED_NAMES"),
    ...[...pyFunction(reviewsPy, "serve").matchAll(/review\["(\w+)"\]\s*=/g)]
      .map((m) => m[1] as string)
      .filter((name) => !pyWords(reviewsPy, "_SERVED_NAMES").includes(name)),
  ];

  it("reads the backend (a guard over nothing would pass for nothing)", () => {
    expect(served.length).toBeGreaterThan(35);
    expect(served).toEqual(
      expect.arrayContaining(["id", "status", "allowed_decisions", "host_critical"]),
    );
  });

  it("has exactly the keys of the TypeScript type SoarReview", () => {
    expect(sorted(tsKeys("SoarReview"))).toEqual(sorted(served));
  });

  it("has exactly the keys of the fixture the tests serve (every key, none the backend does not send)", () => {
    expect(sorted(Object.keys(review()))).toEqual(sorted(served));
  });
});

describe("the detail", () => {
  const extras = [
    ...pyFunction(reviewsPy, "get_detail").matchAll(/review\["(\w+)"\](?=,|\s*=)/g),
  ].map((m) => m[1] as string);

  it("adds to the review exactly what the type and the fixture add: raw, history, history_truncated, related_alerts, related_total", () => {
    const expected = ["raw", "history", "history_truncated", "related_alerts", "related_total"];
    expect(sorted([...new Set(extras)])).toEqual(sorted(expected));
    const typed = tsKeys("SoarReviewDetail").filter((key) => !tsKeys("SoarReview").includes(key));
    expect(sorted(typed)).toEqual(sorted(expected));
    const fixture = Object.keys(detailOf()).filter((key) => !Object.keys(review()).includes(key));
    expect(sorted(fixture.filter((key) => key !== "history_truncated"))).toEqual(
      sorted(expected.filter((key) => key !== "history_truncated")),
    );
  });

  it("serves a history event with at, event, actor, actor_role and payload; a related alert with the queue's seven fields", () => {
    const event = /events\.append\(\s*\{([\s\S]*?)\}\s*\)/.exec(pyFunction(reviewsPy, "_history"));
    expect([...(event?.[1] ?? "").matchAll(/"(\w+)":/g)].map((m) => m[1])).toEqual(
      tsKeys("SoarHistoryEvent"),
    );
    const alert = /rows = \[\s*\{([\s\S]*?)\}\s*for /.exec(
      pyFunction(reviewsPy, "_related_alerts"),
    );
    expect(
      sorted([...(alert?.[1] ?? "").matchAll(/"(\w+)":/g)].map((m) => m[1] as string)),
    ).toEqual(sorted(tsKeys("SoarRelatedAlert")));
  });

  it("names the two events of its history as the page words them", () => {
    const sql = pyFunction(reviewsPy, "_history");
    const events = [
      ...(/event_type IN \(([^)]*)\)/.exec(sql)?.[1] ?? "").matchAll(/'([^']+)'/g),
    ].map((m) => m[1] as string);
    expect(sorted(events)).toEqual(sorted(Object.keys(S.soar.detail.history.event)));
  });

  it("serves the actor as a username or null and the role as tier1, tier2, admin or system (the page reads both)", () => {
    expect(pyWords(reviewsPy, "_PAYLOAD_ROLES")).toEqual(["tier1", "tier2", "admin"]);
    expect(pyFunction(reviewsPy, "_history")).toContain("a.actor_role");
  });
});

describe("the readers of the served keys see every key (the guard fails closed)", () => {
  const HOW =
    'add a key of the review as review["name"] = … in serve() (or its name to _SERVED_NAMES), a key of the detail as ' +
    'review["name"] = … in get_detail(): .update(, setdefault(, ** and |= add keys that this guard cannot read, so a key ' +
    "added that way would be served and compared with nothing";

  it.each(["serve", "get_detail"])(
    "builds the keys of %s() in the two forms the guard reads",
    (name) => {
      expect(unreadableKeyForms(pyFunction(reviewsPy, name)), HOW).toEqual([]);
    },
  );

  // A function of the shape of serve(), whose words in comments, docstring and strings are the forms the guard refuses.
  const PLAIN = [
    "def serve(row, role, cfg):",
    '    """Not review.update(x), setdefault( or **."""',
    "    # review.update(x) and {**review} are what is refused",
    '    review = dict(zip(NAMES, row, strict=True))  # a "#" in a comment, and a quote \'',
    '    review["a"] = "setdefault( ** |= .update("',
    "    return review",
  ].join("\n");

  it("refuses each form that adds a key unseen (mutants of a function of the shape of serve)", () => {
    const mutants: Array<[string, string]> = [
      [".update(", '    review.update(extra="x")\n    return review'],
      ["setdefault(", '    review.setdefault("extra", "x")\n    return review'],
      ["** unpacking", '    review = {**review, "extra": "x"}\n    return review'],
      ["|= merge", '    review |= {"extra": "x"}\n    return review'],
    ];
    for (const [form, line] of mutants) {
      const mutant = PLAIN.replace("    return review", line);
      expect(mutant, form).not.toBe(PLAIN);
      // the reader of serve() does not see the key this mutant adds: that is what the refusal is for
      expect([...mutant.matchAll(/review\["(\w+)"\]\s*=/g)].map((m) => m[1])).not.toContain(
        "extra",
      );
      expect(unreadableKeyForms(mutant), form).toEqual([form]);
    }
  });

  it("is not tripped by the words in a comment, a docstring or a string, and reads a key built the plain way", () => {
    expect(unreadableKeyForms(PLAIN)).toEqual([]);
    expect(unreadableKeyForms(`${PLAIN}\n    review.update(b=1)`)).toEqual([".update("]);
  });
});

describe("the closed sets", () => {
  it("are the backend's: statuses, kinds, action types", () => {
    expect(sorted(SOAR_STATUSES)).toEqual(sorted(pyWords(reviewsPy, "STATUSES")));
    expect(sorted(SOAR_KINDS)).toEqual(sorted(pyWords(reviewsPy, "KINDS")));
    expect(sorted(SOAR_ACTION_TYPES)).toEqual(sorted(pyWords(reviewsPy, "ACTION_TYPES")));
  });

  it("have a word each in the page, and severities are the webhook's three", () => {
    for (const status of pyWords(reviewsPy, "STATUSES"))
      expect(S.soar.status).toHaveProperty(status);
    for (const type of pyWords(reviewsPy, "ACTION_TYPES"))
      expect(S.soar.actionType).toHaveProperty(type);
    expect(sorted(SOAR_SEVERITIES)).toEqual(["error", "info", "warning"]);
  });

  it("words every outcome the web writes to the audit trail and every reason n8n's push can be ignored for", () => {
    const outcomes = ["ok", "failed", "unavailable", "conflict", "locked", "invalid_state"];
    for (const outcome of [...outcomes, "created", "updated", "ignored"]) {
      expect(S.soar.detail.history.outcome, outcome).toHaveProperty(outcome);
    }
    // the outcomes of a push are the ones the webhook names, the reasons of an ignored one are all worded
    expect(/Literal\["created", "updated", "ignored"\]/.test(noticePy)).toBe(true);
    for (const reason of ["stale", "terminal", "decided"]) {
      expect(noticePy).toContain(`"ignored", "${reason}"`);
      expect(S.soar.detail.history.reason).toHaveProperty(reason);
    }
  });
});

describe("the limits", () => {
  it("are the page's: the note, the search, the page size, the history", () => {
    expect(NOTE_MAX).toBe(pyNumber(routerPy, "NOTE_MAX"));
    expect(Q_MAX).toBe(pyNumber(reviewsPy, "Q_MAX_LENGTH"));
    expect(SOAR_PAGE_SIZE).toBe(pyNumber(reviewsPy, "PAGE_SIZE_DEFAULT"));
    expect(SOAR_PAGE_SIZE).toBeLessThanOrEqual(pyNumber(reviewsPy, "PAGE_SIZE_MAX"));
    expect(S.soar.detail.history.truncated).toContain(String(pyNumber(reviewsPy, "HISTORY_MAX")));
  });

  it("leave the largest body the page can send (a note of NOTE_MAX characters, four bytes each) far under the body limit", () => {
    const biggest = JSON.stringify({ decision: "undo", note: "😀".repeat(NOTE_MAX) });
    expect(new TextEncoder().encode(biggest).length).toBeLessThan(
      pyNumber(routerPy, "BODY_MAX_BYTES"),
    );
  });
});

describe("the decision route's answers", () => {
  const codes = [...routerPy.matchAll(/status_code=(\d{3})/g)].map((m) => Number(m[1]));

  it("are exactly 403, 404, 409, 413, 422 and 503, and the page words every one of them on the row", () => {
    expect(sorted([...new Set(codes)].map(String))).toEqual([
      "403",
      "404",
      "409",
      "413",
      "422",
      "503",
    ]);
    const detail: Record<number, unknown> = {
      403: "forbidden",
      404: "review not found",
      409: { reason: "locked", review: review() },
      413: "payload too large",
      422: { field: "note", reason: "invalid" },
      503: "busy",
    };
    for (const code of new Set(codes)) {
      const failure = failureOf(new ApiError(code, detail[code]));
      expect(failure.lines.length, String(code)).toBeGreaterThan(0);
      expect(failure.lines[0]?.text.trim(), String(code)).not.toBe("");
    }
  });

  it("has the two 503s the page tells apart, by their detail", () => {
    const details = [...routerPy.matchAll(/status_code=503,\s*detail="([^"]+)"/g)].map(
      (m) => m[1] as string,
    );
    expect(sorted(details)).toEqual(["busy", "soar approval not configured"]);
    expect(failureOf(new ApiError(503, "busy")).lines[0]?.text).toBe(S.soar.result.busy);
    expect(failureOf(new ApiError(503, "soar approval not configured")).lines[0]?.text).toBe(
      S.soar.result.notConfigured,
    );
    expect(routerPy).toContain('headers={"Retry-After": RETRY_AFTER_S}');
  });

  it("refuses with a 409 whose detail is {reason, review}, reasons locked and invalid_state", () => {
    expect(routerPy).toContain('detail={"reason": refused.reason, "review": refused.review}');
    expect(sorted(["locked", "invalid_state"])).toEqual(
      sorted(
        [...reviewsPy.matchAll(/"(locked|invalid_state)"/g)]
          .map((m) => m[1] as string)
          .filter((v, i, all) => all.indexOf(v) === i),
      ),
    );
  });

  it("refuses a bad body with a 422 whose detail is {field, reason}: the note (invalid, too_long) is the person's, the rest generic", () => {
    const fields = [...routerPy.matchAll(/_bad\("(\w+)", "(\w+)"\)/g)].map(
      (m) => `${m[1]}:${m[2]}`,
    );
    expect(sorted([...new Set(fields)])).toEqual(
      sorted([
        "body:invalid",
        "decision:required",
        "decision:invalid",
        "note:invalid",
        "note:too_long",
      ]),
    );
    expect(failureOf(new ApiError(422, { field: "note", reason: "too_long" })).lines[0]?.text).toBe(
      S.soar.result.noteTooLong,
    );
    for (const field of ["body", "decision"]) {
      expect(failureOf(new ApiError(422, { field, reason: "invalid" })).lines[0]?.text).toBe(
        S.common.unknownError,
      );
    }
  });
});

describe("the count", () => {
  it("answers {count, latest_received_at}", () => {
    const body = /return \{"count": count, "latest_received_at": latest\}/.test(routerPy);
    expect(body).toBe(true);
  });
});
