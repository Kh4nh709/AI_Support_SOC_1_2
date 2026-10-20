// src/api/adminTypes.test.ts — the response types of api/admin.ts against the handlers they describe.
//
// TypeScript types are erased, so nothing compared them to the backend, and a field that the handler always
// sends could be written `?` (or left out) without any test noticing: that is how `width_threshold_pct` and
// `hard_block_tally` stayed optional after P11-T06 made them certain. This test closes that.
//
// Each entry names a type (`Type`, `Type.prop` for a literal nested in it, or `fn:name` for the literal an
// inline `Promise<{...}>` answers with) and the keys the handler sends, copied from the handler and listed in
// `keys` (always present) and `optional` (the handler may leave them out). It checks, in this order:
//   1. the type in api/admin.ts has exactly those required keys and those optional keys;
//   2. where the handler builds the answer in a form that can be read (a dict literal, a dataclass or pydantic
//      class, a tuple of names), the keys the backend source builds are exactly `keys` plus `optional`: so
//      the list above cannot drift from the handler either.
// An answer whose keys the handler assembles by other means has no `backend`; its list is the copy.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { OVERVIEW_SECTIONS } from "./admin";
import { dictKeys, wrapDictLiterals } from "./adminTypesSource";

const BACKEND = join("..", "backend", "app");
// The second comparison below reads the backend with every dict literal wrapped, as `ruff format` lays out one that
// outgrows its line, so an anchor written for today's one-line layout fails here and not on the day of a wrap.
let wrapped = false;
const py = (...path: string[]): string => {
  const text = readFileSync(join(BACKEND, ...path), "utf8");
  return wrapped ? wrapDictLiterals(text) : text;
};
const router = (name: string): string => py("web", "routers", name);

// --- reading the TypeScript ---------------------------------------------------------------------------------

const stripComments = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

/** The text of api/admin.ts without its comments, where the braces of a type are only a type's. */
const TS = stripComments(readFileSync(join("src", "api", "admin.ts"), "utf8"));

/** The text between the `{` at `open` and its closing `}`. */
function braceBody(text: string, open: number): string {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  throw new Error("unbalanced braces");
}

type Prop = { name: string; optional: boolean; type: string };

/** The properties of an object type's body, split at the `;` that is not inside a nested type. */
function tsProps(body: string): Prop[] {
  const props: Prop[] = [];
  let depth = 0;
  let start = 0;
  const flush = (end: number): void => {
    const segment = body.slice(start, end).trim();
    if (segment === "") return;
    const m = /^([A-Za-z_]\w*)(\?)?\s*:\s*([\s\S]*)$/.exec(segment);
    if (m === null) throw new Error(`cannot read the property: ${segment}`);
    props.push({ name: m[1] as string, optional: m[2] === "?", type: (m[3] as string).trim() });
  };
  for (let i = 0; i < body.length; i += 1) {
    const ch = body.charAt(i);
    if ("{[(<".includes(ch)) depth += 1;
    else if ("}])>".includes(ch)) depth -= 1;
    else if (ch === ";" && depth === 0) {
      flush(i);
      start = i + 1;
    }
  }
  flush(body.length);
  return props;
}

/** The body of the first `{...}` in `text`. */
function firstLiteral(text: string): string {
  const open = text.indexOf("{");
  if (open === -1) throw new Error(`no object literal in: ${text}`);
  return braceBody(text, open);
}

/** The properties of `Type`, of `Type.prop...` (a literal nested in a property's type), or of `fn:name`. */
function tsPropsOf(path: string): Prop[] {
  if (path.startsWith("fn:")) {
    const at = TS.search(new RegExp(`function ${path.slice(3)}\\(`));
    if (at === -1) throw new Error(`no function ${path.slice(3)} in api/admin.ts`);
    const promise = TS.indexOf("Promise<", at);
    return tsProps(firstLiteral(TS.slice(promise)));
  }
  const [name, ...nested] = path.split(".");
  const declared = new RegExp(`export type ${name} = \\{`).exec(TS);
  if (declared === null) throw new Error(`no object type ${name} in api/admin.ts`);
  let props = tsProps(braceBody(TS, declared.index + declared[0].length - 1));
  for (const part of nested) {
    const prop = props.find((p) => p.name === part);
    if (prop === undefined) throw new Error(`${path}: no property ${part}`);
    props = tsProps(firstLiteral(prop.type));
  }
  return props;
}

// --- reading the Python -------------------------------------------------------------------------------------

/** The annotated fields of a dataclass or pydantic class (not its methods, docstring or `model_config`). */
function pyClassFields(source: string, cls: string): string[] {
  const head = new RegExp(`^class ${cls}\\b.*:[ \\t]*$`, "m").exec(source);
  if (head === null) throw new Error(`class ${cls} not found`);
  const rest = source.slice(head.index + head[0].length);
  const end = /^\S/m.exec(rest);
  const body = (end === null ? rest : rest.slice(0, end.index)).replace(/"""[\s\S]*?"""/g, "");
  return [...body.matchAll(/^ {4}([A-Za-z_]\w*):/gm)].map((m) => m[1] as string);
}

const quoted = (text: string | undefined): string[] =>
  [...(text ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);

/** The names in a Python tuple or set written `NAME = (...)` / `NAME: ... = (...)`. */
function pyNames(source: string, pattern: RegExp): string[] {
  const body = pattern.exec(source)?.[1];
  if (body === undefined) throw new Error(`not found: ${String(pattern)}`);
  return quoted(body);
}

// --- the entries --------------------------------------------------------------------------------------------

type Entry = {
  path: string;
  keys: string[];
  optional?: string[];
  backend?: () => string[];
};

const users = (): string => router("admin_users.py");
const llm = (): string => router("admin_llm.py");
const overview = (): string => router("admin_overview.py");
const rules = (): string => router("admin_rules.py");
const digest = (): string => router("admin_digest.py");
const labels = (): string => router("labels.py");
const audit = (): string => router("admin_audit.py");
const tier1Labels = (): string => py("tier1", "labels.py");

const ENTRIES: Entry[] = [
  // --- users (admin_users.py) ---
  {
    path: "UserRow",
    keys: [
      "user_id",
      "username",
      "display_name",
      "role",
      "is_active",
      "locked_until",
      "failed_logins",
      "last_login_at",
      "created_at",
    ],
    backend: () => {
      const columns = /^_COLUMNS = \(([\s\S]*?)\n\)/m.exec(users())?.[1];
      return quoted(columns)
        .join("")
        .split(",")
        .map((c) => c.trim());
    },
  },
  {
    path: "UsersResponse",
    keys: ["users"],
    backend: () => dictKeys(users(), /return \{(?=\s*"users")/),
  },
  {
    path: "NewUser",
    keys: ["username", "display_name", "role", "password"],
    backend: () =>
      pyNames(users(), /def api_create_user[\s\S]*?_no_unknown_keys\(body, \(([^)]*)\)\)/),
  },
  {
    path: "UserChanges",
    keys: [],
    optional: ["role", "display_name", "is_active"],
    backend: () => pyNames(users(), /^_UPDATABLE = \(([^)]*)\)/m),
  },
  {
    path: "fn:createUser",
    keys: ["user_id"],
    backend: () => dictKeys(users(), /return \{(?=\s*"user_id": user_id)/),
  },

  // --- LLM usage and limits (admin_llm.py) ---
  {
    path: "LimitsOut",
    keys: ["cap_usd", "quota_per_24h", "timeout_s", "sources", "bounds"],
    backend: () => dictKeys(llm(), /return \{(?=\s*"cap_usd")/),
  },
  {
    path: "LimitSource",
    keys: ["source", "updated_at", "updated_by_name", "clamped"],
    backend: () => dictKeys(llm(), /\{(?=\s*"source": source\.source)/),
  },
  {
    path: "LimitsOut.bounds",
    keys: ["min", "max"],
    backend: () => dictKeys(llm(), /\{(?=\s*"min": low)/),
  },
  {
    path: "fn:putLlmLimits",
    keys: ["limits"],
    backend: () => dictKeys(llm(), /return \{(?=\s*"limits": limits_out)/),
  },
  {
    path: "LlmUsage",
    keys: [
      "range",
      "month",
      "by_pipeline_role",
      "quota",
      "recent",
      "limits",
      "limits_error",
      "tool_calls",
    ],
    backend: () => dictKeys(llm(), /return \{(?=\s*"range": range_)/),
  },
  {
    // `_month` is `month_figures`' three keys spread, plus `projected_usd` (P11-T20 row 50 shared them with
    // the overview's `llm_month`).
    path: "LlmUsage.month",
    keys: ["spent_usd", "cap_usd", "pct", "projected_usd"],
    backend: () => [
      ...dictKeys(llm(), /return \{(?=\s*"spent_usd")/),
      ...dictKeys(llm(), /return \{(?=\s*\*\*month_figures\()/),
    ],
  },
  {
    path: "LlmUsage.quota",
    keys: ["limit", "window", "users"],
    backend: () => dictKeys(llm(), /"quota": \{/),
  },
  {
    path: "LlmUsage.quota.users",
    keys: ["username", "display_name", "used", "remaining"],
    backend: () => dictKeys(llm(), /\{(?=\s*"username": username)/),
  },
  {
    path: "PipelineRoleRow",
    keys: [
      "pipeline",
      "role",
      "calls",
      "with_result",
      "stopped",
      "input_tokens",
      "output_tokens",
      "latency_p50_ms",
      "latency_p95_ms",
      "cost_usd",
    ],
    backend: () => dictKeys(llm(), /\{(?=\s*"pipeline": pipeline)/),
  },
  {
    path: "RecentRun",
    keys: [
      "run_id",
      "created_at",
      "pipeline",
      "role",
      "subject_type",
      "subject_id",
      "input_tokens",
      "output_tokens",
      "latency_ms",
      "outcome",
      "cost_usd",
    ],
    backend: () => dictKeys(llm(), /\{(?=\s*"run_id": run_id)/),
  },

  // --- overview, job retry, inventory (admin_overview.py, web/main.py) ---
  {
    path: "OverviewResponse",
    keys: ["range", "errors", ...OVERVIEW_SECTIONS],
    backend: () => [
      ...dictKeys(overview(), /body: dict\[str, Any\] = \{/),
      ...[
        ...(/sections = \(([\s\S]*?)\n {4}\)/.exec(overview())?.[1] ?? "").matchAll(/\("(\w+)",/g),
      ].map((m) => m[1] as string),
    ],
  },
  {
    path: "OverviewResponse.errors",
    keys: ["section", "error"],
    backend: () => dictKeys(overview(), /errors\.append\(\s*\{/),
  },
  {
    path: "OverviewResponse.alerts_by_day",
    keys: ["day", "total", "heads", "duplicates"],
    backend: () => dictKeys(overview(), /\{(?=\s*"day": day\.isoformat)/),
  },
  {
    path: "OverviewResponse.by_source",
    keys: ["rows", "rejected"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"rows")/),
  },
  {
    path: "OverviewResponse.by_source.rows",
    keys: ["source", "alerts", "heads"],
    backend: () => dictKeys(overview(), /\{(?=\s*"source": source)/),
  },
  {
    path: "OverviewResponse.top_agents",
    keys: ["agent_name", "alerts"],
    backend: () => dictKeys(overview(), /\{(?=\s*"agent_name": agent_name)/),
  },
  {
    path: "OverviewResponse.funnel",
    keys: ["by_status", "triage"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"by_status")/),
  },
  {
    path: "OverviewResponse.funnel.triage",
    keys: ["ready", "unavailable", "pending", "none"],
    backend: () => dictKeys(overview(), /triage = \{/),
  },
  {
    path: "OverviewResponse.waiting",
    keys: ["count", "oldest_received_at"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"count": count)/),
  },
  {
    path: "OverviewResponse.health",
    keys: ["checked_at", "ok", "checks"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"checked_at")/),
  },
  {
    path: "HealthCheck",
    keys: ["name", "ok", "value", "threshold", "detail"],
    backend: () => pyClassFields(py("infra", "health.py"), "CheckResult"),
  },
  {
    path: "FailedJob",
    keys: ["job_id", "job_type", "subject_id", "attempts", "last_error", "locked_at", "created_at"],
    backend: () => dictKeys(overview(), /\{(?=\s*"job_id": job_id,\s*"job_type")/),
  },
  {
    path: "OverviewResponse.inventory",
    keys: ["assets", "identities", "iocs", "loaded_at"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"assets")/),
  },
  {
    // DEC-203: the same three figures as `LlmUsage.month`, built by `admin_llm.month_figures`.
    path: "OverviewResponse.llm_month",
    keys: ["spent_usd", "cap_usd", "pct"],
    backend: () => dictKeys(llm(), /return \{(?=\s*"spent_usd")/),
  },
  {
    path: "fn:retryJob",
    keys: ["job_id", "status"],
    backend: () => dictKeys(overview(), /return \{(?=\s*"job_id": job_id,\s*"status")/),
  },
  {
    path: "LoadReport",
    keys: ["assets", "identities", "iocs", "deactivated", "warnings"],
    backend: () => pyClassFields(py("enrichment", "inventory.py"), "LoadReport"),
  },

  // --- auto-close rules (admin_rules.py) ---
  {
    // `width_threshold_pct` is on every row since P11-T06 (api_list_rules adds it to each).
    path: "RuleRow",
    keys: [
      "rule_id",
      "name",
      "enabled",
      "match",
      "match_json",
      "reason",
      "created_by",
      "created_at",
      "width_pct",
      "width_threshold_pct",
    ],
    backend: () => [
      ...dictKeys(rules(), /result\.append\(\s*\{/),
      ...dictKeys(rules(), /\{(?=\s*\*\*row,\s*"width_threshold_pct")/),
    ],
  },
  {
    path: "RuleCondition",
    keys: ["field", "op", "value"],
    backend: () => pyNames(py("ingest", "autoclose.py"), /set\(item\.keys\(\)\) != \{([^}]*)\}/),
  },
  {
    // `hard_block_tally` is always present since P11-T06: null, or the tally of a preview with no cluster.
    path: "SimulateResult",
    keys: [
      "clusters",
      "alerts",
      "by_severity",
      "by_asset_criticality",
      "samples",
      "hard_block_tally",
    ],
    backend: () => [
      ...pyClassFields(py("ingest", "autoclose.py"), "SimulateStats"),
      ...new Set([...rules().matchAll(/result\["(\w+)"\] =/g)].map((m) => m[1] as string)),
    ],
  },
  {
    path: "HardBlockTally",
    keys: ["matched", "blocks"],
    backend: () => dictKeys(rules(), /result\["hard_block_tally"\] = \{/),
  },
  {
    path: "HardBlockTally.blocks",
    keys: ["code", "count"],
    backend: () => dictKeys(rules(), /\{(?=\s*"code": code,\s*"count": count)/),
  },
  {
    path: "fn:createRule",
    keys: ["rule_id", "name", "enabled"],
    backend: () => dictKeys(rules(), /return \{(?=\s*"rule_id": rule_id,\s*"name": body\.name)/),
  },
  {
    path: "fn:toggleRule",
    keys: ["rule_id", "name", "enabled"],
    backend: () => dictKeys(rules(), /return \{(?=\s*"rule_id": rule_id,\s*"name": name)/),
  },

  // --- daily digest (admin_digest.py) ---
  {
    path: "DigestRow",
    keys: [
      "alert_id",
      "rule_id",
      "description",
      "severity",
      "category",
      "agent_name",
      "occurrence_count",
      "first_seen_at",
      "last_seen_at",
      "autoclose_rule_id",
      "autoclose_rule_name",
      "suggested_action",
      "disagreement",
      "reviewed_verdict",
      "reviewed_by_name",
      "reviewed_at",
      "reopened_by_review",
    ],
    backend: () => pyClassFields(digest(), "DigestRowOut"),
  },
  {
    path: "DigestResponse",
    keys: ["day", "today", "rules_enabled", "rows"],
    backend: () => pyClassFields(digest(), "DigestOut"),
  },
  {
    path: "fn:reviewDigest",
    keys: ["row", "reopened"],
    backend: () => pyClassFields(digest(), "ReviewOut"),
  },

  // --- blind labelling (labels.py, tier1/labels.py) ---
  {
    // `frozen` and `candidates_present` are on every answer since P11-T08.
    path: "LabelsNext",
    keys: ["cluster_id", "done", "total", "cluster", "frozen", "candidates_present"],
    backend: () => [
      ...dictKeys(labels(), /return \{(?=\s*"cluster_id": progress\.cluster_id)/),
      ...dictKeys(labels(), /\{(?=\s*\*\*payload,)/),
    ],
  },
  {
    path: "LabelCluster",
    keys: [
      "alert_id",
      "rule_id",
      "rule_level",
      "severity",
      "description",
      "agent_name",
      "alert_time",
      "alert_user",
      "srcip",
      "dstip",
      "category",
      "raw_log",
      "raw_log_truncated_for_display",
      "occurrence_count",
      "first_seen",
      "last_seen",
      "playbook",
      "correlation",
      "gold_cluster_id",
    ],
    backend: () => pyNames(tier1Labels(), /^VIEW_KEYS: [^=]*= \(([\s\S]*?)\n\)/m),
  },
  {
    path: "LabelCluster.correlation",
    keys: ["rows", "samples"],
    backend: () => dictKeys(tier1Labels(), /correlation = \{/),
  },
  {
    path: "CorrelationRow",
    keys: ["rule_id", "category", "cluster_count", "alert_count", "first_seen", "last_seen"],
    backend: () => pyClassFields(tier1Labels(), "CorrelationView"),
  },
  {
    path: "CorrelationSample",
    keys: [
      "alert_id",
      "rule_id",
      "category",
      "severity",
      "occurrence_count",
      "alert_time",
      "description",
      "raw_log",
    ],
    backend: () => dictKeys(tier1Labels(), /samples\.append\(\s*\{/),
  },
  {
    path: "NewLabel",
    keys: ["labeler", "cluster_id", "label", "confidence"],
    optional: ["note"],
    backend: () => pyClassFields(labels(), "LabelIn"),
  },
  {
    path: "fn:postLabel",
    keys: ["cluster_id", "done", "total", "next"],
    backend: () => dictKeys(labels(), /return \{(?=\s*"cluster_id": result\.cluster_id)/),
  },
  {
    path: "fn:undoLabel",
    keys: ["undone_cluster_id", "done", "total"],
    backend: () => dictKeys(labels(), /return \{(?=\s*"undone_cluster_id")/),
  },

  // --- audit log (admin_audit.py) ---
  {
    path: "AuditEvent",
    keys: [
      "audit_id",
      "created_at",
      "event_type",
      "actor_role",
      "actor_username",
      "subject_id",
      "payload",
    ],
    backend: () => dictKeys(audit(), /\{(?=\s*"audit_id": audit_id)/),
  },
  {
    path: "AuditResponse",
    keys: ["events", "next_cursor", "total"],
    backend: () => dictKeys(audit(), /return \{(?=\s*"events": events)/),
  },
];

/** The object types of api/admin.ts that are not an answer of a handler, and why. */
const NOT_AN_ANSWER: Record<string, string> = {
  AuditFilters: "the query string of getAudit, which admin.test.ts pins",
};

const sorted = (names: readonly string[]): string[] => [...names].sort();

describe("the response types of api/admin.ts equal the keys of their handlers", () => {
  it.each(ENTRIES.map((e) => [e.path, e] as const))("%s", (_path, entry) => {
    const props = tsPropsOf(entry.path);
    const required = props.filter((p) => !p.optional).map((p) => p.name);
    const optional = props.filter((p) => p.optional).map((p) => p.name);
    // 1. the type says exactly what the handler sends, and what it may leave out
    expect(sorted(required), `${entry.path}: required keys of the type`).toEqual(
      sorted(entry.keys),
    );
    expect(sorted(optional), `${entry.path}: optional keys of the type`).toEqual(
      sorted(entry.optional ?? []),
    );
    // 2. and that list is what the backend source builds
    if (entry.backend !== undefined) {
      expect(sorted(entry.backend()), `${entry.path}: keys in the backend`).toEqual(
        sorted([...entry.keys, ...(entry.optional ?? [])]),
      );
    }
  });

  it("covers every object type of api/admin.ts, so a new answer is not left unpinned", () => {
    const declared = [...TS.matchAll(/^export type (\w+) = \{/gm)].map((m) => m[1] as string);
    const pinned = new Set(ENTRIES.map((e) => e.path.split(".")[0]));
    const missing = declared.filter((name) => !pinned.has(name) && !(name in NOT_AN_ANSWER));
    expect(missing).toEqual([]);
    expect(declared.length).toBeGreaterThan(25);
  });

  it("covers every function that answers with an inline object", () => {
    const inline = [...TS.matchAll(/function (\w+)\([^)]*\)[^{]*?Promise<\{/g)].map(
      (m) => `fn:${m[1] as string}`,
    );
    const pinned = new Set(ENTRIES.map((e) => e.path));
    expect(inline.filter((path) => !pinned.has(path))).toEqual([]);
    expect(inline.length).toBeGreaterThan(5);
  });

  it("has the two keys P11-T06 made certain required, not optional", () => {
    const rule = tsPropsOf("RuleRow");
    expect(rule.find((p) => p.name === "width_threshold_pct")?.optional).toBe(false);
    const simulate = tsPropsOf("SimulateResult");
    expect(simulate.find((p) => p.name === "hard_block_tally")?.optional).toBe(false);
    expect(simulate.find((p) => p.name === "hard_block_tally")?.type).toBe("HardBlockTally | null");
  });
});

describe("the keys of the backend are read the same when its dict literals are wrapped", () => {
  beforeAll(() => {
    wrapped = true;
  });
  afterAll(() => {
    wrapped = false;
  });
  const withBackend = ENTRIES.flatMap((e) =>
    e.backend === undefined ? [] : [[e.path, e] as const],
  );
  it.each(withBackend)("%s", (_path, entry) => {
    expect(sorted(entry.backend?.() ?? []), `${entry.path}: keys in the wrapped backend`).toEqual(
      sorted([...entry.keys, ...(entry.optional ?? [])]),
    );
  });
});

describe("the readers this test uses", () => {
  it("tsProps tells a required key from an optional one, and skips what is nested", () => {
    expect(
      tsProps(
        "a: string; b?: number; c: { d?: string; e: number }[] | null; f: Record<string, number>",
      ),
    ).toEqual([
      { name: "a", optional: false, type: "string" },
      { name: "b", optional: true, type: "number" },
      { name: "c", optional: false, type: "{ d?: string; e: number }[] | null" },
      { name: "f", optional: false, type: "Record<string, number>" },
    ]);
  });

  it("dictKeys reads the top-level keys of a dict literal and not the nested ones", () => {
    const source = 'return {"a": 1, "b": {"c": 2}, "d": "x: {y}", "e": [{"f": 3}]}';
    expect(dictKeys(source, /return \{/)).toEqual(["a", "b", "d", "e"]);
  });

  it("pyClassFields reads annotated fields and not methods, docstrings or the code after the class", () => {
    const source = [
      "class A(BaseModel):",
      '    """A: not a field.',
      '    b: neither."""',
      "",
      "    x: int",
      "    y: str | None = None",
      "    model_config = {}",
      "",
      "    def f(self, z: int):",
      "        w: int = 3",
      "",
      "other: int = 1",
    ].join("\n");
    expect(pyClassFields(source, "A")).toEqual(["x", "y"]);
  });
});
