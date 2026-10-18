// The condition builder's vocabulary (P11-T14, spec §4.4): a typed copy of `autoclose._WHITELIST`
// (backend/app/ingest/autoclose.py), so the builder can only offer a field/operator pair the server accepts,
// and the pure rules that turn what an admin typed into the `{field, op, value}` conditions of a rule.
//
// `RULE_WHITELIST`, `RULE_OPS` and `OP_VALUE_KIND` are PINNED by backend/tests/test_rules_whitelist_pin.py,
// which reads this file as text and compares it with the server (every field's operators, every scalar type,
// the operator vocabulary and the shape of each operator's value). Keep each field on its own line, in the
// form `name: { type: "...", ops: [...] },`: that is what the test reads. The server still has the last word:
// a 422 from `simulate` is shown at the condition.
//
// What the server accepts as a value (`_value_ok`, `_scalar_ok`):
//   eq      one scalar of the field's type
//   in      a non-empty list of scalars of the field's type
//   cidr    a string `ip_network(strict=False)` reads (a bare IP passes too)
//   prefix  any string, the empty one included
//   lte     an integer (`rule_level` only)
// A port or `rule_level` is a whole JSON number (`"443"`, `443.5` are refused; `443.0` is a float to Python),
// and a boolean is never an integer. A condition is exactly `{field, op, value}`; `[]` matches everything.
import type { RuleCondition } from "../../api/admin";

/** The five operators. */
export const RULE_OPS = ["eq", "in", "cidr", "prefix", "lte"] as const;
export type RuleOp = (typeof RULE_OPS)[number];

/** What one value of a field is: `_scalar_ok`. */
export type ScalarType = "string" | "integer" | "boolean";

/** Field -> its scalar type and the operators it allows, in the order the builder lists them. */
export const RULE_WHITELIST = {
  rule_id: { type: "string", ops: ["eq", "in"] },
  category: { type: "string", ops: ["eq", "in"] },
  srcip: { type: "string", ops: ["eq", "in", "cidr"] },
  dstip: { type: "string", ops: ["eq", "in", "cidr"] },
  agent_name: { type: "string", ops: ["eq", "in", "prefix"] },
  agent_id: { type: "string", ops: ["eq", "in", "prefix"] },
  alert_user: { type: "string", ops: ["eq", "in"] },
  decoder: { type: "string", ops: ["eq", "in"] },
  dst_port: { type: "integer", ops: ["eq", "in"] },
  src_port: { type: "integer", ops: ["eq", "in"] },
  rule_level: { type: "integer", ops: ["eq", "lte"] },
  asset_criticality: { type: "string", ops: ["eq", "in"] },
  identity_privileged: { type: "boolean", ops: ["eq"] },
  ioc_reputation: { type: "string", ops: ["eq", "in"] },
} as const satisfies Record<string, { type: ScalarType; ops: readonly RuleOp[] }>;

export type RuleField = keyof typeof RULE_WHITELIST;

/** The fields, in the whitelist's order. */
export const RULE_FIELDS = Object.keys(RULE_WHITELIST) as RuleField[];

/**
 * The shape of the value each operator takes, whatever the field: `scalar` is one value of the field's type,
 * `list` a non-empty list of them, `text` a string, `integer` a whole number.
 */
export const OP_VALUE_KIND = {
  eq: "scalar",
  in: "list",
  cidr: "text",
  prefix: "text",
  lte: "integer",
} as const satisfies Record<RuleOp, "scalar" | "list" | "text" | "integer">;

/** The operators a field allows. */
export function opsOf(field: RuleField): readonly RuleOp[] {
  return RULE_WHITELIST[field].ops;
}

/** The scalar type of a field's values. */
export function typeOf(field: RuleField): ScalarType {
  return RULE_WHITELIST[field].type;
}

export function isRuleField(value: unknown): value is RuleField {
  return typeof value === "string" && Object.hasOwn(RULE_WHITELIST, value);
}

/** Whether the whitelist lets `field` use `op`. */
export function allows(field: RuleField, op: RuleOp): boolean {
  return (opsOf(field) as readonly RuleOp[]).includes(op);
}

// --- what the admin types -----------------------------------------------------------------------------------

/** One row of the builder. `text` is what is in the value box; a boolean field's is `"true"` or `"false"`. */
export type DraftRow = { id: number; field: RuleField; op: RuleOp; text: string };

/** The row a fresh builder starts with, and "+ Thêm điều kiện" adds. */
export function newDraftRow(id: number): DraftRow {
  return { id, field: "rule_id", op: "eq", text: "" };
}

/** What a value box holds when a field of this type is chosen. */
function blankText(type: ScalarType): string {
  return type === "boolean" ? "true" : "";
}

/**
 * A row after its field was changed: the operator stays when the new field allows it and falls back to the
 * field's first operator otherwise, and the text is kept unless the new field's values are of another type
 * (a boolean box has no free text).
 */
export function withField(row: DraftRow, field: RuleField): DraftRow {
  const op = allows(field, row.op) ? row.op : (opsOf(field)[0] ?? "eq");
  const text = typeOf(field) === typeOf(row.field) ? row.text : blankText(typeOf(field));
  return { ...row, field, op, text };
}

/** A row after its operator was changed (the caller only offers the field's own operators). */
export function withOp(row: DraftRow, op: RuleOp): DraftRow {
  return allows(row.field, op) ? { ...row, op } : row;
}

/** Why a value box cannot be turned into a value. */
export type ValueProblem = "not_integer" | "list_empty" | "list_blank_item" | "not_boolean";

export type Parsed<T> = { ok: true; value: T } | { ok: false; problem: ValueProblem };

/** A decimal literal, with an optional sign and fraction: not hex, not an exponent, not blank. */
const DECIMAL = /^[-+]?\d+(\.\d+)?$/;

/**
 * A whole number from text. `Number.isInteger` is the check (`443.5` is none, and the server refuses it as
 * well), kept inside the safe range so that the number sent is the number typed; `443.0` is the integer 443,
 * which is what the server gets as JSON.
 */
export function parseInteger(text: string): Parsed<number> {
  const trimmed = text.trim();
  if (!DECIMAL.test(trimmed)) return { ok: false, problem: "not_integer" };
  const number = Number(trimmed);
  return Number.isInteger(number) && Math.abs(number) <= Number.MAX_SAFE_INTEGER
    ? { ok: true, value: number }
    : { ok: false, problem: "not_integer" };
}

function parseScalar(type: ScalarType, text: string): Parsed<string | number | boolean> {
  if (type === "integer") return parseInteger(text);
  if (type === "boolean") {
    if (text === "true") return { ok: true, value: true };
    if (text === "false") return { ok: true, value: false };
    return { ok: false, problem: "not_boolean" };
  }
  return { ok: true, value: text };
}

/**
 * The value of a row, in the shape its operator takes (`OP_VALUE_KIND`), or why there is none.
 * A string is sent as typed (the server accepts the empty one for `eq` and `prefix`); a `cidr` and the items
 * of a list are trimmed, since a space is never part of a network or of a list's separator. A list is
 * comma-separated and holds no blank item.
 */
export function parseValue(row: DraftRow): Parsed<string | number | boolean | (string | number)[]> {
  const type = typeOf(row.field);
  switch (OP_VALUE_KIND[row.op]) {
    case "scalar":
      return parseScalar(type, row.text);
    case "integer":
      return parseInteger(row.text);
    case "text":
      return { ok: true, value: row.op === "cidr" ? row.text.trim() : row.text };
    case "list": {
      if (row.text.trim() === "") return { ok: false, problem: "list_empty" };
      const items: (string | number)[] = [];
      for (const piece of row.text.split(",")) {
        const item = piece.trim();
        if (item === "") return { ok: false, problem: "list_blank_item" };
        const parsed = parseScalar(type, item);
        if (!parsed.ok) return parsed;
        items.push(parsed.value as string | number);
      }
      return { ok: true, value: items };
    }
  }
}

export type ParsedRow =
  { ok: true; condition: RuleCondition } | { ok: false; problem: ValueProblem };

/** A row as the `{field, op, value}` the server reads (the keys in that order, so a key made of it is stable). */
export function toCondition(row: DraftRow): ParsedRow {
  const value = parseValue(row);
  return value.ok
    ? { ok: true, condition: { field: row.field, op: row.op, value: value.value } }
    : value;
}

/**
 * The rule's conditions when every row is good, else `null`. This is the array "Xem trước" sends and
 * "Tạo rule" is bound to.
 */
export function matchOf(rows: readonly DraftRow[]): RuleCondition[] | null {
  const conditions: RuleCondition[] = [];
  for (const row of rows) {
    const parsed = toCondition(row);
    if (!parsed.ok) return null;
    conditions.push(parsed.condition);
  }
  return conditions;
}

/** The identity of a set of conditions: two arrays that would be sent as the same JSON are the same preview. */
export function matchKey(match: readonly RuleCondition[]): string {
  return JSON.stringify(match);
}

// --- what the hard blocks make useless ----------------------------------------------------------------------

/**
 * Values a rule can name but can never close, because a hard block (G8') runs first and stops the cluster:
 * `asset_criticality` high (block 3), a malicious or suspicious `ioc_reputation` (block 6) and a privileged
 * identity (block 5). The builder says so beside the condition; the preview's tally says how many were hit.
 */
const NEVER_CLOSED: Readonly<Record<string, readonly (string | boolean)[]>> = {
  asset_criticality: ["high"],
  ioc_reputation: ["malicious", "suspicious"],
  identity_privileged: [true],
};

/** The values of a condition that no rule can close (empty when there are none). `eq` and `in` only. */
export function hardBlockedValues(condition: RuleCondition): (string | boolean)[] {
  if (condition.op !== "eq" && condition.op !== "in") return [];
  const blocked = Object.hasOwn(NEVER_CLOSED, condition.field)
    ? (NEVER_CLOSED[condition.field] ?? [])
    : [];
  const values = Array.isArray(condition.value) ? condition.value : [condition.value];
  return values.filter((v): v is string | boolean => blocked.includes(v as string | boolean));
}

// --- how a stored condition is shown ------------------------------------------------------------------------

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/** A value as the chips show it: a string quoted, a number or a boolean bare, a list in brackets. */
export function formatValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(formatValue).join(", ")}]`;
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return safeJson(value);
}

/**
 * One stored condition as `field op value`. A `match` is whatever the database holds (the server only
 * validates what it is given, and a row may predate it), so anything that is not a `{field, op, value}` is
 * shown as its JSON, never dropped and never a crash.
 */
export function formatCondition(condition: unknown): string {
  if (typeof condition === "object" && condition !== null && !Array.isArray(condition)) {
    const c = condition as Record<string, unknown>;
    if (typeof c.field === "string" && typeof c.op === "string" && "value" in c) {
      return `${c.field} ${c.op} ${formatValue(c.value)}`;
    }
  }
  return safeJson(condition);
}
