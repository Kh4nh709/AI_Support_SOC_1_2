// src/features/admin/ruleFields.test.ts — the condition builder's vocabulary (P11-T14): the typed copy of the
// server's whitelist, and the pure rules that turn what an admin typed into `{field, op, value}`. The copy
// itself is pinned against `autoclose._WHITELIST` by backend/tests/test_rules_whitelist_pin.py; here are the
// behaviours the builder rests on.
import {
  OP_VALUE_KIND,
  RULE_FIELDS,
  RULE_OPS,
  RULE_WHITELIST,
  allows,
  formatCondition,
  formatValue,
  hardBlockedValues,
  isRuleField,
  matchKey,
  matchOf,
  newDraftRow,
  opsOf,
  parseInteger,
  parseValue,
  toCondition,
  typeOf,
  withField,
  withOp,
  type DraftRow,
  type RuleField,
  type RuleOp,
} from "./ruleFields";

const row = (field: RuleField, op: RuleOp, text: string, id = 1): DraftRow => ({
  id,
  field,
  op,
  text,
});

describe("the whitelist copy", () => {
  // The table of the P11-T14 brief, written out by hand: what the server's `_WHITELIST` says today.
  const EXPECTED: Record<string, string[]> = {
    rule_id: ["eq", "in"],
    category: ["eq", "in"],
    srcip: ["eq", "in", "cidr"],
    dstip: ["eq", "in", "cidr"],
    agent_name: ["eq", "in", "prefix"],
    agent_id: ["eq", "in", "prefix"],
    alert_user: ["eq", "in"],
    decoder: ["eq", "in"],
    dst_port: ["eq", "in"],
    src_port: ["eq", "in"],
    rule_level: ["eq", "lte"],
    asset_criticality: ["eq", "in"],
    identity_privileged: ["eq"],
    ioc_reputation: ["eq", "in"],
  };

  it("has the fourteen fields, in the server's order, each with its operators", () => {
    expect(RULE_FIELDS).toEqual(Object.keys(EXPECTED));
    for (const field of RULE_FIELDS) expect([...opsOf(field)], field).toEqual(EXPECTED[field]);
  });

  it("types the three integer fields and the one boolean, and every other field as a string", () => {
    const types = Object.fromEntries(RULE_FIELDS.map((field) => [field, typeOf(field)]));
    expect(types).toEqual({
      rule_id: "string",
      category: "string",
      srcip: "string",
      dstip: "string",
      agent_name: "string",
      agent_id: "string",
      alert_user: "string",
      decoder: "string",
      dst_port: "integer",
      src_port: "integer",
      rule_level: "integer",
      asset_criticality: "string",
      identity_privileged: "boolean",
      ioc_reputation: "string",
    });
  });

  it("names five operators, and each is allowed by some field", () => {
    expect([...RULE_OPS]).toEqual(["eq", "in", "cidr", "prefix", "lte"]);
    for (const op of RULE_OPS) {
      expect(
        RULE_FIELDS.some((field) => allows(field, op)),
        op,
      ).toBe(true);
    }
    expect(Object.keys(OP_VALUE_KIND).sort()).toEqual([...RULE_OPS].sort());
  });

  it("lets identity_privileged use eq only, and refuses cidr on a category", () => {
    expect(allows("identity_privileged", "eq")).toBe(true);
    expect(allows("identity_privileged", "in")).toBe(false);
    expect(allows("category", "cidr")).toBe(false);
    expect(allows("rule_level", "lte")).toBe(true);
    expect(allows("dst_port", "lte")).toBe(false);
  });

  it("knows a field by name and nothing else, a hostile name included", () => {
    expect(isRuleField("srcip")).toBe(true);
    for (const bad of ["constructor", "__proto__", "toString", "risk_score", "", 5, null]) {
      expect(isRuleField(bad), String(bad)).toBe(false);
    }
    expect(Object.keys(RULE_WHITELIST)).toEqual([...RULE_FIELDS]);
  });
});

describe("a draft row", () => {
  it("starts as rule_id eq, empty", () => {
    expect(newDraftRow(7)).toEqual({ id: 7, field: "rule_id", op: "eq", text: "" });
  });

  it("keeps its operator when the new field allows it, and its text when the type is the same", () => {
    expect(withField(row("rule_id", "in", "5715, 531"), "category")).toEqual(
      row("category", "in", "5715, 531"),
    );
  });

  it("falls back to the new field's first operator when the old one is not allowed", () => {
    expect(withField(row("srcip", "cidr", "10.0.0.0/8"), "category").op).toBe("eq");
    expect(withField(row("agent_name", "prefix", "lab-"), "rule_level").op).toBe("eq");
    expect(withField(row("rule_level", "lte", "7"), "dst_port").op).toBe("eq");
    expect(withField(row("rule_id", "in", "x"), "identity_privileged").op).toBe("eq");
  });

  it("clears the text when the field's values are of another type, and a boolean starts as true", () => {
    expect(withField(row("rule_id", "eq", "5715"), "dst_port").text).toBe(""); // string -> integer
    expect(withField(row("dst_port", "eq", "443"), "identity_privileged").text).toBe("true");
    expect(withField(row("identity_privileged", "eq", "false"), "category").text).toBe("");
    expect(withField(row("identity_privileged", "eq", "false"), "identity_privileged").text).toBe(
      "false",
    );
  });

  it("changes the operator only to one of the field's own", () => {
    expect(withOp(row("srcip", "eq", "x"), "cidr").op).toBe("cidr");
    const stays = row("category", "eq", "x");
    expect(withOp(stays, "cidr")).toBe(stays);
  });
});

describe("parseInteger", () => {
  it.each([
    ["443", 443],
    [" 80 ", 80],
    ["0", 0],
    ["-5", -5],
    ["+7", 7],
    ["443.0", 443], // a whole number: the server gets the JSON number 443
    ["007", 7],
  ])("reads %j as the integer %d", (text, value) => {
    expect(parseInteger(text)).toEqual({ ok: true, value });
  });

  it.each([
    "",
    "  ",
    "abc",
    "443.5",
    "4e2",
    "0x1F",
    "1,5",
    "--1",
    "12 3",
    "Infinity",
    "NaN",
    "٤٤٣",
  ])("refuses %j", (text) => {
    expect(parseInteger(text)).toEqual({ ok: false, problem: "not_integer" });
  });

  it("refuses a number the JSON text could not hold exactly", () => {
    expect(parseInteger("9007199254740993")).toEqual({ ok: false, problem: "not_integer" });
    expect(parseInteger("9007199254740991")).toEqual({ ok: true, value: 9007199254740991 });
  });
});

describe("parseValue", () => {
  it("trims an eq string, as it trims a cidr and the items of a list: the space round a pasted value is never the value", () => {
    expect(parseValue(row("category", "eq", "recon"))).toEqual({ ok: true, value: "recon" });
    expect(parseValue(row("agent_name", "eq", " web 01 "))).toEqual({
      ok: true,
      value: "web 01", // the space inside stays
    });
    expect(parseValue(row("alert_user", "eq", "\tops\n "))).toEqual({ ok: true, value: "ops" });
  });

  it("sends an empty eq string, and one of spaces only, as the empty string: the server accepts it", () => {
    expect(parseValue(row("category", "eq", ""))).toEqual({ ok: true, value: "" });
    expect(parseValue(row("category", "eq", "   "))).toEqual({ ok: true, value: "" });
  });

  it("sends an eq port, or rule_level, as a JSON number", () => {
    expect(parseValue(row("dst_port", "eq", "443"))).toEqual({ ok: true, value: 443 });
    expect(parseValue(row("rule_level", "eq", "12"))).toEqual({ ok: true, value: 12 });
    expect(parseValue(row("dst_port", "eq", "443.5"))).toEqual({
      ok: false,
      problem: "not_integer",
    });
    expect(parseValue(row("dst_port", "eq", ""))).toEqual({ ok: false, problem: "not_integer" });
  });

  it("sends identity_privileged as a boolean, never as text", () => {
    expect(parseValue(row("identity_privileged", "eq", "true"))).toEqual({ ok: true, value: true });
    expect(parseValue(row("identity_privileged", "eq", "false"))).toEqual({
      ok: true,
      value: false,
    });
    expect(parseValue(row("identity_privileged", "eq", "yes"))).toEqual({
      ok: false,
      problem: "not_boolean",
    });
  });

  it("sends lte as a whole number", () => {
    expect(parseValue(row("rule_level", "lte", "7"))).toEqual({ ok: true, value: 7 });
    expect(parseValue(row("rule_level", "lte", "7.5"))).toEqual({
      ok: false,
      problem: "not_integer",
    });
    expect(parseValue(row("rule_level", "lte", "seven"))).toEqual({
      ok: false,
      problem: "not_integer",
    });
  });

  it("trims a cidr and leaves a prefix as typed, the empty prefix included", () => {
    expect(parseValue(row("srcip", "cidr", " 10.0.0.0/8 "))).toEqual({
      ok: true,
      value: "10.0.0.0/8",
    });
    expect(parseValue(row("srcip", "cidr", "10.0.0.1"))).toEqual({ ok: true, value: "10.0.0.1" });
    expect(parseValue(row("agent_name", "prefix", "lab-"))).toEqual({ ok: true, value: "lab-" });
    expect(parseValue(row("agent_name", "prefix", ""))).toEqual({ ok: true, value: "" });
    expect(parseValue(row("agent_name", "prefix", " lab "))).toEqual({ ok: true, value: " lab " });
  });

  it("splits an in list on commas and trims each item", () => {
    expect(parseValue(row("rule_id", "in", "5715,  531 ,40112"))).toEqual({
      ok: true,
      value: ["5715", "531", "40112"],
    });
    expect(parseValue(row("rule_id", "in", "5715"))).toEqual({ ok: true, value: ["5715"] });
  });

  it("makes an integer list of numbers, and refuses it when one item is not whole", () => {
    expect(parseValue(row("dst_port", "in", "22, 443"))).toEqual({ ok: true, value: [22, 443] });
    expect(parseValue(row("dst_port", "in", "22, 44.5"))).toEqual({
      ok: false,
      problem: "not_integer",
    });
    expect(parseValue(row("dst_port", "in", "22, http"))).toEqual({
      ok: false,
      problem: "not_integer",
    });
  });

  it("refuses an empty list, and a list with a blank item", () => {
    expect(parseValue(row("rule_id", "in", ""))).toEqual({ ok: false, problem: "list_empty" });
    expect(parseValue(row("rule_id", "in", "  "))).toEqual({ ok: false, problem: "list_empty" });
    expect(parseValue(row("rule_id", "in", "a,,b"))).toEqual({
      ok: false,
      problem: "list_blank_item",
    });
    expect(parseValue(row("rule_id", "in", "a,"))).toEqual({
      ok: false,
      problem: "list_blank_item",
    });
  });
});

describe("a condition", () => {
  it("is exactly {field, op, value}, the keys in that order", () => {
    const parsed = toCondition(row("dst_port", "eq", "443"));
    expect(parsed).toEqual({ ok: true, condition: { field: "dst_port", op: "eq", value: 443 } });
    if (parsed.ok) expect(Object.keys(parsed.condition)).toEqual(["field", "op", "value"]);
  });

  it("carries the problem of a bad value", () => {
    expect(toCondition(row("dst_port", "eq", "x"))).toEqual({ ok: false, problem: "not_integer" });
  });

  it("makes a match of all the rows, and none when one is bad", () => {
    expect(
      matchOf([row("category", "eq", "recon", 1), row("dst_port", "in", "53, 123", 2)]),
    ).toEqual([
      { field: "category", op: "eq", value: "recon" },
      { field: "dst_port", op: "in", value: [53, 123] },
    ]);
    expect(matchOf([row("category", "eq", "recon", 1), row("dst_port", "eq", "x", 2)])).toBeNull();
  });

  it("makes [] of no row: a rule with no condition matches everything, and the server accepts it", () => {
    expect(matchOf([])).toEqual([]);
  });

  it("has a key that is the same for the same conditions and differs for any change", () => {
    const base = [
      { field: "category", op: "eq", value: "recon" },
      { field: "dst_port", op: "in", value: [53, 123] },
    ];
    expect(matchKey(base)).toBe(matchKey(structuredClone(base)));
    expect(matchKey(base)).not.toBe(matchKey([base[0]!]));
    expect(matchKey(base)).not.toBe(matchKey([...base].reverse()));
    expect(matchKey([{ field: "dst_port", op: "eq", value: 53 }])).not.toBe(
      matchKey([{ field: "dst_port", op: "eq", value: "53" }]),
    );
    expect(matchKey([])).toBe("[]");
  });
});

describe("what the hard blocks make useless", () => {
  const c = (field: string, op: string, value: unknown) => ({ field, op, value });

  it("finds asset_criticality high, a malicious or suspicious ioc_reputation, and a privileged identity", () => {
    expect(hardBlockedValues(c("asset_criticality", "eq", "high"))).toEqual(["high"]);
    expect(hardBlockedValues(c("ioc_reputation", "eq", "malicious"))).toEqual(["malicious"]);
    expect(
      hardBlockedValues(c("ioc_reputation", "in", ["clean", "suspicious", "malicious"])),
    ).toEqual(["suspicious", "malicious"]);
    expect(hardBlockedValues(c("identity_privileged", "eq", true))).toEqual([true]);
  });

  it("finds nothing in a value a rule can close", () => {
    expect(hardBlockedValues(c("asset_criticality", "eq", "low"))).toEqual([]);
    expect(hardBlockedValues(c("asset_criticality", "in", ["low", "medium", "unknown"]))).toEqual(
      [],
    );
    expect(hardBlockedValues(c("ioc_reputation", "eq", "clean"))).toEqual([]);
    expect(hardBlockedValues(c("identity_privileged", "eq", false))).toEqual([]);
    expect(hardBlockedValues(c("category", "eq", "high"))).toEqual([]);
    expect(hardBlockedValues(c("agent_name", "prefix", "high"))).toEqual([]);
    expect(hardBlockedValues(c("constructor", "eq", "high"))).toEqual([]);
  });
});

describe("how a stored condition is shown", () => {
  it("quotes a string, leaves a number and a boolean bare, and puts a list in brackets", () => {
    expect(formatValue("ops")).toBe('"ops"');
    expect(formatValue(53)).toBe("53");
    expect(formatValue(true)).toBe("true");
    expect(formatValue(["5715", 531])).toBe('["5715", 531]');
    expect(formatValue([])).toBe("[]");
    expect(formatValue(null)).toBe("null");
  });

  it("writes field, operator and value", () => {
    expect(formatCondition({ field: "dst_port", op: "eq", value: 53 })).toBe("dst_port eq 53");
    expect(formatCondition({ field: "agent_name", op: "prefix", value: "lab-" })).toBe(
      'agent_name prefix "lab-"',
    );
    expect(formatCondition({ field: "rule_id", op: "in", value: ["5715"] })).toBe(
      'rule_id in ["5715"]',
    );
  });

  it("escapes a hostile string inside its quotes, and shows anything that is not a condition as JSON", () => {
    expect(formatCondition({ field: "decoder", op: "eq", value: 'a"b\n<script>' })).toBe(
      'decoder eq "a\\"b\\n<script>"',
    );
    expect(formatCondition("just text")).toBe('"just text"');
    expect(formatCondition(null)).toBe("null");
    expect(formatCondition(undefined)).toBe("undefined");
    expect(formatCondition([1, 2])).toBe("[1,2]");
    expect(formatCondition({ field: "x", op: "eq" })).toBe('{"field":"x","op":"eq"}');
    expect(formatCondition({ field: 5, op: "eq", value: 1 })).toBe(
      '{"field":5,"op":"eq","value":1}',
    );
  });
});
