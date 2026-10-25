// src/features/admin/knowledgeModel.test.ts — the form of a knowledge draft as plain values (P13-T06): what the
// stored draft becomes in the form, what an edit sends back (the changed model fields, never a closed one), and
// where a fault of V1-V5 is shown.
import { KNOWLEDGE_MODEL_FIELDS, type KnowledgeDraftFields } from "../../api/admin";
import {
  changedFields,
  editsOf,
  faultsByField,
  formOf,
  isDirty,
  linesOf,
  sameTags,
  textOfLines,
  type DraftForm,
} from "./knowledgeModel";

const STORED: KnowledgeDraftFields = {
  title: "Quét cổng định kỳ từ máy giám sát",
  conclusion: "closed_benign",
  category: "recon",
  mitre_ids: ["T1046"],
  soar_scenario: "SC03",
  rule_ids: ["100190"],
  log_source: "wazuh",
  tags: ["port_scan", "firewall"],
  summary: "Máy giám sát quét cổng đều đặn.",
  distinguishing_signals: ["Nguồn thuộc dải giám sát", "Lặp lại theo giờ"],
  check_next_time: ["Xác nhận lịch quét"],
  confidence_note: "Chỉ dựa trên một quyết định.",
};

describe("linesOf and textOfLines", () => {
  it("splits at line ends, trims each line and drops the empty ones", () => {
    expect(linesOf("  một \n\n hai\r\n   \nba  ")).toEqual(["một", "hai", "ba"]);
    expect(linesOf("")).toEqual([]);
    expect(linesOf("  \n \n")).toEqual([]);
  });

  it("joins a list with one item to a line", () => {
    expect(textOfLines(["a", "b"])).toBe("a\nb");
    expect(textOfLines([])).toBe("");
    expect(linesOf(textOfLines(["a", "b", "c"]))).toEqual(["a", "b", "c"]);
  });
});

describe("formOf", () => {
  it("lays the six model fields of a stored draft out as form values", () => {
    expect(formOf(STORED)).toEqual({
      title: "Quét cổng định kỳ từ máy giám sát",
      summary: "Máy giám sát quét cổng đều đặn.",
      signals: "Nguồn thuộc dải giám sát\nLặp lại theo giờ",
      checks: "Xác nhận lịch quét",
      note: "Chỉ dựa trên một quyết định.",
      tags: ["port_scan", "firewall"],
    });
  });

  it("makes an empty form of a draft with no text, and of fields of the wrong type", () => {
    const empty: DraftForm = { title: "", summary: "", signals: "", checks: "", note: "", tags: [] };
    expect(formOf({})).toEqual(empty);
    const hostile = {
      title: 7,
      summary: null,
      distinguishing_signals: "not a list",
      check_next_time: [1, "ok", null],
      confidence_note: { a: 1 },
      tags: ["a", 2, "b"],
    } as unknown as Partial<KnowledgeDraftFields>;
    expect(formOf(hostile)).toEqual({ ...empty, checks: "ok", tags: ["a", "b"] });
  });
});

describe("isDirty, changedFields and editsOf", () => {
  const initial = formOf(STORED);

  it("see no change in a form that was only opened", () => {
    expect(isDirty(initial, { ...initial })).toBe(false);
    expect(changedFields(initial, { ...initial })).toEqual([]);
    expect(editsOf(initial, { ...initial }, false)).toEqual({});
  });

  it("see no change in white space at the ends, or in the order of the tags", () => {
    const touched: DraftForm = {
      ...initial,
      title: `  ${initial.title}  `,
      signals: `\n${initial.signals}\n\n`,
      tags: ["firewall", "port_scan"],
    };
    expect(isDirty(initial, touched)).toBe(false);
    expect(editsOf(initial, touched, false)).toEqual({});
  });

  it("send only the field that changed, in the form the route reads", () => {
    expect(editsOf(initial, { ...initial, title: "  Tiêu đề khác " }, false)).toEqual({
      title: "Tiêu đề khác",
    });
    expect(editsOf(initial, { ...initial, summary: "Tóm tắt khác" }, false)).toEqual({
      summary: "Tóm tắt khác",
    });
    expect(editsOf(initial, { ...initial, signals: "Một\n\nHai " }, false)).toEqual({
      distinguishing_signals: ["Một", "Hai"],
    });
    expect(editsOf(initial, { ...initial, checks: "" }, false)).toEqual({ check_next_time: [] });
    expect(editsOf(initial, { ...initial, note: "Ghi chú khác" }, false)).toEqual({
      confidence_note: "Ghi chú khác",
    });
    expect(editsOf(initial, { ...initial, tags: ["port_scan"] }, false)).toEqual({
      tags: ["port_scan"],
    });
  });

  it("send several changed fields together, and name them", () => {
    const form: DraftForm = { ...initial, title: "A", note: "B", tags: [] };
    expect(editsOf(initial, form, false)).toEqual({ title: "A", confidence_note: "B", tags: [] });
    expect(changedFields(initial, form)).toEqual(["title", "tags", "confidence_note"]);
    expect(isDirty(initial, form)).toBe(true);
  });

  it("send all six when the draft had no text, even those left empty", () => {
    const blank = formOf({});
    expect(editsOf(blank, { ...blank, title: "Mới" }, true)).toEqual({
      title: "Mới",
      tags: [],
      summary: "",
      distinguishing_signals: [],
      check_next_time: [],
      confidence_note: "",
    });
  });

  it("never name a field that is not one of the six model fields", () => {
    const edit = editsOf(
      initial,
      { title: "1", summary: "2", signals: "3", checks: "4", note: "5", tags: ["x"] },
      false,
    );
    expect(Object.keys(edit).sort()).toEqual([...KNOWLEDGE_MODEL_FIELDS].sort());
    for (const closed of ["conclusion", "category", "mitre_ids", "soar_scenario", "rule_ids"]) {
      expect(edit).not.toHaveProperty(closed);
    }
  });
});

describe("sameTags", () => {
  it("compares tags as sets", () => {
    expect(sameTags(["a", "b"], ["b", "a"])).toBe(true);
    expect(sameTags(["a"], ["a", "b"])).toBe(false);
    expect(sameTags([], [])).toBe(true);
    expect(sameTags(["a", "a"], ["a"])).toBe(true);
  });
});

describe("faultsByField", () => {
  it("puts a fault at the field named after the colon, the order of the route kept", () => {
    const result = faultsByField([
      { rule: "v3_ipv4", field: "summary" },
      { rule: "v5_length", field: "summary" },
      { rule: "v5_empty", field: "title" },
      { rule: "v2_closed", field: "category" },
    ]);
    expect(result.byField.summary).toEqual([
      { rule: "v3_ipv4", field: "summary" },
      { rule: "v5_length", field: "summary" },
    ]);
    expect(result.byField.title).toEqual([{ rule: "v5_empty", field: "title" }]);
    expect(result.byField.category).toEqual([{ rule: "v2_closed", field: "category" }]);
    expect(result.general).toEqual([]);
  });

  it("puts a fault with no matching field above the form", () => {
    const result = faultsByField([
      { rule: "v1_schema", field: "root" },
      { rule: "v1_schema", field: "unexpected_key" },
      { rule: "v1_tags", field: "unknown_tag" },
      { rule: "weird", field: null },
      { rule: "v9_new", field: "not_a_field" },
    ]);
    expect(result.general).toHaveLength(5);
    expect(Object.keys(result.byField)).toEqual([]);
  });

  it("does not take a name of the prototype chain for a field", () => {
    const result = faultsByField([
      { rule: "v5_length", field: "constructor" },
      { rule: "v5_length", field: "__proto__" },
      { rule: "v5_length", field: "toString" },
    ]);
    expect(result.general).toHaveLength(3);
    expect(Object.keys(result.byField)).toEqual([]);
  });
});
