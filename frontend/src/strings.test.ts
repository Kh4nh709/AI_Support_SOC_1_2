import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ALERT_STATUSES } from "./api/tier1";
import { CASE_STATUSES, HELD_CONCLUSION, MODEL_CONCLUSIONS } from "./api/tier2";
import { MIN_QUOTE_CHARS, S, bandCodeOfLabel, failureKindLabel, labelOf } from "./strings";

it("names the two Tier-1 closing decisions, escalate and reopen", () => {
  expect(S.decision.falsePositive).toBe("Đóng — dương tính giả");
  expect(S.decision.benign).toBe("Đóng — lành tính");
  expect(S.decision.acknowledge).toBe("Nhận xử lý");
  expect(S.decision.escalate).toBeTruthy();
  expect(S.decision.reopen).toBeTruthy();
});

it("labels the three case conclusions exactly", () => {
  expect(S.conclusion.concluded_fp).toBe("Dương tính giả");
  expect(S.conclusion.concluded_policy_violation).toBe("Vi phạm chính sách");
  expect(S.conclusion.confirmed_incident).toBe("Xác nhận sự cố");
  expect(Object.keys(S.conclusion).sort()).toEqual([
    "concluded_fp",
    "concluded_policy_violation",
    "confirmed_incident",
  ]);
});

it("keeps the scope note of a confirmed incident beside the conclusion", () => {
  expect(S.case.scopeNote).toMatch(/^Kết luận này chỉ ghi nhận sự cố/);
});

it("labels the four risk bands, the column 'Mức' is risk_band and not severity", () => {
  expect(Object.keys(S.band).sort()).toEqual(["critical", "high", "low", "medium"]);
  expect(S.queue.col.band).toBe("Mức");
});

// Rulings R8 and R13: the UI shows the server's risk_band text, and one table maps it to the code the
// queue's filter and counts speak. The literal table is the backend's (queue.risk_band, BAND_CODES).
describe("the risk band label <-> code table", () => {
  const TABLE: [string, string][] = [
    ["Thấp", "low"],
    ["Vừa", "medium"],
    ["Cao", "high"],
    ["Rất cao", "critical"],
  ];

  it.each(TABLE)("%s is %s, both ways", (label, code) => {
    expect(labelOf(S.band, code)).toBe(label);
    expect(bandCodeOfLabel(label)).toBe(code);
  });

  it("knows no code for a label it does not have, or for a missing one", () => {
    for (const other of [
      "Nghiêm trọng",
      "Trung bình",
      "rất cao",
      "",
      "constructor",
      "toString",
      "critical",
      "high",
      null,
      undefined,
    ]) {
      expect(bandCodeOfLabel(other)).toBeNull();
    }
  });
});

it("keeps the words of `severity` apart from the words of the risk band", () => {
  expect(S.severity).toEqual({
    critical: "Nghiêm trọng",
    high: "Cao",
    medium: "Trung bình",
    low: "Thấp",
  });
  expect(S.severity.critical).not.toBe(S.band.critical);
});

it("labels every alert status the Jinja page labelled", () => {
  expect(S.status).toMatchObject({
    received: "Đã nhận",
    duplicate: "Bản sao",
    enriching: "Đang làm giàu dữ liệu",
    queued_tier1: "Chờ xử lý",
    tier1_active: "Đang xử lý",
    auto_closed: "Tự động đóng",
    escalated_tier2: "Đã chuyển tier 2",
    closed_fp: "Đã đóng — dương tính giả",
    closed_benign: "Đã đóng — lành tính",
    closed_confirmed: "Đã đóng — xác nhận sự cố",
  });
});

it("has a label for every status of the two database CHECKs, and the lists are the database's", () => {
  const schema = readFileSync(join("..", "docs", "Schema", "schema.sql"), "utf8");
  const quoted = (name: string): string[] => {
    // the LAST definition of the constraint in schema.sql is the one in force (a migration drops and re-adds it)
    const all = [
      ...schema.matchAll(new RegExp(`CONSTRAINT ${name} CHECK \\(([\\s\\S]*?)\\)\\)`, "g")),
    ];
    const last = all[all.length - 1]?.[1] ?? "";
    return [...last.matchAll(/'([a-z_0-9]+)'/g)].map((m) => m[1] ?? "");
  };
  expect([...ALERT_STATUSES].sort()).toEqual(quoted("ck_alerts_status").sort());
  expect([...CASE_STATUSES].sort()).toEqual(quoted("ck_cases_status").sort());
  for (const status of ALERT_STATUSES) {
    // `duplicate` and the enrichment states are shown only on the pages that have a label for them
    expect(S.status, status).toHaveProperty(status);
  }
  for (const status of CASE_STATUSES) expect(S.caseStatus, status).toHaveProperty(status);
});

it("labels `archived`, the status of the old queue closed out without review (DEC-212)", () => {
  expect(S.status.archived).toBe("Đã lưu trữ");
  expect(S.caseStatus.archived).toBe("Đã lưu trữ");
  expect(S.headStatus.archived).toBe("Đã lưu trữ");
  expect(labelOf(S.status, "archived")).toBe("Đã lưu trữ");
  expect(labelOf(S.caseStatus, "archived")).toBe("Đã lưu trữ");
  // not worded as a person's close
  expect(S.status.archived).not.toBe(S.status.closed_benign);
  expect(S.status.archived).not.toMatch(/đóng/i);
  expect(S.admin.eventType["alert.archived"]).toBe("Lưu trữ alert (dọn hàng đợi)");
  expect(S.admin.eventType["case.archived"]).toBe("Lưu trữ case (dọn hàng đợi)");
});

it("says 'ẩn — nhánh mù' for the blind arm and 'chưa có' for no result yet", () => {
  expect(S.ai1.hidden).toBe("ẩn — nhánh mù");
  expect(S.ai1.none).toBe("chưa có");
});

it("carries the two column headings and the live indicator", () => {
  expect(S.alert.infoHeading).toBe("THÔNG TIN ALERT");
  expect(S.alert.aiHeading).toBe("PHÂN TÍCH AI ①");
  expect(S.case.aiHeading).toBe("PHÂN TÍCH AI ②");
  expect(S.live.on).toBe("Trực tiếp");
  expect(S.live.off).toBe("Mất kết nối");
});

it("carries the login errors of the spec §3.1", () => {
  expect(S.login.invalid).toBe("Sai tên đăng nhập hoặc mật khẩu");
  expect(S.login.locked("09:45")).toBe("Tài khoản bị khoá đến 09:45");
  expect(S.login.disabled).toBe("Đăng nhập đang tắt");
});

it("carries the 503 copy of a decision and the two ② dead ends", () => {
  expect(S.decision.timeout).toBe("Hết thời gian xử lý, chưa ghi gì — thử lại");
  expect(S.ai2.stalled(5)).toBe("Chưa được xử lý sau 5 phút — kiểm tra worker");
  expect(S.ai2.failed).toBe("Phân tích thất bại — có thể thử lại");
});

// The Jinja page prints "Playbook: <name>" under a run that used one.
it("words the playbook line of a run as the Jinja page does", () => {
  expect(S.ai2.playbook("ssh_brute_force")).toBe("Playbook: ssh_brute_force");
});

it("says a page past the last one of the case list is empty, not that there is no case", () => {
  expect(S.case.pastEnd).toBe("Không còn case ở trang này.");
  expect(S.case.pastEnd).not.toBe(S.case.empty);
});

it("names the four evidence marks of ②", () => {
  expect(Object.keys(S.ai2.mark).sort()).toEqual([
    "not_in_case",
    "quote_not_found",
    "quote_too_short",
    "verified",
  ]);
});

// The Jinja page and this UI must say the same thing about ②: the label tables of the backend are the
// source, and a label edited on one side only would go unseen without this read. The tables move
// between modules (P10-T03 moves CONCLUSION_LABELS out of the router, P10-T13 deletes the router), so
// no file is named: the test finds the one file under backend/app/ that *defines* each table.
const BACKEND_APP = join("..", "backend", "app");

const pyFiles = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? pyFiles(path) : path.endsWith(".py") ? [path] : [];
  });

/** The one definition of `name` under `root`: its file and the text inside the braces. */
function definition(name: string, pattern: RegExp, root: string): { path: string; body: string } {
  const found = pyFiles(root).flatMap((path) => {
    const body = pattern.exec(readFileSync(path, "utf8"))?.[1];
    return body === undefined ? [] : [{ path, body }];
  });
  const [only] = found;
  if (found.length !== 1 || !only) {
    const where = found.map((f) => f.path).join(", ") || "no file";
    throw new Error(
      `expected exactly one definition of ${name} under ${root}, found ${found.length} (${where})`,
    );
  }
  return only;
}

/**
 * A module-level `NAME: dict[str, str] = {"key": "value", ...}` of the backend, as an object. A line
 * that only imports the name, or a commented-out copy, is not a definition; two definitions are an error.
 */
function pyDict(name: string, root = BACKEND_APP): Record<string, string> {
  const pattern = new RegExp(`^${name}(?::\\s*dict\\[str,\\s*str\\])?\\s*=\\s*\\{([^}]*)\\}`, "m");
  const { body } = definition(name, pattern, root);
  const pairs = [...body.matchAll(/^\s*"([^"]+)":\s*"([^"]*)",?\s*$/gm)];
  return Object.fromEntries(pairs.map((m) => [m[1], m[2]]));
}

/** A module-level `NAME = 8` of the backend, as a number. */
function pyInt(name: string, root = BACKEND_APP): number {
  return Number(definition(name, new RegExp(`^${name}\\s*=\\s*(\\d+)\\s*$`, "m"), root).body);
}

/** A module-level `NAME: tuple[str, ...] = ("a", "b", ...)` of the backend, as a list (a literal tuple only). */
function pyTuple(name: string, root = BACKEND_APP): string[] {
  const pattern = new RegExp(
    `^${name}(?::\\s*tuple\\[str,\\s*\\.\\.\\.\\])?\\s*=\\s*\\(([^)]*)\\)`,
    "m",
  );
  const { body } = definition(name, pattern, root);
  return [...body.matchAll(/"([^"]*)"/g)].map((m) => m[1] as string);
}

/** A module-level `NAME = "text"` of the backend, as a string. */
function pyString(name: string, root = BACKEND_APP): string {
  return definition(name, new RegExp(`^${name}\\s*=\\s*"([^"]*)"\\s*$`, "m"), root).body;
}

describe("finding a backend definition", () => {
  const root = mkdtempSync(join(tmpdir(), "p10t07-py-"));
  const put = (file: string, text: string): void => {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), text);
  };
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("finds the one file that defines the table, wherever it is, and ignores its importers", () => {
    put("a/labels.py", 'LABELS: dict[str, str] = {\n    "x": "X",\n    "y": "Y",\n}\n');
    put("b/user.py", "from a.labels import LABELS\n# LABELS: dict[str, str] = {}\n");
    put("c/count.py", "MIN_CHARS = 8\n");
    expect(pyDict("LABELS", root)).toEqual({ x: "X", y: "Y" });
    expect(pyInt("MIN_CHARS", root)).toBe(8);
  });

  it("refuses a name defined twice, so a copy left behind in the old module goes red", () => {
    put("d/again.py", 'LABELS: dict[str, str] = {\n    "x": "other",\n}\n');
    expect(() => pyDict("LABELS", root)).toThrow(/exactly one definition of LABELS.*found 2/);
  });

  it("refuses a name defined nowhere, so a deleted table cannot pass for a matching one", () => {
    expect(() => pyDict("NOWHERE", root)).toThrow(/exactly one definition of NOWHERE.*found 0/);
    expect(() => pyInt("NOWHERE", root)).toThrow(/found 0/);
  });
});

describe("② labels follow the backend", () => {
  it("reads the backend tables (a parse that finds nothing would compare nothing)", () => {
    expect(Object.keys(pyDict("CONCLUSION_LABELS")).sort()).toEqual([
      "confirmed_incident",
      "false_positive",
      "need_more_data",
      "policy_violation",
    ]);
    expect(Object.keys(pyDict("STOPPED_TEXT")).length).toBe(5);
  });

  it("labels the suggested conclusion as the backend CONCLUSION_LABELS do", () => {
    expect(S.ai2.suggestedConclusion).toEqual(pyDict("CONCLUSION_LABELS"));
    expect(S.ai2.suggestedConclusion).toEqual({
      false_positive: "Không phải sự cố",
      policy_violation: "Có vi phạm nội quy, không phải tấn công",
      confirmed_incident: "Là sự cố thật",
      need_more_data: "Cần thêm dữ liệu",
    });
  });

  it("keeps the three case-conclusion labels apart from the suggested ones", () => {
    expect(S.conclusion.confirmed_incident).toBe("Xác nhận sự cố");
    expect(S.ai2.suggestedConclusion.confirmed_incident).not.toBe(S.conclusion.confirmed_incident);
  });

  it("says why a run stopped as the backend STOPPED_TEXT does", () => {
    expect(S.ai2.stoppedBy).toEqual(pyDict("STOPPED_TEXT"));
  });

  // INT-T02 / DEC-211 R6: a provider 402 is `permanent` for ② and for the drafts (R4), so the word that
  // used to say only "the model refused" names the provider as well. Both are the same sentence on purpose.
  it("words `permanent` for ②, and `llm_permanent` for a draft, as a refusal of the provider or the model", () => {
    const sentence =
      "nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại";
    expect(S.ai2.stoppedBy.permanent).toBe(sentence);
    expect(pyDict("STOPPED_TEXT").permanent).toBe(sentence); // the case page shows the server's own text
    expect(S.admin.knowledgePage.warning.llm_permanent).toBe(
      "Nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại.",
    );
    for (const text of [S.ai2.stoppedBy.permanent, S.admin.knowledgePage.warning.llm_permanent]) {
      expect(text.toLowerCase()).toContain("nhà cung cấp");
      expect(text.toLowerCase()).toContain("mô hình");
      expect(text).toContain("402");
    }
  });

  it("keeps the short words of the admin LLM table short", () => {
    // `admin.llmPage.stopped` is a table cell: the longer 402 sentence is `unavailable`'s, as it was, and
    // `permanent` stays the short word.
    expect(S.admin.llmPage.stopped.permanent).toBe("bị từ chối, không thử lại");
    expect(S.admin.llmPage.stopped.permanent.length).toBeLessThan(40);
  });

  it("says a quote is too short in the words of the backend's MIN_QUOTE_CHARS", () => {
    expect(pyInt("MIN_QUOTE_CHARS")).toBe(MIN_QUOTE_CHARS);
    expect(S.ai2.mark.quote_too_short).toContain(`ngắn hơn ${MIN_QUOTE_CHARS} ký tự`);
    expect(S.ai2.mark.quote_too_short).toContain("ngắn hơn 8 ký tự");
  });
});

// DEC-217: the three values a STORED ① row may hold are `llm.verdicts.STORED_ACTIONS` (a row written before the
// decision holds `needs_review`, and the admin LLM page shows it as it is). What a NEW run may hold is
// `GATED_ACTIONS`, now the two.
function pyStoredActions(): string[] {
  return pyTuple("STORED_ACTIONS");
}

// P14-T03 (DEC-213): ① always concludes `false_positive | true_positive`. DEC-217: the gate's checks are warnings
// beside that verdict, and the UI says which. The words are the UI's, the closed values are the backend's: a reason
// added there without a label here would show as its code, so both sides are compared.
describe("① verdict and warning labels follow the backend", () => {
  it("reads the backend tuples (a parse that finds nothing would compare nothing)", () => {
    expect(pyStoredActions()).toEqual(["false_positive", "needs_review", "true_positive"]);
    expect(pyTuple("HELD_REASONS")).toHaveLength(9);
    expect(pyTuple("FP_POLICY_FIELDS")).toHaveLength(5);
  });

  it("labels the verdicts of ① as TP and FP, and keeps the label of a stored needs_review (Cần xem xét)", () => {
    expect(S.ai1.action).toEqual({
      false_positive: "FP",
      needs_review: "Cần xem xét",
      true_positive: "TP",
    });
    expect(Object.keys(S.ai1.action).sort()).toEqual([...pyStoredActions()].sort());
    expect(S.ai1.action).not.toHaveProperty("escalate");
  });

  it("words every reason the backend can return, in its order, and no other", () => {
    expect(Object.keys(S.ai1.heldReason)).toEqual(pyTuple("HELD_REASONS"));
    expect(S.ai1.heldReason).toEqual({
      facts_mismatch: "AI khai dữ kiện lệch với hệ thống",
      no_verified_quote: "không có dẫn chứng kiểm chứng được",
      "fp_policy:severity": "alert mức critical",
      "fp_policy:ioc_reputation": "IOC độc hại hoặc đáng ngờ",
      "fp_policy:asset_criticality": "tài sản quan trọng hoặc chưa rõ",
      "fp_policy:identity_privileged": "tài khoản đặc quyền",
      "fp_policy:playbook_rule": "không khớp bảng quyết định đã duyệt",
      verifier_disagrees: "bộ kiểm tra không đồng ý",
      verifier_invalid: "bộ kiểm tra không trả lời hợp lệ",
    });
  });

  it("writes the conclusion line of the alert page as the spec has it", () => {
    expect(S.ai1.conclusion).toBe("AI kết luận");
    expect(S.ai1.confidenceNote("cao")).toBe("(độ tin cậy cao)");
    // the phrase is bold on the page (spec 4.3), so it is a string of its own
    expect(S.ai1.heldDash).toBe("—");
    // DEC-217: the gate's checks are warnings beside the verdict, never a verdict held back for a person
    expect(S.ai1.held).toBe("có cảnh báo kiểm chứng");
    expect(S.ai1.heldBecause(["a", "b"])).toBe(": a, b");
    expect(S.ai1.heldBecause(["a"])).toBe(": a");
    expect(S.ai1.heldBecause([])).toBe("");
  });

  it("says no ① warning word that the system held or kept the verdict back for a person", () => {
    const words = [S.ai1.held, ...Object.values(S.ai1.heldReason)];
    for (const word of words) {
      expect(word).not.toMatch(/giữ lại|hệ thống giữ/);
    }
    expect(Object.keys(S.ai1.heldReason)).toHaveLength(9);
  });
});

describe("② held-reason labels follow the backend", () => {
  it("words the two causes the backend names, and no other", () => {
    const causes = [pyString("HELD_NO_VERIFIED_EVIDENCE"), pyString("HELD_HIGH_INJECTION")];
    expect(causes).toEqual(["no_verified_evidence", "high_severity_injection_finding"]);
    expect(Object.keys(S.ai2.heldReason)).toEqual(causes);
    expect(S.ai2.heldReason).toEqual({
      no_verified_evidence: "không có bằng chứng kiểm chứng được",
      high_severity_injection_finding: "phát hiện dấu hiệu chèn lệnh mức cao",
    });
  });

  it("writes the conclusion line of the case page as the spec has it", () => {
    expect(S.ai2.conclusion).toBe("AI kết luận");
    expect(S.ai2.heldLine(["x", "y"])).toBe("— hệ thống giữ lại vì: x, y");
    expect(S.ai2.heldLine([])).toBe("— hệ thống giữ lại"); // held, with no cause to name (M5)
  });

  it("holds the model's three conclusions and the system's own as the backend does (M5)", () => {
    expect([...MODEL_CONCLUSIONS]).toEqual(pyTuple("MODEL_CONCLUSIONS"));
    expect(pyTuple("MODEL_CONCLUSIONS")).toHaveLength(3); // a parse that finds nothing compares nothing
    expect(Object.keys(S.ai2.suggestedConclusion)).toEqual([...MODEL_CONCLUSIONS, HELD_CONCLUSION]);
  });
});

// The columns show no model, latency, token or cost line (the evaluation reads those from `llm_runs`, not
// the screen), so no label for one is kept: an entry nothing reads is a string that can drift unseen.
it("keeps no label for a model, time, token or cost line, which no screen shows", () => {
  expect(S.ai1).not.toHaveProperty("model");
  expect(S.ai1).not.toHaveProperty("latency");
  expect(S.ai1).not.toHaveProperty("cost");
  expect(S.ai1).not.toHaveProperty("heading");
  expect(S.ai1).not.toHaveProperty("quote");
  expect(S.ai2).not.toHaveProperty("model");
  expect(S.ai2).not.toHaveProperty("tokens");
  expect(S.ai2).not.toHaveProperty("cost");
  expect(S.ai2).not.toHaveProperty("heading");
  expect(S.ai2).not.toHaveProperty("injection");
  expect(S.case).not.toHaveProperty("reasonOfConclusion");
  expect(S.common).not.toHaveProperty("none");
});

it("writes no English-only label where a Vietnamese one is named by the spec", () => {
  expect(S.app.name).toBe("AI Support SOC");
  expect(S.nav.admin).toBe("Quản trị");
  expect(S.nav).not.toHaveProperty("adminLegacy");
});

// The category of an alert is shown by a Vietnamese label (the code stays beside it). The backend's PRIORITY
// tuple (ingest/category.py) is every category the mapper can emit, so each one has a label here: S1 added
// `credential_access` to it, and a category with no label would be shown as its raw code.
describe("the category labels follow the backend PRIORITY", () => {
  const priority = (): string[] => {
    const pattern = /^PRIORITY(?::\s*tuple\[str,\s*\.\.\.\])?\s*=\s*\(([^)]*)\)/m;
    const { body } = definition("PRIORITY", pattern, BACKEND_APP);
    return [...body.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
  };

  it("reads the tuple (a parse that finds nothing would compare nothing)", () => {
    expect(priority()).toContain("ssh_brute_force");
    expect(priority()).toContain("credential_access");
    expect(priority().length).toBeGreaterThanOrEqual(13);
  });

  it("has a label for every category, and none for a category the backend does not have", () => {
    expect(Object.keys(S.category).sort()).toEqual([...priority()].sort());
  });

  it("says credential_access in Vietnamese, and an unknown category as its code", () => {
    expect(labelOf(S.category, "credential_access")).toBe("Đánh cắp thông tin xác thực");
    expect(labelOf(S.category, "new_thing")).toBe("new_thing");
    expect(labelOf(S.category, "constructor")).toBe("constructor");
  });
});

// P14-T07 (DEC-213, spec 4.3): the percentage and the "RAG not applied" notice. The kinds are the backend's
// (`rag.failures.FAILURE_KINDS`, also what a lookup records), the words are the UI's; both sides are compared, and
// the sentences are written out in full so that one edited in strings.ts alone goes red.
describe("RAG percentage and notice follow the backend", () => {
  it("reads the backend's kinds (a parse that finds nothing would compare nothing)", () => {
    expect(pyTuple("FAILURE_KINDS")).toEqual([
      "rate_limit",
      "timeout",
      "auth",
      "quota",
      "provider_error",
      "vectordb_unreachable",
    ]);
  });

  it("words every failure kind the backend can record, in its order, and no other", () => {
    expect(Object.keys(S.rag.failureKind)).toEqual(pyTuple("FAILURE_KINDS"));
    expect(S.rag.failureKind).toEqual({
      rate_limit: "Voyage vượt giới hạn tốc độ",
      timeout: "Voyage quá thời gian chờ",
      auth: "thiếu hoặc sai API key Voyage",
      quota: "Voyage hết hạn mức",
      provider_error: "lỗi phía Voyage",
      vectordb_unreachable: "không kết nối được vector DB",
    });
  });

  it("says the percentage as the spec has it", () => {
    expect(S.rag.match(87)).toBe("trùng 87% với tri thức đã duyệt");
    expect(S.rag.match(0)).toBe("trùng 0% với tri thức đã duyệt");
  });

  it("says the notice of an alert and of a case as the brief has it", () => {
    expect(S.rag.notApplied("alert", "lỗi phía Voyage")).toBe(
      "⚠ Không áp dụng RAG cho alert này: lỗi phía Voyage — AI đã phân tích không có tri thức tham khảo.",
    );
    expect(S.rag.notApplied("case", "lỗi phía Voyage")).toBe(
      "⚠ Không áp dụng RAG cho case này: lỗi phía Voyage — AI đã phân tích không có tri thức tham khảo.",
    );
  });

  it("gives the words of a kind the table has, and nothing for any other name", () => {
    for (const [kind, label] of Object.entries(S.rag.failureKind)) {
      expect(failureKindLabel(kind)).toBe(label);
    }
    // never the code itself, never a name from the prototype chain, never a blank
    for (const other of [
      "cosmic_ray",
      "<b>x</b>",
      "",
      "constructor",
      "toString",
      "__proto__",
      "hasOwnProperty",
    ]) {
      expect(failureKindLabel(other), other).toBeNull();
    }
    expect(failureKindLabel(null)).toBeNull();
    expect(failureKindLabel(undefined)).toBeNull();
  });

  it("words the lookup of the admin page", () => {
    expect(Object.keys(S.admin.knowledgePage.draft.left.lookup.status).sort()).toEqual([
      "budget",
      "empty",
      "failed",
      "ok",
    ]);
  });
});

describe("labelOf", () => {
  it("returns the label of a known code", () => {
    expect(labelOf(S.status, "queued_tier1")).toBe("Chờ xử lý");
  });

  it("returns the raw code for a code with no label, never a blank", () => {
    expect(labelOf(S.status, "quarantined")).toBe("quarantined");
    expect(labelOf(S.band, "urgent")).toBe("urgent");
  });

  it("does not answer from the prototype chain", () => {
    for (const hostile of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      expect(labelOf(S.status, hostile)).toBe(hostile);
    }
  });

  it("shows a dash for a missing code", () => {
    for (const missing of [null, undefined, ""]) {
      expect(labelOf(S.status, missing)).toBe("—");
    }
  });
});
