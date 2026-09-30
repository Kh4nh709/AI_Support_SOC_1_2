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
import { MIN_QUOTE_CHARS, S, bandCodeOf, labelOf } from "./strings";

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

// Ruling R8/R13: the server's `risk_band` is a Vietnamese label (`tier2.case_view._BAND_LABELS`), and
// one table pairs it with the code the colours are keyed by.
it("words the four risk bands as the server does: Thấp, Vừa, Cao, Rất cao", () => {
  expect(S.band).toEqual({ critical: "Rất cao", high: "Cao", medium: "Vừa", low: "Thấp" });
});

it("reads the band code of a server label, and of nothing else", () => {
  expect(bandCodeOf("Thấp")).toBe("low");
  expect(bandCodeOf("Vừa")).toBe("medium");
  expect(bandCodeOf("Cao")).toBe("high");
  expect(bandCodeOf("Rất cao")).toBe("critical");
  for (const code of Object.keys(S.band) as (keyof typeof S.band)[]) {
    expect(bandCodeOf(S.band[code])).toBe(code);
  }
  // The old labels of the band table, the codes themselves, other words and non-strings are unknown.
  for (const other of ["Nghiêm trọng", "Trung bình", "critical", "high", "", "cao", "toString"]) {
    expect(bandCodeOf(other), other).toBeNull();
  }
  for (const nothing of [null, undefined, 3, {}, ["Cao"]]) expect(bandCodeOf(nothing)).toBeNull();
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

  it("says a quote is too short in the words of the backend's MIN_QUOTE_CHARS", () => {
    expect(pyInt("MIN_QUOTE_CHARS")).toBe(MIN_QUOTE_CHARS);
    expect(S.ai2.mark.quote_too_short).toContain(`ngắn hơn ${MIN_QUOTE_CHARS} ký tự`);
    expect(S.ai2.mark.quote_too_short).toContain("ngắn hơn 8 ký tự");
  });
});

it("labels the model, time and cost of ① and the model, tokens and cost of ②", () => {
  expect(S.ai1.model).toBe("Mô hình");
  expect(S.ai1.latency).toBe("Thời gian");
  expect(S.ai1.cost).toBe("Chi phí");
  expect(S.ai2.model).toBe("Mô hình");
  expect(S.ai2.tokens).toBe("Token");
  expect(S.ai2.cost).toBe("Chi phí");
});

it("writes no English-only label where a Vietnamese one is named by the spec", () => {
  expect(S.app.name).toBe("AI Support SOC");
  expect(S.nav.adminLegacy).toBe("Quản trị (UI cũ)");
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
