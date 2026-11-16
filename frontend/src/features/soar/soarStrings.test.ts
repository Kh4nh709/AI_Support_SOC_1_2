// src/features/soar/soarStrings.test.ts — the words of the page "Phản hồi SOAR" (S.soar): a word for every member of each closed set
// the API names, so a status or an action type the backend can send is never shown as a bare code by a gap in the table, and
// the composed lines say exactly what the card says. A code the table has no word for is still shown as the code (labelOf).
import { S, labelOf } from "../../strings";
import {
  SOAR_ACTION_TYPES,
  SOAR_DECISIONS,
  SOAR_KINDS,
  SOAR_SEVERITIES,
  SOAR_STATUSES,
} from "../../api/soar";
import { TABS } from "./soarParams";

/** Every string a table or a function of `S.soar` can say, called with plain arguments. */
function wordsOf(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (typeof value === "function") {
    const said = (value as (...args: unknown[]) => unknown)(1, 2, 3);
    return typeof said === "string" ? [said] : [];
  }
  if (typeof value === "object" && value !== null) return Object.values(value).flatMap(wordsOf);
  return [];
}

describe("the closed sets have a word each", () => {
  it.each([
    ["status", SOAR_STATUSES, S.soar.status],
    ["actionType", SOAR_ACTION_TYPES, S.soar.actionType],
    ["severity", SOAR_SEVERITIES, S.soar.severity],
    ["decision", SOAR_DECISIONS, S.soar.decision],
    ["kind", SOAR_KINDS, S.soar.kind],
  ] as const)("S.soar.%s has a word for each code and for nothing else", (name, codes, table) => {
    for (const code of codes) {
      expect(Object.hasOwn(table, code), `${name}.${code}`).toBe(true);
      expect(labelOf(table, code)).not.toBe(code);
    }
    expect(Object.keys(table).sort()).toEqual([...codes].sort());
  });

  it("has a word for each tab", () => {
    for (const tab of TABS) expect(S.soar.tabs[tab], tab).toBeTruthy();
  });

  it("words the two audit events of the page and every outcome of the history", () => {
    expect(Object.keys(S.soar.detail.history.event).sort()).toEqual([
      "soar.review_decided",
      "soar.review_received",
    ]);
    for (const outcome of [
      "created",
      "updated",
      "ignored",
      "ok",
      "failed",
      "unavailable",
      "conflict",
      "invalid_state",
      "locked",
    ]) {
      expect(Object.hasOwn(S.soar.detail.history.outcome, outcome), outcome).toBe(true);
    }
  });

  it("shows a code it has no word for as the code, and never a name from the prototype chain as a label", () => {
    expect(labelOf(S.soar.status, "paused")).toBe("paused");
    expect(labelOf(S.soar.actionType, "constructor")).toBe("constructor");
    expect(labelOf(S.soar.severity, "__proto__")).toBe("__proto__");
    expect(labelOf(S.soar.detail.history.event, "toString")).toBe("toString");
  });
});

describe("the words", () => {
  it("has no empty word anywhere in S.soar", () => {
    const words = wordsOf(S.soar);
    expect(words.length).toBeGreaterThan(150);
    expect(words.filter((word) => word.trim() === "")).toEqual([]);
  });

  it("is Vietnamese: the title, the tabs, the statuses and the filter words are the Owner's", () => {
    expect(S.soar.title).toBe("Phản hồi SOAR");
    expect(S.soar.tabs).toMatchObject({
      open: "Đang mở",
      done: "Đã xử lý",
      expired: "Hết hạn",
      notice: "Thông báo",
    });
    expect(S.soar.status).toMatchObject({
      kept: "Đã giữ",
      undone: "Đã gỡ",
      false_positive: "Dương tính giả",
      expired: "Hết hạn",
      processing: "Đang xử lý",
    });
    expect(S.soar.simulated).toBe("GIẢ LẬP");
    expect(S.soar.working).toBe("Đang xử lý…");
  });

  it("says the composed lines whole", () => {
    expect(S.soar.timer.autoUndo("22:40", "59:58")).toBe("Tự gỡ lúc 22:40 · còn 59:58");
    expect(S.soar.timer.holding(30)).toBe("Đang giữ · nhắc mỗi 30 phút");
    expect(S.soar.timer.waitingClose).toBe("Chờ SOAR đóng phiếu");
    expect(S.soar.heldBy("binh")).toBe("Đang xử lý (binh)");
    expect(S.soar.result.ok("Đã giữ")).toBe("Đã cập nhật: Đã giữ");
    expect(S.soar.result.conflict("Đã gỡ")).toBe("Phiếu đã được xử lý ở nơi khác: Đã gỡ");
    expect(S.soar.result.toast("K7QM2XHP", "Đã giữ")).toBe("Phiếu K7QM2XHP: Đã giữ");
    expect(S.soar.dialog.noteCount(12, 500)).toBe("12/500");
    expect(S.soar.dialog.subject("K7QM2XHP", "Chặn IP 1.2.3.4")).toBe(
      "Phiếu K7QM2XHP: Chặn IP 1.2.3.4",
    );
    expect(S.soar.range(1, 50, 120)).toBe("Hiển thị 1–50 trên 120");
    expect(S.soar.detail.history.change("Đang mở", "Đã gỡ")).toBe("Đang mở → Đã gỡ");
    expect(S.soar.notice.more(3)).toBe("Còn 3 thông báo khác, xem ở mục “Thông báo”.");
    expect(S.soar.signal.notification.body(2)).toBe("Có 2 phiếu đang mở");
  });

  it("names no model and no product of the pipeline in what it says to a person (the page is about the SOAR)", () => {
    const text = wordsOf(S.soar).join("\n");
    expect(text).not.toMatch(/glm|gpt|deepseek|claude|qwen|llama|gemini|mistral|kimi/i);
  });
});
