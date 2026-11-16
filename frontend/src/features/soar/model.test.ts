// src/features/soar/model.test.ts — what the page works out of a review: the colour of a score, the words of a status
// and an action, the buttons a person may press, the countdown and the reminder. Clocks are fixed numbers.
import {
  NOTE_MAX,
  actionTextOf,
  buttonsOf,
  cleanDeep,
  formatCountdown,
  scoreTone,
  statusText,
  stripControls,
  timersOf,
} from "./model";
import { notice, review } from "./fixtures";
import { S } from "../../strings";

describe("scoreTone", () => {
  it.each([
    [100, "critical"],
    [70, "critical"],
    [69, "high"],
    [40, "high"],
    [39, "medium"],
    [0, "medium"],
  ] as const)("colours %i as %s: red from 70, orange from 40, yellow below", (score, tone) => {
    expect(scoreTone(score)).toBe(tone);
  });
});

describe("statusText", () => {
  it.each([
    ["open", "Đang mở"],
    ["processing", "Đang xử lý"],
    ["kept", "Đã giữ"],
    ["undone", "Đã gỡ"],
    ["false_positive", "Dương tính giả"],
    ["expired", "Hết hạn"],
    ["info", "Thông tin"],
  ] as const)("words %s as %s", (status, word) => {
    expect(statusText({ status, locked_by: null })).toBe(word);
  });

  it("says who holds a row that is being processed, whole", () => {
    expect(statusText({ status: "processing", locked_by: "an" })).toBe("Đang xử lý (an)");
  });

  it("shows a status it has no word for as its code, and never a prototype name as a label", () => {
    expect(statusText({ status: "paused" as never, locked_by: null })).toBe("paused");
    expect(statusText({ status: "constructor" as never, locked_by: null })).toBe("constructor");
  });
});

describe("actionTextOf", () => {
  it("prefers n8n's own text", () => {
    expect(actionTextOf(review())).toBe("Chặn IP 79.79.78.202 trên pfSense");
  });

  it("falls back to the Vietnamese word of the action type, then to the code itself", () => {
    expect(actionTextOf(review({ action_text: null }))).toBe("Chặn IP");
    expect(actionTextOf(review({ action_text: "" }))).toBe("Chặn IP");
    expect(actionTextOf(review({ action_text: null, action_type: "make_coffee" as never }))).toBe(
      "make_coffee",
    );
    expect(actionTextOf(notice())).toBe(S.common.missing);
  });
});

describe("buttonsOf", () => {
  it("keeps the buttons whose decision the caller may take, with n8n's label", () => {
    expect(buttonsOf(review())).toEqual([
      { decision: "keep", label: "✅ Giữ chặn" },
      { decision: "undo", label: "↩️ Gỡ chặn IP" },
    ]);
  });

  it("drops a button the role may not press, or the state does not allow", () => {
    expect(buttonsOf(review({ allowed_decisions: ["keep"] })).map((b) => b.decision)).toEqual([
      "keep",
    ]);
    expect(buttonsOf(review({ allowed_decisions: [] }))).toEqual([]);
  });

  it("gives a notice none, whatever it carries", () => {
    expect(buttonsOf(notice())).toEqual([]);
    expect(
      buttonsOf(notice({ buttons: [{ decision: "keep", label: "x" }], allowed_decisions: [] })),
    ).toEqual([]);
  });

  it("shows no button for a decision this UI cannot send, and no label that is blank", () => {
    const odd = review({
      buttons: [
        { decision: "keep", label: "   " },
        { decision: "nuke" as never, label: "Nổ" },
      ],
      allowed_decisions: ["keep", "nuke" as never],
    });
    expect(buttonsOf(odd)).toEqual([{ decision: "keep", label: S.soar.decision.keep }]);
  });

  it("does not break on a review with no buttons or no allowed list", () => {
    expect(buttonsOf({ buttons: null, allowed_decisions: null } as never)).toEqual([]);
    expect(buttonsOf({} as never)).toEqual([]);
  });

  it("limits the note to 500 characters", () => {
    expect(NOTE_MAX).toBe(500);
  });
});

describe("formatCountdown", () => {
  it.each([
    [0, "00:00"],
    [-5000, "00:00"],
    [1, "00:01"],
    [59_000, "00:59"],
    [3_598_000, "59:58"],
    [3_600_000, "1:00:00"],
    [3_725_000, "1:02:05"],
  ])("writes %i ms as %s", (ms, text) => {
    expect(formatCountdown(ms)).toBe(text);
  });
});

describe("timersOf at fixed clocks", () => {
  const at = (iso: string) => Date.parse(iso);

  it("counts down to auto_expire_at while it is ahead, with the clock in +07", () => {
    // 15:40:03Z is 22:40 in Asia/Ho_Chi_Minh
    const row = review({ auto_expire_at: "2026-11-13T15:40:03+00:00" });
    expect(timersOf(row, at("2026-11-13T14:40:05+00:00")).expiry).toEqual({
      kind: "ahead",
      clock: "22:40",
      left: "59:58",
    });
  });

  it("says the SOAR has yet to close the ticket once the time is past and the status is still open", () => {
    const row = review({ auto_expire_at: "2026-11-13T15:40:03+00:00" });
    expect(timersOf(row, at("2026-11-13T15:40:04+00:00")).expiry).toEqual({ kind: "past" });
    expect(timersOf(row, at("2026-11-13T15:40:03+00:00")).expiry).toEqual({ kind: "past" });
  });

  it("shows nothing for a past time on a row that is not open, and no countdown on a row that has ended", () => {
    const past = "2026-11-13T15:40:03+00:00";
    const later = at("2026-11-13T16:00:00+00:00");
    const before = at("2026-11-13T14:00:00+00:00");
    for (const status of ["kept", "undone", "false_positive", "expired"] as const) {
      expect(timersOf(review({ status, auto_expire_at: past }), later).expiry, status).toBeNull();
    }
    for (const status of ["undone", "false_positive", "expired"] as const) {
      expect(timersOf(review({ status, auto_expire_at: past }), before).expiry, status).toBeNull();
    }
    expect(
      timersOf(review({ status: "processing", auto_expire_at: past }), later).expiry,
    ).toBeNull();
  });

  it("counts down for a kept ticket too while auto_expire_at is ahead (the page shows what n8n says), but never says it is waiting to be closed", () => {
    const row = review({ status: "kept", auto_expire_at: "2026-11-13T15:40:03+00:00" });
    expect(timersOf(row, at("2026-11-13T14:40:05+00:00")).expiry).toEqual({
      kind: "ahead",
      clock: "22:40",
      left: "59:58",
    });
    expect(timersOf(row, at("2026-11-13T15:40:04+00:00")).expiry).toBeNull();
  });

  it("shows nothing without a time, with an unreadable one, and for a notice", () => {
    const now = at("2026-11-13T14:00:00+00:00");
    expect(timersOf(review({ auto_expire_at: null }), now).expiry).toBeNull();
    expect(timersOf(review({ auto_expire_at: "tomorrow" }), now).expiry).toBeNull();
    expect(timersOf(notice({ auto_expire_at: "2026-11-13T15:40:03+00:00" }), now)).toEqual({
      expiry: null,
      hold: null,
    });
  });

  it("holds an isolation or a locked account, with its reminder interval", () => {
    const now = at("2026-11-13T14:00:00+00:00");
    for (const action_type of ["isolate_host", "disable_user"] as const) {
      const row = review({
        action_type,
        remind_every_minutes: 30,
        next_remind_at: "2026-11-13T14:30:00+00:00",
      });
      expect(timersOf(row, now).hold).toEqual({ minutes: 30, due: false });
    }
  });

  it("highlights the reminder once next_remind_at is past (and at the instant)", () => {
    const row = review({
      action_type: "isolate_host",
      remind_every_minutes: 30,
      next_remind_at: "2026-11-13T14:30:00+00:00",
    });
    expect(timersOf(row, at("2026-11-13T14:30:00+00:00")).hold).toEqual({ minutes: 30, due: true });
    expect(timersOf(row, at("2026-11-13T15:00:00+00:00")).hold).toEqual({ minutes: 30, due: true });
  });

  it("has no hold line for another action, for an interval of 0 or none, or for a row that has ended", () => {
    const now = at("2026-11-13T14:00:00+00:00");
    const base = { action_type: "isolate_host" as const, remind_every_minutes: 30 };
    expect(timersOf(review({ ...base, action_type: "block_ip" }), now).hold).toBeNull();
    expect(timersOf(review({ ...base, remind_every_minutes: 0 }), now).hold).toBeNull();
    expect(timersOf(review({ ...base, remind_every_minutes: null }), now).hold).toBeNull();
    expect(timersOf(review({ ...base, status: "undone" }), now).hold).toBeNull();
    expect(timersOf(review({ ...base, status: "expired" }), now).hold).toBeNull();
    expect(timersOf(review({ ...base, status: "kept" }), now).hold).toEqual({
      minutes: 30,
      due: false,
    });
  });

  it("is not due with no next_remind_at, or an unreadable one", () => {
    const now = at("2026-11-13T14:00:00+00:00");
    const base = { action_type: "disable_user" as const, remind_every_minutes: 10 };
    expect(timersOf(review({ ...base, next_remind_at: null }), now).hold?.due).toBe(false);
    expect(timersOf(review({ ...base, next_remind_at: "soon" }), now).hold?.due).toBe(false);
  });
});

describe("stripControls: bidi and zero-width controls never reach the page", () => {
  const CONTROLS = [
    ...Array.from({ length: 5 }, (_, i) => 0x200b + i), // U+200B-U+200F
    ...Array.from({ length: 5 }, (_, i) => 0x202a + i), // U+202A-U+202E
    ...Array.from({ length: 10 }, (_, i) => 0x2060 + i), // U+2060-U+2069
    0xfeff,
    // the invisible letters and marks of the second review: the Arabic letter mark, the Mongolian vowel separator, the soft
    // hyphen, the Hangul fillers, and the Tag characters (U+E0000-U+E007F, which spell text nobody can see)
    0x061c,
    0x180e,
    0x00ad,
    0x115f,
    0x1160,
    0x3164,
    0xffa0,
    0xe0000,
    0xe0001,
    0xe0041,
    0xe007f,
  ];

  it.each(CONTROLS.map((code) => [code.toString(16).toUpperCase(), code] as const))(
    "removes U+%s",
    (_hex, code) => {
      expect(stripControls(`a${String.fromCodePoint(code)}b`)).toBe("ab");
    },
  );

  it("makes a reversed label plain, and leaves ordinary text alone", () => {
    expect(stripControls("\u202Eetelet\u202C Giữ \u2066chặn\u2069")).toBe("etelet Giữ chặn");
    expect(stripControls("Chặn IP 79.79.78.202 · pfSense ✅ Đã gỡ — #65")).toBe(
      "Chặn IP 79.79.78.202 · pfSense ✅ Đã gỡ — #65",
    );
    expect(stripControls("")).toBe("");
  });

  it("does not touch the code points next to the ranges", () => {
    for (const code of [
      0x200a, 0x2010, 0x2029, 0x202f, 0x205f, 0x206a, 0xfefe, 0xac, 0x61b, 0x115e, 0x1161, 0x3163,
      0xff9f, 0xe0080,
    ]) {
      const text = `a${String.fromCodePoint(code)}b`;
      expect(stripControls(text), code.toString(16)).toBe(text);
    }
  });
});

describe("cleanDeep: every text of what n8n sent, wherever it is", () => {
  it("cleans the strings of nested objects and arrays, and keeps ids, numbers, nulls and the shape", () => {
    const row = {
      id: "K7QM2XHP",
      title: "\u202Ex",
      score: 50,
      note: null,
      simulated: false,
      buttons: [{ decision: "keep", label: "\u200Bgiữ\u200F" }],
      raw: { a: ["\u2066b\u2069", { c: "\uFEFFd" }] },
      related_alerts: [{ alert_id: "a\u200Bb", description: "e\u202Ef" }],
    };
    expect(cleanDeep(row)).toEqual({
      id: "K7QM2XHP",
      title: "x",
      score: 50,
      note: null,
      simulated: false,
      buttons: [{ decision: "keep", label: "giữ" }],
      raw: { a: ["b", { c: "d" }] },
      // an alert id is a key of our own database: it is not touched, so its link still finds the alert
      related_alerts: [{ alert_id: "a\u200Bb", description: "ef" }],
    });
  });

  it("does not change what it is given, and returns what has no text as it is", () => {
    const input = { title: "\u202Ex" };
    cleanDeep(input);
    expect(input.title).toBe("\u202Ex");
    expect(cleanDeep(7)).toBe(7);
    expect(cleanDeep(null)).toBeNull();
    expect(cleanDeep(undefined)).toBeUndefined();
  });
});
