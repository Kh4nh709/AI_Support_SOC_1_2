// src/features/admin/labModel.test.ts — the pure parts of the lab pages (P14-T10): the time the form takes and
// sends, what the form checks before it posts, the counter after a label, and the words of a refusal.
import type { InfiniteData } from "@tanstack/react-query";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  LAB_FIELDS,
  LAB_FIELD_REASONS,
  LAB_LABELS,
  LAB_PURPOSES,
  type LabAlert,
  type LabAlertsResponse,
} from "../../api/admin";
import { DISPLAY_TZ, formatDateTime } from "../../format";
import { S } from "../../strings";
import {
  DISPLAY_OFFSET,
  checkNewRun,
  isNewRunField,
  labFieldText,
  labRowErrorText,
  localInputToIso,
  newRunBody,
  withLabel,
  type NewRunValues,
} from "./labModel";

describe("the time the form takes", () => {
  it("is the console's own zone, +07:00, the zone every time on the console is shown in", () => {
    expect(DISPLAY_TZ).toBe("Asia/Ho_Chi_Minh");
    // Pinned to the zone itself and not to a number written twice: the offset Intl gives for it.
    const offset = new Intl.DateTimeFormat("en", {
      timeZone: DISPLAY_TZ,
      timeZoneName: "longOffset",
    })
      .formatToParts(new Date("2026-11-04T00:00:00Z"))
      .find((part) => part.type === "timeZoneName")?.value;
    expect(offset).toBe(`GMT${DISPLAY_OFFSET}`);
  });

  it("reads a minute-precision value and sends it with the offset", () => {
    expect(localInputToIso("2026-11-04T09:30")).toBe("2026-11-04T09:30:00+07:00");
  });

  it("reads a value that has seconds and sends them", () => {
    expect(localInputToIso("2026-11-04T09:30:45")).toBe("2026-11-04T09:30:45+07:00");
  });

  it("keeps the milliseconds some engines add to a time that has seconds", () => {
    expect(localInputToIso("2026-11-04T09:30:45.000")).toBe("2026-11-04T09:30:45.000+07:00");
    expect(localInputToIso("2026-11-04T09:30:45.250")).toBe("2026-11-04T09:30:45.250+07:00");
    // but not a fraction of any other length, nor one after a time with no seconds
    expect(localInputToIso("2026-11-04T09:30:45.5")).toBeNull();
    expect(localInputToIso("2026-11-04T09:30.000")).toBeNull();
  });

  it("is the same instant the console shows back, whatever zone the browser is in", () => {
    // formatDateTime shows Asia/Ho_Chi_Minh: what was typed comes back as typed.
    const iso = localInputToIso("2026-11-04T23:59:30");
    expect(iso).not.toBeNull();
    expect(formatDateTime(iso)).toBe("04/11/2026 23:59:30");
    // and it is 16:59:30 UTC, the instant the server stores
    expect(new Date(iso ?? "").toISOString()).toBe("2026-11-04T16:59:30.000Z");
  });

  it.each(["", "   ", "2026-11-04", "09:30", "2026-11-04 09:30", "2026-13-04T09:30", "not a time"])(
    "reads %j as nothing",
    (value) => {
      expect(localInputToIso(value)).toBeNull();
    },
  );

  it("reads a five-digit year, which a browser can hold, as nothing rather than as another year", () => {
    expect(localInputToIso("12345-01-01T00:00")).toBeNull();
  });
});

describe("what the create form checks before it posts", () => {
  const good: NewRunValues = {
    name: "Lần chạy 1",
    purpose: "test",
    starts: "2026-11-04T09:00",
    ends: "2026-11-04T11:00",
  };

  it("finds nothing wrong with a complete run", () => {
    expect(checkNewRun(good)).toEqual({});
  });

  it("asks for each of the four inputs", () => {
    expect(checkNewRun({ name: "", purpose: null, starts: "", ends: "" })).toEqual({
      name: "empty",
      purpose: "required",
      starts_at: "required",
      ends_at: "required",
    });
  });

  it("takes a name that is only white space for an empty one", () => {
    expect(checkNewRun({ ...good, name: " \t " })).toEqual({ name: "empty" });
  });

  it("counts a name in characters, as the server does, and allows exactly the longest", () => {
    expect(checkNewRun({ ...good, name: "a".repeat(80) })).toEqual({});
    expect(checkNewRun({ ...good, name: "a".repeat(81) })).toEqual({ name: "too_long" });
    // 80 characters that are two UTF-16 units each (a letter outside the BMP) are still 80
    expect(checkNewRun({ ...good, name: "\u{1D400}".repeat(80) })).toEqual({});
    // the length is that of the name once trimmed, which is what the server measures
    expect(checkNewRun({ ...good, name: ` ${"a".repeat(80)} ` })).toEqual({});
  });

  it("calls a time the browser cannot give a value for invalid, and an empty one required", () => {
    expect(checkNewRun({ ...good, starts: "2026-11-04", ends: "" })).toEqual({
      starts_at: "invalid",
      ends_at: "required",
    });
  });

  it("does not judge the order of the two times: that is the server's answer, not_after_starts", () => {
    expect(checkNewRun({ ...good, starts: "2026-11-04T11:00", ends: "2026-11-04T09:00" })).toEqual(
      {},
    );
  });

  it("names the four inputs by the field the server names them with", () => {
    expect(["name", "purpose", "starts_at", "ends_at"].every((f) => isNewRunField(f))).toBe(true);
    expect(isNewRunField("body")).toBe(false);
    expect(isNewRunField("label")).toBe(false);
    expect(isNewRunField("constructor")).toBe(false);
  });
});

describe("the body of the create call", () => {
  it("is the trimmed name, the purpose and the two times with the offset", () => {
    expect(
      newRunBody({
        name: "  Lần chạy 1 ",
        purpose: "kb",
        starts: "2026-11-04T09:00",
        ends: "2026-11-04T11:00:30",
      }),
    ).toEqual({
      name: "Lần chạy 1",
      purpose: "kb",
      starts_at: "2026-11-04T09:00:00+07:00",
      ends_at: "2026-11-04T11:00:30+07:00",
    });
  });

  it("is nothing for a run that is not complete", () => {
    expect(
      newRunBody({
        name: "x",
        purpose: null,
        starts: "2026-11-04T09:00",
        ends: "2026-11-04T10:00",
      }),
    ).toBeNull();
    expect(
      newRunBody({ name: "x", purpose: "kb", starts: "", ends: "2026-11-04T10:00" }),
    ).toBeNull();
    expect(
      newRunBody({ name: "x", purpose: "kb", starts: "2026-11-04T09:00", ends: "nope" }),
    ).toBeNull();
  });
});

describe("the words of a 422 beside its field", () => {
  const text = (field: (typeof LAB_FIELDS)[number], reason: (typeof LAB_FIELD_REASONS)[number]) =>
    labFieldText(field, reason);

  it("has a Vietnamese text for every field and reason pair, and none of them is a code", () => {
    for (const field of LAB_FIELDS) {
      for (const reason of LAB_FIELD_REASONS) {
        const shown = text(field, reason);
        expect(shown.trim(), `${field}/${reason}`).not.toBe("");
        for (const code of [...LAB_FIELD_REASONS, ...LAB_FIELDS, "not_after_starts"]) {
          expect(shown, `${field}/${reason}`).not.toContain(code);
        }
      }
    }
  });

  it("says in its own words that the name is in use, that the end is not after the start, that a name is too long", () => {
    expect(text("name", "taken")).toBe(S.admin.lab.fieldReason.taken);
    expect(text("ends_at", "not_after_starts")).toBe(S.admin.lab.fieldReason.not_after_starts);
    expect(text("name", "too_long")).toContain("80");
  });

  it("words `invalid` of a time with the years the server allows, and of the others without them", () => {
    for (const field of ["starts_at", "ends_at"] as const) {
      expect(text(field, "invalid")).toContain("2000");
      expect(text(field, "invalid")).toContain("2099");
    }
    expect(text("name", "invalid")).not.toContain("2099");
    expect(text("purpose", "invalid")).not.toContain("2099");
  });
});

describe("the words of a refused label, on its row", () => {
  const R = S.admin.lab.runPage.rowError;

  it("words the two 409s and the 404 of the label routes", () => {
    expect(labRowErrorText({ kind: "not_a_queue_head", status: 409 })).toBe(R.not_a_queue_head);
    expect(labRowErrorText({ kind: "outside_every_run", status: 409 })).toBe(R.outside_every_run);
    expect(labRowErrorText({ kind: "not_found", status: 404 })).toBe(R.not_found);
  });

  it("words a 422 on the label, and says the console's generic text for anything else", () => {
    expect(labRowErrorText({ kind: "field", status: 422, field: "label", reason: "invalid" })).toBe(
      S.admin.lab.fieldReason.invalidLabel,
    );
    for (const refusal of [
      { kind: "overlap", status: 409 },
      { kind: "other", status: 500 },
      { kind: "other", status: 0 },
      { kind: "field", status: 422, field: "name", reason: "taken" },
    ] as const) {
      expect(labRowErrorText(refusal)).toBe(S.common.unknownError);
    }
  });

  it("shows no code in any of them", () => {
    for (const text of [R.not_a_queue_head, R.outside_every_run, R.not_found]) {
      expect(text).not.toMatch(/not_a_queue_head|outside_every_run|not_found/);
    }
  });
});

describe("withLabel, the counter after a label", () => {
  const alert = (id: string, label: LabAlert["label"]): LabAlert => ({
    alert_id: id,
    received_at: "2026-11-04T02:00:00Z",
    alert_time: "2026-11-04T02:00:00Z",
    rule_id: "99001",
    rule_level: 5,
    severity: "medium",
    description: `mô tả ${id}`,
    agent_name: "host-1",
    alert_user: null,
    srcip: "10.0.0.1",
    dstip: "10.0.0.2",
    category: "c",
    mitre_ids: [],
    occurrence_count: 1,
    raw_log: "log",
    raw_log_truncated_for_display: false,
    label,
  });
  const run = {
    run_id: "r",
    name: "n",
    purpose: "test",
    starts_at: "s",
    ends_at: "e",
    total: 4,
    labelled: 1,
  } as const;
  const data = (): InfiniteData<LabAlertsResponse, string | null> => ({
    pageParams: [null, "a2"],
    pages: [
      { run, alerts: [alert("a1", "true_positive"), alert("a2", null)], next_after: "a2" },
      {
        run: { ...run, labelled: 99 },
        alerts: [alert("a3", null), alert("a4", null)],
        next_after: null,
      },
    ],
  });
  const labelled = (d: InfiniteData<LabAlertsResponse, string | null>) => d.pages[0]?.run.labelled;
  const labelOf = (d: InfiniteData<LabAlertsResponse, string | null>, id: string) =>
    d.pages.flatMap((p) => p.alerts).find((a) => a.alert_id === id)?.label;

  it("counts one more when an alert that had no label gets one, and sets the label on its row", () => {
    const next = withLabel(data(), "a2", "false_positive");
    expect(labelled(next)).toBe(2);
    expect(labelOf(next, "a2")).toBe("false_positive");
  });

  it("finds the alert on a later page, and counts it in the run of the first page", () => {
    const next = withLabel(data(), "a4", "true_positive");
    expect(labelled(next)).toBe(2);
    expect(labelOf(next, "a4")).toBe("true_positive");
    // the later page's own copy of the run is not what the counter reads
    expect(next.pages[1]?.run.labelled).toBe(99);
  });

  it("counts nothing more when a label is changed to the other one", () => {
    const next = withLabel(data(), "a1", "false_positive");
    expect(labelled(next)).toBe(1);
    expect(labelOf(next, "a1")).toBe("false_positive");
  });

  it("counts one less when a label is cleared, and leaves the row with none", () => {
    const next = withLabel(data(), "a1", null);
    expect(labelled(next)).toBe(0);
    expect(labelOf(next, "a1")).toBeNull();
  });

  it("counts nothing for clearing what was not there, or for setting what already was", () => {
    expect(labelled(withLabel(data(), "a2", null))).toBe(1);
    expect(labelled(withLabel(data(), "a1", "true_positive"))).toBe(1);
  });

  it("never goes below none, whatever the counter held", () => {
    const odd = data();
    if (odd.pages[0] !== undefined) odd.pages[0].run = { ...run, labelled: 0 };
    expect(labelled(withLabel(odd, "a1", null))).toBe(0);
  });

  it("leaves the data as it was for an alert it does not hold", () => {
    const before = data();
    expect(withLabel(before, "nowhere", "true_positive")).toBe(before);
  });

  it("returns new data and does not change the data it was given", () => {
    const before = data();
    const next = withLabel(before, "a2", "true_positive");
    expect(next).not.toBe(before);
    expect(labelled(before)).toBe(1);
    expect(labelOf(before, "a2")).toBeNull();
    // a page that held nothing of the alert, and is not the one that counts, is the same object
    expect(next.pages[1]).toBe(before.pages[1]);
    expect(next.pageParams).toEqual(before.pageParams);
  });
});

// Fix round 1, M5: a word nobody reads is a word nobody keeps equal to the page (`fieldReason.invalid` and
// `runPage.route` were two). Every string, and every function that makes one, of the three blocks the lab pages read
// is read somewhere in their source as `.name` or `["name"]`; the names of the two tables that are indexed by a
// vocabulary (the labels, the purposes) are read by that vocabulary. The check goes by name, not by path: a name that
// two blocks share is found if either is read.
describe("the words of the lab pages", () => {
  const SOURCES = [
    "labModel.ts",
    "LabRunsPage.tsx",
    "LabRunCreatePanel.tsx",
    "LabRunPage.tsx",
    "LabAlertRow.tsx",
  ];
  const code = SOURCES.map((name) =>
    readFileSync(join("src", "features", "admin", name), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, ""),
  ).join("\n");
  const DYNAMIC = new Set<string>([...LAB_LABELS, ...LAB_PURPOSES]);

  /** The names of the strings and of the functions that make one, at any depth. */
  function names(value: unknown, skip: ReadonlySet<string> = new Set()): string[] {
    if (typeof value !== "object" || value === null) return [];
    return Object.entries(value).flatMap(([name, item]) => {
      if (skip.has(name)) return [];
      return typeof item === "object" ? names(item, skip) : [name];
    });
  }
  const lab = S.admin.lab;
  const NAMES = [
    ...names(lab.fieldReason),
    ...names(lab.runsPage, new Set(["purposeHelp"])),
    ...names(lab.runPage),
  ];

  it("reads a name in each of three blocks (a check over no names would pass for nothing)", () => {
    expect(NAMES.length).toBeGreaterThan(30);
    expect(code.length).toBeGreaterThan(5000);
    expect(NAMES).toContain("invalidTime");
    expect(NAMES).toContain("loadMore");
  });

  it.each(NAMES)("%s is read by a page", (name) => {
    const read = new RegExp(`\\.${name}\\b|\\[["']${name}["']\\]`).test(code);
    expect(read || DYNAMIC.has(name), `S.admin.lab: nothing reads ${name}`).toBe(true);
  });

  it("finds the two that were left unused, if they come back", () => {
    for (const unused of ["route", "invalid"]) {
      expect(new RegExp(`\\.${unused}\\b|\\[["']${unused}["']\\]`).test(code), unused).toBe(false);
    }
    expect(Object.keys(lab.fieldReason)).not.toContain("invalid");
    expect(Object.keys(lab.runPage)).not.toContain("route");
  });

  it("holds a text for every purpose and every label of the backend's vocabularies", () => {
    expect(Object.keys(lab.purpose).sort()).toEqual([...LAB_PURPOSES].sort());
    expect(Object.keys(lab.runsPage.create.purposeHelp).sort()).toEqual([...LAB_PURPOSES].sort());
    expect(Object.keys(lab.label).sort()).toEqual([...LAB_LABELS, "none"].sort());
    for (const label of LAB_LABELS) expect(lab.runPage.action[label]).toBeTruthy();
  });
});
