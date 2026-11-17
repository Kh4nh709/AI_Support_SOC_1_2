// src/api/tier2Contract.test.ts — the timeline row and the checks of a run of ②, as api/tier2.ts and the page read them, against
// the backend that serves them (backend/app/tier2/investigation_view.py, `present_run`). TypeScript types are erased, so nothing
// else compares the two: a key the backend adds and the type, the fixture or `timelineOf` do not know is a page that quietly
// reads `undefined`; a key the type promises and the backend does not send is one that is never there (DEC-223 added
// `technique_name`, `technique_known` and `checks`). The same way soarContract.test.ts holds the SOAR page to its backend.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { timelineRow } from "../features/tier2/runFixtures";
import { timelineOf } from "../features/tier2/runModel";
import type { RunView } from "./tier2";

const viewPy = readFileSync(join("..", "backend", "app", "tier2", "investigation_view.py"), "utf8");
const tsApi = readFileSync(join("src", "api", "tier2.ts"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\/\/.*$/gm, "");

/** The body of a Python function: from its `def` to the next top-level `def`, `class`, decorator or comment banner. */
function pyFunction(source: string, name: string): string {
  const start = source.indexOf(`def ${name}(`);
  if (start === -1) throw new Error(`no def ${name}`);
  const rest = source.slice(start + 1);
  const end = rest.search(/\n(?:def |class |@|# ──|# -{5})/);
  return end === -1 ? rest : rest.slice(0, end);
}

/** The quoted keys at the top of the literal that `present_run` builds under `"name": ` (`[` or `{`), up to `until`. */
function servedKeys(name: string, open: string, until: string): string[] {
  const body = pyFunction(viewPy, "present_run");
  const start = body.indexOf(`"${name}": ${open}`);
  if (start === -1) throw new Error(`no "${name}" in present_run`);
  const end = body.indexOf(until, start);
  if (end === -1) throw new Error(`no ${until} after "${name}" in present_run`);
  return [...body.slice(start + name.length + 4, end).matchAll(/^\s*"(\w+)":/gm)].map(
    (m) => m[1] as string,
  );
}

/** The property names of the type `name` of api/tier2.ts, or of a literal type written after `prop:` inside it. */
function tsProps(name: string, prop?: string): string[] {
  let from = tsApi.indexOf(`export type ${name} =`);
  if (from === -1) throw new Error(`no type ${name}`);
  if (prop !== undefined) from = tsApi.indexOf(`${prop}?: {`, from);
  const open = tsApi.indexOf("{", from);
  let depth = 0;
  let close = open;
  for (let i = open; i < tsApi.length; i += 1) {
    if (tsApi[i] === "{") depth += 1;
    if (tsApi[i] === "}" && --depth === 0) {
      close = i;
      break;
    }
  }
  const keys: string[] = [];
  let level = 0;
  for (const line of tsApi.slice(open + 1, close).split("\n")) {
    if (level === 0) {
      const found = /^\s*(\w+)\??:/.exec(line);
      if (found !== null) keys.push(found[1] as string);
    }
    level += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
  }
  return keys;
}

const sorted = (words: readonly string[]): string[] => [...words].sort();

describe("a served timeline row", () => {
  const served = servedKeys("timeline", "[", "for (entry, time)");

  it("reads the backend (a guard over nothing would pass for nothing)", () => {
    expect(served).toEqual(
      expect.arrayContaining(["alert_id", "time", "what", "tactic", "technique"]),
    );
  });

  it("carries, beside the model's own words, the server's check of the technique against the local ATT&CK document", () => {
    expect(served).toEqual([
      "alert_id",
      "time",
      "what",
      "tactic",
      "technique",
      "technique_name",
      "technique_known",
    ]);
  });

  it("has exactly the keys of the TypeScript type TimelineRow", () => {
    expect(sorted(tsProps("TimelineRow"))).toEqual(sorted(served));
  });

  it("has exactly the keys of the fixture the tests serve", () => {
    expect(sorted(Object.keys(timelineRow()))).toEqual(sorted(served));
  });

  it("is read by timelineOf with every one of those keys", () => {
    const run = { run_id: "r", created_at: null, result: null, timeline: [timelineRow()] };
    const [row] = timelineOf(run as RunView);
    expect(sorted(Object.keys(row ?? {}))).toEqual(sorted(served));
  });
});

describe("the checks of a served run", () => {
  const served = servedKeys("checks", "{", "}");

  it("is the one count of timeline rows whose technique the local document does not hold", () => {
    expect(served).toEqual(["technique_not_in_reference"]);
  });

  it("has exactly the keys of the TypeScript type of RunView.checks", () => {
    expect(sorted(tsProps("RunView", "checks"))).toEqual(sorted(served));
  });
});
