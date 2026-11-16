// src/guards.test.ts — the security guards of the spec §6
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
const files = (d: string): string[] =>
  readdirSync(d).flatMap((f) => {
    const p = join(d, f);
    return statSync(p).isDirectory()
      ? files(p)
      : /\.(ts|tsx)$/.test(p) && !/\.test\./.test(p)
        ? [p]
        : [];
  });
const src = files("src").map((p) => [p, readFileSync(p, "utf8")] as const);

it("scans the non-test source (a guard over no files would pass for nothing)", () => {
  const scanned = src.map(([p]) => p);
  expect(scanned).toContain(join("src", "app.tsx"));
  expect(scanned).toContain(join("src", "format.ts"));
  expect(scanned).toContain(join("src", "strings.ts"));
  expect(scanned.some((p) => /\.test\./.test(p))).toBe(false);
});

it("scans the admin console too, so its zero count of dangerouslySetInnerHTML is a count and not a gap", () => {
  const scanned = src.map(([p]) => p);
  for (const name of ["AdminLayout.tsx", "ConfirmDialog.tsx", "adminKeys.ts", "UsersPage.tsx"]) {
    expect(scanned).toContain(join("src", "features", "admin", name));
  }
  expect(scanned).toContain(join("src", "api", "admin.ts"));
});

// A call of `eval`, not any identifier that ends in it: `retrieval(` is not a call of eval.
const EVAL_CALL = /\beval\s*\(/;

it("matches a call of eval and nothing that merely ends in it", () => {
  for (const call of ["eval(x)", "eval (x)", "window.eval('1')", "x = eval(\n)"]) {
    expect(EVAL_CALL.test(call), call).toBe(true);
  }
  for (const other of ["retrieval(x)", "medieval(1)", "my_eval(x)", "evaluate(x)", "evalue"]) {
    expect(EVAL_CALL.test(other), other).toBe(false);
  }
});

// Ruling R5: `localStorage` never appears in non-test source, comments included. The token
// lives in memory, sessionStorage and a BroadcastChannel only (spec §3).
//
// One file is let through, by its exact path (SR-T2, the Owner's own list for the page "Phản hồi SOAR": the new-ticket
// signal's switch and the dismissed notices "live in localStorage"). It holds two non-secret preferences and nothing of
// the session; the tests below read it to prove that, and prove no other file of src/ is let through.
const LOCAL_STORAGE_HOME = join("src", "features", "soar", "storage.ts");
const NEEDLES: [string, (text: string) => boolean][] = [
  ["dangerouslySetInnerHTML", (t) => t.includes("dangerouslySetInnerHTML")],
  ["eval(", (t) => EVAL_CALL.test(t)],
  ["new Function", (t) => t.includes("new Function")],
  ["localStorage", (t) => t.includes("localStorage")],
  // P11-T10: the admin console is in the app; no link leaves for the API port (the old Jinja console).
  [":8000", (t) => t.includes(":8000")],
  ["adminLegacy", (t) => t.includes("adminLegacy")],
];

it.each(NEEDLES)("no %s in src", (name, found) => {
  expect(
    src
      .filter(([p, t]) => found(t) && !(name === "localStorage" && p === LOCAL_STORAGE_HOME))
      .map(([p]) => p),
  ).toEqual([]);
});

// The one file that may name `localStorage`, held to what it is for. It was let through by its path, and three loose tests
// read it; a generic writer added to it passed them all. So the file is held to its exact shape: its code names
// `localStorage` in four fixed calls on two fixed keys and nowhere else, its exports are a list, the files that import it are
// a list (with the names they take), and what it keeps of the dismissed notices is the shape of a notice id. Each rule is a
// function of the SOURCE TEXT, so the tests below also run it on mutated copies of the real file (never on the real file) and
// see every mutation fail.
const STORAGE_EXPORTS = [
  "DISMISSED_CAP",
  "DISMISSED_KEY",
  "NOTICE_ID",
  "SIGNAL_KEY",
  "readDismissed",
  "readSignalOn",
  "writeDismissed",
  "writeSignalOn",
];
const STORAGE_CALLS = [
  "getItem(DISMISSED_KEY)",
  "getItem(SIGNAL_KEY)",
  "setItem(DISMISSED_KEY)",
  "setItem(SIGNAL_KEY)",
];
/** Every string literal of the file: the two keys, the two values of the flag, and a type name. */
const STORAGE_STRINGS = ["0", "1", "soc.soar.dismissed", "soc.soar.signal", "string"];
const STORAGE_IMPORTERS: Record<string, string[]> = {
  [join("src", "features", "soar", "SignalSwitch.tsx")]: ["readSignalOn"],
  [join("src", "features", "soar", "SoarPage.tsx")]: ["readDismissed", "writeDismissed"],
  [join("src", "features", "soar", "signal.ts")]: ["readSignalOn", "writeSignalOn"],
};
/** The shape of the id of a notice (spec section 2): N and twelve letters, digits, `_` or `-`. */
const NOTICE_ID_SOURCE = "NOTICE_ID = /^N[A-Za-z0-9_-]{12}$/";

/** The code of a source with its comments taken out, so a comment that quotes a word is not a use of it. */
const codeOf = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

/** What is wrong with the source of the one file that may name `localStorage`; `[]` when nothing is. */
function storageFaults(source: string): string[] {
  const code = codeOf(source);
  const faults: string[] = [];
  const names = code.match(/localStorage/g) ?? [];
  if (names.length !== 4) faults.push(`names localStorage ${names.length} times, not 4`);
  const calls = [...code.matchAll(/localStorage\.(getItem|setItem)\((SIGNAL_KEY|DISMISSED_KEY)\b/g)]
    .map((m) => `${m[1]}(${m[2]})`)
    .sort();
  if (calls.join() !== STORAGE_CALLS.join()) faults.push(`calls ${calls.join() || "none"}`);
  // no way round the four calls: a window, a global, a computed name, an eval, the Storage prototype, an import
  if (
    /\b(window|globalThis|self|top|parent|document|Reflect|eval|Function|require)\b|(?<!local)Storage\b|\bimport\b/.test(
      code,
    )
  ) {
    faults.push("reaches the store, or another module, some other way");
  }
  if (/token|session|password|auth/i.test(code)) faults.push("names the session");
  const keys = [...code.matchAll(/\b(?:SIGNAL_KEY|DISMISSED_KEY)\s*=\s*"([^"]*)"/g)]
    .map((m) => m[1])
    .sort();
  if (keys.join() !== ["soc.soar.dismissed", "soc.soar.signal"].join()) {
    faults.push(`keys ${keys.join()}`);
  }
  const exported = [
    ...code.matchAll(
      /^export\s+(?:async\s+)?(?:const|let|var|function|class|type|interface|enum)\s+(\w+)/gm,
    ),
  ]
    .map((m) => m[1])
    .sort();
  if (exported.join() !== STORAGE_EXPORTS.join() || /^export\s*(\*|\{|default)/m.test(code)) {
    faults.push(`exports ${exported.join()}`);
  }
  // every string of the code is one of a fixed list (no third key, no name built from parts), and no other quote form is used
  const strings = [...new Set([...code.matchAll(/"([^"\n]*)"/g)].map((m) => m[1]))].sort();
  if (strings.join() !== STORAGE_STRINGS.join() || /['`]/.test(code)) {
    faults.push(`strings ${strings.join()}`);
  }
  if (!code.includes(NOTICE_ID_SOURCE)) faults.push("the shape of a notice id is not pinned");
  return faults;
}

type Sources = readonly (readonly [string, string])[];

/** Which files import the storage module, and the names each takes (`*` for any other way of importing it). */
function importersOf(sources: Sources): Record<string, string[]> {
  const home = join("src", "features", "soar", "storage");
  const found: Record<string, string[]> = {};
  for (const [path, text] of sources) {
    const code = codeOf(text);
    const from = [
      ...code.matchAll(/\b(?:import|export)\s+(?:type\s+)?([^;"']*?)\s*from\s*["']([^"']+)["']/g),
    ].map((m) => [m[1] ?? "", m[2] ?? ""] as const);
    const bare = [...code.matchAll(/\bimport\s*\(?\s*["']([^"']+)["']/g)].map(
      (m) => ["*", m[1] ?? ""] as const,
    );
    for (const [clause, specifier] of [...from, ...bare]) {
      if (!specifier.startsWith(".")) continue;
      const target = join(dirname(path), specifier).replace(/\.(tsx?|js)$/, "");
      if (target !== home) continue;
      const braces = /^\{([^}]*)\}$/.exec(clause.trim().replace(/^type\s+/, ""));
      const names =
        braces === null
          ? ["*"]
          : (braces[1] ?? "")
              .split(",")
              .map((n) =>
                n
                  .trim()
                  .replace(/^type\s+/, "")
                  .replace(/\s+as\s+\w+$/, ""),
              )
              .filter((n) => n !== "");
      found[path] = [...(found[path] ?? []), ...names].sort();
    }
  }
  return found;
}

/** What is wrong with the list of files that import the storage module; `[]` when it is the pinned one. */
function importerFaults(sources: Sources): string[] {
  const found = importersOf(sources);
  const faults: string[] = [];
  for (const [path, names] of Object.entries(found)) {
    const allowed = STORAGE_IMPORTERS[path];
    if (allowed === undefined) faults.push(`${path} imports it`);
    else if (names.join() !== [...allowed].sort().join())
      faults.push(`${path} takes ${names.join()}`);
  }
  for (const path of Object.keys(STORAGE_IMPORTERS)) {
    if (!(path in found)) faults.push(`${path} no longer imports it`);
  }
  return faults;
}

describe("the one file that may name localStorage", () => {
  const home = src.find(([p]) => p === LOCAL_STORAGE_HOME)?.[1] ?? "";

  it("is scanned, and is the only source file that names it", () => {
    expect(home).not.toBe("");
    expect(src.filter(([, t]) => t.includes("localStorage")).map(([p]) => p)).toEqual([
      LOCAL_STORAGE_HOME,
    ]);
  });

  it("names it in four fixed calls on two fixed keys, exports exactly its list, and has nothing else of the store", () => {
    expect(storageFaults(home)).toEqual([]);
    expect(codeOf(home).match(/localStorage/g)).toHaveLength(4);
  });

  it("is imported by exactly the files that need it, for exactly the names they need", () => {
    expect(importerFaults(src)).toEqual([]);
    expect(Object.keys(importersOf(src)).sort()).toEqual(Object.keys(STORAGE_IMPORTERS).sort());
  });

  it("is not imported by the session, the auth code or the API client", () => {
    const owners = src.filter(([p]) => /^src[\\/](auth|api)[\\/]/.test(p));
    expect(owners.length).toBeGreaterThan(5);
    expect(owners.filter(([, t]) => /features[\\/]soar|soar[\\/]storage/.test(t))).toEqual([]);
  });

  // The mutations, run on copies of the text and never on the file: each is what a careless change would be, and each fails.
  describe.each<[string, (text: string) => string]>([
    [
      "a generic writer",
      (t) =>
        `${t}\nexport function put(key: string, value: string): void {\n  try {\n    localStorage.setItem(key, value);\n  } catch {\n    // nothing\n  }\n}\n`,
    ],
    ["a bracket access", (t) => `${t}\nconst peek = (k: string) => localStorage[k];\n`],
    ["an alias", (t) => `${t}\nconst store = localStorage;\n`],
    [
      "window.localStorage",
      (t) =>
        t.replace("localStorage.getItem(SIGNAL_KEY)", "window.localStorage.getItem(SIGNAL_KEY)"),
    ],
    ["a computed global", (t) => `${t}\nconst g = globalThis["local" + "Storage"];\n`],
    ["an eval", (t) => `${t}\nconst h = (0, eval)("local" + "Storage");\n`],
    [
      "a call on another key",
      (t) => t.replace("localStorage.setItem(SIGNAL_KEY", 'localStorage.setItem("soc.session"'),
    ],
    [
      "a third key",
      (t) => t.replace('"soc.soar.signal"', '"soc.soar.signal"; const OTHER_KEY = "soc.x"'),
    ],
    ["a new export", (t) => `${t}\nexport const extra = 1;\n`],
    ["a re-export", (t) => `${t}\nexport * from "./signal";\n`],
    ["an import of the session", (t) => `import { loadSession } from "../../auth/session";\n${t}`],
    ["a word of the session", (t) => `${t}\nconst bearer = "token";\n`],
    ["a relaxed notice id", (t) => t.replace("/^N[A-Za-z0-9_-]{12}$/", "/^.{1,64}$/")],
    [
      "a removed export",
      (t) => t.replace("export function writeSignalOn", "function writeSignalOn"),
    ],
  ])("a mutation of the file, %s", (_name, mutate) => {
    it("is found", () => {
      const mutated = mutate(home);
      expect(mutated).not.toBe(home);
      expect(storageFaults(mutated)).not.toEqual([]);
    });
  });

  const SWITCH = join("src", "features", "soar", "SignalSwitch.tsx");
  describe.each<[string, Sources]>([
    [
      "the session imports it",
      [
        ...src,
        [
          join("src", "auth", "AuthProvider.tsx"),
          'import { readDismissed } from "../features/soar/storage";',
        ],
      ],
    ],
    [
      "the API client imports it",
      [
        ...src,
        [
          join("src", "api", "client.ts"),
          'import { writeDismissed } from "../features/soar/storage";',
        ],
      ],
    ],
    [
      "a new page imports it",
      [
        ...src,
        [join("src", "features", "soar", "Elsewhere.tsx"), 'import * as store from "./storage";'],
      ],
    ],
    [
      "a lazy import of it",
      [
        ...src,
        [join("src", "features", "admin", "Lazy.tsx"), 'const m = import("../soar/storage");'],
      ],
    ],
    [
      "a re-export of it",
      [
        ...src,
        [join("src", "features", "soar", "again.ts"), 'export { readSignalOn } from "./storage";'],
      ],
    ],
    [
      "an importer takes one name more",
      src.map(
        ([p, t]) =>
          [
            p,
            p === SWITCH
              ? t.replace("import { readSignalOn }", "import { readSignalOn, writeSignalOn }")
              : t,
          ] as const,
      ),
    ],
    [
      "an importer stops importing it",
      src.filter(([p]) => p !== join("src", "features", "soar", "signal.ts")),
    ],
  ])("a mutation of the importers, %s", (_name, mutated) => {
    it("is found", () => {
      expect(importerFaults(mutated)).not.toEqual([]);
    });
  });
});

// P10-T13 deleted the Jinja pages. A comment that still cites one of their modules points a reader at a
// file that is not there; the words they carried are the UI's own now (`strings.ts`), and the tables the
// UI follows have their homes in `backend/app/tier1` and `backend/app/tier2`.
const DELETED_MODULES = ["alerts_pages", "cases_pages", "case_analyze_pages"];

it.each(DELETED_MODULES)("cites no %s, a Jinja module that no longer exists", (name) => {
  expect(src.filter(([, t]) => t.includes(name)).map(([p]) => p)).toEqual([]);
});
