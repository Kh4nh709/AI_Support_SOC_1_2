// src/features/ti/tiSource.test.ts — the shape of the page's own source, read as text: where a link may be made, what may never appear in it, and
// that no invisible character is hiding in it. The behaviour is tested by TiPage.safety.test.tsx; this holds the places it depends on, so a
// later edit that adds an `href` or an HTML sink somewhere else is a red test and not a review remark.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { hasInvisible } from "../../visibleText";

const DIR = join("src", "features", "ti");
const ALL = readdirSync(DIR).filter((name) => /\.(ts|tsx)$/.test(name));
const SOURCES = ALL.filter((name) => !/\.test\./.test(name) && name !== "testkit.tsx");
const read = (name: string): string => readFileSync(join(DIR, name), "utf8");
// Code only: the comments are prose (they name the very things this guard refuses), so they are left out of what is scanned.
const code = (name: string): string =>
  read(name)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");

it("scans the page's own source (a guard over no files would pass for nothing)", () => {
  expect(SOURCES).toEqual(
    expect.arrayContaining([
      "TiPage.tsx",
      "TiTable.tsx",
      "TiDetail.tsx",
      "CopyButton.tsx",
      "Reference.tsx",
      "download.ts",
      "defang.ts",
      "DayChart.tsx",
      "MalwareChart.tsx",
      "ExportControl.tsx",
    ]),
  );
  expect(SOURCES.length).toBeGreaterThan(15);
});

describe("no HTML sink, no way to build markup, no eval", () => {
  const SINKS: Array<[string, RegExp]> = [
    ["innerHTML", /innerHTML/],
    ["outerHTML", /outerHTML/],
    ["dangerouslySetInnerHTML", /dangerouslySetInnerHTML/],
    ["insertAdjacentHTML", /insertAdjacentHTML/],
    ["document.write", /document\s*\.\s*write/],
    ["createContextualFragment", /createContextualFragment/],
    ["DOMParser", /DOMParser/],
    ["srcdoc", /srcdoc/i],
    ["eval(", /\beval\s*\(/],
    ["new Function", /new Function/],
    ["Range", /\bnew Range\b/],
    ["window.open", /window\s*\.\s*open\s*\(/],
    ["location assignment", /\blocation\s*(\.\s*(href|assign|replace)\s*[=(]|\s*=)/],
    ["fetch(", /\bfetch\s*\(/],
    ["XMLHttpRequest", /XMLHttpRequest/],
    ["WebSocket", /WebSocket/],
    ["sendBeacon", /sendBeacon/],
    ["new Image", /new Image\b/],
    ["localStorage", /localStorage/],
  ];
  it.each(SINKS)("has no %s in any non-test file", (_name, pattern) => {
    expect(SOURCES.filter((name) => pattern.test(code(name)))).toEqual([]);
  });
});

describe("a link or a source is made in exactly one place each", () => {
  it("has `href` in Reference.tsx (the reference's link), defang.ts (the address abuseChHref parsed and judged) and download.ts (the object URL of a file), and nowhere else", () => {
    expect(SOURCES.filter((name) => /\bhref\b/.test(code(name))).sort()).toEqual([
      "Reference.tsx",
      "defang.ts",
      "download.ts",
    ]);
    // in defang.ts it is only the address of the URL that was parsed
    expect([...code("defang.ts").matchAll(/\bhref\b/g)]).toHaveLength(1);
    expect(code("defang.ts")).toMatch(/return url\.href;/);
  });

  it("makes an anchor `<a` only in Reference.tsx, and an anchor element only in download.ts", () => {
    expect(SOURCES.filter((name) => /<a[\s>]/.test(code(name)))).toEqual(["Reference.tsx"]);
    expect(SOURCES.filter((name) => /createElement\s*\(/.test(code(name)))).toEqual([
      "download.ts",
    ]);
    expect(code("download.ts")).toMatch(/createElement\("a"\)/);
  });

  it("gives the one link of the page its address from abuseChHref and nothing else", () => {
    const reference = code("Reference.tsx");
    expect([...reference.matchAll(/href=\{([^}]*)\}/g)].map((m) => m[1])).toEqual(["href"]);
    expect(reference).toMatch(/const href = abuseChHref\(reference\)/);
    expect(reference).toMatch(/rel="noopener noreferrer"/);
    expect(reference).toMatch(/target="_blank"/);
  });

  it("names the downloaded file from the format alone (a table), never from a parameter that could be data", () => {
    const download = code("download.ts");
    expect(download).toMatch(/const name = fileNameOf\(format\)/);
    expect(download).toMatch(/link\.download = name/);
    expect([...download.matchAll(/\.download\s*=\s*([^;]*);/g)].map((m) => m[1])).toEqual(["name"]);
    expect(download).toMatch(/TI_EXPORT_FILES\[format\]/);
  });

  it("has no `src`, `srcSet`, `poster`, `action`, `formAction`, `data=` or `ping` attribute, and no image, frame, object, embed, link or script element", () => {
    const ATTRIBUTES = /\b(src|srcSet|poster|action|formAction|ping|xlinkHref)\s*=/;
    const ELEMENTS =
      /<(img|iframe|object|embed|link|script|video|audio|source|picture|base|meta)[\s/>]/;
    expect(SOURCES.filter((name) => ATTRIBUTES.test(code(name)))).toEqual([]);
    expect(SOURCES.filter((name) => ELEMENTS.test(code(name)))).toEqual([]);
  });

  it("makes no `title` attribute out of data (a tooltip would print a value that is not defanged)", () => {
    expect(SOURCES.filter((name) => /\btitle=\{/.test(code(name)))).toEqual([]);
  });
});

describe("an IOC is not the key of anything", () => {
  it("builds no class name by joining a field of an IOC", () => {
    // a class comes from a closed table (FILL, SWATCH) or is written out; a value of the feed is only ever a child
    expect(
      SOURCES.filter((name) =>
        /className=\{`[^`]*\$\{[^}]*(value|malware|threat|reference|tags?)\b/.test(code(name)),
      ),
    ).toEqual([]);
  });
});

describe("no invisible character hides in the code of the page or in its tests", () => {
  it.each(ALL)("%s", (name) => {
    expect(hasInvisible(read(name)), name).toBe(false);
  });

  it("covers the API module and its tests too", () => {
    for (const name of [
      "ti.ts",
      "ti.test.ts",
      "tiContract.test.ts",
      "clientBlob.test.ts",
      "client.ts",
    ]) {
      expect(hasInvisible(readFileSync(join("src", "api", name), "utf8")), name).toBe(false);
    }
  });
});
