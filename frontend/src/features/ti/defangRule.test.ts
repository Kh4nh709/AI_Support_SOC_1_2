// src/features/ti/defangRule.test.ts — the invariants of `defang` (TI12), as the review measured them and as a generated corpus holds them: a
// value that is a URL, a name or an address in ANY of the shapes a browser reads leaves no live host behind, whatever its type says; the rule
// is its own fixed point; and it takes time in proportion to the value. Every value is made up (documentation ranges, example.* names).
import { defang } from "./defang";

const DOT_CHARS = /[.\u3002\uff0e\uff61]/;
/** The text with every bracketed dot taken out: what is left of it has no dot that is not defanged. */
const unbracketedDot = (text: string): boolean => DOT_CHARS.test(text.replaceAll("[.]", ""));
/** The part of a value a type `url` or `domain` must have no dot in: up to its first `/`, `?` or `#`. */
const head = (text: string): string => {
  const at = text.search(/[/?#]/);
  return at === -1 ? text : text.slice(0, at);
};
/**
 * The authorities of an output, found the way the rule defines them and not the way it is written: what follows a scheme-relative start,
 * a scheme and two or more slashes, or a special scheme and any slashes, up to the next / \ ? # or white space.
 */
function authorities(out: string): string[] {
  const found: string[] = [];
  const lead = /^[/\\]{2,}([^/\\?#]*)/.exec(out);
  if (lead !== null) found.push(lead[1] as string);
  for (const m of out.matchAll(/[A-Za-z][A-Za-z0-9+-]*:[/\\]{2,}([^/\\?#]*)/g))
    found.push(m[1] as string);
  for (const m of out.matchAll(
    /(?<![A-Za-z0-9+-])(?:hxxps?|fxps?|https?|ftps?|wss?|file):[/\\]*([^/\\?#]*)/gi,
  ))
    found.push(m[1] as string);
  return found;
}
const SPECIAL = new Set(["http:", "https:", "ftp:", "ws:", "wss:", "file:"]);
/** Whether WHATWG `new URL` reads the text as a URL of a special scheme with a host. */
function live(text: string): boolean {
  try {
    const url = new URL(text);
    return SPECIAL.has(url.protocol) && url.hostname !== "";
  } catch {
    return false;
  }
}
/** The property of the review: no output is a live URL, and none is one when it is read after `http:` (a scheme-relative value). */
const isLiveAsIs = (out: string): boolean =>
  live(out) || (/^[/\\]{2}/.test(out) && live(`http:${out}`));
/** And the same after the white space at the edges is trimmed (a browser skips it; so does a chat that links what it finds). */
const isLive = (out: string): boolean => isLiveAsIs(out) || isLiveAsIs(out.trim());

describe("the cases the review measured (TI12 I1, M1, M2)", () => {
  // [value, type, what it was before: raw host or wrong, output]
  const CASES: Array<[string, string, string]> = [
    // an embedded scheme no longer short-circuits the value
    ["evil.com?http://x", "domain", "evil[.]com?hxxp://x"],
    ["evil.com/r?u=http://x.org", "url", "evil[.]com/r?u=hxxp://x[.]org"],
    ["ws://evil.com/?q=http://x", "url", "ws://evil[.]com/?q=hxxp://x"],
    ["ws://evil.com/x", "url", "ws://evil[.]com/x"],
    ["//evil.com/http://x", "url", "//evil[.]com/hxxp://x"],
    // an empty authority is skipped to the next non-slash run, as a browser does
    ["http:///evil.com/x", "url", "hxxp:///evil[.]com/x"],
    ["http:\\\\evil.com\\x", "url", "hxxp:\\\\evil[.]com\\x"],
    ["http:evil.com", "url", "hxxp:evil[.]com"],
    ["HTTP:evil.com", "url", "HxxP:evil[.]com"],
    ["file:///evil.com/x", "url", "file:///evil[.]com/x"],
    // a name is not an IPv6 address because it is made of hex digits and colons
    ["bad.cafe.de::1", "domain", "bad[.]cafe[.]de::1"],
    // degenerate shapes the first version was not a fixed point on
    ["::.", "domain", "::[.]"],
    ["ftp://::..", "url", "fxp://::[.][.]"],
    ["http://.::/:", "url", "hxxp://[.]::/:"],
  ];
  it.each(CASES)("%s [%s] -> %s", (value, type, shown) => {
    expect(defang(value, type)).toBe(shown);
    expect(defang(shown, type)).toBe(shown);
  });

  // under the types a feed may carry besides url and domain: the shape of the value decides
  const OTHER_TYPES = ["ip:port", "md5_hash", "email", "something_new"];
  const OTHER: Array<[string, string]> = [
    ["evil.com/path", "evil[.]com/path"],
    ["1.2.3.4/x", "1.2.3[.]4/x"],
    ["1.2.3.4:80/x", "1.2.3[.]4:80/x"],
    ["evil.com:8080/x", "evil[.]com:8080/x"],
    ["ws://evil.com/x", "ws://evil[.]com/x"],
    ["wss://evil.com/x", "wss://evil[.]com/x"],
    ["smb://evil.com/share", "smb://evil[.]com/share"],
    ["//evil.com/path", "//evil[.]com/path"],
    ["\\\\evil.com\\share", "\\\\evil[.]com\\share"],
    ["http:evil.com", "hxxp:evil[.]com"],
    ["http:\\\\evil.com\\x", "hxxp:\\\\evil[.]com\\x"],
    ["mailto:a@evil.com", "mailto:a@evil[.]com"],
    ["a@evil.com", "a@evil[.]com"],
    ["xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd[.]xn--p1ai"],
    [
      "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
      "\u043f\u0440\u0438\u043c\u0435\u0440[.]\u0440\u0444",
    ],
    ["evil.com?http://x", "evil[.]com?hxxp://x"],
    ["bad.cafe.de::1", "bad[.]cafe[.]de::1"],
  ];
  it.each(
    OTHER_TYPES.flatMap((type) => OTHER.map(([value, shown]) => [value, type, shown] as const)),
  )("%s [%s] -> %s", (value, type, shown) => {
    expect(defang(value, type)).toBe(shown);
    expect(defang(shown, type)).toBe(shown);
  });
});

describe("the authority of every scheme is defanged, wherever it sits in the value", () => {
  it.each<[string, string]>([
    // any scheme followed by two or more slashes, whichever slash: only http, https, ftp and ftps are renamed
    ["gopher://evil.example.com/x", "gopher://evil[.]example[.]com/x"],
    ["ssh:\\\\evil.example.com", "ssh:\\\\evil[.]example[.]com"],
    ["ftps://evil.example.com/x", "fxps://evil[.]example[.]com/x"],
    ["wss://evil.example.com/x", "wss://evil[.]example[.]com/x"],
    ["file://evil.example.com/x", "file://evil[.]example[.]com/x"],
    // nested, after text, after another scheme that is no URL
    ["x http://evil.example.com y", "x hxxp://evil[.]example[.]com y"],
    ["view-source:http://evil.example.com/", "view-source:hxxp://evil[.]example[.]com/"],
    ["javascript:ws://evil.example.com/", "javascript:ws://evil[.]example[.]com/"],
    ["a:b:c:http://evil.example.com", "a:b:c:hxxp://evil[.]example[.]com"],
    // the user name and the port are part of the authority, the last @ ends the user
    ["ws://a.b@c.d@evil.example.com:80/x", "ws://a[.]b@c[.]d@evil[.]example[.]com:80/x"],
    // a backslash ends the authority, as it does for a browser
    ["http://evil.example.com\\@x.example.org", "hxxp://evil[.]example[.]com\\@x[.]example[.]org"],
    // a scheme that is not special and has one slash or none has no authority
    ["tel:+1.555.0100", "tel:+1.555.0100"],
    ["C:\\Windows\\Temp\\a.exe", "C:\\Windows\\Temp\\a.exe"],
  ])("%s -> %s", (value, shown) => {
    expect(defang(value, "something_new")).toBe(shown);
    expect(defang(shown, "something_new")).toBe(shown);
  });

  it("brackets a host after an @ of a mailto-like value, and nothing else of such a value", () => {
    expect(defang("mailto:first.last@evil.example.com?subject=a.b", "email")).toBe(
      "mailto:first.last@evil[.]example[.]com?subject=a.b",
    );
  });
});

describe("a type url or domain has no unbracketed dot before its first / ? or # and none in any authority", () => {
  const VALUES = [
    "evil.com",
    "a.b.c",
    "1.2.3",
    "1.2.3.4",
    "1.2.3.4:80",
    "evil.com:80@x.org",
    "u.v@evil.com",
    "evil.com\\x.org",
    "1https\\\\a.b:c.d@[::1]:80",
    "a.b.http://evil.com",
    "x.y:z.w",
    "[evil.com]",
    "<b>evil.com</b>",
    "evil.com?a.b",
    "evil.com#a.b",
    "evil\u3002com\uff0eorg",
    "http://a.b.c/d.e",
    "//a.b/c.d",
    "ws://a.b:c.d@e.f/g.h",
    "evil.com?http://x.y/z.w",
    "../a.b/c.d",
  ];
  it.each(VALUES.flatMap((v) => ["url", "domain"].map((t) => [v, t] as const)))(
    "%s [%s]",
    (value, type) => {
      const out = defang(value, type);
      expect(unbracketedDot(head(out)), out).toBe(false);
      for (const authority of authorities(out)) expect(unbracketedDot(authority), out).toBe(false);
      expect(defang(out, type)).toBe(out);
    },
  );

  it("leaves the path, the query and the fragment after the first delimiter as they are", () => {
    expect(defang("evil.com/a.b?c.d#e.f", "url")).toBe("evil[.]com/a.b?c.d#e.f");
    expect(defang("evil.com?a.b", "domain")).toBe("evil[.]com?a.b");
  });
});

describe("the IPv6 rule is for an IPv6 address, and the domain rule comes first for a domain", () => {
  it.each<[string, string, string]>([
    ["2001:db8::1", "ip:port", "2001[:]db8[:][:]1"],
    ["2001:db8::1", "domain", "2001[:]db8[:][:]1"],
    ["fe80::1", "ip:port", "fe80[:][:]1"],
    ["::ffff:192.0.2.1", "ip:port", "[:][:]ffff[:]192.0.2[.]1"],
    ["::ffff:192.0.2.1", "domain", "[:][:]ffff[:]192[.]0[.]2[.]1"],
    ["[2001:db8::1]:443", "ip:port", "[2001[:]db8[:][:]1]:443"],
    // an empty port is a port that is not there: the address is the same address
    ["[::1]:", "ip:port", "[[:][:]1]:"],
    ["ws://u:p@[::1]:/x", "url", "ws://u:p@[[:][:]1]:/x"],
    // not IPv6: dots outside a trailing dotted quad, a letter that is no hex digit, one colon only
    ["bad.cafe.de::1", "ip:port", "bad[.]cafe[.]de::1"],
    ["deadbeef.example.com::1", "something_new", "deadbeef[.]example[.]com::1"],
    ["cafe:1.2", "something_new", "cafe:1.2"],
    ["abcd:ef01", "something_new", "abcd:ef01"],
    ["host:80", "something_new", "host:80"],
  ])("%s [%s] -> %s", (value, type, shown) => {
    expect(defang(value, type)).toBe(shown);
    expect(defang(shown, type)).toBe(shown);
  });
});

describe("a host that has no dot to bracket cannot be a host of a special scheme either", () => {
  it.each<[string, string]>([
    // a name with no dot, under a scheme a browser reads and we do not rename, or with no scheme at all (`//`)
    ["ws://localhost/x", "ws://localhost[.]/x"],
    ["wss://intranet:8443/x", "wss://intranet[.]:8443/x"],
    ["ws://1234", "ws://1234[.]"],
    ["ws:localhost", "ws:localhost[.]"],
    ["file://srv/share", "file://srv[.]/share"],
    ["//intranet/x", "//intranet[.]/x"],
    ["\\\\srv\\share", "\\\\srv[.]\\share"],
    ["ws://u@localhost", "ws://u@localhost[.]"],
    // the renamed schemes are no schemes any more, and a non-special scheme is no URL a browser fetches: nothing to add
    ["http://localhost/x", "hxxp://localhost/x"],
    ["smb://srv/share", "smb://srv/share"],
    // the slashes are skipped to the host, as for http (so `ws:///x` has the host x), and a file URL has its host only after exactly two
    ["ws:///x", "ws:///x[.]"],
    ["///x", "///x[.]"],
    ["file:///srv/share", "file:///srv/share"],
    // an empty host, and a drive letter of a file path, are not hosts
    ["ws://", "ws://"],
    ["file:C:/Windows", "file:C:/Windows"],
    ["file:///C:/Windows", "file:///C:/Windows"],
  ])("%s -> %s", (value, shown) => {
    expect(defang(value, "url")).toBe(shown);
    expect(defang(shown, "url")).toBe(shown);
    expect(isLive(shown)).toBe(false);
  });
});

describe("a bracketed host has the colons inside its brackets bracketed, whatever follows the ] (TI14 N1)", () => {
  // the reviewer's five: a zero-padded port of six digits or more is a port to a browser
  const CASES: Array<[string, string]> = [
    ["ws://[2001:db8::1]:000080/x", "ws://[2001[:]db8[:][:]1]:000080/x"],
    ["wss://u@[::1]:0000000/x", "wss://u@[[:][:]1]:0000000/x"],
    ["ws:/[::1]:0000080", "ws:/[[:][:]1]:0000080"],
    ["//[2001:db8::1]:0000080/x", "//[2001[:]db8[:][:]1]:0000080/x"],
    ["\\\\[2001:db8::a]:0000000443\\x", "\\\\[2001[:]db8[:][:]a]:0000000443\\x"],
    // twenty digits, garbage, nothing, a second colon, a second bracket, an IPv4 tail
    ["ws://[::1]:00000000000000000000/x", "ws://[[:][:]1]:00000000000000000000/x"],
    ["ws://[::1]x/", "ws://[[:][:]1]x/"],
    ["ws://[::1]:80:90/", "ws://[[:][:]1]:80:90/"],
    ["ws://[::1]]/", "ws://[[:][:]1]]/"],
    ["ws://[::1]:8a/", "ws://[[:][:]1]:8a/"],
    ["ws://[::ffff:1.2.3.4]:000080/", "ws://[[:][:]ffff[:]1[.]2[.]3[.]4]:000080/"],
    ["ws://[::1]", "ws://[[:][:]1]"],
    // the same as a value of its own
    ["[::1]:00000000000000000000", "[[:][:]1]:00000000000000000000"],
    ["[::1]x", "[[:][:]1]x"],
    ["[2001:db8::1]:0000080", "[2001[:]db8[:][:]1]:0000080"],
  ];
  const ALL_TYPES = ["url", "domain", "ip:port", "md5_hash", "email", "something_new"];
  it.each(CASES.flatMap(([value, shown]) => ALL_TYPES.map((t) => [value, t, shown] as const)))(
    "%s [%s] -> %s",
    (value, type, shown) => {
      expect(defang(value, type)).toBe(shown);
      expect(defang(shown, type)).toBe(shown);
      expect(isLive(shown)).toBe(false);
    },
  );

  it("keeps an unbalanced bracket as it is: no `]`, no bracketed host", () => {
    expect(defang("ws://[::1/x", "url")).toBe("ws://[::1/x");
    expect(defang("ws://x[::1]/", "url")).toBe("ws://x[::1]/");
  });
});

describe("white space at the edges of a value changes nothing (TI14 N2)", () => {
  it.each<[string, string, string]>([
    [" //[::1]/x", "ip:port", " //[[:][:]1]/x"],
    [" //[2001:db8::1]:443/x", "ip:port", " //[2001[:]db8[:][:]1]:443/x"],
    [" //evil.example/x", "ip:port", " //evil[.]example/x"],
    ["ws://[::1] ", "url", "ws://[[:][:]1] "],
    ["\t//evil.example/x\n", "something_new", "\t//evil[.]example/x\n"],
    ["  ws://localhost  ", "url", "  ws://localhost[.]  "],
    ["\u00a0http://evil.example/\u00a0", "url", "\u00a0hxxp://evil[.]example/\u00a0"],
  ])("%j [%s] -> %j", (value, type, shown) => {
    expect(defang(value, type)).toBe(shown);
    expect(defang(shown, type)).toBe(shown);
    expect(isLive(shown)).toBe(false);
  });

  it("is the same as the trimmed value with the edges put back, for every value of a list and every type", () => {
    const values = [
      "http://evil.example/x",
      "//evil.example",
      "ws://[::1]:000080/x",
      "evil.example",
      "1.2.3.4",
      "::ffff:1.2.3.4",
      "mailto:a@evil.example",
      "abcdef",
      "",
      "ws://localhost",
    ];
    for (const value of values) {
      for (const type of ["url", "domain", "ip:port", "something_new"]) {
        for (const [before, after] of [
          [" ", ""],
          ["", " "],
          ["\t ", "\n"],
          ["\u0001", " "],
        ]) {
          expect(defang(before + value + after, type), `${before + value + after}`).toBe(
            before + defang(value, type) + after,
          );
        }
      }
    }
  });

  it("does not make a value of nothing but white space anything else", () => {
    for (const value of [" ", "   ", "\t\n", "\u00a0 "]) expect(defang(value, "url")).toBe(value);
  });
});

describe("what the rule still does not cover (said in DEC-224), as the code does it", () => {
  it("leaves a name that is not at the start, not in an authority and not after an @, for a type that is not url or domain", () => {
    expect(defang("see evil.example.com now", "something_new")).toBe("see evil.example.com now");
    // for a url or a domain it is before the first delimiter, so it is bracketed
    expect(defang("see evil.example.com now", "url")).toBe("see evil[.]example[.]com now");
  });
  it("leaves a name written in a path, a query or a fragment", () => {
    expect(defang("http://x.example.com/see.other.example.org", "url")).toBe(
      "hxxp://x[.]example[.]com/see.other.example.org",
    );
  });
  it("leaves a percent-encoded dot, which is no dot to the text and a dot to a browser, as it is (a special scheme still gets its marker)", () => {
    expect(defang("http://evil%2eexample%2ecom/x", "url")).toBe("hxxp://evil%2eexample%2ecom/x");
    expect(defang("ws://evil%2ecom/x", "url")).toBe("ws://evil%2ecom[.]/x");
  });
});

// ── a generated corpus ───────────────────────────────────────────────────────────────────────────────────────

/** A small deterministic generator (mulberry32): the same corpus on every run. */
function generator(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SCHEMES = [
  "http",
  "https",
  "ftp",
  "ftps",
  "ws",
  "wss",
  "file",
  "smb",
  "mailto",
  "hxxp",
  "HTTP",
  "HtTps",
  "a.b",
  "javascript",
  "view-source",
  "x",
  "",
];
const GLUE = [":", ":/", "://", ":///", ":\\\\", ":\\/", ":/\\", "//", "\\\\", ":////", "", "::"];
const USERS = ["", "", "u@", "u:p@", "evil.com@", "a.b:c.d@", "@"];
const HOSTS = [
  "evil.com",
  "a.b.c.example",
  "1.2.3.4",
  "203.0.113.9:8080",
  "[::1]",
  "[2001:db8::1]:80",
  "2001:db8::1",
  "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
  "xn--e1afmkfd.xn--p1ai",
  "evil.com.",
  "x.y",
  "a.b:80",
  "bad.cafe.de::1",
  "localhost",
  "x",
  "1234",
  "[::1]:",
  "[2001:db8::1]:000080",
  "[::1]:0000000",
  "[::1]:00000000000000000000",
  "[::1]x",
  "[::1]:80:90",
  "[::1]]",
  "[::1]:8a",
  "[1:2:3:4:5:6:7:8]",
  "0x7f.1",
  "2130706433",
  "evil.com:",
  "evil%2ecom",
  "[v1.fe]",
  "evil\u3002com",
  "[::ffff:1.2.3.4]",
  "[::1",
  "::",
  ".",
  "..",
  "",
];
const TAILS = [
  "",
  "/",
  "/p.q",
  "?q=a.b",
  "#f.g",
  "\\x",
  "@x.org",
  ":80",
  "/http://x.org",
  "?u=ws://y.net/z",
  "/\\//",
];
const NOISE = ["", "", "", ".", ":", "/", "\\", "?", "#", "@", "[", "]", " ", "a", "1", "x."];
const ALPHABET = [
  ".",
  ":",
  "/",
  "\\",
  "?",
  "#",
  "@",
  "[",
  "]",
  "a",
  "1",
  "x",
  "E",
  "-",
  "h",
  "t",
  "p",
  "s",
  "w",
  "f",
  "l",
  "e",
  "i",
  ":",
  ".",
  "/",
  "%",
  " ",
];
/** White space and a control character at the edge of a value: a browser skips them, and so does the rule. */
const EDGES = ["", "", "", "", " ", "  ", "\t", "\n", "\u0001", " \t"];
const TYPES = ["url", "domain", "ip:port", "md5_hash", "email", "something_new", ""];

function corpus(count: number, seed: number): string[] {
  const next = generator(seed);
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)] as T;
  const values: string[] = [];
  for (let i = 0; i < count; i += 1) {
    if (next() < 0.35) {
      // raw characters of the alphabet of the problem
      let raw = "";
      const length = 1 + Math.floor(next() * 22);
      for (let k = 0; k < length; k += 1) raw += pick(ALPHABET);
      values.push(raw);
      continue;
    }
    let value = pick(EDGES);
    const units = 1 + Math.floor(next() * 3);
    for (let u = 0; u < units; u += 1) {
      value += pick(NOISE) + pick(SCHEMES) + pick(GLUE) + pick(USERS) + pick(HOSTS) + pick(TAILS);
    }
    values.push(value + pick(EDGES));
  }
  return values;
}

describe("a generated corpus (schemes, slashes and back-slashes, users, nested URLs, IPv4 and IPv6, IDN, the characters . : / \\ ? # @ [ ])", () => {
  // A fixed seed, so the run is the same every time; TI_DEFANG_SEED and TI_DEFANG_COUNT run another corpus (a longer hunt, by hand).
  const VALUES = corpus(
    Number(process.env.TI_DEFANG_COUNT ?? 12_000),
    Number(process.env.TI_DEFANG_SEED ?? 20261117),
  );

  it("is a corpus worth the name: varied, and with schemes, slashes, addresses and names in it", () => {
    expect(new Set(VALUES).size).toBeGreaterThan(9_000);
    expect(VALUES.filter((v) => /^\s*(?:https?|wss?|ftps?|file):/i.test(v)).length).toBeGreaterThan(
      500,
    );
    expect(VALUES.filter((v) => v.includes("[::")).length).toBeGreaterThan(300);
  });

  it("leaves no output that WHATWG `new URL` reads as a URL of a special scheme with a host, nor one that is when read after `http:`", () => {
    const failures: string[] = [];
    for (const value of VALUES) {
      for (const type of TYPES) {
        const out = defang(value, type);
        if (isLive(out))
          failures.push(`${JSON.stringify(value)} [${type}] -> ${JSON.stringify(out)}`);
      }
    }
    expect(failures.slice(0, 10)).toEqual([]);
  }, 120_000);

  it("treats the white space at the edges of a value as nothing: the same as the trimmed value with the edges put back", () => {
    const failures: string[] = [];
    for (const value of VALUES) {
      for (const type of TYPES) {
        const inner = value.replace(/^[\s\u0000-\u0020]+|[\s\u0000-\u0020]+$/g, "");
        const wrapped = ` \t${inner}\n `;
        if (defang(wrapped, type) !== ` \t${defang(inner, type)}\n `) {
          failures.push(`${JSON.stringify(inner)} [${type}]`);
        }
      }
    }
    expect(failures.slice(0, 10)).toEqual([]);
  }, 120_000);

  it("is its own fixed point: defanging the output changes nothing", () => {
    const failures: string[] = [];
    for (const value of VALUES) {
      for (const type of TYPES) {
        const once = defang(value, type);
        const twice = defang(once, type);
        if (twice !== once)
          failures.push(
            `${JSON.stringify(value)} [${type}] -> ${JSON.stringify(once)} -> ${JSON.stringify(twice)}`,
          );
      }
    }
    expect(failures.slice(0, 10)).toEqual([]);
  }, 120_000);

  it("holds the invariants of a type url or domain: no dot before the first / ? or #, none in any authority", () => {
    const failures: string[] = [];
    for (const value of VALUES) {
      for (const type of ["url", "domain"]) {
        const out = defang(value, type);
        let bad = unbracketedDot(head(out));
        for (const authority of authorities(out)) if (unbracketedDot(authority)) bad = true;
        if (bad) failures.push(`${JSON.stringify(value)} [${type}] -> ${JSON.stringify(out)}`);
      }
    }
    expect(failures.slice(0, 10)).toEqual([]);
  }, 120_000);
});

// ── time ─────────────────────────────────────────────────────────────────────────────────────────────────────

describe("the time it takes is in proportion to the value", () => {
  const SHAPES = [
    ".",
    ":",
    "/",
    "\\",
    "@",
    "a",
    "1",
    "a.",
    "a:",
    "a:a:",
    "a:/",
    "[.]",
    "http://",
    "http:",
    "::",
    "a::",
    ":.",
    "@a.",
    "x.y@",
    "a1",
    "a-",
    "//a.",
    "\\\\a:",
    "http://a.",
  ];
  const TYPES_TIMED = ["url", "domain", "ip:port", "something_new"];
  const run = (shape: string, length: number): number => {
    const value = shape.repeat(Math.ceil(length / shape.length)).slice(0, length);
    let best = Infinity;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const started = performance.now();
      for (const type of TYPES_TIMED) defang(value, type);
      best = Math.min(best, performance.now() - started);
    }
    return best;
  };

  it("takes a few milliseconds for 2 048 characters of any shape, for four types", () => {
    for (const shape of SHAPES) expect(run(shape, 2048), shape).toBeLessThan(50);
  });

  it("takes about four times as long for four times the length, not sixteen (no shape of it is quadratic)", () => {
    for (const shape of SHAPES) {
      const small = run(shape, 8192);
      const large = run(shape, 32768);
      expect(large, `${shape}: ${small.toFixed(2)} ms -> ${large.toFixed(2)} ms`).toBeLessThan(
        Math.max(small, 3) * 12,
      );
    }
  });
});
