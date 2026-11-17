// src/features/ti/tiParams.test.ts — the view of the Threat Intel page (the filters, the search and the page) as URL search params:
// what is read from a URL is validated here, so the API never sees a value it would refuse (a 422), and "any confidence" is no
// parameter at all.
import {
  EMPTY_VIEW,
  cleanMalware,
  cleanQuery,
  filtersOf,
  listQueryOf,
  readView,
  viewSearch,
  viewToParams,
  type TiView,
} from "./tiParams";

const read = (search: string): TiView => readView(new URLSearchParams(search));

describe("readView", () => {
  it("is the empty view for an empty URL", () => {
    expect(read("")).toEqual(EMPTY_VIEW);
    expect(EMPTY_VIEW).toEqual({
      source: null,
      type: "",
      malware: "",
      from: "",
      to: "",
      minConfidence: null,
      q: "",
      page: 1,
    });
  });

  it("reads every filter that is valid", () => {
    expect(
      read(
        "source=urlhaus&type=domain&malware=Example.Rat&from=2026-11-01&to=2026-11-17&min_confidence=75&q=abc&page=3",
      ),
    ).toEqual({
      source: "urlhaus",
      type: "domain",
      malware: "Example.Rat",
      from: "2026-11-01",
      to: "2026-11-17",
      minConfidence: 75,
      q: "abc",
      page: 3,
    });
  });

  describe("source is a closed set", () => {
    it.each(["threatfox", "urlhaus", "malwarebazaar"])("keeps %s", (source) => {
      expect(read(`source=${source}`).source).toBe(source);
    });
    it.each(["", "evil", "ThreatFox", "constructor", "__proto__", "toString", "threatfox,urlhaus"])(
      "drops %j",
      (source) => {
        expect(read(`source=${encodeURIComponent(source)}`).source).toBeNull();
      },
    );
  });

  describe("type is a token of at most 64 characters, lower-cased", () => {
    it.each([
      ["ip:port", "ip:port"],
      ["IP:Port", "ip:port"],
      ["sha256_hash", "sha256_hash"],
      ["a".repeat(64), "a".repeat(64)],
    ])("reads %s as %s", (given, kept) => {
      expect(read(`type=${given}`).type).toBe(kept);
    });
    it.each(["a b", "a".repeat(65), "<x>", "a/b", "é", "%00"])("drops %j", (given) => {
      expect(read(`type=${encodeURIComponent(given)}`).type).toBe("");
    });
  });

  describe("malware is text of at most 256 characters with nothing the database refuses", () => {
    it("keeps a name, trimmed, and one of exactly 256 characters", () => {
      expect(read("malware=%20Example.Rat%20").malware).toBe("Example.Rat");
      expect(read(`malware=${"a".repeat(256)}`).malware).toBe("a".repeat(256));
    });
    it("drops one of 257 characters, a NUL, a lone surrogate", () => {
      expect(read(`malware=${"a".repeat(257)}`).malware).toBe("");
      expect(read("malware=a%00b").malware).toBe("");
      // a URL cannot carry a lone surrogate (URLSearchParams turns it into U+FFFD), but the box and the functions can
      expect(cleanMalware("a\ud800b")).toBe("");
    });
    it("counts a character outside the BMP once, as the server does", () => {
      const astral = "\u{1d11e}".repeat(256);
      expect(astral.length).toBe(512);
      expect(readView(new URLSearchParams([["malware", astral]])).malware).toBe(astral);
      expect(readView(new URLSearchParams([["malware", `${astral}x`]])).malware).toBe("");
    });
  });

  describe("dates are YYYY-MM-DD and a real day, never a time", () => {
    it.each(["2026-11-17", "2026-02-28", "2028-02-29", "1970-01-01", "2999-12-31"])(
      "keeps %s",
      (day) => {
        expect(read(`from=${day}&to=${day}`)).toMatchObject({ from: day, to: day });
      },
    );
    it.each([
      "2026-02-30",
      "2026-13-01",
      "2026-00-10",
      "2026-11-00",
      "2027-02-29",
      "2026-11-17T10:00",
      "2026-11-17T10:00:00Z",
      "2026-11-17 10:00",
      "17/11/2026",
      "2026-1-1",
      "20261117",
      "2026-11-17 ",
      "0000-01-01",
      "1969-12-31",
      "3000-01-01",
      "today",
      "",
    ])("drops %j", (day) => {
      const view = read(`from=${encodeURIComponent(day)}&to=${encodeURIComponent(day)}`);
      expect(view.from).toBe("");
      expect(view.to).toBe("");
    });
  });

  describe("min_confidence is 1..100, and 0 is 'any'", () => {
    it.each([
      ["1", 1],
      ["75", 75],
      ["100", 100],
    ])("reads %s", (given, kept) => {
      expect(read(`min_confidence=${given}`).minConfidence).toBe(kept);
    });
    it.each(["0", "", "101", "-5", "7.5", "abc", "075", "00", "1e2", "+5", " 5", "999999999999"])(
      "reads %j as any",
      (given) => {
        expect(read(`min_confidence=${encodeURIComponent(given)}`).minConfidence).toBeNull();
      },
    );
  });

  describe("q is trimmed and at most 128 characters", () => {
    it("trims, and cuts a longer one to 128 characters", () => {
      expect(read("q=%20%20abc%20").q).toBe("abc");
      expect(read(`q=${"a".repeat(200)}`).q).toBe("a".repeat(128));
      expect(read(`q=${"a".repeat(128)}`).q).toBe("a".repeat(128));
    });
    it("never cuts inside a character outside the BMP", () => {
      const astral = "\u{1d11e}".repeat(200);
      const q = readView(new URLSearchParams([["q", astral]])).q;
      expect(Array.from(q)).toHaveLength(128);
      expect(q).toBe("\u{1d11e}".repeat(128));
      expect(() => encodeURIComponent(q)).not.toThrow();
    });
    it("drops one with a NUL or a lone surrogate", () => {
      expect(read("q=a%00b").q).toBe("");
      expect(cleanQuery("a\udc00")).toBe("");
    });
    it("keeps the characters of a literal search", () => {
      expect(read(`q=${encodeURIComponent("% _ \\ ' ; --")}`).q).toBe("% _ \\ ' ; --");
    });
  });

  describe("page is a whole number from 1", () => {
    it.each([
      ["1", 1],
      ["2", 2],
      ["999999", 999999],
      ["1000000", 1_000_000],
    ])("reads %s", (given, kept) => {
      expect(read(`page=${given}`).page).toBe(kept);
    });
    it.each(["0", "-1", "1.5", "abc", "", "01", "1000001", "99999999", "1e3"])(
      "reads %j as 1",
      (given) => {
        expect(read(`page=${given}`).page).toBe(1);
      },
    );
  });

  it("reads the first of a repeated parameter and ignores a parameter it does not know", () => {
    expect(read("source=urlhaus&source=threatfox&evil=1&expired=true&page_size=500")).toEqual({
      ...EMPTY_VIEW,
      source: "urlhaus",
    });
  });
});

describe("cleanQuery", () => {
  it("is the text the box means", () => {
    expect(cleanQuery("  abc  ")).toBe("abc");
    expect(cleanQuery("a".repeat(300))).toHaveLength(128);
    expect(cleanQuery("a\u0000b")).toBe("");
    expect(cleanQuery("")).toBe("");
  });
});

describe("viewToParams and viewSearch", () => {
  it("write only what differs from the empty view", () => {
    expect(viewToParams(EMPTY_VIEW).toString()).toBe("");
    expect(viewSearch(EMPTY_VIEW)).toBe("");
    expect(viewSearch({ ...EMPTY_VIEW, page: 2 })).toBe("?page=2");
    expect(viewSearch({ ...EMPTY_VIEW, source: "urlhaus", minConfidence: 50 })).toBe(
      "?source=urlhaus&min_confidence=50",
    );
  });

  it("never write a min_confidence of 0, and a view round-trips", () => {
    expect(viewToParams({ ...EMPTY_VIEW, minConfidence: 0 }).has("min_confidence")).toBe(false);
    const view: TiView = {
      source: "malwarebazaar",
      type: "sha256_hash",
      malware: "Example.Loader",
      from: "2026-11-01",
      to: "2026-11-17",
      minConfidence: 90,
      q: "a&b=c",
      page: 4,
    };
    expect(readView(viewToParams(view))).toEqual(view);
  });
});

describe("what the API is asked", () => {
  it("is the page and the filters that are set, and no min_confidence for any", () => {
    expect(listQueryOf(EMPTY_VIEW)).toEqual({ page: 1 });
    expect(listQueryOf({ ...EMPTY_VIEW, page: 3, source: "urlhaus", minConfidence: 75 })).toEqual({
      page: 3,
      source: "urlhaus",
      minConfidence: 75,
    });
    expect("minConfidence" in listQueryOf(EMPTY_VIEW)).toBe(false);
  });

  it("is the same filters without the page for the export", () => {
    expect(filtersOf({ ...EMPTY_VIEW, page: 9, q: "x", from: "2026-11-01" })).toEqual({
      q: "x",
      from: "2026-11-01",
    });
  });
});
