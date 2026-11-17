// src/features/ti/defang.test.ts — what the Threat Intel page shows of an IOC's value, and the one place it may be a link.
// Every value here is made up: the documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32) and example.* names.
import { abuseChHref, defang, isAbuseChReference } from "./defang";

describe("defang: a URL", () => {
  it.each<[string, string]>([
    ["http://evil.example.com/a.php?x=1", "hxxp://evil[.]example[.]com/a.php?x=1"],
    ["https://evil.example.net/", "hxxps://evil[.]example[.]net/"],
    ["https://evil.example.net", "hxxps://evil[.]example[.]net"],
    ["ftp://files.example.com/x.bin", "fxp://files[.]example[.]com/x.bin"],
    // the scheme keeps its case, only the two t's go
    ["HTTP://Evil.Example.com/A", "HxxP://Evil[.]Example[.]com/A"],
    // a port and a user are in the authority, which loses every dot
    [
      "http://user.name:pw@evil.example.com:8080/x",
      "hxxp://user[.]name:pw@evil[.]example[.]com:8080/x",
    ],
    // an IPv4 host is an address: its last dot, as the address is shown everywhere else
    ["http://203.0.113.9:8080/bin.sh", "hxxp://203.0.113[.]9:8080/bin.sh"],
    ["http://203.0.113.9/bin.sh", "hxxp://203.0.113[.]9/bin.sh"],
    // an IPv6 host: each colon of the address
    ["http://[2001:db8::1]:8080/x", "hxxp://[2001[:]db8[:][:]1]:8080/x"],
    // the path, the query and the fragment are left as they are
    [
      "https://evil.example.com/a.b/c.d?e=f.g#h.i",
      "hxxps://evil[.]example[.]com/a.b/c.d?e=f.g#h.i",
    ],
    // a URL carried inside the query is not live either
    [
      "http://evil.example.com/r?u=http://other.example.net/x",
      "hxxp://evil[.]example[.]com/r?u=hxxp://other[.]example[.]net/x",
    ],
  ])("%s -> %s", (value, shown) => {
    expect(defang(value, "url")).toBe(shown);
  });

  it("gives a URL with no scheme every dot, and one a hidden character hides the scheme of too", () => {
    expect(defang("evil.example.com/path.exe", "url")).toBe("evil[.]example[.]com/path[.]exe");
    // a zero-width space inside `http` breaks the scheme: nothing is a scheme, so every dot goes
    expect(defang("ht\u200btp://evil.example.com/a.php", "url")).toBe(
      "ht\u200btp://evil[.]example[.]com/a[.]php",
    );
  });

  it("defangs a URL whatever the type says it is", () => {
    expect(defang("http://evil.example.com/a", "domain")).toBe("hxxp://evil[.]example[.]com/a");
    expect(defang("http://evil.example.com/a", "sha256_hash")).toBe(
      "hxxp://evil[.]example[.]com/a",
    );
    expect(defang("http://evil.example.com/a", "something_new")).toBe(
      "hxxp://evil[.]example[.]com/a",
    );
  });
});

describe("defang: a domain", () => {
  it.each<[string, string]>([
    ["evil.example.com", "evil[.]example[.]com"],
    ["Evil.Example.COM", "Evil[.]Example[.]COM"],
    ["evil.example.com.", "evil[.]example[.]com[.]"],
    ["example.xn--p1ai", "example[.]xn--p1ai"],
    ["localhost", "localhost"],
    // the ideographic and full-width full stops are dots to a browser
    ["evil\u3002example\uff0ecom", "evil[.]example[.]com"],
  ])("%s -> %s", (value, shown) => {
    expect(defang(value, "domain")).toBe(shown);
  });

  it("completes a domain that was defanged by hand in one place only", () => {
    expect(defang("evil[.]example.com", "domain")).toBe("evil[.]example[.]com");
  });
});

describe("defang: an address", () => {
  it.each<[string, string, string]>([
    ["192.0.2.10", "ip:port", "192.0.2[.]10"],
    ["192.0.2.10:443", "ip:port", "192.0.2[.]10:443"],
    ["198.51.100.7:8080", "ip:port", "198.51.100[.]7:8080"],
    // an IPv4 address is an address whatever the type says
    ["203.0.113.5", "domain", "203.0.113[.]5"],
    // IPv6 has no dot: each colon of the address is bracketed; a bracketed address keeps its brackets and its port
    ["2001:db8::1", "ip:port", "2001[:]db8[:][:]1"],
    ["[2001:db8::1]:443", "ip:port", "[2001[:]db8[:][:]1]:443"],
    ["[::1]:80", "ip:port", "[[:][:]1]:80"],
    // an IPv4 tail loses its last dot as well
    ["::ffff:192.0.2.1", "ip:port", "[:][:]ffff[:]192.0.2[.]1"],
  ])("%s (%s) -> %s", (value, type, shown) => {
    expect(defang(value, type)).toBe(shown);
  });
});

describe("defang: a hash, and what has nothing to defang", () => {
  const DIGESTS = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e",
    "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
  ];
  it.each(DIGESTS)("leaves the hash %s alone", (hash) => {
    for (const type of ["sha256_hash", "md5_hash", "sha1_hash", "ip:port", "domain", "url"]) {
      expect(defang(hash, type)).toBe(hash);
    }
  });

  it("leaves a value of a type it knows nothing about alone unless it looks like a name, a URL or an address", () => {
    expect(defang("Emotet", "malware_name")).toBe("Emotet");
    expect(defang("C:\\Windows\\Temp\\a", "path")).toBe("C:\\Windows\\Temp\\a");
    expect(defang("evil.example.com", "something_new")).toBe("evil[.]example[.]com");
    expect(defang("192.0.2.4:80", "something_new")).toBe("192.0.2[.]4:80");
    expect(defang("", "url")).toBe("");
  });
});

describe("defang: a value that is already defanged is not defanged twice", () => {
  it.each<[string, string]>([
    ["hxxp://evil[.]com", "url"],
    ["hxxps://evil[.]example[.]com/a.php", "url"],
    ["fxp://files[.]example[.]com/x", "url"],
    ["evil[.]example[.]com", "domain"],
    ["192.0.2[.]10", "ip:port"],
    ["192.0.2[.]10:443", "ip:port"],
    ["192[.]0[.]2[.]10", "ip:port"],
    ["2001[:]db8[:][:]1", "ip:port"],
    ["[2001[:]db8[:][:]1]:443", "ip:port"],
    ["hxxp://203.0.113[.]9:8080/bin.sh", "url"],
    ["hxxp://[2001[:]db8[:][:]1]:8080/x", "url"],
  ])("%s (%s) stays as it is", (value, type) => {
    expect(defang(value, type)).toBe(value);
  });

  it("is a fixed point: defanging the output changes nothing, for every shape above", () => {
    const corpus: Array<[string, string]> = [
      ["http://evil.example.com/a.php?x=1", "url"],
      ["HTTP://Evil.Example.com/A", "url"],
      ["hxxp://evil.example.com/a", "url"],
      ["http://user.name:pw@evil.example.com:8080/x", "url"],
      ["http://203.0.113.9:8080/bin.sh", "url"],
      ["http://[2001:db8::1]:8080/x", "url"],
      ["http://evil.example.com/r?u=http://other.example.net/x", "url"],
      ["evil.example.com/path.exe", "url"],
      ["evil.example.com", "domain"],
      ["evil[.]example.com", "domain"],
      ["192.0.2.10:443", "ip:port"],
      ["2001:db8::1", "ip:port"],
      ["[2001:db8::1]:443", "ip:port"],
      ["::ffff:192.0.2.1", "ip:port"],
      ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256_hash"],
      ['<a href="http://evil.example.com">x</a>', "url"],
      ["evil.example.com", "something_new"],
    ];
    for (const [value, type] of corpus) {
      const once = defang(value, type);
      expect(defang(once, type), `${value} (${type})`).toBe(once);
    }
  });
});

describe("defang: a value with markup stays text", () => {
  it("keeps every character of a markup value, and defangs only what is a name or a URL in it", () => {
    expect(defang("<img src=x onerror=alert(1)>", "url")).toBe("<img src=x onerror=alert(1)>");
    expect(defang("javascript:alert(1)", "url")).toBe("javascript:alert(1)");
    expect(defang('<a href="http://evil.example.com">x</a>', "url")).toBe(
      '<a href="hxxp://evil[.]example[.]com">x</a>',
    );
    expect(defang("<b>evil.example.com</b>", "domain")).toBe("<b>evil[.]example[.]com</b>");
    expect(defang("=cmd|' /C calc'!A0", "url")).toBe("=cmd|' /C calc'!A0");
  });
});

describe("defang: a long value does not take long", () => {
  it("handles 2 048 characters of dots, colons and slashes at once", () => {
    for (const shape of [".", ":", "/", "a.", "[.]", "http://"]) {
      const value = shape.repeat(Math.ceil(2048 / shape.length)).slice(0, 2048);
      const started = Date.now();
      for (const type of ["url", "domain", "ip:port", "x"]) defang(value, type);
      expect(Date.now() - started).toBeLessThan(500);
    }
  });
});

describe("abuseChHref and isAbuseChReference: the one link of the page", () => {
  const ALLOWED = [
    "https://threatfox.abuse.ch/ioc/1234567/",
    "https://urlhaus.abuse.ch/url/1234567/",
    "https://bazaar.abuse.ch/sample/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/",
    "https://threatfox.abuse.ch",
    "HTTPS://ThreatFox.Abuse.CH/ioc/1/",
    "https://threatfox.abuse.ch:443/ioc/1/",
  ];
  it.each(ALLOWED)("%s is a link", (url) => {
    expect(isAbuseChReference(url)).toBe(true);
    const href = abuseChHref(url);
    expect(href).not.toBeNull();
    // the href is what was parsed and judged, not the text that came
    expect(new URL(href as string).protocol).toBe("https:");
    expect(["threatfox.abuse.ch", "urlhaus.abuse.ch", "bazaar.abuse.ch"]).toContain(
      new URL(href as string).hostname,
    );
  });

  it.each<[string, string]>([
    ["https://threatfox.abuse.ch/ioc/1234567/", "https://threatfox.abuse.ch/ioc/1234567/"],
    ["HTTPS://ThreatFox.Abuse.CH/ioc/1/", "https://threatfox.abuse.ch/ioc/1/"],
    ["https://threatfox.abuse.ch", "https://threatfox.abuse.ch/"],
    ["https://threatfox.abuse.ch:443/ioc/1/", "https://threatfox.abuse.ch/ioc/1/"],
    ["https://urlhaus.abuse.ch/url/1/?a=b#c", "https://urlhaus.abuse.ch/url/1/?a=b#c"],
  ])("links %s to the address that was parsed and judged: %s", (url, href) => {
    expect(abuseChHref(url)).toBe(href);
  });

  const REFUSED: Array<[string, string]> = [
    ["http, not https", "http://threatfox.abuse.ch/ioc/1/"],
    [
      "a look-alike host that begins with an abuse.ch name",
      "https://threatfox.abuse.ch.evil.example/ioc/1/",
    ],
    ["the abuse.ch name only in the path", "https://evil.example/threatfox.abuse.ch"],
    ["the abuse.ch name only in the query", "https://evil.example/?u=https://threatfox.abuse.ch/"],
    ["a user that spells an abuse.ch name", "https://threatfox.abuse.ch@evil.example/ioc/1/"],
    ["a user in front of the right host", "https://user@threatfox.abuse.ch/ioc/1/"],
    ["a user and a password", "https://user:pw@urlhaus.abuse.ch/"],
    ["another port", "https://threatfox.abuse.ch:8443/ioc/1/"],
    ["a port that is not a number", "https://threatfox.abuse.ch:evil/ioc/1/"],
    ["another abuse.ch host", "https://www.abuse.ch/"],
    ["the bare domain", "https://abuse.ch/"],
    ["a sub-domain of an allowed host", "https://x.threatfox.abuse.ch/"],
    ["a trailing dot", "https://threatfox.abuse.ch./ioc/1/"],
    ["no scheme", "threatfox.abuse.ch/ioc/1/"],
    ["a scheme-relative URL", "//threatfox.abuse.ch/ioc/1/"],
    ["a scheme with no slashes", "https:threatfox.abuse.ch"],
    ["one slash", "https:/threatfox.abuse.ch/"],
    ["a backslash that moves the host", "https://evil.example\\@threatfox.abuse.ch/"],
    ["a backslash after the host", "https://threatfox.abuse.ch\\@evil.example/"],
    ["a space", "https://threatfox.abuse.ch /ioc/1/"],
    ["a leading space", " https://threatfox.abuse.ch/ioc/1/"],
    ["a newline in the host", "https://threat\nfox.abuse.ch/"],
    ["a zero-width space in the host", "https://threatfox.abuse.ch\u200b/"],
    ["a right-to-left override", "https://threatfox.abuse.ch/\u202eioc/1/"],
    ["a non-ASCII host", "https://threatfox.abuse.ch\uff0eevil.example/"],
    ["javascript:", "javascript:alert(1)"],
    ["data:", "data:text/html,<script>alert(1)</script>"],
    ["a markup value", "<a href=https://threatfox.abuse.ch/>x</a>"],
    ["an empty string", ""],
    ["only spaces", "   "],
  ];
  it.each(REFUSED)("is not a link: %s", (_name, url) => {
    expect(isAbuseChReference(url)).toBe(false);
    expect(abuseChHref(url)).toBeNull();
  });

  it("does not throw on a hostile string", () => {
    for (const url of [
      "https://",
      "https://[",
      "https://%",
      "http://:::",
      "\u0000",
      "https://a b",
    ]) {
      expect(() => isAbuseChReference(url)).not.toThrow();
      expect(isAbuseChReference(url)).toBe(false);
    }
  });
});
