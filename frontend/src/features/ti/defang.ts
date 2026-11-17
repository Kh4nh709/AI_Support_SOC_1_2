// What the Threat Intel page shows of an IOC's value (DEC-224, spec section 8), and the one place a value may become a link.
//
// `defang(value, type)` is the text the page prints for a URL, a domain or an address: it can be read, and pasted into a chat or a
// ticket, without becoming a live link. It is a DISPLAY rule only: the copy button copies the original, and nothing here (or on
// the page) builds a link, a request or an attribute out of a value. It is ONE rule with invariants (TI12), tested over the cases a
// review measured and over a generated corpus (defangRule.test.ts):
//
//   1. AUTHORITIES. For every type but a hash, every scheme (`[A-Za-z][A-Za-z0-9+-]*`) followed by `:` and a run of `/` and `\`, and a value
//      that begins with two slashes of either kind (scheme-relative), has its AUTHORITY defanged, wherever it sits in the value. A browser
//      skips slashes to the host for a special scheme, so an empty authority is skipped to the next run that is not a slash
//      (`http:///evil.com`, `http:\\evil.com`, `http:evil.com`). A scheme with no slash, or one, is looked at only when it is special
//      (http, https, ftp, ftps, ws, wss, file): `mailto:a@evil.com`, `tel:` and `C:\path` have no authority. The authority is the text up to
//      the next `/`, `\`, `?` or `#`. EVERY dot of it is bracketed (`[.]`; the full stops a browser reads as dots too), its
//      user name included, an IPv4 host included; a bracketed or bare IPv6 address has every colon bracketed (`[:]`) as well. Only
//      `http`, `https`, `ftp` and `ftps` are renamed (`hxxp`, `hxxps`, `fxp`, `fxps`; the case of the other letters is kept). An
//      authority is also cut where a scheme with an authority of its own begins inside it (`javascript://a.com:http://b.com`).
//      A host with no dot at all (`localhost`, `1234`) has nothing to bracket. Where a value BEGINS (after the white space and control
//      characters a browser skips) with `ws:`, `wss:`, `file://` or two slashes, a browser reads it as a URL of a special scheme, and its
//      host is the text after the last `@` of the first authority: if that host has no `[` in it, its name gets a trailing `[.]` that no
//      host can have (`ws://localhost[.]/x`, `//intranet[.]/x`). So no output is a URL of a special scheme with a host.
//   2. WHAT IS LEFT. The text that is not in an authority gets the no-scheme rules: a name or an address at the START of the value, up
//      to the next `/ \ ? # : @` or white space (`evil.com/path`, `1.2.3[.]4/x`, `evil.com:80`, IDN and punycode names), and the name after
//      an `@` (`mailto:a@evil.com`, `a@evil.com`). A name is labels of letters, digits, `_` and `-` joined by dots, the last label letters
//      only (2 to 63) or `xn--…`; an IPv4 address there loses only its last dot (the Owner's `1.2.3[.]4`).
//   3. A TYPE `url` OR `domain` has no unbracketed dot before the first `/`, `?` or `#` of the value (so none in a scheme, a name, an
//      address, a port or a user, whatever its shape), and none in any authority. The path, the query and the fragment are not touched.
//   4. IPv6 is only a real IPv6 shape: hexadecimal groups and at least two colons, dots only in a trailing dotted quad. `bad.cafe.de::1`
//      is a name; the domain rule comes first for a type `domain` that is not that shape. A bare address that is the whole value keeps the
//      last dot of an IPv4 tail (`::ffff:192.0.2[.]1`); in a type `url` or `domain`, or in an authority, every dot goes.
//   5. A VALUE of hexadecimal digits only (a hash) is returned as it is, whatever its type says; a hash-typed value that is not hex is
//      treated like any other.
//   6. FIXED POINT. `defang(defang(x, t), t) === defang(x, t)`: a bracket that is there is kept, and what is rewritten is only what has
//      not been. The text is scanned once, left to right, so the time is in proportion to its length.
//
// What it does not cover (DEC-224): see there. The shape decides first and the type only decides what has no shape of its own (a
// `url` or `domain` has every dot before its first delimiter bracketed, whatever it looks like).
//
// Hidden characters are not this file's matter: the page escapes them for display after this (`display.ts`), so the rules above
// work on the value as it is.

/** Dots a browser reads as one: the full stop, the ideographic full stop, the full-width full stop, the halfwidth ideographic one. */
const DOT = "\\.\\u3002\\uFF0E\\uFF61";
/** An existing `[.]` (kept) or a bare dot (bracketed). */
const DOT_TOKEN = new RegExp(`\\[\\.\\]|[${DOT}]`, "g");
const COLON_TOKEN = /\[:\]|:/g;

const bracketDots = (text: string): string =>
  text.replace(DOT_TOKEN, (found) => (found === "[.]" ? found : "[.]"));
const bracketColons = (text: string): string =>
  text.replace(COLON_TOKEN, (found) => (found === "[:]" ? found : "[:]"));

const HEX = /^[0-9A-Fa-f]+$/;
const IPV4_PLAIN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
/** `a.b.c.d` with an optional port; each dot may already be `[.]`. No range check: a malformed address is still defanged as one. */
const IPV4 = /^\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}(?::\d{1,5})?$/;
/** An IPv6 address: groups of up to four hex digits with at least two colons (`::` included), the last group a dotted quad at most. */
const IPV6_ADDRESS = /^(?:[0-9A-Fa-f]{0,4}:){2,}(?:[0-9A-Fa-f]{0,4}|\d{1,3}(?:\.\d{1,3}){3})$/;
/** What may follow the `]` of a whole value that is a bracketed address: a port of any length, or text with no delimiter, scheme or user in it. */
const ADDRESS_TAIL = /^[^/\\?#:@[\]]*(?::\d*)?$/;
/** A name: labels of letters, digits, `_` and `-` (any script) joined by dots, the last label letters only or punycode. */
const NAME_LIKE = new RegExp(
  `^(?:[\\p{L}\\p{N}_-]+[${DOT}])+(?:\\p{L}{2,63}|xn--[a-z0-9-]+)[${DOT}]?$`,
  "iu",
);
/** The first delimiter of a value: where a `url` or `domain` stops having to be free of dots. */
const DELIMITER = /[/?#]/;
/** What ends an authority: a slash of either kind, `?` or `#` (a browser reads white space in a user name as part of it). */
const AUTHORITY_STOP = /[/\\?#]/;
/** Where a browser reads a special scheme at the start of a text: scheme-relative slashes, or `scheme:` and its slashes (a scheme has dots). */
const START_SITE = /^(?:([/\\]{2,})|([A-Za-z][A-Za-z0-9+.-]*):([/\\]*))/;
/** Where an authority ends, for a browser: a slash of either kind, `?` or `#`. */
const DELIMITER_ANY = /[/\\?#]/;
const SCHEME_CHAR = /[A-Za-z0-9+-]/;
const LETTER = /[A-Za-z]/;
/** The name after an `@`, and the name or address at the start of a text. */
const AFTER_AT = /@([^\s/\\?#:@]+)/g;
const LEADING = /^(\s*)([^\s/\\?#:@]+)/;

const isSlash = (char: string | undefined): boolean => char === "/" || char === "\\";

function ipv4(address: string): string {
  // already defanged (by hand, or by this function): leave it
  if (address.includes("[.]")) return address;
  return address.replace(/\.(\d{1,3})((?::\d{1,5})?)$/, "[.]$1$2");
}

/** Where the `]` that ends the `[` at 0 is, skipping the `[.]` and `[:]` that were put there; -1 when there is none. */
function closingBracket(text: string): number {
  let at = 1;
  while (at < text.length) {
    if (text.startsWith("[.]", at) || text.startsWith("[:]", at)) at += 3;
    else if (text[at] === "]") return at;
    else at += 1;
  }
  return -1;
}

/**
 * A bracketed host: the colons inside the brackets are bracketed, WHATEVER follows the `]` (a port of any length, a zero-padded one, a
 * second colon, garbage, nothing: a browser reads a port its own way, and a host that is an IPv6 address to it must not be one here), and
 * the dots after the `]` are too. `address` is for a whole value (not an authority): the inside must be a real IPv6 shape and what
 * follows a port or plain text (`ADDRESS_TAIL`); null when the text is not a bracketed host.
 */
function bracketedHost(text: string, everyDot: boolean, address: boolean): string | null {
  // a `[.]` or a `[:]` at the start is what an earlier pass wrote for a dot or a colon, not the brackets of a host
  if (text[0] !== "[" || text.startsWith("[.]") || text.startsWith("[:]")) return null;
  const close = closingBracket(text);
  if (close === -1) return null;
  const inside = text.slice(1, close);
  const after = text.slice(close + 1);
  // a whole value is an address with a port or a little garbage after it, not a URL that happens to begin with one (those are read in pieces)
  if (address && !(IPV6_ADDRESS.test(inside) && ADDRESS_TAIL.test(after))) return null;
  return `[${ipv6Text(inside, everyDot)}]${bracketDots(after)}`;
}

/** The defanged IPv6 address (bracketed, with whatever follows, or bare) or null when the text is not one. */
function ipv6(text: string, everyDot: boolean): string | null {
  const bracketed = bracketedHost(text, everyDot, true);
  if (bracketed !== null) return bracketed;
  return IPV6_ADDRESS.test(text) ? ipv6Text(text, everyDot) : null;
}

function ipv6Text(address: string, everyDot: boolean): string {
  const colons = bracketColons(address);
  return everyDot ? bracketDots(colons) : colons.replace(/\.(\d{1,3})$/, "[.]$1");
}

/** A host, with its port: a bracketed host (whatever follows its `]`), a bare IPv6 address, or every dot of it. */
const hostOf = (hostPort: string): string =>
  bracketedHost(hostPort, true, false) ?? ipv6(hostPort, true) ?? bracketDots(hostPort);

/** An authority: the user name loses every dot, the host as `hostOf` says. */
function authorityOf(authority: string): string {
  const at = authority.lastIndexOf("@");
  const user = at === -1 ? "" : bracketDots(authority.slice(0, at + 1));
  return user + hostOf(authority.slice(at + 1));
}

/** `http` is `hxxp`, `https` is `hxxps`, `ftp` is `fxp`: the letters around the change keep their case. */
const renamed = (scheme: string): string =>
  scheme.replace(/^(h)tt/i, "$1xx").replace(/^(f)tp/i, "$1xp");

/** What a scheme is to a browser: one that is renamed here, one that is special and is not, or any other. */
function schemeKind(scheme: string): "renamed" | "ws" | "file" | null {
  switch (scheme.toLowerCase()) {
    case "http":
    case "https":
    case "ftp":
    case "ftps":
    case "hxxp":
    case "hxxps":
    case "fxp":
    case "fxps":
      return "renamed";
    case "ws":
    case "wss":
      return "ws";
    case "file":
      return "file";
    default:
      return null;
  }
}

/** The scheme that ends at `colon`, read backwards no further than `from`: where it starts, or `colon` when there is none. */
function schemeStart(value: string, from: number, colon: number): number {
  let start = colon;
  while (start > from && SCHEME_CHAR.test(value[start - 1] as string)) start -= 1;
  while (start < colon && !LETTER.test(value[start] as string)) start += 1;
  return start;
}

/** Whether a scheme followed by `slashes` slashes has an authority: a special one has it after any number, another after two. */
const hasAuthority = (scheme: string, slashes: number): boolean =>
  schemeKind(scheme) !== null || slashes >= 2;

/**
 * Where the authority that begins at `from` ends: at the next `/`, `\`, `?` or `#`, or where a scheme with an authority of
 * its own begins INSIDE it (`javascript://a.com:http://b.com`, whose first authority would reach to the slash of the second), so that
 * the nested one is read for what it is. One scan, stopping at the end it finds.
 */
function authorityEnd(value: string, from: number): number {
  let at = from;
  while (at < value.length) {
    const char = value[at] as string;
    if (AUTHORITY_STOP.test(char)) break;
    if (char === ":") {
      const start = schemeStart(value, from, at);
      if (start < at) {
        let after = at + 1;
        while (after < value.length && isSlash(value[after])) after += 1;
        if (hasAuthority(value.slice(start, at), after - at - 1)) return start;
      }
    }
    at += 1;
  }
  return at;
}

/** The defanged authority that begins at `from`, and where it ends. */
function takeAuthority(value: string, from: number): { text: string; end: number } {
  const end = authorityEnd(value, from);
  return { text: authorityOf(value.slice(from, end)), end };
}

type Piece = { text: string; authority: boolean };

/**
 * The value cut into the authorities (already defanged, with their scheme and slashes) and the text between them. One pass, left to
 * right: a colon is looked at once, the scheme before it is read backwards no further than the last thing taken, and an authority is
 * read once, when it is taken.
 */
function pieces(value: string): Piece[] {
  const found: Piece[] = [];
  const length = value.length;
  let taken = 0; // the text before this has been put in a piece
  let from = 0; // where the next colon is looked for, and how far back its scheme may reach
  let lead = 0;
  while (lead < length && isSlash(value[lead])) lead += 1;
  if (lead >= 2) {
    // scheme-relative: it begins with an authority, which a browser reads after `http:`
    const authority = takeAuthority(value, lead);
    found.push({ text: value.slice(0, lead) + authority.text, authority: true });
    taken = from = authority.end;
  }
  for (;;) {
    const colon = value.indexOf(":", from);
    if (colon === -1) break;
    const start = schemeStart(value, from, colon);
    from = colon + 1;
    if (start === colon) continue;
    const scheme = value.slice(start, colon);
    let run = from;
    while (run < length && isSlash(value[run])) run += 1;
    if (!hasAuthority(scheme, run - from)) continue;
    const kind = schemeKind(scheme);
    const authority = takeAuthority(value, run);
    if (start > taken) found.push({ text: value.slice(taken, start), authority: false });
    found.push({
      text:
        (kind === "renamed" ? renamed(scheme) : scheme) +
        ":" +
        value.slice(from, run) +
        authority.text,
      authority: true,
    });
    taken = from = authority.end;
  }
  if (taken < length) found.push({ text: value.slice(taken), authority: false });
  return found;
}

/** A name or an address as the no-scheme rules read it (a `url` or `domain` has every dot of it bracketed). */
function token(text: string, strict: boolean): string {
  if (strict) return bracketDots(text);
  if (IPV4_PLAIN.test(text)) return text.replace(/\.(\d{1,3})$/, "[.]$1");
  return NAME_LIKE.test(text) ? bracketDots(text) : text;
}

/** The text between the authorities: the name after an `@`, and the name or address the value starts with. */
function between(text: string, atStart: boolean, strict: boolean): string {
  const afterAt = text.replace(AFTER_AT, (_found, name: string) => `@${token(name, strict)}`);
  if (!atStart) return afterAt;
  return afterAt.replace(
    LEADING,
    (_found, space: string, name: string) => space + token(name, strict),
  );
}

/**
 * A value that BEGINS (after the white space and control characters a browser skips) with a scheme-relative `//`, or with `ws:`, `wss:`
 * or `file://`, is a URL of a special scheme to a browser, and its host is the text after the last `@` of the first authority, wherever
 * the pieces above cut it. A host with no `[` in it (no dot of it was bracketed: `localhost`, `1234`, or the `localhost` after the
 * last `@` of a nested scheme) is still a host: its name gets the trailing `[.]` no host can have, so that no output is such a URL.
 */
function unparseable(out: string): string {
  let at = 0;
  while (at < out.length && out.charCodeAt(at) <= 0x20) at += 1;
  const found = START_SITE.exec(out.slice(at));
  if (found === null) return out;
  let begin: number;
  if (found[1] !== undefined) begin = at + found[1].length;
  else {
    const scheme = (found[2] as string).toLowerCase();
    const slashes = (found[3] as string).length;
    if (scheme !== "ws" && scheme !== "wss" && !(scheme === "file" && slashes === 2)) return out;
    begin = at + (found[2] as string).length + 1 + slashes;
  }
  const stop = out.slice(begin).search(DELIMITER_ANY);
  const authority = stop === -1 ? out.slice(begin) : out.slice(begin, begin + stop);
  const hostAt = authority.lastIndexOf("@") + 1;
  const host = authority.slice(hostAt);
  const port = host.indexOf(":");
  const name = port === -1 ? host : host.slice(0, port);
  if (name === "" || host.includes("[")) return out;
  const end = begin + hostAt + name.length;
  return `${out.slice(0, end)}[.]${out.slice(end)}`;
}

const isEdge = (char: string): boolean => char.charCodeAt(0) <= 0x20 || /\s/.test(char);

/**
 * The text of a value as the page prints it. Never throws, and returns a string for any input. The white space and the control
 * characters at its two edges (which a browser skips, and the importer strips) are set aside and put back unchanged: an edge space
 * changes nothing.
 */
export function defang(value: string, type: string): string {
  if (typeof value !== "string" || value === "") return "";
  let start = 0;
  let end = value.length;
  while (start < end && isEdge(value[start] as string)) start += 1;
  while (end > start && isEdge(value[end - 1] as string)) end -= 1;
  if (start === 0 && end === value.length) return defanged(value, type);
  return value.slice(0, start) + defanged(value.slice(start, end), type) + value.slice(end);
}

function defanged(value: string, type: string): string {
  if (value === "") return "";
  if (HEX.test(value)) return value;
  const kind = typeof type === "string" ? type.trim().toLowerCase() : "";
  const strict = kind === "url" || kind === "domain";
  if (!strict && IPV4.test(value)) return ipv4(value);
  const address = ipv6(value, strict);
  if (address !== null) return address;
  const out = pieces(value)
    .map((piece, index) =>
      piece.authority ? piece.text : between(piece.text, index === 0, strict),
    )
    .join("");
  if (!strict) return unparseable(out);
  // a url or a domain: no dot that is not bracketed before its first delimiter
  const cut = out.search(DELIMITER);
  return unparseable(
    cut === -1 ? bracketDots(out) : bracketDots(out.slice(0, cut)) + out.slice(cut),
  );
}

/** The three hosts of abuse.ch's own pages for an IOC: ThreatFox, URLhaus and MalwareBazaar. */
export const ABUSE_CH_HOSTS: readonly string[] = [
  "threatfox.abuse.ch",
  "urlhaus.abuse.ch",
  "bazaar.abuse.ch",
];

/** Printable ASCII after `https://`: no space, no control or invisible character, nothing a browser would read differently. */
const REFERENCE_SHAPE = /^https:\/\/[!-~]*$/i;

/**
 * The address a reference may be linked to, or null. It is a link ONLY when the text is `https://` followed by printable ASCII
 * (no space, no backslash, no invisible character), parses as a URL, has no user name and no password, no port but the default
 * one, and a host that is exactly one of `ABUSE_CH_HOSTS` (a look-alike such as `threatfox.abuse.ch.evil.example`, a host that
 * is only in the path or in the user name, a sub-domain, a trailing dot: no). What is returned is the address that was parsed
 * and judged (`URL.href`), never the text that came.
 */
export function abuseChHref(reference: string): string | null {
  if (typeof reference !== "string") return null;
  if (!REFERENCE_SHAPE.test(reference) || reference.includes("\\")) return null;
  let url: URL;
  try {
    url = new URL(reference);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "" || url.port !== "") return null;
  if (!ABUSE_CH_HOSTS.includes(url.hostname)) return null;
  return url.href;
}

/** Whether a reference is one the page may link to (see `abuseChHref`). */
export function isAbuseChReference(url: string): boolean {
  return abuseChHref(url) !== null;
}
