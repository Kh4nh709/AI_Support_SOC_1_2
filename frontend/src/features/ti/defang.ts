// What the Threat Intel page shows of an IOC's value (DEC-224, spec section 8), and the one place a value may become a link.
//
// `defang(value, type)` is the text the page prints for a URL, a domain or an address: it can be read, and pasted into a chat or a
// ticket, without becoming a live link. It is a DISPLAY rule only: the copy button copies the original, and nothing here (or on
// the page) builds a link, a request or an attribute out of a value. The rules, by what the value is:
//
//   a URL        the scheme of every `http`, `https`, `ftp`, `ftps` followed by `://` anywhere in the value loses its two t's
//                (`hxxp://`, `hxxps://`, `fxp://`; the case of the other letters is kept), and the AUTHORITY after it (the text up to
//                the next `/`, `?`, `#` or white space) loses every dot: `[.]`. An authority that is an IPv4 address is shown as an
//                address (its last dot), one that is a bracketed IPv6 address as an IPv6 address (below). The path, the query and
//                the fragment are left as they are, except that a URL carried inside them is defanged by the same rule.
//                A value of the type `url` with no such scheme (or whose scheme a hidden character breaks) has every dot defanged.
//   a domain     every dot: `evil.example.com` is `evil[.]example[.]com` (so are the ideographic and full-width full stops, which a
//                browser reads as dots).
//   an IPv4      the last dot: `192.0.2.10` is `192.0.2[.]10`, `192.0.2.10:443` is `192.0.2[.]10:443`.
//   an IPv6      every colon of the address is bracketed: `2001:db8::1` is `2001[:]db8[:][:]1`, and `[2001:db8::1]:443` is
//                `[2001[:]db8[:][:]1]:443` (the brackets and the port after them are the value's own); an IPv4 tail loses its last dot.
//   a hash       a value of hexadecimal digits only is returned as it is, whatever its type says.
//   anything else is returned as it is, unless it has the shape of a URL, an address or a name, in which case it is treated as one.
//
// The SHAPE decides first and the type only decides what has no shape of its own (a `url` with no scheme, a `domain` that is a
// single label): a hash-typed value that is a URL is a URL here. A value that is already defanged is not defanged twice (a bracket
// that is there is kept, the rest is completed): `defang(defang(x, t), t) === defang(x, t)`.
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
/** `a.b.c.d` with an optional port; each dot may already be `[.]`. No range check: a malformed address is still defanged as one. */
const IPV4 = /^\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}(?::\d{1,5})?$/;
const IPV6_BRACKETED = /^\[([0-9A-Fa-f:.]+)\](:\d{1,5})?$/;
const IPV6_BARE = /^[0-9A-Fa-f:.]+$/;
/** A host name: labels of letters, digits, `_` and `-`, a last label of letters, an optional trailing dot and port. */
const DOMAIN_LIKE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,63}\.?(?::\d{1,5})?$/;
/** A scheme with its slashes, and the authority after them. Defanged spellings (`hxxp`, `fxp`) are matched too: they get their dots. */
const SCHEME_AUTHORITY = /(h(?:tt|xx)ps?|f(?:tp|xp)s?):\/\/([^\s/?#]*)/gi;

const colonsIn = (text: string): number => text.split(":").length - 1;

function ipv4(address: string): string {
  // already defanged (by hand, or by this function): leave it
  if (address.includes("[.]")) return address;
  return address.replace(/\.(\d{1,3})((?::\d{1,5})?)$/, "[.]$1$2");
}

/** The defanged IPv6 address (bracketed with a port, or bare) or null when the text is not one. */
function ipv6(text: string): string | null {
  const bracketed = IPV6_BRACKETED.exec(text);
  if (bracketed !== null) {
    const inner = bracketed[1] as string;
    if (colonsIn(inner) < 2) return null;
    return `[${ipv6Inner(inner)}]${bracketed[2] ?? ""}`;
  }
  if (IPV6_BARE.test(text) && colonsIn(text) >= 2) return ipv6Inner(text);
  return null;
}

function ipv6Inner(inner: string): string {
  return bracketColons(inner).replace(/\.(\d{1,3})$/, "[.]$1");
}

function hostOf(hostPort: string): string {
  if (IPV4.test(hostPort)) return ipv4(hostPort);
  return ipv6(hostPort) ?? bracketDots(hostPort);
}

function authorityOf(authority: string): string {
  const at = authority.lastIndexOf("@");
  if (at === -1) return hostOf(authority);
  return bracketDots(authority.slice(0, at + 1)) + hostOf(authority.slice(at + 1));
}

/** `http` is `hxxp`, `https` is `hxxps`, `ftp` is `fxp`: the letters around the change keep their case. */
function schemeOf(scheme: string): string {
  return scheme.replace(/^(h)tt/i, "$1xx").replace(/^(f)tp/i, "$1xp");
}

/** The text the page prints for an IOC's `value` of this `type`. Never throws, and returns a string for any input. */
export function defang(value: string, type: string): string {
  if (typeof value !== "string" || value === "") return "";
  if (HEX.test(value)) return value;
  let schemed = false;
  const out = value.replace(SCHEME_AUTHORITY, (_found, scheme: string, authority: string) => {
    schemed = true;
    return `${schemeOf(scheme)}://${authorityOf(authority)}`;
  });
  if (schemed) return out;
  const kind = typeof type === "string" ? type.trim().toLowerCase() : "";
  if (kind === "url") return bracketDots(value);
  if (IPV4.test(value)) return ipv4(value);
  const six = ipv6(value);
  if (six !== null) return six;
  if (kind === "domain" || DOMAIN_LIKE.test(value)) return bracketDots(value);
  return value;
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
