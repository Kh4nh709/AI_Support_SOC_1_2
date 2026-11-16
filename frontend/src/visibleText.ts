// The characters a person cannot see, and the text with each of them written out as its escape. Shared by the audit page (the
// summary lines and the payload, features/admin/auditSummary.ts) and by the page of the SOAR tickets (the raw body n8n sent):
// it is a module of its own so that the page every role opens does not carry the audit page's 42 event builders to get it.

// The C0 controls but tab, line feed and carriage return; DEL and the C1 controls; the soft hyphen; the
// combining grapheme joiner; the Arabic letter mark; the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0); the
// mongolian vowel separator; the zero-width and bidi marks, the line and paragraph separators, the word joiner
// and its invisible neighbours; the blank braille pattern; the variation selectors (U+FE00 to U+FE0F); the
// byte-order mark; the interlinear annotation marks; and the Tag characters (U+E0001, U+E0020 to U+E007F),
// which spell ASCII text a person cannot see and a model may read. A right-to-left override among them could
// make one name read as another. The Tag characters are outside the BMP, so the pattern has the `u` flag.
// Text in other scripts (Vietnamese in NFC or NFD, CJK, Arabic, Hebrew) is none of these and is left alone.
const INVISIBLE_RANGES: readonly (readonly [number, number])[] = [
  [0x00, 0x08],
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x61c, 0x61c],
  [0x115f, 0x1160],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x2800, 0x2800],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff9, 0xfffb],
  [0xe0001, 0xe0001],
  [0xe0020, 0xe007f],
];
/** The escape of a code point as the text shows it: four hex digits, or `{...}` for one outside the BMP. */
const escapeOf = (code: number): string =>
  code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, "0")}`;
// The ranges as the inside of a character class, each end an escape: no control character is written into
// the source, and none can be lost from it.
const CLASS = INVISIBLE_RANGES.map(
  ([from, to]) => `${escapeOf(from)}${from === to ? "" : `-${escapeOf(to)}`}`,
).join("");
const INVISIBLE = new RegExp(`[${CLASS}]`, "gu");

/** True when the text holds a character a person cannot see. */
export const hasInvisible = (text: string): boolean => new RegExp(`[${CLASS}]`, "u").test(text);

/**
 * A text with each character a person cannot see written as its escape (`\u` and four hex digits, or
 * `\u{...}` outside the BMP), so what is shown is what is there.
 */
export function visible(text: string): string {
  return text.replace(INVISIBLE, (ch) => escapeOf(ch.codePointAt(0) ?? 0));
}
