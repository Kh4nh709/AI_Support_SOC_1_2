// A whole-word search for the "leak markers" of the blind-arm tests (P14-T03 fix round 1, M6). A marker such as
// "FP" or "TP" must be found as a word and never inside another one ("SFTP", "HTTP", "ATTP"), or an unrelated
// word of the page would fail a test that is about ①. The edges are Unicode letters, digits and the underscore,
// so a Vietnamese phrase ("AI kết luận") and a code (`fp_policy:severity`) are matched whole too.
//
// Test support only: nothing in the product imports it.

const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Whether `word` occurs in `text` as a word of its own. */
export function containsWord(text: string, word: string): boolean {
  if (word === "") return false;
  return new RegExp(`(?<![\\p{L}\\p{N}_])${escape(word)}(?![\\p{L}\\p{N}_])`, "u").test(text);
}

/** The markers of `words` that occur in `text` as words: `[]` is a text with no leak. */
export function wordsFound(text: string, words: readonly string[]): string[] {
  return words.filter((word) => containsWord(text, word));
}

/** The markers of `phrases` that occur in `text` as plain substrings (a phrase may be glued to a neighbour). */
export function phrasesFound(text: string, phrases: readonly string[]): string[] {
  return phrases.filter((phrase) => phrase !== "" && text.includes(phrase));
}

/**
 * The text of `root`, read per text node and joined with a line break. `textContent` glues the text of
 * neighbouring elements ("Đề xuất" beside "Cần xem xét" reads "Đề xuấtCần xem xét"), so a whole-word search over
 * it loses a marker at the seam; here the seam is a line break, a non-letter, and a marker at the edge of an
 * element is still a word of its own. A phrase never spans two text nodes.
 */
export function textOf(root: Node): string {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const parts: string[] = [];
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    const text = node.textContent ?? "";
    if (text !== "") parts.push(text);
  }
  return parts.join("\n");
}
