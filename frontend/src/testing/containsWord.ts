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
