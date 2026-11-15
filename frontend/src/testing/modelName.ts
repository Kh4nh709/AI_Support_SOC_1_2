// The G5 guard of the AI analysis panels (DEC-221): the model's name appears nowhere on the page. A test reads
// everything a person or a screen reader could read in a container (its text, and the attributes that carry words) and
// holds it against this pattern. "mô hình" is the Vietnamese word for a model and is not a name, so it does not match;
// "model:" is the label of a line that would name one.
export const MODEL_NAME = /glm|gpt|deepseek|claude|model:/i;

/** The attributes a tooltip, a label or an image's text can carry. */
const WORDY = ["title", "aria-label", "aria-description", "alt", "placeholder", "value"];

/** The text of `root` and the value of every attribute in it that says something to a person. */
export function readableOf(root: Element): string[] {
  const words = [root.textContent ?? ""];
  for (const element of [root, ...root.querySelectorAll("*")]) {
    for (const name of WORDY) {
      const value = element.getAttribute(name);
      if (value !== null && value !== "") words.push(value);
    }
  }
  return words;
}

/** What in `root` reads as a model's name: the empty list when the guard holds. */
export function modelNamesIn(root: Element): string[] {
  return readableOf(root).filter((word) => MODEL_NAME.test(word));
}
