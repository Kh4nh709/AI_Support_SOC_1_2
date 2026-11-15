// The G5 guard of the AI analysis panels (DEC-221): the model's name appears nowhere on the page. A test reads
// everything a person or a screen reader could read in a container (its text, and the attributes that carry words or a
// link: a tooltip, a label, a link's target, every `data-*` value) and holds it against this pattern. "mô hình" is the
// Vietnamese word for a model and is not a name, so it does not match; "model:" is the label of a line that would name one.
// The names are the families the product could be pointed at; the retrieval service the RAG notice names ("Voyage") is a
// different matter and is not a model's name here.
export const MODEL_NAME = /glm|gpt|deepseek|claude|qwen|llama|gemini|mistral|kimi|model:/i;

/** The attributes a tooltip, a label or an image's text can carry. */
const WORDY = ["title", "aria-label", "aria-description", "alt", "placeholder", "value"];

/** The attributes of `element` that say something to a person or a link: the wordy ones, every `data-*`, and `href`. */
function attributesOf(element: Element): string[] {
  const names = [
    ...WORDY,
    ...element.getAttributeNames().filter((name) => name.startsWith("data-")),
    "href",
  ];
  const values: string[] = [];
  for (const name of names) {
    const value = element.getAttribute(name);
    if (value !== null && value !== "") values.push(value);
  }
  return values;
}

/** The text of `root` and the value of every attribute in it that says something to a person or a link. */
export function readableOf(root: Element): string[] {
  const words = [root.textContent ?? ""];
  for (const element of [root, ...root.querySelectorAll("*")]) words.push(...attributesOf(element));
  return words;
}

/** What in `root` reads as a model's name: the empty list when the guard holds. */
export function modelNamesIn(root: Element): string[] {
  return readableOf(root).filter((word) => MODEL_NAME.test(word));
}
