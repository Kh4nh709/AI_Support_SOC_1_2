// How the Threat Intel page prints the text of an IOC. Every field of an IOC came from a public feed, and the importer does not refuse
// a bidirectional override or a zero-width character in one: a right-to-left override can make a name read as another, a zero-width
// space can hide a letter. So what the page PRINTS of a field is `shown(text)`: each character a person cannot see is written out
// as its escape (`\u202e`), the same way the audit page and the raw body of a SOAR ticket do (src/visibleText.ts). What the page
// COPIES is the original text, which `shown` never touches. (A value that really contains the characters `\u202e` is shown the
// same as one that contains the override: the copy button is the way to tell them apart.)
import { visible } from "../../visibleText";
import { defang } from "./defang";

/** The text of a field as the page prints it: invisible characters written out, everything else as it is. */
export const shown = (text: string): string => visible(text);

/** The value of an IOC as the page prints it: defanged for its type, then the invisible characters written out. */
export const shownValue = (ioc: { value: string; type: string }): string =>
  shown(defang(ioc.value, ioc.type));

/** At most `max` characters (counted as code points, so no pair is cut) of the text, with an ellipsis when something was cut. */
export function clipped(text: string, max: number): string {
  const characters = Array.from(text);
  return characters.length <= max ? text : `${characters.slice(0, max - 1).join("")}…`;
}
