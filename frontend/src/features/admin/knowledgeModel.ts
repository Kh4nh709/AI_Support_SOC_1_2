// The form of a knowledge draft as plain values (P13-T06), apart from the component that draws it, so what an edit
// sends can be tested without a page.
//
//   - A list field (`distinguishing_signals`, `check_next_time`) is one line per item in its box: `linesOf` and
//     `textOfLines` are the two directions, and a blank line is no item.
//   - What changed is told on trimmed values and on the tags as a set, so a space at the end of a line or a tag
//     picked, dropped and picked again is not an edit. `editsOf` then names only the fields that changed, or all six
//     when the draft had no text (there is nothing for the route to keep). It names the six MODEL fields and no
//     other: the closed fields are the source's and the route refuses a request that names one.
//   - A fault of V1-V5 is shown at the field named after the colon; one with no field of the draft is shown above
//     the form (`faultsByField`).
import {
  KNOWLEDGE_CLOSED_FIELDS,
  KNOWLEDGE_MODEL_FIELDS,
  type KnowledgeDraftFields,
  type KnowledgeEdit,
  type KnowledgeFault,
  type KnowledgeModelField,
} from "../../api/admin";

/** The editable values: a text per text field, one line per item for the two lists, and the tags picked. */
export type DraftForm = {
  title: string;
  summary: string;
  signals: string;
  checks: string;
  note: string;
  tags: readonly string[];
};

/** The lines of a box: trimmed, the empty ones dropped. */
export function linesOf(text: string): string[] {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** The box of a list: one item to a line. */
export function textOfLines(items: readonly string[]): string {
  return items.join("\n");
}

const textOf = (value: unknown): string => (typeof value === "string" ? value : "");

const itemsOf = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

/** The form of a stored draft; a field that is missing or of the wrong type is empty. `{}` (no text) is an empty form. */
export function formOf(draft: Partial<KnowledgeDraftFields>): DraftForm {
  return {
    title: textOf(draft.title),
    summary: textOf(draft.summary),
    signals: textOfLines(itemsOf(draft.distinguishing_signals)),
    checks: textOfLines(itemsOf(draft.check_next_time)),
    note: textOf(draft.confidence_note),
    tags: itemsOf(draft.tags),
  };
}

/** The same tags, whatever the order and the repeats. */
export function sameTags(a: readonly string[], b: readonly string[]): boolean {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...left].every((tag) => right.has(tag));
}

/** What the route reads of a form, by the name of the model field. */
function valueOf(form: DraftForm, field: KnowledgeModelField): string | string[] {
  switch (field) {
    case "title":
      return form.title.trim();
    case "summary":
      return form.summary.trim();
    case "distinguishing_signals":
      return linesOf(form.signals);
    case "check_next_time":
      return linesOf(form.checks);
    case "confidence_note":
      return form.note.trim();
    case "tags":
      return [...form.tags];
  }
}

function same(field: KnowledgeModelField, a: DraftForm, b: DraftForm): boolean {
  const left = valueOf(a, field);
  const right = valueOf(b, field);
  if (field === "tags") return sameTags(left as string[], right as string[]);
  if (typeof left === "string") return left === right;
  return JSON.stringify(left) === JSON.stringify(right);
}

/** The model fields whose value differs between the two forms, in the order of `KNOWLEDGE_MODEL_FIELDS`. */
export function changedFields(initial: DraftForm, current: DraftForm): KnowledgeModelField[] {
  return KNOWLEDGE_MODEL_FIELDS.filter((field) => !same(field, initial, current));
}

export function isDirty(initial: DraftForm, current: DraftForm): boolean {
  return changedFields(initial, current).length > 0;
}

/**
 * The `edited` of an approval: the fields that changed, or all six with `sendAll` (a draft with no text). Only the
 * six model fields can be named here, never a closed one.
 */
export function editsOf(initial: DraftForm, current: DraftForm, sendAll: boolean): KnowledgeEdit {
  const fields = sendAll ? KNOWLEDGE_MODEL_FIELDS : changedFields(initial, current);
  const edit: Record<string, string | string[]> = {};
  for (const field of fields) edit[field] = valueOf(current, field);
  return edit as KnowledgeEdit;
}

/** The twelve fields of a draft: where a fault named after one of them is shown. */
const DRAFT_FIELDS: ReadonlySet<string> = new Set([
  ...KNOWLEDGE_MODEL_FIELDS,
  ...KNOWLEDGE_CLOSED_FIELDS,
]);

export type FaultPlaces = {
  /** By field of the draft, the order of the route kept. A field with no fault is absent. */
  byField: Partial<Record<string, KnowledgeFault[]>>;
  /** The faults with no field of the draft (`root`, `unexpected_key`, `unknown_tag`, a name with no colon). */
  general: KnowledgeFault[];
};

/** Sorts the faults of a 422 into the field each belongs to, and the ones that belong to none. */
export function faultsByField(faults: readonly KnowledgeFault[]): FaultPlaces {
  const byField: Record<string, KnowledgeFault[]> = {};
  const general: KnowledgeFault[] = [];
  for (const fault of faults) {
    if (fault.field !== null && DRAFT_FIELDS.has(fault.field)) {
      (byField[fault.field] ??= []).push(fault);
    } else {
      general.push(fault);
    }
  }
  return { byField, general };
}
