// The filters of the table: the source, the type, the malware, a range of dates, the minimum confidence, and the search box, in one form.
// They act when the form is sent, so a half-typed word is not a request; the page puts the view in the URL and the query follows the URL.
// Every value is checked (`tiParams.viewOfDraft`) before it leaves the form, so the API never sees one it would refuse: the date inputs
// give `YYYY-MM-DD` only, "any confidence" (empty, or 0, the bottom of the box so that the arrows can reach it) is NO parameter, and the
// search is at most 128 characters. The boxes belong to the page (`draft`): it knows when they say something the URL does not, and the
// export waits for the person to send them.
import { useId, useRef, type FormEvent } from "react";
import { TI_MALWARE_MAX, TI_Q_MAX, TI_SOURCES, TI_TYPE_MAX } from "../../api/ti";
import { S, labelOf } from "../../strings";
import type { Draft } from "./tiParams";

const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";
const FIELD =
  "rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";
const LABEL = "flex max-w-full flex-col gap-1 text-xs text-muted";

/** The types the feeds carry today; any other lower-case token may still be typed. */
const KNOWN_TYPES = ["ip:port", "domain", "url", "sha256_hash", "sha1_hash", "md5_hash"] as const;

export function TiFilters({
  draft,
  onDraft,
  filtered,
  onSend,
  onClear,
}: {
  /** What the boxes hold; the page keeps it (the export needs to know when it is not what is applied). */
  draft: Draft;
  onDraft: (next: Draft) => void;
  /** A filter is applied (the URL has one): the clear button is there. */
  filtered: boolean;
  onSend: () => void;
  onClear: () => void;
}) {
  const typeList = useId();
  const search = useRef<HTMLInputElement>(null);
  const set = (name: keyof Draft) => (value: string) => onDraft({ ...draft, [name]: value });

  const send = (event: FormEvent) => {
    event.preventDefault();
    onSend();
  };

  return (
    <form
      role="search"
      aria-label={S.ti.filters.label}
      onSubmit={send}
      className="flex flex-wrap items-end gap-3"
    >
      <label className={LABEL}>
        {S.ti.filters.search}
        <input
          ref={search}
          type="search"
          value={draft.q}
          maxLength={TI_Q_MAX}
          onChange={(event) => set("q")(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          className={`w-72 max-w-full ${FIELD}`}
        />
      </label>
      <label className={LABEL}>
        {S.ti.filters.source}
        <select
          value={draft.source}
          onChange={(event) => set("source")(event.target.value)}
          className={FIELD}
        >
          <option value="">{S.ti.filters.sourceAny}</option>
          {TI_SOURCES.map((source) => (
            <option key={source} value={source}>
              {labelOf(S.ti.source, source)}
            </option>
          ))}
        </select>
      </label>
      <label className={LABEL}>
        {S.ti.filters.type}
        <input
          type="text"
          list={typeList}
          value={draft.type}
          maxLength={TI_TYPE_MAX}
          placeholder={S.ti.filters.typePlaceholder}
          onChange={(event) => set("type")(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          className={`w-40 ${FIELD}`}
        />
        <datalist id={typeList}>
          {KNOWN_TYPES.map((type) => (
            <option key={type} value={type} />
          ))}
        </datalist>
      </label>
      <label className={LABEL}>
        {S.ti.filters.malware}
        <input
          type="text"
          value={draft.malware}
          maxLength={TI_MALWARE_MAX}
          onChange={(event) => set("malware")(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          className={`w-44 ${FIELD}`}
        />
      </label>
      <label className={LABEL}>
        {S.ti.filters.from}
        <input
          type="date"
          value={draft.from}
          min="1970-01-01"
          max="2999-12-31"
          onChange={(event) => set("from")(event.target.value)}
          className={FIELD}
        />
      </label>
      <label className={LABEL}>
        {S.ti.filters.to}
        <input
          type="date"
          value={draft.to}
          min="1970-01-01"
          max="2999-12-31"
          onChange={(event) => set("to")(event.target.value)}
          className={FIELD}
        />
      </label>
      <label className={LABEL}>
        {S.ti.filters.confidence}
        <input
          type="number"
          inputMode="numeric"
          min={0}
          max={100}
          step={1}
          value={draft.confidence}
          onChange={(event) => set("confidence")(event.target.value)}
          className={`w-28 ${FIELD}`}
        />
      </label>
      <button type="submit" className={BUTTON}>
        {S.ti.filters.apply}
      </button>
      {(filtered || Object.values(draft).some(Boolean)) && (
        <button
          type="button"
          className={BUTTON}
          onClick={() => {
            onClear();
            search.current?.focus();
          }}
        >
          {S.ti.filters.clear}
        </button>
      )}
      <p className="basis-full text-xs text-muted">{S.ti.filters.confidenceHint}</p>
    </form>
  );
}
