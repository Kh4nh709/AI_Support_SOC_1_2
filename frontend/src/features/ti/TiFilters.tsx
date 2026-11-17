// The filters of the table: the source, the type, the malware, a range of dates, the minimum confidence, and the search box, in one form.
// They act when the form is sent, so a half-typed word is not a request; the page puts the view in the URL and the query follows the URL.
// Every value is checked (`tiParams`) before it leaves the form, so the API never sees one it would refuse: the date inputs give
// `YYYY-MM-DD` only, "any confidence" (empty, or 0, which is the bottom of the box so the arrows can reach it) is NO parameter, and the search is at most 128 characters. The draft of the form
// follows the URL when the URL changes it (Xoá bộ lọc, the back button), and is left alone while somebody types.
import { useId, useState, type FormEvent } from "react";
import { TI_MALWARE_MAX, TI_Q_MAX, TI_SOURCES, TI_TYPE_MAX, isTiSource } from "../../api/ti";
import { S, labelOf } from "../../strings";
import {
  EMPTY_VIEW,
  cleanConfidence,
  cleanDay,
  cleanMalware,
  cleanQuery,
  cleanType,
  viewSearch,
  type TiView,
} from "./tiParams";

const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";
const FIELD =
  "rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";
const LABEL = "flex flex-col gap-1 text-xs text-muted";

/** The types the feeds carry today; any other lower-case token may still be typed. */
const KNOWN_TYPES = ["ip:port", "domain", "url", "sha256_hash", "sha1_hash", "md5_hash"] as const;

type Draft = {
  source: string;
  type: string;
  malware: string;
  from: string;
  to: string;
  confidence: string;
  q: string;
};

const draftOf = (view: TiView): Draft => ({
  source: view.source ?? "",
  type: view.type,
  malware: view.malware,
  from: view.from,
  to: view.to,
  confidence: view.minConfidence === null ? "" : String(view.minConfidence),
  q: view.q,
});

export function TiFilters({ view, onApply }: { view: TiView; onApply: (next: TiView) => void }) {
  const typeList = useId();
  const key = viewSearch({ ...view, page: 1 });
  const [applied, setApplied] = useState(key);
  const [draft, setDraft] = useState<Draft>(() => draftOf(view));
  if (applied !== key) {
    setApplied(key);
    setDraft(draftOf(view));
  }
  const set = (name: keyof Draft) => (value: string) =>
    setDraft((was) => ({ ...was, [name]: value }));

  const send = (event: FormEvent) => {
    event.preventDefault();
    onApply({
      source: isTiSource(draft.source) ? draft.source : null,
      type: cleanType(draft.type),
      malware: cleanMalware(draft.malware),
      from: cleanDay(draft.from),
      to: cleanDay(draft.to),
      minConfidence: cleanConfidence(draft.confidence.trim()),
      q: cleanQuery(draft.q),
      page: 1,
    });
  };
  const filtered = key !== "";

  return (
    <form
      role="search"
      aria-label={S.ti.filters.label}
      onSubmit={send}
      className="flex flex-wrap items-end gap-3"
    >
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
      <label className={LABEL}>
        {S.ti.filters.search}
        <input
          type="search"
          value={draft.q}
          maxLength={TI_Q_MAX}
          onChange={(event) => set("q")(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          className={`w-72 ${FIELD}`}
        />
      </label>
      <button type="submit" className={BUTTON}>
        {S.ti.filters.apply}
      </button>
      {filtered && (
        <button type="button" className={BUTTON} onClick={() => onApply(EMPTY_VIEW)}>
          {S.ti.filters.clear}
        </button>
      )}
      <p className="basis-full text-xs text-muted">{S.ti.filters.confidenceHint}</p>
    </form>
  );
}
