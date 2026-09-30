// The filters of the queue and the chips of the band counts. Both only report a new set of filters: the page
// puts it in the URL, and the query key follows the URL. The band and the status act when they change; the
// two free-text filters (category, agent) act when the form is sent, so a half-typed word is not a request.
// There is no facet endpoint to list the categories or the agents, hence text and not a select.
import { useState, type FormEvent } from "react";
import { BAND_CODES, isBandCode, type BandCode } from "../../api/types";
import type { QueueFilters } from "../../api/tier1";
import { BAND_OUTLINE, BAND_SOLID } from "../../components/Badge";
import { S, labelOf } from "../../strings";

const CONTROL =
  "rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";
const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";

/** The chips: one per band, its count from `counts_by_band`, most serious first. A pressed chip is the filter. */
export function BandChips({
  counts,
  band,
  onPick,
}: {
  counts: Record<BandCode, number>;
  band: BandCode | undefined;
  /** The band to filter on, or `undefined` to drop the filter (pressing the pressed chip). */
  onPick: (band: BandCode | undefined) => void;
}) {
  return (
    <div role="group" aria-label={S.queue.bandCounts} className="flex flex-wrap gap-2">
      {BAND_CODES.map((code) => {
        const pressed = band === code;
        return (
          <button
            key={code}
            type="button"
            aria-pressed={pressed}
            onClick={() => onPick(pressed ? undefined : code)}
            className={`rounded border px-3 py-1 text-sm font-medium focus-visible:outline-2 focus-visible:outline-text ${
              pressed ? `${BAND_SOLID[code]} border-transparent` : BAND_OUTLINE[code]
            }`}
          >
            {S.queue.bandChip(labelOf(S.band, code), counts[code] ?? 0)}
          </button>
        );
      })}
    </div>
  );
}

export function QueueFilterBar({
  filters,
  filtered,
  onChange,
  onClear,
}: {
  filters: QueueFilters;
  /** Some filter is set (so there is something to clear). */
  filtered: boolean;
  onChange: (next: QueueFilters) => void;
  onClear: () => void;
}) {
  // The drafts of the two text inputs. The page gives the bar a key of the applied values, so the drafts
  // start again when the URL changes them (Xoá bộ lọc, the back button) and not while somebody types.
  const [category, setCategory] = useState(filters.category ?? "");
  const [agent, setAgent] = useState(filters.agent ?? "");

  function send(event: FormEvent) {
    event.preventDefault();
    const next: QueueFilters = { status: filters.status };
    if (filters.band) next.band = filters.band;
    if (category.trim() !== "") next.category = category.trim();
    if (agent.trim() !== "") next.agent = agent.trim();
    onChange(next);
  }

  return (
    <form
      onSubmit={send}
      aria-label={S.queue.filtersLabel}
      className="flex flex-wrap items-end gap-3"
    >
      <label className="flex flex-col gap-1 text-xs text-muted">
        {S.queue.filter.band}
        <select
          className={CONTROL}
          value={filters.band ?? ""}
          onChange={(e) => {
            const value = e.target.value;
            const next: QueueFilters = { ...filters };
            delete next.band;
            if (isBandCode(value)) next.band = value;
            onChange(next);
          }}
        >
          <option value="">{S.queue.filter.all}</option>
          {BAND_CODES.map((code) => (
            <option key={code} value={code}>
              {labelOf(S.band, code)}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        {S.queue.filter.status}
        <select
          className={CONTROL}
          value={filters.status}
          onChange={(e) =>
            onChange({ ...filters, status: e.target.value === "mine" ? "mine" : "queued" })
          }
        >
          <option value="queued">{S.queue.filter.waiting}</option>
          <option value="mine">{S.queue.filter.mine}</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        {S.queue.filter.category}
        <input
          type="text"
          className={CONTROL}
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        {S.queue.filter.agent}
        <input
          type="text"
          className={CONTROL}
          value={agent}
          onChange={(e) => setAgent(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      <button type="submit" className={BUTTON}>
        {S.queue.filter.apply}
      </button>
      {filtered && (
        <button type="button" className={BUTTON} onClick={onClear}>
          {S.queue.filter.clear}
        </button>
      )}
    </form>
  );
}
