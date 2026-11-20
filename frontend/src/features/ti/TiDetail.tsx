// The detail panel of an IOC, opened from a row: every field, the value defanged beside its own copy button, and the reference as a link
// only when it is one of abuse.ch's own pages (`Reference`). The data is the row the list already served (nothing is fetched), kept by
// the page so the panel stays when the list moves to another page. EVERYTHING in it is a text child printed through `shown`; the only
// link is the reference's. Escape and the close button end it, and the focus goes back to the row it came from.
import { useEffect, useId, useRef, type KeyboardEvent } from "react";
import type { TiIoc } from "../../api/ti";
import { KeyValueGrid, type KeyValueItem } from "../../components/KeyValueGrid";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { CopyButton } from "./CopyButton";
import { shown, shownValue } from "./display";
import { Reference } from "./Reference";

const D = S.ti.detail;
const CLOSE =
  "shrink-0 rounded border border-border px-3 py-1 text-sm hover:bg-ground focus-visible:outline-2 focus-visible:outline-text";

const textOrDash = (text: string | null): string =>
  text === null || text === "" ? S.common.missing : shown(text);
const timeOrDash = (iso: string | null): string =>
  iso === null ? S.common.missing : formatDateTime(iso);

function fieldsOf(ioc: TiIoc): KeyValueItem[] {
  const F = D.field;
  const tags = Array.isArray(ioc.tags) ? ioc.tags : [];
  return [
    { label: F.id, value: <span className="font-mono">{String(ioc.id)}</span> },
    {
      label: F.value,
      value: (
        <div className="flex flex-col items-start gap-1">
          <span className="font-mono text-xs wrap-anywhere">{shownValue(ioc)}</span>
          <CopyButton value={ioc.value} id={ioc.id} />
        </div>
      ),
    },
    { label: F.type, value: shown(ioc.type) },
    { label: F.source, value: shown(labelOf(S.ti.source, ioc.source)) },
    { label: F.malware, value: textOrDash(ioc.malware) },
    { label: F.threat, value: textOrDash(ioc.threat) },
    {
      label: F.confidence,
      value: typeof ioc.confidence === "number" ? String(ioc.confidence) : S.common.missing,
    },
    { label: F.tags, value: tags.length === 0 ? D.noTags : tags.map(shown).join(", ") },
    { label: F.reference, value: <Reference reference={ioc.reference} /> },
    { label: F.firstSeen, value: timeOrDash(ioc.first_seen) },
    { label: F.lastSeen, value: timeOrDash(ioc.last_seen) },
    { label: F.importedAt, value: timeOrDash(ioc.imported_at) },
    { label: F.expiresAt, value: timeOrDash(ioc.expires_at) },
    { label: F.expired, value: ioc.expired === true ? D.yes : null },
    { label: F.hitCount, value: String(ioc.hit_count) },
    { label: F.lastHit, value: timeOrDash(ioc.last_hit) },
  ];
}

export function TiDetail({ ioc, onClose }: { ioc: TiIoc; onClose: () => void }) {
  const titleId = useId();
  const box = useRef<HTMLElement>(null);
  // The focus goes to the panel when it opens or moves to another IOC: the person asked for it.
  useEffect(() => {
    box.current?.focus();
  }, [ioc.id]);

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    event.preventDefault();
    onClose();
  };

  return (
    <section
      ref={box}
      aria-labelledby={titleId}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      className="flex w-full min-w-0 flex-col gap-4 rounded border border-border bg-surface p-4 focus:outline-none"
    >
      <div className="flex items-start justify-between gap-3">
        <h2 id={titleId} className="min-w-0 text-base font-semibold wrap-anywhere">
          {D.title(ioc.id)}
        </h2>
        <button type="button" onClick={onClose} className={CLOSE}>
          {D.close}
        </button>
      </div>
      <KeyValueGrid items={fieldsOf(ioc)} columns={1} />
    </section>
  );
}
