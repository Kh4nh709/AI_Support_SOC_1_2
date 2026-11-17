// The export (spec sections 7 and 8): the admin's alone, so for any other role it renders NOTHING (hidden, not disabled; the API
// refuses the others on its own). CSV and blocklist, for the APPLIED filters (the list's), never for what the form holds and "Lọc" has not sent. The file is fetched through the API client as a
// blob (the Bearer header: a plain link to the route would carry none) and handed to the browser as an object URL under the page's own
// fixed name (`download.ts`). A busy server, a request for too many rows and a refusal each say so in words; the blocklist carries the
// reminder that a person reads it before it is fed to a firewall.
import { useId, useState } from "react";
import { ApiError } from "../../api/client";
import {
  TI_EXPORT_MAX_ROWS,
  fetchTiExport,
  isTiBusy,
  type TiExportFormat,
  type TiFilters,
} from "../../api/ti";
import { useAuth } from "../../auth/AuthProvider";
import { Toast } from "../../components/Toast";
import { S } from "../../strings";
import { saveBlob } from "./download";

const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-60";

/** What a failed export says. */
function failureText(error: unknown): string {
  if (isTiBusy(error)) return S.ti.busy;
  if (error instanceof ApiError) {
    if (error.status === 403) return S.ti.export.forbidden;
    const detail = error.detail as { reason?: unknown; limit?: unknown } | null;
    if (
      error.status === 422 &&
      detail !== null &&
      typeof detail === "object" &&
      detail.reason === "too_many_rows"
    ) {
      const limit = typeof detail.limit === "number" ? detail.limit : TI_EXPORT_MAX_ROWS;
      return S.ti.export.tooMany(limit);
    }
  }
  return S.ti.export.failed;
}

export function ExportControl({
  filters,
  unapplied,
}: {
  /** The APPLIED filters (the URL's): what the export is for. */
  filters: TiFilters;
  /** The form holds a filter that has not been sent: the buttons wait, with a hint. */
  unapplied: boolean;
}) {
  const { session } = useAuth();
  const hint = useId();
  const [working, setWorking] = useState<TiExportFormat | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  if (session?.role !== "admin") return null;

  async function run(format: TiExportFormat) {
    setWorking(format);
    setDone(null);
    setFailure(null);
    try {
      const blob = await fetchTiExport(format, filters);
      setDone(S.ti.export.done(saveBlob(blob, format)));
    } catch (error) {
      setFailure(failureText(error));
    } finally {
      setWorking(null);
    }
  }

  const button = (format: TiExportFormat, label: string) => (
    <button
      type="button"
      disabled={working !== null || unapplied}
      aria-describedby={unapplied ? hint : undefined}
      onClick={() => void run(format)}
      className={BUTTON}
    >
      {working === format ? S.ti.export.working : label}
    </button>
  );

  return (
    <div role="group" aria-label={S.ti.export.label} className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3">
        {button("csv", S.ti.export.csv)}
        {button("blocklist", S.ti.export.blocklist)}
        <span className="text-xs text-muted">{S.ti.export.scope(TI_EXPORT_MAX_ROWS)}</span>
      </div>
      {unapplied && (
        <p id={hint} className="text-xs text-medium">
          {S.ti.export.unapplied}
        </p>
      )}
      <p className="text-xs text-muted">{S.ti.export.review}</p>
      {failure !== null && (
        <p role="alert" className="text-sm text-critical">
          {failure}
        </p>
      )}
      {done !== null && <Toast onClose={() => setDone(null)}>{done}</Toast>}
    </div>
  );
}
