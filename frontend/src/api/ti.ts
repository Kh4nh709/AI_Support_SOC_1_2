// The Threat Intel routes (DEC-224, backend/app/web/routers/ti.py), one typed function each. The shapes are written by hand against the
// backend, as the other route files are; src/api/tiContract.test.ts reads the Python source and holds the keys, the bounds and the
// file names to it. EVERYTHING in an IOC (value, malware, threat, tags, reference, type, source) is text that came from a public
// feed: the page renders it as text and builds no link, URL, class name or attribute from it. The closed sets are unions here.
import { ApiError, api, apiBlob } from "./client";

export const TI_SOURCES = ["threatfox", "urlhaus", "malwarebazaar"] as const;
export type TiSource = (typeof TI_SOURCES)[number];

export function isTiSource(value: unknown): value is TiSource {
  return typeof value === "string" && (TI_SOURCES as readonly string[]).includes(value);
}

/** The three ways an import run ends (`ti_import_log.status`): `ok` and `partial` loaded something, `failed` nothing. */
export const TI_LOG_STATUSES = ["ok", "partial", "failed"] as const;
export type TiLogStatus = (typeof TI_LOG_STATUSES)[number];

/** One IOC as the API serves it. Timestamps are ISO 8601 UTC with microseconds; `confidence` is null on every MalwareBazaar row. */
export type TiIoc = {
  id: number;
  source: TiSource;
  /** `ip:port`, `domain`, `url`, `sha256_hash`, …: a lower-case token the importer accepted; any other is shown as it is. */
  type: string;
  value: string;
  malware: string | null;
  threat: string | null;
  confidence: number | null;
  tags: string[];
  reference: string | null;
  first_seen: string;
  last_seen: string;
  imported_at: string;
  expires_at: string;
  expired: boolean;
  /** 0 until the matching of IOCs against logs is built (it is not, DEC-224). */
  hit_count: number;
  last_hit: string | null;
};

/** `GET /api/ti/iocs`. */
export type TiListResponse = {
  rows: TiIoc[];
  total: number;
  page: number;
  page_size: number;
};

/** One day of the series, in GMT+7: the count of each source and their total. The series is dense (a day with none is zeros). */
export type TiDay = {
  day: string;
  threatfox: number;
  urlhaus: number;
  malwarebazaar: number;
  total: number;
};

export type TiMalwareCount = {
  malware: string;
  count: number;
};

/** `GET /api/ti/stats`. `by_day` has exactly `days` entries, oldest first, `today` last. */
export type TiStats = {
  days: number;
  today: string;
  sources: TiSource[];
  by_day: TiDay[];
  top_malware: TiMalwareCount[];
  high_confidence: number;
  matched_in_logs: number;
  imported_today: number;
  newest_malware: string[];
};

/** One row of the import log. `message` is a short closed-vocabulary reason, never a row's content. */
export type TiLog = {
  id: number;
  file: string;
  started_at: string;
  finished_at: string;
  rows_total: number;
  rows_new: number;
  rows_updated: number;
  rows_error: number;
  status: TiLogStatus;
  message: string | null;
};

/** `GET /api/ti/status`. `stale` is true when no successful import finished within `stale_after_hours`, or none ever did. */
export type TiStatus = {
  latest: TiLog | null;
  latest_success: TiLog | null;
  stale: boolean;
  stale_after_hours: number;
};

/** The bounds of the API (the contract test holds each to the backend's constant). */
export const TI_PAGE_SIZE = 50;
export const TI_PAGE_SIZE_MAX = 200;
export const TI_PAGE_MAX = 1_000_000;
export const TI_DAYS = 30;
export const TI_Q_MAX = 128;
export const TI_TYPE_MAX = 64;
export const TI_MALWARE_MAX = 256;
export const TI_VALUE_MAX = 2048;
export const TI_EXPORT_MAX_ROWS = 20_000;
/** What the stats call "high confidence" (`queries.HIGH_CONFIDENCE`), the top of malware the cards and chart show. */
export const TI_HIGH_CONFIDENCE = 75;
export const TI_TOP_MALWARE = 10;
export const TI_NEWEST_MALWARE = 3;

/**
 * What the list and the export filter on. A filter that is not set is left out of the request. `minConfidence` is sent only from 1:
 * "any confidence" is NO parameter, because `min_confidence=0` drops every row whose confidence is null (all of MalwareBazaar).
 */
export type TiFilters = {
  source?: TiSource;
  type?: string;
  malware?: string;
  /** `YYYY-MM-DD`: the page sends dates, never times (the API reads a date as a whole GMT+7 day). */
  from?: string;
  to?: string;
  minConfidence?: number;
  q?: string;
};

export type TiListQuery = TiFilters & { page: number; pageSize?: number };

/** The query string of a set of filters: only what is set, `min_confidence` only from 1. */
export function tiFilterParams(filters: TiFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.source !== undefined) params.set("source", filters.source);
  if (filters.type) params.set("type", filters.type);
  if (filters.malware) params.set("malware", filters.malware);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (
    filters.minConfidence !== undefined &&
    Number.isInteger(filters.minConfidence) &&
    filters.minConfidence >= 1 &&
    filters.minConfidence <= 100
  ) {
    params.set("min_confidence", String(filters.minConfidence));
  }
  if (filters.q) params.set("q", filters.q);
  return params;
}

export function tiListPath(query: TiListQuery): string {
  const params = tiFilterParams(query);
  params.set("page", String(query.page));
  params.set("page_size", String(query.pageSize ?? TI_PAGE_SIZE));
  return `/ti/iocs?${params}`;
}

export function fetchTiIocs(query: TiListQuery, signal?: AbortSignal): Promise<TiListResponse> {
  return api<TiListResponse>(tiListPath(query), { signal });
}

export function fetchTiStats(days: number = TI_DAYS, signal?: AbortSignal): Promise<TiStats> {
  return api<TiStats>(`/ti/stats?${new URLSearchParams({ days: String(days) })}`, { signal });
}

export function fetchTiStatus(signal?: AbortSignal): Promise<TiStatus> {
  return api<TiStatus>("/ti/status", { signal });
}

export const TI_EXPORT_FORMATS = ["csv", "blocklist"] as const;
export type TiExportFormat = (typeof TI_EXPORT_FORMATS)[number];

/**
 * The names of the two downloads: the server's own fixed names (`CSV_FILE` and `BLOCKLIST_FILE` of the router), written here
 * so that the file the browser saves is named by the page, from the format alone and never from anything in the data.
 */
export const TI_EXPORT_FILES: Readonly<Record<TiExportFormat, string>> = {
  csv: "threat-intel-iocs.csv",
  blocklist: "threat-intel-blocklist.txt",
};

export function tiExportPath(format: TiExportFormat, filters: TiFilters): string {
  const params = tiFilterParams(filters);
  params.set("format", format);
  return `/ti/export?${params}`;
}

/** The export as a Blob, fetched with the Bearer header (a plain link would carry none). Admin only: any other role is a 403. */
export function fetchTiExport(
  format: TiExportFormat,
  filters: TiFilters,
  signal?: AbortSignal,
): Promise<Blob> {
  return apiBlob(tiExportPath(format, filters), { signal });
}

/** A `503 {"detail": {"reason": "timeout"}}`: the read outlived the server's statement timeout. "Busy, try again", not an error page. */
export function isTiBusy(error: unknown): boolean {
  if (!(error instanceof ApiError) || error.status !== 503) return false;
  const detail = error.detail;
  return (
    typeof detail === "object" &&
    detail !== null &&
    (detail as { reason?: unknown }).reason === "timeout"
  );
}
