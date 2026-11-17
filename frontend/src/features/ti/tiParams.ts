// The view of the Threat Intel page (the filters, the search and the page) as URL search params, so a reload and a link shared to
// another tab keep it, and the request each view makes. Only what differs from the empty view is written, and only what is valid is
// read: every value that comes from the URL is checked here, before it can reach the API (a value it would refuse is a 422 there).
//   source          one of the three (a closed set)
//   type            a lower-case token of letters, digits and `_ : . -`, at most 64
//   malware         text of at most 256 characters
//   from, to        `YYYY-MM-DD`, a real day: the page sends dates, never times
//   min_confidence  a whole number 1..100; 0, empty or anything else is "any confidence", which is NO parameter (`min_confidence=0`
//                   would drop every row whose confidence is null: all of MalwareBazaar)
//   q               at most 128 characters
//   page            a whole number from 1
// A text the database cannot hold (a NUL, a lone surrogate) is dropped.
import {
  TI_MALWARE_MAX,
  TI_PAGE_MAX,
  TI_Q_MAX,
  TI_TYPE_MAX,
  isTiSource,
  type TiFilters,
  type TiListQuery,
  type TiSource,
} from "../../api/ti";

export type TiView = {
  source: TiSource | null;
  type: string;
  malware: string;
  from: string;
  to: string;
  minConfidence: number | null;
  q: string;
  page: number;
};

export const EMPTY_VIEW: TiView = {
  source: null,
  type: "",
  malware: "",
  from: "",
  to: "",
  minConfidence: null,
  q: "",
  page: 1,
};

/** A half of a UTF-16 pair: a high surrogate not followed by a low one, or a low one not preceded by a high one. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Text the server can store: no NUL, and no lone surrogate (it refuses both with a 422). */
const isStorable = (text: string): boolean =>
  !text.includes("\u0000") && !LONE_SURROGATE.test(text);

const codePoints = (text: string): number => Array.from(text).length;

/** What the search box means: trimmed, at most 128 characters (counted as the server counts them), nothing the database refuses. */
export function cleanQuery(text: string): string {
  const trimmed = text.trim();
  if (!isStorable(trimmed)) return "";
  const characters = Array.from(trimmed);
  return characters.length > TI_Q_MAX ? characters.slice(0, TI_Q_MAX).join("").trim() : trimmed;
}

const TYPE_TOKEN = /^[a-z0-9_:.-]+$/;

/** A type as the filter means it: trimmed, lower-cased (the importer stores the type lower-case), a token of at most 64. */
export function cleanType(text: string): string {
  const type = text.trim().toLowerCase();
  return type.length >= 1 && type.length <= TI_TYPE_MAX && TYPE_TOKEN.test(type) ? type : "";
}

export function cleanMalware(text: string): string {
  const malware = text.trim();
  return malware !== "" && codePoints(malware) <= TI_MALWARE_MAX && isStorable(malware)
    ? malware
    : "";
}

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A `YYYY-MM-DD` that is a real day between 1970 and 2999, or "". */
export function cleanDay(text: string): string {
  const found = DAY.exec(text);
  if (found === null) return "";
  const [year, month, day] = [Number(found[1]), Number(found[2]), Number(found[3])];
  if (year < 1970 || year > 2999) return "";
  const moment = new Date(Date.UTC(year, month - 1, day));
  const real =
    moment.getUTCFullYear() === year &&
    moment.getUTCMonth() === month - 1 &&
    moment.getUTCDate() === day;
  return real ? text : "";
}

/** 1..100, or null for anything else: 0 and empty are "any confidence". */
export function cleanConfidence(text: string): number | null {
  if (!/^(?:100|[1-9]\d?)$/.test(text)) return null;
  return Number(text);
}

export function readView(params: URLSearchParams): TiView {
  const source = params.get("source");
  const rawPage = params.get("page") ?? "";
  const page = /^[1-9]\d{0,6}$/.test(rawPage) ? Number(rawPage) : 1;
  return {
    source: isTiSource(source) ? source : null,
    type: cleanType(params.get("type") ?? ""),
    malware: cleanMalware(params.get("malware") ?? ""),
    from: cleanDay(params.get("from") ?? ""),
    to: cleanDay(params.get("to") ?? ""),
    minConfidence: cleanConfidence(params.get("min_confidence") ?? ""),
    q: cleanQuery(params.get("q") ?? ""),
    page: page > TI_PAGE_MAX ? 1 : page,
  };
}

export function viewToParams(view: TiView): URLSearchParams {
  const params = new URLSearchParams();
  if (view.source !== null) params.set("source", view.source);
  if (view.type !== "") params.set("type", view.type);
  if (view.malware !== "") params.set("malware", view.malware);
  if (view.from !== "") params.set("from", view.from);
  if (view.to !== "") params.set("to", view.to);
  if (view.minConfidence !== null && view.minConfidence >= 1) {
    params.set("min_confidence", String(view.minConfidence));
  }
  if (view.q !== "") params.set("q", view.q);
  if (view.page > 1) params.set("page", String(view.page));
  return params;
}

/** The `?search` of a link to a view: empty for the empty view, so the plain link stays plain. */
export function viewSearch(view: TiView): string {
  const query = viewToParams(view).toString();
  return query === "" ? "" : `?${query}`;
}

/** The filters of a view as the API takes them (also what the export is asked for): what is set, and no page. */
export function filtersOf(view: TiView): TiFilters {
  const filters: TiFilters = {};
  if (view.source !== null) filters.source = view.source;
  if (view.type !== "") filters.type = view.type;
  if (view.malware !== "") filters.malware = view.malware;
  if (view.from !== "") filters.from = view.from;
  if (view.to !== "") filters.to = view.to;
  if (view.minConfidence !== null && view.minConfidence >= 1) {
    filters.minConfidence = view.minConfidence;
  }
  if (view.q !== "") filters.q = view.q;
  return filters;
}

export function listQueryOf(view: TiView): TiListQuery {
  return { ...filtersOf(view), page: view.page };
}
