// What the two AI panels read of a knowledge lookup and say on the Tri thức (RAG) tile (DEC-221): one reader and one tile
// for both tiers (lifted from the Tier 2 run model, so Tier 1 does not write the same logic again). A lookup is the
// object the server serves as `analysis.rag` (Tier 1) or `run.knowledge` (Tier 2); a stored document is data, so every
// key is read safely, and nothing here throws or invents a number. Pure: no component, no query.
import { S } from "../../strings";

/** One approved knowledge entry the lookup scored: its percentage, its title and the conclusion it was learned from. */
export type Candidate = { pct: number; title: string | null; conclusion: string | null };

/** What the lookup of a run came to, as the panels read it, with every key made safe. */
export type Knowledge = {
  state: string;
  failure: string | null;
  best_pct: number | null;
  floor_pct: number | null;
  scored: number | null;
  candidates: Candidate[];
};

/** At most three candidates are listed, best first, as the server sends them. */
const CANDIDATES_SHOWN = 3;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A string that says something; anything else is nothing. */
const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

/** A whole percentage from 0 to 100, else null (`api/rag.ts` holds the lookup's pair to the same rule). */
const pct = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;

const wholeCount = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;

function candidatesOf(value: unknown): Candidate[] {
  if (!Array.isArray(value)) return [];
  return value
    .flatMap((row): Candidate[] => {
      if (!isRecord(row)) return [];
      const percentage = pct(row.pct);
      if (percentage === null) return [];
      return [{ pct: percentage, title: text(row.title), conclusion: text(row.conclusion) }];
    })
    .slice(0, CANDIDATES_SHOWN);
}

/** The lookup as the server serves it, with every key made safe; null when it is not an object with a state. */
export function knowledgeFrom(raw: unknown): Knowledge | null {
  if (!isRecord(raw) || typeof raw.state !== "string") return null;
  return {
    state: raw.state,
    failure: text(raw.failure),
    best_pct: pct(raw.best_pct),
    floor_pct: pct(raw.floor_pct),
    scored: wholeCount(raw.scored),
    candidates: candidatesOf(raw.candidates),
  };
}

export type RagTile = { value: string; note: string };

/**
 * The line under the number of a match: what the best candidate (the first listed: the server sends them best first)
 * was learned from. The mock-up's "trùng sự cố cũ" is for an entry that concluded an incident; a benign entry, a closed
 * false positive and a policy violation say what they are, and a match whose best candidate is not listed (or concluded
 * something this page has no words for) says only that it matched approved knowledge.
 */
function matchedNote(k: Knowledge): string {
  const N = S.analysis.ragNote;
  const conclusion = k.candidates[0]?.conclusion ?? null;
  return conclusion !== null && Object.hasOwn(N.matched, conclusion)
    ? (N.matched as Record<string, string>)[conclusion]!
    : N.matchedOther;
}

/**
 * The Tri thức (RAG) tile: the number for a lookup that kept a match or scored candidates under the floor, and a dash
 * with a short line for the other three states and for each failure kind (`S.analysis.ragNote`). A failure kind the page
 * has no words for is a plain "the lookup failed", never the code.
 */
export function ragTile(k: Knowledge | null): RagTile {
  const N = S.analysis.ragNote;
  const noData: RagTile = { value: S.common.missing, note: N.noData };
  if (k === null) return noData;
  switch (k.state) {
    case "matched":
      return k.best_pct === null ? noData : { value: `${k.best_pct}%`, note: matchedNote(k) };
    case "below_floor":
      return k.best_pct === null
        ? noData
        : { value: `${k.best_pct}%`, note: N.belowFloor(k.floor_pct) };
    case "no_candidate":
      return { value: S.common.missing, note: N.noCandidate };
    case "no_lookup":
      return { value: S.common.missing, note: N.noLookup };
    case "failed":
      return {
        value: S.common.missing,
        note:
          k.failure !== null && Object.hasOwn(N.failedKind, k.failure)
            ? (N.failedKind as Record<string, string>)[k.failure]!
            : N.failed,
      };
    default:
      // a state this page has no words for is shown as it came, never as "no data"
      return { value: S.common.missing, note: k.state };
  }
}
