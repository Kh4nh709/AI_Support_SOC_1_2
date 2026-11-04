// Seeds for the specs of the RAG beside the AI's conclusion (P14-T07, DEC-213, spec 4.3). The stack (scripts/
// ui_e2e_stack.sh) runs with the RAG off and no Voyage key, so nothing in it ever looks anything up. These helpers put
// in the database what a lookup and a ① run would have left when RAG_ENABLED was on, in the shape `rag/lookup.py` and
// `tier1/triage.py` write: a `rag_results` row (status, matches with a score, the closed failure kind) and a new
// newest proposer run, a copy of the one the stub's model wrote, whose `rag_lookup_id` names the lookup its prompt
// held and whose `citation_warnings` carry `rag_not_applied:<kind>` when the lookup failed. `llm_runs` is append-only,
// so the copy is a new row, never an update. No request is sent to Voyage or to anything else.
import { randomUUID } from "node:crypto";
import { sql } from "./fixtures";

const ALERT_ID = /^\d+\.\d+$/;
const KIND = /^[a-z_]+$/;

function alertId(id: string): string {
  if (!ALERT_ID.test(id)) throw new Error(`not an alert id: ${id}`);
  return id;
}

/** A lookup that found approved knowledge: one match per score (0 to 1), the status `ok`. Returns its id. */
export function seedFoundLookup(id: string, scores: readonly number[]): string {
  if (scores.some((s) => !(s >= 0 && s <= 1))) throw new Error("a score is a number from 0 to 1");
  const lookup = randomUUID();
  const matches = JSON.stringify(
    scores.map((score, i) => ({
      entry_id: `e2e-entry-${i}`,
      level: "giong",
      content_sha256: "0".repeat(64),
      score,
    })),
  );
  sql(
    "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, match_notes) " +
      `VALUES ('${lookup}', 'alert', '${alertId(id)}', 'ok', NULL, '${matches}'::jsonb, '{}'::jsonb)`,
  );
  return lookup;
}

/** A lookup that failed with the closed kind `kind` (`rag.failures.FAILURE_KINDS`): the status `failed`. */
export function seedFailedLookup(id: string, kind: string): string {
  if (!KIND.test(kind)) throw new Error(`not a failure kind: ${kind}`);
  const lookup = randomUUID();
  sql(
    "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, match_notes, failure_kind) " +
      `VALUES ('${lookup}', 'alert', '${alertId(id)}', 'failed', NULL, '[]'::jsonb, '{}'::jsonb, '${kind}')`,
  );
  return lookup;
}

/**
 * A new newest ① proposer run for the alert: a copy of the newest one (what the stub's model answered, and the gate's
 * account of it) that names the lookup its prompt held (`lookupId`, or none) and carries `warnings` as its
 * `citation_warnings`. It is dated a minute ahead, so it is the newest whatever the clock of the database does.
 */
export function seedRun(
  id: string,
  options: { lookupId?: string; warnings?: readonly string[] } = {},
): void {
  const lookup = options.lookupId === undefined ? "NULL" : `'${options.lookupId}'::uuid`;
  const warnings =
    options.warnings === undefined ? "NULL" : `'${JSON.stringify(options.warnings)}'::jsonb`;
  sql(
    "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message, " +
      "result, gate_result, rag_lookup_id, citation_warnings, created_at) " +
      `SELECT '${randomUUID()}', pipeline, subject_type, subject_id, role, system_prompt, user_message, ` +
      `result, gate_result, ${lookup}, ${warnings}, clock_timestamp() + interval '1 minute' ` +
      "FROM llm_runs WHERE pipeline = 'triage' AND role = 'proposer' " +
      `AND subject_id = '${alertId(id)}' ORDER BY created_at DESC, run_id DESC LIMIT 1`,
  );
  const copied = Number(
    sql(
      "SELECT count(*) FROM llm_runs WHERE pipeline = 'triage' AND role = 'proposer' " +
        `AND subject_id = '${alertId(id)}' AND created_at > clock_timestamp()`,
    ),
  );
  if (copied !== 1) throw new Error("the seeded run is not the newest proposer run of the alert");
}
