-- ============================================================================
-- 022_true_positive.sql — AI Support SOC
-- DEC-213 (P14-T01): ①'s verdict `escalate` is renamed `true_positive` ("cho phép đổi luôn", Owner
-- 03/11/2026). Runs after 021, as the database owner. KHÔNG sửa 001-021: chúng đã áp.
--
-- ① answers `false_positive | true_positive` (`triage_v3`); after the gate the stored verdict is
-- `false_positive | needs_review | true_positive`, where `needs_review` is only ever the system's
-- ("the gate held it"). The rename is of ①'s verdict vocabulary ONLY. The analyst's escalation keeps its
-- name: the route `POST /api/tier1/alerts/{id}/escalate`, `transitions.escalate`, the event
-- `tier1.escalated`, the status `escalated_tier2`, and the gold labels `false_positive | benign |
-- escalate` (`triage_labels`, 015). ②'s `suggested_conclusion` (`ck_llm_runs_suggested_conclusion`) is
-- not touched either.
--
-- One constraint changes, and nothing else (no table, no column, no index, no right, no row):
--
--   `ck_llm_runs_suggested_action` (003) goes from `false_positive | needs_review | escalate` to
--   `false_positive | needs_review | true_positive`. It is STRICT: no `escalate` any more.
--
-- No old row is rewritten or deleted, and none is read through a compatibility layer: the trial
-- database is wiped, Owner-run, before this build is deployed (spec §4.1 and §11, "xóa db cũ để thuận
-- lợi cho việc điều chỉnh kết luận AI"). `llm_runs` is append-only (017), so a row saying `escalate`
-- could not be rewritten here anyway.
--
-- THE REFUSAL. Nothing reads a stored ① `escalate` (Director ruling, DEC-213), so the `DO` block below
-- counts the `triage` runs that hold the old name in the four places the ruling names, and if there are
-- any, raises and stops: the wipe was skipped, or an alert arrived between the wipe and the deploy
-- (Review Focus 4). The four places are `result.suggested_action` (the stored answer, the only one the
-- CHECK judges), `result.structured_only_verdict` (the verifier's), `gate_result.proposed_verdict` (the
-- model's own claim, which the gate may have held as `needs_review`: the tracked `backups/latest.dump`
-- has six such rows) and `gate_result.final_verdict`. A run is counted once, however many of them say
-- `escalate`. Other copies of the name (`gate_result.proposer_raw`, `gate_result.compared_to`,
-- `verifier_result`, `gate_result.verifier_verdict`) are not read: the check is not wider than the
-- ruling. The block runs BEFORE the constraint is touched, and the whole file is ONE transaction
-- (BEGIN ... COMMIT; `psql -v ON_ERROR_STOP=1` ends the session on the error, which rolls the
-- transaction back), so a refusal changes nothing: the old constraint stays, no row moves, and
-- `schema_migrations` does not record 022. Wipe the trial database per spec §11 (the Owner-run wipe),
-- then run `make migrate` again.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1 · the refusal
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  still_escalate integer;
BEGIN
  SELECT count(*) INTO still_escalate
    FROM llm_runs
   WHERE pipeline = 'triage'
     AND 'escalate' IN (result->>'suggested_action',
                        result->>'structured_only_verdict',
                        gate_result->>'proposed_verdict',
                        gate_result->>'final_verdict');
  IF still_escalate > 0 THEN
    RAISE EXCEPTION '022: % triage runs still say escalate — wipe the trial database first (spec §11); nothing changed', still_escalate;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2 · ck_llm_runs_suggested_action, strict: false_positive | needs_review | true_positive
-- ---------------------------------------------------------------------------
ALTER TABLE llm_runs DROP CONSTRAINT ck_llm_runs_suggested_action;
ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_suggested_action CHECK (
  pipeline <> 'triage'
  OR result IS NULL
  OR result->>'suggested_action' IS NULL
  OR result->>'suggested_action' IN ('false_positive','needs_review','true_positive')
);

INSERT INTO schema_migrations (version) VALUES ('022_true_positive');

COMMIT;
