-- ============================================================================
-- 024_lab.sql — AI Support SOC
-- DEC-213 (P14-T09): the lab runs and the lab labels of Part C. Spec §6 (Owner, 03/11/2026): the ground
-- truth of the measurement is labelled by hand on an admin page, "Gán nhãn lab". Runs after 021, as the
-- database owner. KHÔNG sửa 001-021: chúng đã áp.
--
-- It stands on 021 alone. The number 022 belongs to another card (`022_true_positive.sql`) and 023 to
-- P14-T04 (`023_vector_rag.sql`); this migration neither reads nor changes anything either does (it
-- touches `audit_events`' event CHECK, which 022 and 023 leave alone), so any order of applying them
-- leaves the same schema.
--
-- Two tables and one constraint, and nothing else (no column of an old table, no row):
--
--   1. `lab_runs`: one attack run of the lab. A name (1..80 characters, unique), a purpose (`kb`: the run
--      builds the knowledge base; `test`: the run is scored), and a window `[starts_at, ends_at)`. An alert
--      belongs to the run whose window holds its `received_at`; that is how "which attack run" is known.
--      Two rules the database holds itself:
--        * `ends_at > starts_at` (a window of no time holds no alert, and an empty range would also
--          slip past the exclusion below, which never sees an empty range overlap);
--        * no two windows overlap: an EXCLUDE constraint on `tstzrange(starts_at, ends_at, '[)')` with
--          `&&`. The range is half-open, so a run may start where another ends and an alert received at
--          that instant belongs to the later one, never to both. A GiST index on a range type needs no
--          extension.
--      The run records who created it (`created_by`) and when.
--
--   2. `lab_labels`: the admin's hand label of one alert, `true_positive` (a real attack) or
--      `false_positive` (not an attack). One row per alert (the primary key): relabelling updates it,
--      clearing deletes it. `run_id` is the run the alert's `received_at` falls in, written by the
--      application when the label is set (`lab.labels.set_label`); a CHECK cannot read another table, so
--      the rule that the two agree is the application's, and the rows cannot disagree later because a run
--      is never edited (below) and an alert's `received_at` is written once.
--
--   3. `ck_audit_event_type` gains `lab.run_created` and `lab.labeled`: 38 -> 40 names. The 38 before
--      them are 021's, in 021's order, so a diff against 021 shows two additions and nothing else. Both
--      are written by an admin (`actor_role = 'admin'`, with the actor): `lab.run_created` when a run is
--      recorded, `lab.labeled` when a label is set, changed or cleared (`label` is null when cleared).
--
-- Rights, granted here and not left to 017's default privileges (which reach only a table created by the
-- role that ran 017):
--   * `lab_runs`: `app_rw` SELECT and INSERT. A run is the record the labels stand on; no route edits or
--     deletes one, so UPDATE, DELETE and TRUNCATE are revoked (the REVOKE also removes what the default
--     privileges grant). A run recorded by mistake is removed by the Owner, as the database owner.
--   * `lab_labels`: `app_rw` SELECT, INSERT, UPDATE and DELETE (a label is set, changed and cleared).
--     TRUNCATE is granted on neither: 017's list never names it.
--
-- No old row is rewritten or deleted. The new CHECK holds for every existing audit row: the 38 names it
-- keeps are the 38 that were allowed.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- lab_runs
-- ---------------------------------------------------------------------------
CREATE TABLE lab_runs (
  run_id      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL,
  purpose     text        NOT NULL,
  starts_at   timestamptz NOT NULL,
  ends_at     timestamptz NOT NULL,
  created_by  uuid        NOT NULL REFERENCES users(user_id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT lab_runs_name_key              UNIQUE (name),
  CONSTRAINT ck_lab_runs_name_length        CHECK (length(name) BETWEEN 1 AND 80),
  CONSTRAINT ck_lab_runs_purpose            CHECK (purpose IN ('kb', 'test')),
  CONSTRAINT ck_lab_runs_ends_after_starts  CHECK (ends_at > starts_at),
  CONSTRAINT ex_lab_runs_no_overlap         EXCLUDE USING gist (tstzrange(starts_at, ends_at, '[)') WITH &&)
);

-- ---------------------------------------------------------------------------
-- lab_labels
-- ---------------------------------------------------------------------------
CREATE TABLE lab_labels (
  alert_id    text        PRIMARY KEY REFERENCES alerts(alert_id),
  run_id      uuid        NOT NULL REFERENCES lab_runs(run_id),
  label       text        NOT NULL,
  labeled_by  uuid        NOT NULL REFERENCES users(user_id),
  labeled_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_lab_labels_label CHECK (label IN ('true_positive', 'false_positive'))
);

-- The page counts a run's labels; the FK alone gives the child table no index.
CREATE INDEX ix_lab_labels_run_id ON lab_labels (run_id);

-- ---------------------------------------------------------------------------
-- rights
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON lab_runs TO app_rw;
REVOKE UPDATE, DELETE, TRUNCATE ON lab_runs FROM app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON lab_labels TO app_rw;
REVOKE TRUNCATE ON lab_labels FROM app_rw;

-- ---------------------------------------------------------------------------
-- audit_events — 021's 38 names, in 021's order, then the two of DEC-213.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_events DROP CONSTRAINT ck_audit_event_type;
ALTER TABLE audit_events ADD CONSTRAINT ck_audit_event_type CHECK (event_type IN (
  'alert.received',
  'alert.duplicate_merged',
  'alert.auto_closed',
  'alert.autoclose_blocked_critical',
  'alert.enrich_started',
  'alert.enriched',
  'alert.reopened',
  'job.exhausted',
  'triage.suggested',
  'alert.acknowledged',
  'tier1.decided',
  'tier1.escalated',
  'case.opened',
  'case.truncated',
  'case.analyzed',
  'tier2.concluded',
  'authz.denied',
  'admin.user_created',
  'admin.user_updated',
  'admin.job_retried',
  'admin.autoclose_rule_toggled',
  'autoclose.reviewed',
  'rule.suspected_wrong',
  'llm.gate_forced',
  'llm.builder_violation',
  'health.alarm',
  'label.created',
  'admin.settings_changed',
  'knowledge.drafted',
  'knowledge.approved',
  'knowledge.rejected',
  'knowledge.retired',
  'knowledge.merged',
  'rag.lookup_failed',
  'rag.integrity_failed',
  'knowledge.redraft_requested',
  'alert.archived',
  'case.archived',
  'lab.run_created',
  'lab.labeled'
));

INSERT INTO schema_migrations (version) VALUES ('024_lab');

COMMIT;
