-- ============================================================================
-- 016_alter_alerts_jobs_llm_runs_users.sql — the v1 tables take their v3 shape
--
-- Context pack §6.1, "v3 altered", for the five tables this file owns:
--   alerts        + manager_id, origin_host, suggestion_visible; source CHECKed
--   jobs          job_type set replaced by the six v3 values
--   llm_runs      + the eight columns ① and ② write, role CHECKed
--   users         + the three lockout columns
--   audit_events  event_type set = 21 v1 names + 6 v3 names
--
-- Runs after 014. It does not depend on 015 (another P1 task owns it, in parallel):
-- the two files touch no common table, so either merge order works. Does not touch
-- 001-014: they have applied.
--
-- Every one of the five tables is EMPTY — measured 06/09/2026 on `soc_dev`,
-- `soc_test` and the v1 `soc` database — so the two DROP/ADD CONSTRAINT pairs
-- below need no data migration and no NOT VALID. If some database does hold a
-- row that the new set refuses, ADD CONSTRAINT fails there and that is the
-- correct behaviour: the row is the defect, not the constraint.
--
-- ── Three places where §6.1 and the v1 database disagreed ───────────────────
--
-- (1) `alerts.source` ALREADY EXISTS. `002_alerts.sql:434` created it as
--     `source text NOT NULL DEFAULT 'wazuh'` with NO CHECK. §6.1's
--     "`source ∈ wazuh|lab|replay`" is therefore a missing CONSTRAINT, not a
--     missing column: `ADD COLUMN source` here would fail with
--     `column "source" of relation "alerts" already exists`. Measured.
--
-- (2) `alerts.sampled_for_control` HAS NEVER EXISTED (DEC-022). §6.1 and
--     architecture §5 both order it dropped, but it is a jsonb payload KEY
--     inside a `jsonb_build_object(...)` audit event
--     (`docs/phase-3-auto-close.md:166`), not a column — measured on the
--     migrated `soc_dev`, where `alerts` has 51 columns and none is named
--     that. The clause is kept rather than struck, and satisfied literally
--     with `DROP COLUMN IF EXISTS`: the migration states the contract, and
--     here it is a verified no-op that emits `NOTICE … skipping` and exits 0.
--     Do not go looking for the column.
--
-- (3) `ck_jobs_job_type` WAS `('enrich','triage')` — measured, not read off a
--     document. Architecture §5 shows five values; §6.1 gives six, including
--     `pull`; §0 makes the context pack the higher source of truth, so the six
--     v3 values win and `enrich` ceases to exist. After this file,
--     `INSERT … ('pull', …)` succeeds and `('enrich', …)` fails — the exact
--     inversion of the v1 database.
--
-- ── What is deliberately NOT here ──────────────────────────────────────────
--
-- `role` is nullable and `ck_llm_runs_role` admits NULL. §6.1 writes
-- "`llm_runs` + `role ∈ proposer|verifier|investigator`" — a closed set for a
-- value that is PRESENT, not a NOT NULL. v1 rows carry no role at all, and a
-- bare `role IN (…)` would reject every insert that omits it.
--
-- `stopped_by` gets no CHECK. §6.1 gives it no closed set, and inventing one
-- would be an extension of a frozen contract.
--
-- `manager_id` and `origin_host` stay nullable for the same reason: §6.1 lists
-- the columns and no NOT NULL. It also keeps the DEC-019 replay path cheap.
-- `suggestion_visible` DOES get `NOT NULL DEFAULT true` — §6.1 writes the
-- default explicitly and DEC-023 annotated the clause with the NOT NULL, since
-- a tri-state flag on the blind branch is a defect magnet. Transcription, not
-- extension.
--
-- `cost_usd numeric(10,5)` is $0.00001 granularity. Measured 06/09/2026: one
-- trivial `deepseek-v4-flash` call costs about $0.0000287, which this column
-- stores as 0.00003. Per-call cost is therefore held ROUNDED; any total that
-- needs precision must be summed from `input_tokens`/`output_tokens`.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- alerts — §6.1: + manager_id, origin_host, suggestion_visible; source CHECKed
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD COLUMN manager_id  text,          -- §6.3 WAZUH_MANAGER_ID, e.g. 'IA1803'
                   ADD COLUMN origin_host text,          -- predecoder.hostname
                   ADD COLUMN suggestion_visible boolean NOT NULL DEFAULT true;

-- See note (2): states the contract, drops nothing on any database we have.
ALTER TABLE alerts DROP COLUMN IF EXISTS sampled_for_control;

-- See note (1): the column was already here, only the closed set was missing.
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_source
  CHECK (source IN ('wazuh','lab','replay'));

-- ---------------------------------------------------------------------------
-- jobs — §6.1 + §6.5: pull (every 60 s), pipeline(intake_id), triage(alert_id),
-- investigate(case_id), digest (daily 08:00), health (every 5 min). See note (3).
-- ---------------------------------------------------------------------------
ALTER TABLE jobs DROP CONSTRAINT ck_jobs_job_type;
ALTER TABLE jobs ADD CONSTRAINT ck_jobs_job_type
  CHECK (job_type IN ('pipeline','triage','investigate','digest','health','pull'));

-- ---------------------------------------------------------------------------
-- llm_runs — the eight columns ① and ② write. `gate_result` is written for
-- every row (G11); `verifier_result` and `evidence_check` only where the step
-- runs, hence all three nullable.
-- ---------------------------------------------------------------------------
ALTER TABLE llm_runs ADD COLUMN role            text,
                     ADD COLUMN model_id        text,
                     ADD COLUMN prompt_version  text,          -- git sha
                     ADD COLUMN gate_result     jsonb,
                     ADD COLUMN verifier_result jsonb,
                     ADD COLUMN evidence_check  jsonb,
                     ADD COLUMN cost_usd        numeric(10,5),
                     ADD COLUMN stopped_by      text;

ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_role
  CHECK (role IS NULL OR role IN ('proposer','verifier','investigator'));

-- ---------------------------------------------------------------------------
-- users — §6.1: the three columns the lockout and session-invalidation paths
-- read. `failed_logins` counts from zero for every existing row, so the
-- DEFAULT plus NOT NULL backfills them; the two timestamps mean "never" when
-- NULL, which is the correct state for an account that has never been locked.
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN sessions_invalid_before timestamptz,
                  ADD COLUMN failed_logins integer NOT NULL DEFAULT 0,
                  ADD COLUMN locked_until  timestamptz;

-- ---------------------------------------------------------------------------
-- audit_events — §6.1: 21 v1 names + 6 v3 names = 27.
--
-- The first 21 are the constraint 008 froze, dumped from the live database with
-- `pg_get_constraintdef` and kept in that order, so a diff against the old
-- definition shows six additions and nothing else. 008's reasoning still holds
-- and is not repeated here: this CHECK guards the VALID STRING SET, not the
-- emission policy, which is why names the current phase never emits stay in it.
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
  'label.created'
));

INSERT INTO schema_migrations (version) VALUES ('016_alter_alerts_jobs_llm_runs_users');

COMMIT;
