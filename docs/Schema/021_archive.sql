-- ============================================================================
-- 021_archive.sql — AI Support SOC
-- DEC-212: archive the old queue (Owner ruling 30/10/2026). Runs after 020, as the database
-- owner. KHÔNG sửa 001-020: chúng đã áp.
--
-- Everything that arrived before the cutoff the Owner names (2026-10-30T20:15:00+07:00) is
-- closed out WITHOUT review: the queue heads and the investigating cases. Those are not analyst
-- decisions and must never be read as one, so they do not get `closed_fp` / `closed_benign`
-- (which `rag/history.py`, the blind arm's reveal and the evaluation and agreement views count
-- as a person's decision). They get a status of their own: `archived`, for alerts and for cases.
--
-- Five constraint changes, and nothing else (no table, no column, no index, no right):
--
--   1. `ck_alerts_status` gains `archived`: 10 -> 11 statuses.
--
--   2. `ck_alerts_g3_terminal_phai_co_closed_at` and `ck_alerts_h2_dong_boi_nguoi_phai_seal` gain
--      `archived`: an archived alert has `closed_at` AND `sealed_at`. G3 is the rule for every
--      terminal status; H2 is the rule for a close that is final (an archived head must stop
--      drawing duplicates: `ix_alerts_dedup` and `find_open_cluster` look at
--      `closed_at IS NULL OR sealed_at IS NULL`, so a sealed head is never an open cluster).
--      `ck_alerts_h3_escalate_khong_seal` is untouched: only `escalated_tier2` is kept unsealed,
--      and an archived alert is not that any more.
--
--   3. `ck_cases_status` gains `archived`: 4 -> 5.
--
--   4. `ck_cases_ket_luan_phai_co_moc`: an archived case has `concluded_at` and
--      `conclusion_reason`, and its `concluded_by` MAY be NULL: nobody concluded it. For the
--      three human conclusions the rule is what it was (all three columns). `concluded_by`
--      stays NULL only for `archived`.
--
--   5. `ck_audit_event_type` gains `alert.archived` and `case.archived`: 36 -> 38 names. The 36
--      before them are 020's, in 020's order, so a diff against 020 shows two additions and
--      nothing else. Both are written by `domain.transitions.archive_before`, one per alert and
--      one per case, as `actor_role = 'system'` with no actor.
--
-- No reopen. The way back is the backup taken before the archive was applied (runbook,
-- "Archiving the old queue (DEC-212)"). Nothing here touches a row: the data change is the
-- command `python -m app.domain.archive`, run by the Owner after this migration.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------
ALTER TABLE alerts DROP CONSTRAINT ck_alerts_status;
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_status CHECK (status IN (
  'received', 'duplicate', 'auto_closed',
  'enriching', 'queued_tier1', 'tier1_active', 'escalated_tier2',
  'closed_fp', 'closed_benign', 'closed_confirmed',
  'archived'));

ALTER TABLE alerts DROP CONSTRAINT ck_alerts_g3_terminal_phai_co_closed_at;
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_g3_terminal_phai_co_closed_at CHECK (
  status NOT IN ('duplicate','auto_closed','closed_fp','closed_benign','closed_confirmed','archived')
  OR closed_at IS NOT NULL
);

ALTER TABLE alerts DROP CONSTRAINT ck_alerts_h2_dong_boi_nguoi_phai_seal;
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_h2_dong_boi_nguoi_phai_seal CHECK (
  status NOT IN ('closed_fp','closed_benign','closed_confirmed','archived')
  OR sealed_at IS NOT NULL
);

-- ---------------------------------------------------------------------------
-- cases
-- ---------------------------------------------------------------------------
ALTER TABLE cases DROP CONSTRAINT ck_cases_status;
ALTER TABLE cases ADD CONSTRAINT ck_cases_status CHECK (status IN (
  'investigating',
  'concluded_fp', 'concluded_policy_violation', 'confirmed_incident',
  'archived'));

ALTER TABLE cases DROP CONSTRAINT ck_cases_ket_luan_phai_co_moc;
ALTER TABLE cases ADD CONSTRAINT ck_cases_ket_luan_phai_co_moc CHECK (
  status = 'investigating'
  OR (concluded_at IS NOT NULL AND conclusion_reason IS NOT NULL
      AND (concluded_by IS NOT NULL OR status = 'archived'))
);

-- ---------------------------------------------------------------------------
-- audit_events — 020's 36 names, in 020's order, then the two of DEC-212.
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
  'case.archived'
));

INSERT INTO schema_migrations (version) VALUES ('021_archive');

COMMIT;
