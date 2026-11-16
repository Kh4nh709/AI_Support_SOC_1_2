-- ============================================================================
-- 025_soar_reviews.sql — AI Support SOC
-- "Phản hồi SOAR" on the web (spec 2026-11-16, section 6; Owner, 16/11/2026): the SOAR (n8n) acts first on an
-- alert (blocks an IP, isolates a host, kills a process, ...) and opens a REVIEW TICKET for the analyst on duty;
-- until now the ticket was a Telegram message with two buttons. n8n now pushes the ticket to this web
-- (`POST /webhook/soar-notices`), an analyst presses a button on the page, and the backend calls n8n back.
-- Runs after 024, as the database owner. KHÔNG sửa 001-024: chúng đã áp.
--
-- One table and one constraint, and nothing else (no column of an old table, no row):
--
--   1. `soar_reviews`: one ticket, keyed by n8n's own id (a review is 8 characters of [A-HJ-NP-Z2-9], a notice
--      is `N` + 12; the id is stable across resends). Two kinds: `review` (has buttons, is decided) and `notice`
--      (a line of information, never decided). The columns are the fields n8n sends, flattened (`case_id`,
--      `case_number`, the `action_*`, `scenario_*` fields), plus what the web adds:
--        * `locked_by`, `locked_at`, `prev_status`: the web's own lock. A person pressing a button takes the row
--          (`status = 'processing'`) before the call to n8n, so two people cannot both act on one ticket, and
--          no transaction stays open during the call. `prev_status` is the state the row had before the lock
--          (a lock older than two minutes is released to it): the one column beyond the Owner's list, because
--          only the row can say which state that was;
--        * `last_error`: why the last press did not finish; `last_sent_at`: the `sent_at` of the newest body
--          applied (an older one that arrives late is ignored); `raw`: that body, exactly as n8n sent it;
--          `updated_at`.
--      The closed sets are CHECKs: `kind`, `status` (n8n's six plus `processing`, which is the web's and is
--      never sent by n8n), `severity`, `action_type`, `action_via`, `prev_status` (n8n's six: a lock is released
--      to a state that is never itself a lock). A `processing` row names who locked it, since when and the state
--      to go back to (`ck_soar_reviews_processing_lock`).
--      Three indexes, one per way the page looks a ticket up: by state, newest first, and by case.
--
--   2. `ck_audit_event_type` gains `soar.review_received` and `soar.review_decided`: 40 -> 42 names. The 40 before
--      them are 024's, in 024's order, so a diff against 024 shows two additions and nothing else. The first is
--      the system's (`actor_role = 'system'`, no actor: n8n's push), the second a person's (an analyst or an
--      admin, with the actor: a button pressed).
--
-- Rights, granted here and not left to 017's default privileges (which reach only a table created by the role
-- that ran 017): `app_rw` SELECT, INSERT and UPDATE on `soar_reviews` (a ticket is created by n8n's push and
-- changed by pushes and by presses). A ticket is never deleted by the application: DELETE and TRUNCATE are
-- revoked (the REVOKE also removes what the default privileges grant).
--
-- No old row is rewritten or deleted. The new CHECK holds for every existing audit row: the 40 names it keeps
-- are the 40 that were allowed.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- soar_reviews
-- ---------------------------------------------------------------------------
CREATE TABLE soar_reviews (
  id                    text        PRIMARY KEY,
  kind                  text        NOT NULL,
  status                text        NOT NULL,
  severity              text        NOT NULL DEFAULT 'info',
  title                 text,
  simulated             boolean     NOT NULL DEFAULT false,
  case_id               text,
  case_number           bigint,
  action_type           text,
  action_text           text,
  action_target         text,
  action_via            text,
  action_agent          text,
  host                  text,
  agent_id              text,
  user_name             text,
  src_ip                text,
  domain                text,
  scenario_id           text,
  scenario_name         text,
  score                 integer,
  note                  text,
  buttons               jsonb       NOT NULL DEFAULT '[]'::jsonb,
  created_at            timestamptz NOT NULL,
  auto_expire_at        timestamptz,
  remind_every_minutes  integer     NOT NULL DEFAULT 0,
  next_remind_at        timestamptz,
  decided_by            text,
  decided_at            timestamptz,
  result                text,
  last_error            text,
  locked_by             text,
  locked_at             timestamptz,
  prev_status           text,
  last_sent_at          timestamptz NOT NULL,
  raw                   jsonb       NOT NULL,
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_soar_reviews_kind        CHECK (kind IN ('review', 'notice')),
  CONSTRAINT ck_soar_reviews_status      CHECK (status IN
    ('open', 'kept', 'undone', 'false_positive', 'expired', 'info', 'processing')),
  CONSTRAINT ck_soar_reviews_severity    CHECK (severity IN ('info', 'warning', 'error')),
  CONSTRAINT ck_soar_reviews_action_type CHECK (action_type IS NULL OR action_type IN
    ('block_ip', 'sinkhole_domain', 'isolate_host', 'disable_user', 'disable_xp_cmdshell', 'kill_process')),
  CONSTRAINT ck_soar_reviews_action_via  CHECK (action_via IS NULL OR action_via IN ('pfsense', 'wazuh')),
  CONSTRAINT ck_soar_reviews_prev_status CHECK (prev_status IS NULL OR prev_status IN
    ('open', 'kept', 'undone', 'false_positive', 'expired', 'info')),
  CONSTRAINT ck_soar_reviews_processing_lock CHECK (status <> 'processing'
    OR (locked_by IS NOT NULL AND locked_at IS NOT NULL AND prev_status IS NOT NULL))
);

CREATE INDEX ix_soar_reviews_status      ON soar_reviews (status);
CREATE INDEX ix_soar_reviews_created_at  ON soar_reviews (created_at DESC);
CREATE INDEX ix_soar_reviews_case_number ON soar_reviews (case_number);

-- ---------------------------------------------------------------------------
-- rights
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON soar_reviews TO app_rw;
REVOKE DELETE, TRUNCATE ON soar_reviews FROM app_rw;

-- ---------------------------------------------------------------------------
-- audit_events — 024's 40 names, in 024's order, then the two of the SOAR reviews.
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
  'lab.labeled',
  'soar.review_received',
  'soar.review_decided'
));

INSERT INTO schema_migrations (version) VALUES ('025_soar_reviews');

COMMIT;
