-- ============================================================================
-- 019_admin_console.sql — AI Support SOC
-- DEC-200: the admin console v1.1 (spec docs/superpowers/specs/2026-10-18-admin-console-v1-1-design.md).
-- Runs after 018, as the database owner. KHÔNG sửa 001-018: chúng đã áp.
--
-- Three changes:
--
--   1. `settings` — the three LLM limits the admin may change on the web (spec §5.2). A row
--      overrides the `.env` value of the same name; no row means "not overridden". Only these
--      three keys, each a positive integer (all three are `int` in `infra/config.py`), and always
--      who changed it. The application reads it through ONE accessor, `infra/settings.py`, which
--      is fail-closed: a read that fails stops the model calls, it never falls back to `.env`.
--      `app_rw` reaches it through 017's `ALTER DEFAULT PRIVILEGES`, as every table created
--      after 017 by the migrator does. The bounds the web route enforces (cap 1–1000, quota
--      1–200, timeout 10–600) are the route's; the database only refuses what no value of any
--      bound could make sense of (zero, negative, an unknown key).
--
--   2. `users.last_login_at` — stamped by `infra/auth.login` on a successful login, in the same
--      UPDATE that resets `failed_logins` (spec §5.1). NULL for an account that never signed in;
--      the users page says "chưa đăng nhập" for it.
--
--   3. `ck_audit_event_type` gains `admin.settings_changed` — 27 → 28 names. A change of the
--      limits writes one row, `{changes: [{key, old, new}]}`. The 27 names before it are 016's,
--      in 016's order, so a diff against 016 shows one addition and nothing else.
-- ============================================================================

BEGIN;

CREATE TABLE settings (
  key        text        PRIMARY KEY,
  value      integer     NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid        NOT NULL REFERENCES users (user_id),
  CONSTRAINT ck_settings_key CHECK (key IN (
    'LLM_MONTHLY_USD_CAP',
    'ANALYZE_QUOTA_PER_USER_DAY',
    'LLM_TIMEOUT_S'
  )),
  CONSTRAINT ck_settings_value_duong CHECK (value > 0)
);

ALTER TABLE users ADD COLUMN last_login_at timestamptz;

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
  'admin.settings_changed'
));

INSERT INTO schema_migrations (version) VALUES ('019_admin_console');

COMMIT;
