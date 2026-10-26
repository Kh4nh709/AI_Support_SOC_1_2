-- ============================================================================
-- 020_learned_knowledge.sql — AI Support SOC
-- DEC-210: learned knowledge and RAG for ① and ② (spec docs/superpowers/specs/2026-10-24-learned-knowledge-rag-design.md,
-- §6 and §7.2). Runs after 019, as the database owner. KHÔNG sửa 001-019: chúng đã áp.
--
-- Every frozen contract this feature changes changes here and only here (spec §6):
--
--   1. Three tables.
--        `knowledge_drafts`  what the model proposes from a conclusion; one per source (an alert
--                            is decided once, a case concluded once), reviewed by an admin.
--        `knowledge_entries` what an admin approved. The database is the source of the content:
--                            `content` is the full Markdown, front matter included, and
--                            `content_sha256` its hash; `kb_learned/` holds the published copy
--                            and can be rebuilt from these rows. `fingerprint_tsv` is generated
--                            from `fingerprint` in the `simple` configuration (no stemming, no
--                            stop words: the fingerprint is made of ids, rule numbers and
--                            category words, and Vietnamese has no English stemmer to trust) and
--                            carries the GIN index the candidate search reads.
--        `rag_results`       one stored lookup per alert or case, with the history, the matches
--                            and the agent's reasons (`match_notes`, admin display only). ① and ②
--                            read the newest row for their subject at prompt time and never wait.
--      Foreign keys only where the target is a row the feature itself owns (an entry, a user).
--      `llm_run_id` is a plain uuid, as `llm_runs.rag_lookup_id` is: `llm_runs` is append-only and
--      written in the same transaction as these rows, and the two ids point at each other.
--      `entry_id` and `lookup_id` carry no DEFAULT: the application assigns them (the entry's id
--      is its file name), the way it assigns `llm_runs.run_id`. `draft_id` does have one.
--
--   2. `llm_runs`: `rag_lookup_id`, the lookup a run is tied to. On a `rag_lookup` run it is that
--      run's own lookup (its id); on a ① or ② row it is the lookup whose material the prompt held, and
--      it is set only when the learned section reached the prompt. So it is NULL when RAG is off,
--      when no lookup was usable (none, `failed`, `budget`), and when the token budget cut the whole
--      section (the row's warnings then name the cut but it has no id), and for every run of the
--      other pipelines. Also new: the pipelines
--      `rag_lookup` and `knowledge_draft`; the roles `retriever` and `drafter`. ① stays on
--      `alert` and ② on `case`; the two new pipelines may run on either, because a lookup and a
--      draft are made for an alert as well as for a case. Nothing else about the old pairing moves.
--
--   3. `jobs.job_type` gains `rag_lookup` and `knowledge_draft` (6 -> 8). A job's subject is
--      `alert:<alert_id>` or `case:<case_uuid>`; single-flight is the existing partial unique
--      index `ux_jobs_mot_job_song_moi_subject` on (job_type, subject_id).
--
--   4. `ck_audit_event_type` gains eight names: 28 -> 36. The 28 before them are 019's, in 019's
--      order, so a diff against 019 shows eight additions and nothing else. The eighth,
--      `knowledge.redraft_requested`, is an admin asking for a text-less draft to be made again.
--
--   5. `ix_alerts_soar_dedup_key`: an expression index on the SOAR case key, for the history
--      query ("the earlier alerts of this case"). A query uses it only when it writes the
--      expression exactly as it is written here.
--
--   6. Rights. 020 grants `app_rw` SELECT, INSERT and UPDATE on `knowledge_drafts` and
--      `knowledge_entries`, and SELECT and INSERT on `rag_results`, itself. The
--      rights do not depend on 017's `ALTER DEFAULT PRIVILEGES`: those bind only the role that
--      ran 017 (`soc` on Compose), so a table created by any other applying role would leave
--      `app_rw` with nothing, and the lookup and the draft job would then die on `permission
--      denied` (019's lesson, P11-T01 review finding 5). No DELETE in the grant: nothing deletes
--      a draft, an entry (it is retired) or a result. (Where the applier is the role 017's
--      defaults name, as on Compose, those defaults add DELETE as well; no code uses it.)
--      `rag_results` is append-only: a lookup is stored once and read, nothing updates it (the
--      newest row is the lookup), so UPDATE, DELETE and TRUNCATE are revoked from `app_rw` there,
--      which also takes back what 017's defaults gave it.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- knowledge_entries first: the drafts point at it.
-- ---------------------------------------------------------------------------
CREATE TABLE knowledge_entries (
  entry_id         uuid        PRIMARY KEY,
  version          integer     NOT NULL DEFAULT 1,
  status           text        NOT NULL DEFAULT 'active',
  conclusion       text        NOT NULL,
  category         text        NOT NULL,
  mitre_ids        text[]      NOT NULL DEFAULT '{}',
  tags             text[]      NOT NULL DEFAULT '{}',
  soar_scenario    text,
  rule_ids         text[]      NOT NULL DEFAULT '{}',
  log_source       text,
  fingerprint      text        NOT NULL,
  fingerprint_tsv  tsvector    GENERATED ALWAYS AS (to_tsvector('simple', fingerprint)) STORED,
  content          text        NOT NULL,
  content_sha256   text        NOT NULL,
  file_path        text        NOT NULL,
  source_alert_ids text[]      NOT NULL DEFAULT '{}',
  source_case_ids  uuid[]      NOT NULL DEFAULT '{}',
  evidence         jsonb       NOT NULL DEFAULT '[]',
  approved_by      uuid,
  approved_at      timestamptz,
  supersedes_entry uuid,
  CONSTRAINT ck_knowledge_entries_status CHECK (status IN ('active', 'retired')),
  CONSTRAINT ck_knowledge_entries_conclusion CHECK (conclusion IN (
    'closed_fp',
    'closed_benign',
    'concluded_fp',
    'concluded_policy_violation',
    'confirmed_incident'
  )),
  CONSTRAINT ck_knowledge_entries_version_duong CHECK (version >= 1),
  CONSTRAINT ck_knowledge_entries_content_sha256 CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT fk_knowledge_entries_approver FOREIGN KEY (approved_by) REFERENCES users (user_id),
  CONSTRAINT fk_knowledge_entries_supersedes FOREIGN KEY (supersedes_entry)
    REFERENCES knowledge_entries (entry_id)
);
CREATE INDEX ix_knowledge_entries_fingerprint_tsv
  ON knowledge_entries USING gin (fingerprint_tsv);

CREATE TABLE knowledge_drafts (
  draft_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  source_kind         text        NOT NULL,
  source_id           text        NOT NULL,
  conclusion          text        NOT NULL,
  status              text        NOT NULL DEFAULT 'pending',
  draft               jsonb       NOT NULL DEFAULT '{}',
  warnings            jsonb       NOT NULL DEFAULT '[]',
  llm_run_id          uuid,
  duplicate_of_entry  uuid,
  conflict_with_entry uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  reviewed_by         uuid,
  reviewed_at         timestamptz,
  review_note         text,
  CONSTRAINT ux_knowledge_drafts_source UNIQUE (source_kind, source_id),
  CONSTRAINT ck_knowledge_drafts_source_kind CHECK (source_kind IN ('alert', 'case')),
  CONSTRAINT ck_knowledge_drafts_conclusion CHECK (conclusion IN (
    'closed_fp',
    'closed_benign',
    'concluded_fp',
    'concluded_policy_violation',
    'confirmed_incident'
  )),
  CONSTRAINT ck_knowledge_drafts_status CHECK (
    status IN ('pending', 'approved', 'rejected', 'merged')
  ),
  CONSTRAINT fk_knowledge_drafts_reviewer FOREIGN KEY (reviewed_by) REFERENCES users (user_id),
  CONSTRAINT fk_knowledge_drafts_duplicate_of FOREIGN KEY (duplicate_of_entry)
    REFERENCES knowledge_entries (entry_id),
  CONSTRAINT fk_knowledge_drafts_conflict_with FOREIGN KEY (conflict_with_entry)
    REFERENCES knowledge_entries (entry_id)
);

CREATE TABLE rag_results (
  lookup_id    uuid        PRIMARY KEY,
  subject_kind text        NOT NULL,
  subject_id   text        NOT NULL,
  status       text        NOT NULL,
  history      jsonb,
  matches      jsonb,
  match_notes  jsonb,
  llm_run_id   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_rag_results_subject_kind CHECK (subject_kind IN ('alert', 'case')),
  CONSTRAINT ck_rag_results_status CHECK (status IN ('ok', 'empty', 'failed', 'budget'))
);
-- "The newest lookup for this subject", which is what ① and ② read at prompt time.
CREATE INDEX ix_rag_results_subject ON rag_results (subject_kind, subject_id, created_at DESC);

-- Rights, granted here and not left to 017's default privileges (header, note 6).
GRANT SELECT, INSERT, UPDATE ON knowledge_drafts, knowledge_entries TO app_rw;
-- `rag_results` is append-only (header, note 6): the REVOKE also removes what 017's default
-- privileges grant on a table created by the role that ran 017.
GRANT SELECT, INSERT ON rag_results TO app_rw;
REVOKE UPDATE, DELETE, TRUNCATE ON rag_results FROM app_rw;

-- ---------------------------------------------------------------------------
-- llm_runs — the lookup's id; two pipelines, two roles. The table is append-only (017): adding a
-- column and replacing CHECKs are DDL, which the row triggers do not see.
-- ---------------------------------------------------------------------------
ALTER TABLE llm_runs ADD COLUMN rag_lookup_id uuid;

ALTER TABLE llm_runs DROP CONSTRAINT ck_llm_runs_pipeline;
ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_pipeline
  CHECK (pipeline IN ('triage', 'investigate', 'rag_lookup', 'knowledge_draft'));

ALTER TABLE llm_runs DROP CONSTRAINT ck_llm_runs_pipeline_khop_subject;
ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_pipeline_khop_subject CHECK (
  (pipeline = 'triage'      AND subject_type = 'alert')
  OR (pipeline = 'investigate' AND subject_type = 'case')
  OR (pipeline IN ('rag_lookup', 'knowledge_draft') AND subject_type IN ('alert', 'case'))
);

ALTER TABLE llm_runs DROP CONSTRAINT ck_llm_runs_role;
ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_role
  CHECK (role IS NULL OR role IN ('proposer', 'verifier', 'investigator', 'retriever', 'drafter'));

-- ---------------------------------------------------------------------------
-- jobs — 016's six types, in 016's order, then the two new ones.
-- ---------------------------------------------------------------------------
ALTER TABLE jobs DROP CONSTRAINT ck_jobs_job_type;
ALTER TABLE jobs ADD CONSTRAINT ck_jobs_job_type CHECK (job_type IN (
  'pipeline',
  'triage',
  'investigate',
  'digest',
  'health',
  'pull',
  'rag_lookup',
  'knowledge_draft'
));

-- ---------------------------------------------------------------------------
-- audit_events — 019's 28 names, in 019's order, then the eight of DEC-210.
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
  'knowledge.redraft_requested'
));

-- ---------------------------------------------------------------------------
-- The history query's index. The expression is the SOAR case key; it must be written exactly
-- like this in the query for the planner to use the index.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_soar_dedup_key ON alerts ((raw_payload #>> '{enrichment,case,dedup_key}'));

INSERT INTO schema_migrations (version) VALUES ('020_learned_knowledge');

COMMIT;
