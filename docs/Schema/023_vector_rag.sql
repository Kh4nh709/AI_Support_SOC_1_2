-- ============================================================================
-- 023_vector_rag.sql — AI Support SOC
-- DEC-213 (P14-T04): the contracts of Part B, Voyage embeddings in an independent pgvector.
-- Runs after 021, as the database owner. KHÔNG sửa 001-021: chúng đã áp.
--
-- It stands on 021 alone. The number 022 belongs to another card (`022_true_positive.sql`) and this
-- migration neither reads nor changes anything that one does, so either order of applying them leaves
-- the same schema.
--
-- Three changes, and nothing else (no table, no index, no right, no row):
--
--   1. `ck_jobs_job_type` gains `knowledge_embed`: 8 -> 9 types, 020's eight first and in 020's
--      order. The job embeds one approved entry in `vectordb` (the derived index); its subject is
--      the entry's uuid as text, and single-flight is the existing partial unique index
--      `ux_jobs_mot_job_song_moi_subject` on (job_type, subject_id). Only `rag-worker` will claim it
--      (P14-T05); this migration only lets the row exist.
--
--   2. `rag_results.failure_kind text NULL`: why a lookup `failed`, as a closed kind, never as the
--      provider's own words. The CHECK says: NULL, or the row `failed` for one of the six kinds
--      `rate_limit | timeout | auth | quota | provider_error | vectordb_unreachable`. So an `ok`,
--      `empty` or `budget` row never carries one, and a `failed` row MAY have none: the rows 020
--      wrote before this column existed are such rows, and they are not rewritten.
--
--   3. `rag_results.ranked jsonb NULL`: the list of `{entry_id, score}` the rerank gave (the admin
--      page shows it; `match_notes` stays empty, a reranker writes no text). It has no CHECK and no
--      default, like `matches`; the application writes the list.
--
-- Rights are untouched. 020 granted `app_rw` SELECT and INSERT on `rag_results` at table level and
-- revoked UPDATE, DELETE and TRUNCATE (the table is append-only: a lookup is stored once and read),
-- so the two new columns follow that: written with the row, never changed after it.
--
-- No old row is rewritten or deleted. Adding a nullable column takes no rewrite, and the new CHECK
-- holds for every existing row (failure_kind is NULL on all of them).
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- jobs — 020's eight types, in 020's order, then the new one.
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
  'knowledge_draft',
  'knowledge_embed'
));

-- ---------------------------------------------------------------------------
-- rag_results — the failure kind and the rerank's list.
-- ---------------------------------------------------------------------------
ALTER TABLE rag_results ADD COLUMN failure_kind text;
ALTER TABLE rag_results ADD COLUMN ranked jsonb;

ALTER TABLE rag_results ADD CONSTRAINT ck_rag_results_failure_kind CHECK (
  failure_kind IS NULL
  OR (status = 'failed' AND failure_kind IN (
    'rate_limit',
    'timeout',
    'auth',
    'quota',
    'provider_error',
    'vectordb_unreachable'
  ))
);

INSERT INTO schema_migrations (version) VALUES ('023_vector_rag');

COMMIT;
