BEGIN;
-- ============================================================================
-- schema.sql — AI Support SOC · toàn bộ schema PostgreSQL
--
-- TỆP NÀY ĐƯỢC SINH TỰ ĐỘNG bằng cách ghép migrations/*.sql theo thứ tự.
-- KHÔNG SỬA TRỰC TIẾP — sửa migration rồi chạy lại build_schema.py.
--   Kiểm trong CI:  python3 build_schema.py --check
--
-- Nguồn : 001_bang_nen.sql, 002_alerts.sql, 003_jobs_audit_llm.sql, 004_indexes_alerts.sql, 005_index_lop_bao_ve_2.sql, 006_chot_hop_dong.sql, 007_users.sql, 008_audit_event_type.sql, 009_audit_actor.sql, 010_enrich_cache.sql, 011_auth.sql, 012_hop_dong_job_llm.sql, 013_assets_enrichment.sql, 014_intake_cursor_heartbeat.sql, 015_labels_reviews_notes_eval_health.sql, 016_alter_alerts_jobs_llm_runs_users.sql, 017_append_only_and_roles.sql
-- Đích  : PostgreSQL 16 (đã chạy thử trên 16.15)
-- Dùng  : psql -d <db> -v ON_ERROR_STOP=1 -f schema.sql
--
-- Mọi giá trị trong tệp này truy được về một dòng cụ thể trong bộ đặc tả
-- Phase 1-7 + kiến trúc tổng quát. Bảng truy vết đầy đủ: schema-notes.md.
-- ============================================================================


-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/001_bang_nen.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 001_bang_nen.sql — AI Support SOC
-- Các bảng KHÔNG phụ thuộc `alerts`. Phải chạy trước 002.
--   assets · identities · iocs      (enrichment/ · Phase 4)
--   autoclose_rules                 (ingest/     · Phase 3)
--   cases                           (tier2/      · Phase 6, 7)
--   rejected_alerts                 (ingest/     · Phase 1)
-- Mọi giá trị đều truy được về đặc tả; xem bảng truy vết trong schema-notes.md.
-- ============================================================================


CREATE TABLE IF NOT EXISTS schema_migrations (
  version     text        PRIMARY KEY,
  applied_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- assets — Phase 4:82 `SELECT * FROM assets WHERE hostname = $agent_name`
-- Nối theo GIÁ TRỊ, không FK cứng (Phase 4:87, KT B2:196).
-- `criticality`: 4 giá trị lấy từ công thức risk_score, Phase 4:161.
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
  hostname     text        PRIMARY KEY,
  criticality  text        NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_assets_criticality
    CHECK (criticality IN ('crown_jewel','high','normal','low'))
);

-- ---------------------------------------------------------------------------
-- identities — Phase 4:83 `SELECT * FROM identities WHERE username = $alert_user`
-- `is_privileged`: Phase 4:162 `context += 15 if identity.is_privileged else 0`
-- ---------------------------------------------------------------------------
CREATE TABLE identities (
  username       text        PRIMARY KEY,
  is_privileged  boolean     NOT NULL DEFAULT false,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- iocs — Phase 4:84
--   `SELECT * FROM iocs WHERE value IN ($srcip,$dstip) AND expires_at > now()`
-- `reputation`: 3 giá trị, Phase 4:163
-- ---------------------------------------------------------------------------
CREATE TABLE iocs (
  value       text        PRIMARY KEY,
  reputation  text        NOT NULL,
  expires_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_iocs_reputation
    CHECK (reputation IN ('malicious','suspicious','clean'))
);

-- ---------------------------------------------------------------------------
-- autoclose_rules — DDL nguyên văn Phase 3:83-91.
-- CẢNH BÁO ĐẶT TÊN: cột `rule_id` ở đây là uuid của rule auto-close,
-- KHÁC hoàn toàn `alerts.rule_id` (id rule Wazuh, dạng text "40112").
-- Hai cột trùng tên, khác nghĩa, khác kiểu. Xem schema-notes.md · Cần bổ sung #7.
-- ---------------------------------------------------------------------------
CREATE TABLE autoclose_rules (
  rule_id     uuid        PRIMARY KEY,
  name        text        NOT NULL,
  enabled     boolean     NOT NULL DEFAULT true,
  match       jsonb       NOT NULL,
  reason      text        NOT NULL,
  created_by  uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Phase 3:143-146 · truy vấn nạp cache, ORDER BY TẤT ĐỊNH
CREATE INDEX ix_autoclose_rules_enabled
  ON autoclose_rules (created_at ASC, rule_id ASC)
  WHERE enabled = true;

-- ---------------------------------------------------------------------------
-- cases — Phase 6:169-171 (INSERT), Phase 7:144-149 (UPDATE), Phase 7:125.
-- `status`: 4 giá trị, KT B3:246 + Phase 7:146.
--   concluded_* CHỈ tồn tại ở đây, KHÔNG phải giá trị của alerts.status.
--   Xem mâu thuẫn M-A trong schema-notes.md.
-- ---------------------------------------------------------------------------
CREATE TABLE cases (
  case_id            uuid        PRIMARY KEY,
  title              text        NOT NULL,
  status             text        NOT NULL DEFAULT 'investigating',
  severity           text        NOT NULL,
  created_by         uuid        NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  last_analyzed_at   timestamptz,
  conclusion_reason  text,
  concluded_by       uuid,
  concluded_at       timestamptz,

  CONSTRAINT ck_cases_status CHECK (status IN (
    'investigating',
    'concluded_fp', 'concluded_policy_violation', 'confirmed_incident')),

  CONSTRAINT ck_cases_severity
    CHECK (severity IN ('critical','high','medium','low')),

  -- G3 áp cho cases: kết luận thì phải có mốc + người chịu trách nhiệm.
  -- Phase 7:144-149 ghi cả ba cột trong cùng một UPDATE.
  CONSTRAINT ck_cases_ket_luan_phai_co_moc CHECK (
    status = 'investigating'
    OR (concluded_at IS NOT NULL AND concluded_by IS NOT NULL
        AND conclusion_reason IS NOT NULL)
  )
);

-- ---------------------------------------------------------------------------
-- rejected_alerts — Phase 1:459 "Ghi một dòng rejected_alerts
--   (payload gốc + lý do + source_ip + thời điểm)".
-- Tên cột KHÔNG có trong đặc tả; xem Cần bổ sung #4.
-- Phase 1:466 — thông điệp lỗi không được chứa tên class/message của exception.
-- ---------------------------------------------------------------------------
CREATE TABLE rejected_alerts (
  rejected_id  bigint      GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  raw_payload  jsonb       NOT NULL,
  reason       text        NOT NULL,
  source_ip    text        NOT NULL DEFAULT '',
  received_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES ('001_bang_nen');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/002_alerts.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 002_alerts.sql — bảng trung tâm, 51 cột + case_alerts
-- Phụ thuộc 001 (cases, autoclose_rules).
-- Mỗi cột có chú thích <TỆP>:<DÒNG> trỏ về nguồn trong đặc tả.
--   KT=kien-truc  P1..P7=phase-1..phase-7
-- ============================================================================


CREATE TABLE alerts (
  -- ── ① Từ SIEM · Phase 1 Khối 1 (P1:49-70) ────────────────────────────────
  alert_id           text        PRIMARY KEY,          -- P1:51  `_source.id`, KHÔNG lấy `_id` (P1:84)
  rule_id            text        NOT NULL,             -- P1:52  id rule Wazuh, dạng text ("40112")
  rule_level         integer     NOT NULL,             -- P1:66  `_source.rule.level`
  severity           text        NOT NULL,             -- P1:147-151 quy đổi từ rule_level
  description        text        NOT NULL,             -- P1:53  bắt buộc, thiếu → 400
  agent_name         text        NOT NULL,             -- P1:54  bắt buộc, là 1 trong 4 cột khóa cụm
  alert_time         timestamptz NOT NULL,             -- P1:55  giờ Wazuh phát hiện; UTC (P1:143)

  agent_id           text,                             -- P1:64  tùy chọn → NULL
  agent_ip           text,                             -- P1:64  tùy chọn → NULL. text chứ không inet:
                                                       --        parse hỏng không được làm mất alert (P1:18)
  alert_user         text,                             -- P1:63  dstuser ưu tiên, fallback srcuser; thiếu → NULL
  decoder            text,                             -- P1:69  decoder.name, fallback .parent
  event_time         timestamptz,                      -- P1:70  giờ trong dòng log gốc; parse hỏng → NULL (P1:141)
  raw_log            text        NOT NULL DEFAULT '',  -- P1:65  thiếu → ''; cắt ở 1000 KB (C3, P1:308)

  -- G4 + B1 (KT:380, P1:100, P2:144) · srcip/dstip KHÔNG BAO GIỜ NULL.
  -- Đây là điều kiện để 4 cột khóa cụm dùng `=` thuần và vào được Index Cond.
  srcip              text        NOT NULL DEFAULT '',  -- P1:61
  dstip              text        NOT NULL DEFAULT '',  -- P1:61
  -- C2 (KT:418, P1:98) · cổng thiếu/không đọc được → 0, không NULL
  src_port           integer     NOT NULL DEFAULT 0,   -- P1:62
  dst_port           integer     NOT NULL DEFAULT 0,   -- P1:62

  mitre_ids          text[]      NOT NULL DEFAULT '{}',-- P1:67  thiếu → []
  rule_groups        text[]      NOT NULL DEFAULT '{}',-- P1:68  thiếu → []

  -- ── Phân giải category · Phase 1 Khối 5 (C5) ─────────────────────────────
  category           text        NOT NULL,             -- P1:197 khóa CHÍNH: tra playbook, đo lường
  categories         text[]      NOT NULL DEFAULT '{}',-- P1:198 ngữ cảnh; CẤM dùng tra playbook/đo lường
  resolved_by        text        NOT NULL,             -- P1:158 tầng đã quyết; 'none' khi unknown (P1:202)
  mapping_version    text        NOT NULL,             -- P1:191 để biết alert nào cần phân loại lại

  -- ── ② Cờ suy ra · Phase 1 Khối 7 (C3, C4) ────────────────────────────────
  -- 3 trạng thái, KHÔNG phải 2: NULL = "không khẳng định được" (P1:266-273)
  srcip_is_private   boolean,                          -- P1:276
  dstip_is_private   boolean,                          -- P1:276
  raw_log_truncated  boolean     NOT NULL DEFAULT false, -- P1:311
  source             text        NOT NULL DEFAULT 'wazuh', -- P1:434
  is_synthetic       boolean     NOT NULL DEFAULT false,   -- P1:82 · webhook LUÔN đặt false

  -- ── ③ Vòng đời · trục 1: status (KT B3:236-244) ──────────────────────────
  status             text        NOT NULL DEFAULT 'received',
  event_bucket_hash  text        NOT NULL,             -- B6 (KT:209) · đổi tên từ `fingerprint`
                                                       -- KHÔNG phải khóa cụm (P1:236), KHÔNG đếm cụm (P1:254)
  duplicate_of       text        REFERENCES alerts(alert_id),  -- D-C4: cụm = duplicate_of IS NULL
  occurrence_count   integer     NOT NULL DEFAULT 1,   -- P2:240
  case_id            uuid        REFERENCES cases(case_id),    -- P6:180
  autoclose_rule_id  uuid        REFERENCES autoclose_rules(rule_id), -- P3:157, P3:525

  -- Mốc thời gian ĐIỀU KHIỂN — G5/R7/B2: DB sinh, không phải Python/SIEM
  received_at        timestamptz NOT NULL DEFAULT now(),  -- P1:448
  first_seen_at      timestamptz NOT NULL DEFAULT now(),  -- P1:448 · trần tuổi cụm
  last_seen_at       timestamptz NOT NULL DEFAULT now(),  -- P1:448 · cửa sổ trượt (D-C2)
  acknowledged_at    timestamptz,                         -- P6:89  · MỐC SLA
  acknowledged_by    uuid,                                -- P6:90  · người ĐẦU TIÊN mở (P6-2)
  closed_at          timestamptz,                         -- P1:441 · "đã kết thúc vòng đời"
  sealed_at          timestamptz,                         -- B4 (P2:214) · "cụm còn hút hay không"
  close_reason       text,                                -- P1:441

  -- ── ④ Trục 2: xử lý nền (KT:259) · KHÔNG phải status ─────────────────────
  triage_status         text     NOT NULL DEFAULT 'pending', -- P1:440, P5:137
  triaged_count         integer  NOT NULL DEFAULT 0,         -- P2:313 · mốc cho needs_retriage
  risk_score            integer,                             -- P4:168 · NULL khi chưa enrich
  risk_score_components jsonb,                               -- KT:294 · từng khoản cộng
  asset_context         jsonb,                               -- P4:299
  identity_context      jsonb,                               -- P4:299
  ioc_context           jsonb,                               -- P4:299
  lookup_status         jsonb,                               -- P4:307 · {"asset":"found","ioc":"skipped"}

  -- ── ⑤ Nguyên bản · G9 (KT:385) giữ nguyên vẹn, KHÔNG cắt xén ─────────────
  raw_payload        jsonb       NOT NULL,             -- P1:444

  -- ══ RÀNG BUỘC CƯỠNG CHẾ ═════════════════════════════════════════════════

  -- Tập giá trị status. concluded_* KHÔNG có ở đây — chúng thuộc cases.status.
  -- Căn cứ: KT:251-255 (bảng ánh xạ kết luận case → alerts.status) + P7:315-319.
  -- Xem mâu thuẫn M-A trong schema-notes.md.
  CONSTRAINT ck_alerts_status CHECK (status IN (
    'received', 'duplicate', 'auto_closed',
    'enriching', 'queued_tier1', 'tier1_active', 'escalated_tier2',
    'closed_fp', 'closed_benign', 'closed_confirmed')),

  -- Trục 2, tách bạch với status (M3). 'ready' theo P5:137 (câu SQL duy nhất
  -- ghi cột này); P3:178 viết 'done' là chữ cũ. Xem mâu thuẫn M-B.
  CONSTRAINT ck_alerts_triage_status
    CHECK (triage_status IN ('pending','ready','unavailable')),

  CONSTRAINT ck_alerts_severity
    CHECK (severity IN ('critical','high','medium','low')),

  -- ── G3 (KT:379, P2:500) · MỌI trạng thái kết thúc PHẢI set closed_at ─────
  -- 5 trạng thái terminal của alerts theo KT B3:236-244.
  CONSTRAINT ck_alerts_g3_terminal_phai_co_closed_at CHECK (
    status NOT IN ('duplicate','auto_closed','closed_fp','closed_benign','closed_confirmed')
    OR closed_at IS NOT NULL
  ),

  -- ── H2/P6-3 (P6:263, P6:290) · đóng bởi NGƯỜI thì set CẢ sealed_at ──────
  -- auto_closed cố ý KHÔNG nằm trong danh sách này (M4, P3:308): cụm nhiễu
  -- vẫn hút bản sao cho tới khi sweeper niêm hoặc chạm trần 30 phút.
  CONSTRAINT ck_alerts_h2_dong_boi_nguoi_phai_seal CHECK (
    status NOT IN ('closed_fp','closed_benign','closed_confirmed')
    OR sealed_at IS NOT NULL
  ),

  -- ── H3 (P6:264, P6:200) · escalated_tier2 KHÔNG set sealed_at ───────────
  -- Cụm đang điều tra vẫn phải hút bản sao (D-C5).
  CONSTRAINT ck_alerts_h3_escalate_khong_seal CHECK (
    status <> 'escalated_tier2' OR sealed_at IS NULL
  ),

  -- ── P2:227,255 · bản sao đặt CẢ closed_at LẪN sealed_at ngay lúc INSERT ──
  -- Thiếu sealed_at thì bản sao thoả nhánh 2 của vị từ "cụm còn hút" và trở
  -- thành ứng viên gốc cho lần tra sau (D2).
  CONSTRAINT ck_alerts_ban_sao_phai_seal_va_tro_goc CHECK (
    status <> 'duplicate'
    OR (duplicate_of IS NOT NULL AND closed_at IS NOT NULL AND sealed_at IS NOT NULL)
  ),

  -- Không tự trỏ về chính mình (chặn cụm tự tham chiếu)
  CONSTRAINT ck_alerts_khong_tu_tro CHECK (duplicate_of IS DISTINCT FROM alert_id),

  -- D6 (P2:401) · last_seen_at không bao giờ lùi về trước first_seen_at
  CONSTRAINT ck_alerts_last_seen_khong_lui CHECK (last_seen_at >= first_seen_at),

  -- D3 (P2:398) · occurrence_count đếm từ 1 (chính alert gốc)
  CONSTRAINT ck_alerts_occurrence_toi_thieu_1 CHECK (occurrence_count >= 1),
  CONSTRAINT ck_alerts_triaged_count_khong_am CHECK (triaged_count >= 0),

  -- E2/P4-3 (P4:168) · risk_score = min(100, …) → trần 100, chỉ cộng → sàn 0
  CONSTRAINT ck_alerts_risk_score_0_100
    CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100),

  -- C1/B6 (P1:212) · sha256 hex = đúng 64 ký tự
  CONSTRAINT ck_alerts_hash_sha256_hex
    CHECK (event_bucket_hash ~ '^[0-9a-f]{64}$'),

  -- C3 (P1:308) · RAW_LOG_MAX_BYTES = 1_024_000. Cắt ở ingest/, nhưng DB
  -- chặn lần hai để một đường ghi khác không lách qua.
  CONSTRAINT ck_alerts_raw_log_tran_1000kb
    CHECK (octet_length(raw_log) <= 1024000)
);

-- ---------------------------------------------------------------------------
-- case_alerts — Phase 6:172-179. "Đây là lúc DUY NHẤT correlation được lưu"
-- (P6:181). Trước đó correlation là truy vấn, sau đó là bảng này.
-- Trần MAX_ALERTS_PER_CASE = 200 (P6-4) cưỡng chế ở tầng ứng dụng — nó là
-- ràng buộc trên SỐ DÒNG mỗi case, không biểu diễn được bằng CHECK.
-- ---------------------------------------------------------------------------
CREATE TABLE case_alerts (
  case_id   uuid        NOT NULL REFERENCES cases(case_id),
  alert_id  text        NOT NULL REFERENCES alerts(alert_id),
  added_by  uuid        NOT NULL,                    -- P6:173
  added_at  timestamptz NOT NULL DEFAULT now(),      -- P6:173
  PRIMARY KEY (case_id, alert_id)
);

INSERT INTO schema_migrations (version) VALUES ('002_alerts');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/003_jobs_audit_llm.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 003_jobs_audit_llm.sql — hàng đợi job + hai bảng ghi vết append-only
-- Không FK tới alerts/cases: `subject_id` là ĐA HÌNH (giữ cả alert_id text
-- lẫn case_id uuid), nên phải là text. Xem schema-notes.md · quyết định Q3.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- jobs — hàng đợi nằm TRONG PostgreSQL, không cần Redis (KT A2:62).
-- Vòng lặp worker: P4:42-50 `FOR UPDATE SKIP LOCKED`.
-- ---------------------------------------------------------------------------
CREATE TABLE jobs (
  job_id        bigint      GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, -- P4:42
  job_type      text        NOT NULL,                    -- P4:42
  subject_id    text        NOT NULL,                    -- P4:42
  status        text        NOT NULL DEFAULT 'pending',  -- P4:44
  scheduled_at  timestamptz NOT NULL DEFAULT now(),      -- P4:44 · backoff ghi vào đây
  locked_at     timestamptz,                             -- P4:49 · worker chết → nhặt lại
  attempts      integer     NOT NULL DEFAULT 0,          -- P4:49
  last_error    text,                                    -- P4:57
  created_at    timestamptz NOT NULL DEFAULT now(),

  -- Hai loại job, P5-1:38 "Số job | 1 | 2 (`enrich`, `triage`)"
  CONSTRAINT ck_jobs_job_type CHECK (job_type IN ('enrich','triage')),

  -- Trước 006: KHÔNG có CHECK trên `status`, vì đặc tả nêu 'pending' (P4:44), 'running'
  -- (P4:49), 'failed' (P4:68) nhưng KHÔNG nêu giá trị cho job chạy XONG.
  -- Bịa một giá trị rồi cưỡng chế nó là vượt quá đặc tả.
  -- Chốt S1 (25/08) đã thêm 'succeeded' → ck_jobs_status nằm ở migration 006.

  -- P4-7:58 · JOB_MAX_ATTEMPTS = 3
  CONSTRAINT ck_jobs_attempts_khong_am CHECK (attempts >= 0)
);

-- P4:42-47 · truy vấn nhặt job. Partial index: chỉ job đang chờ mới đáng đánh chỉ mục.
CREATE INDEX ix_jobs_pending
  ON jobs (scheduled_at)
  WHERE status = 'pending';

-- P4:70 · nhặt lại job của worker đã chết: locked_at < now() - JOB_LOCK_TIMEOUT_S
CREATE INDEX ix_jobs_running_locked
  ON jobs (locked_at)
  WHERE status = 'running';

-- ---------------------------------------------------------------------------
-- audit_events — append-only (KT A3:90). Không UPDATE, không DELETE.
-- Khóa chính KHÔNG có trong đặc tả — xem Cần bổ sung #2.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
  audit_id    bigint      GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  event_type  text        NOT NULL,   -- P2:245 'alert.duplicate_merged', P6:106 'alert.acknowledged', …
  subject_id  text        NOT NULL,   -- alert_id (text) HOẶC case_id (uuid) — P7:325
  actor_id    uuid,                   -- P6:105 · NULL khi actor_role='system'
  actor_role  text        NOT NULL,   -- P2:246 'system', P5:143 'llm', P6:106 'analyst'
  payload     jsonb,                  -- P2:247
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT ck_audit_actor_role CHECK (actor_role IN ('system','llm','analyst'))
);

-- Phép đo ③ (KT B7:387) JOIN llm_runs ↔ audit_events theo subject_id
CREATE INDEX ix_audit_subject ON audit_events (subject_id, created_at);
CREATE INDEX ix_audit_event_type ON audit_events (event_type, created_at);

-- ---------------------------------------------------------------------------
-- llm_runs — append-only. Cột nguyên văn P5:131-135 + P7:321-324.
-- `user_message` chứa TOÀN BỘ prompt đã gửi (P5:145) — đây là lý do enrichment
-- không cần bảng riêng (KT B2:219).
-- I4 (P7:429) · mỗi lần chạy ② ghi MỘT DÒNG MỚI, không ghi đè.
-- ---------------------------------------------------------------------------
CREATE TABLE llm_runs (
  run_id              uuid        PRIMARY KEY,   -- P5:131 · app cấp, không DEFAULT
  pipeline            text        NOT NULL,      -- P5:135 'triage' · P7:327 'investigate'
  subject_type        text        NOT NULL,      -- P5:135 'alert' · P7:327 'case'
  subject_id          text        NOT NULL,      -- alert_id HOẶC case_id
  system_prompt       text        NOT NULL,      -- P5:132
  user_message        text        NOT NULL,      -- P5:132 · nguyên văn prompt (T7)
  agent_trace         jsonb,                     -- P5:132
  result              jsonb,                     -- P5:132 · NULL khi model hỏng (T6)
  injection_findings  jsonb,                     -- P5:133
  citation_warnings   jsonb,                     -- P5:133
  input_tokens        integer,                   -- P5:134
  output_tokens       integer,                   -- P5:134
  latency_ms          integer,                   -- P5:134
  created_at          timestamptz NOT NULL DEFAULT now(),

  -- M-C · `pipeline` là TEXT, không phải số nguyên. P3:253 viết `pipeline = 1`
  -- là câu cũ; P5:175, P6:35, P7:241 đều dùng chuỗi. Xem schema-notes.md.
  CONSTRAINT ck_llm_runs_pipeline CHECK (pipeline IN ('triage','investigate')),
  CONSTRAINT ck_llm_runs_subject_type CHECK (subject_type IN ('alert','case')),

  -- Hai cặp phải khớp nhau: ① chạy trên alert, ② chạy trên case (P7:20)
  CONSTRAINT ck_llm_runs_pipeline_khop_subject CHECK (
    (pipeline = 'triage'      AND subject_type = 'alert')
    OR (pipeline = 'investigate' AND subject_type = 'case')
  ),

  -- P5-5 · suggested_action là TẬP ĐÓNG BA GIÁ TRỊ; giá trị lạ coi như hỏng.
  -- Cưỡng chế ngay trong DB thay vì tin vào tầng ứng dụng.
  CONSTRAINT ck_llm_runs_suggested_action CHECK (
    pipeline <> 'triage'
    OR result IS NULL
    OR result->>'suggested_action' IS NULL
    OR result->>'suggested_action' IN ('false_positive','needs_review','escalate')
  ),

  -- P7:273 · ② có giá trị thứ tư `need_more_data` mà ① không có
  CONSTRAINT ck_llm_runs_suggested_conclusion CHECK (
    pipeline <> 'investigate'
    OR result IS NULL
    OR result->>'suggested_conclusion' IS NULL
    OR result->>'suggested_conclusion' IN
       ('false_positive','policy_violation','confirmed_incident','need_more_data')
  )
);

-- P6:34-36 · LEFT JOIN hàng đợi Tier 1 lấy gợi ý ①
-- P7:241    · đọc lịch sử ② của một case
CREATE INDEX ix_llm_runs_subject ON llm_runs (subject_id, pipeline, created_at DESC);

INSERT INTO schema_migrations (version) VALUES ('003_jobs_audit_llm');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/004_indexes_alerts.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 004_indexes_alerts.sql
-- Mỗi index kèm TRUY VẤN nó phục vụ và VỊ TRÍ truy vấn đó trong đặc tả.
-- Không có index nào ở đây là "phòng xa" — cái nào không truy được về một câu
-- SQL trong đặc tả thì không tạo.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- ① INDEX DEDUP — index quan trọng nhất của hệ thống.
-- Phục vụ: P2:116-132, câu SELECT chạy TRONG advisory lock của mọi webhook.
-- Nguyên văn index: P2:136-137.
--
-- Vị từ partial PHẢI KHỚP CÚ PHÁP với vị từ truy vấn (D7, P2:402; D-C6).
-- Không phải khớp về mặt logic — khớp về mặt CÚ PHÁP, vì bộ chứng minh vị từ
-- của Postgres so trên cây biểu thức.
--
-- Thứ tự cột: 4 cột khóa cụm (đẳng thức) TRƯỚC, rồi last_seen_at DESC.
--   - 4 cột đẳng thức → tất cả vào Index Cond (điều kiện của B1)
--   - last_seen_at DESC ở cuối → phục vụ LUÔN `ORDER BY last_seen_at DESC
--     LIMIT 1` mà không cần node Sort
-- Thứ tự trong index (rule_id, srcip, agent_name, dstip) chép đúng thứ tự
-- P2:136 — với đẳng thức thuần thì thứ tự không đổi kết quả, nhưng giữ nguyên
-- để người đọc đối chiếu được với đặc tả.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_dedup
  ON alerts (rule_id, srcip, agent_name, dstip, last_seen_at DESC)
  WHERE (closed_at IS NULL OR sealed_at IS NULL) AND status <> 'duplicate';

-- ---------------------------------------------------------------------------
-- ②③④ BA INDEX CORRELATION — P4:267-269, bắt buộc theo P4:395
-- ("thiếu là quét toàn bảng cho mọi alert").
-- Phục vụ: P4:243-259 `summarize_for_prompt()`
--   WHERE (agent_name = $1 OR alert_user = $2 OR srcip = ANY($3))
--     AND alert_time BETWEEN $t - 2h AND $t + 2h
-- Ba index riêng cho ba nhánh OR → Postgres dựng BitmapOr (P4:272).
-- Mỗi index để alert_time làm cột thứ hai để cửa sổ ±2h cũng vào Index Cond.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_corr_agent ON alerts (agent_name, alert_time);
CREATE INDEX ix_alerts_corr_user  ON alerts (alert_user, alert_time);
CREATE INDEX ix_alerts_corr_srcip ON alerts (srcip,      alert_time);

-- ---------------------------------------------------------------------------
-- ⑤ INDEX duplicate_of — P2:305 nói rõ "duplicate_of đã có index".
-- Phục vụ ba truy vấn:
--   - P2:299-302 danh sách tài khoản bị nhắm trong cụm
--   - P6:150-151 fan-out đóng cả cụm  `WHERE duplicate_of = $1`
--   - P7:310-311 kết luận case        `OR duplicate_of IN (…)`
-- Partial: bỏ NULL khỏi index. Dòng gốc (duplicate_of IS NULL) chiếm phần lớn
-- bảng và KHÔNG BAO GIỜ là kết quả của các truy vấn trên.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_duplicate_of
  ON alerts (duplicate_of)
  WHERE duplicate_of IS NOT NULL;

-- ---------------------------------------------------------------------------
-- ⑥ INDEX HÀNG ĐỢI TIER 1 — P6:29-40
--   WHERE status='queued_tier1' AND NOT is_synthetic
--   ORDER BY needs_retriage DESC, risk_score DESC NULLS LAST, first_seen_at ASC
-- `needs_retriage` tính lúc truy vấn (P6:46) nên KHÔNG đánh chỉ mục được;
-- hai khóa sắp xếp còn lại thì có. NULLS LAST trong index để khớp ORDER BY —
-- alert chưa enrich xong không bị đẩy lên đầu (P6:47).
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_queue_tier1
  ON alerts (risk_score DESC NULLS LAST, first_seen_at ASC)
  WHERE status = 'queued_tier1' AND NOT is_synthetic;

-- ---------------------------------------------------------------------------
-- ⑦ INDEX SWEEPER — P3:341-345, chạy khi analyst tắt một rule auto-close:
--   UPDATE alerts SET sealed_at = now()
--   WHERE autoclose_rule_id = $1 AND sealed_at IS NULL
-- Đây là đường "tắt rule có hiệu lực TỨC THÌ" của B4. Không có index thì
-- thao tác tắt rule quét toàn bảng — đúng lúc analyst đang vội.
-- Partial `sealed_at IS NULL` khớp cú pháp với vị từ của UPDATE.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_sweeper
  ON alerts (autoclose_rule_id)
  WHERE autoclose_rule_id IS NOT NULL AND sealed_at IS NULL;

-- ---------------------------------------------------------------------------
-- ⑧ INDEX received_at — phục vụ hai truy vấn đo lường:
--   - P3:277-288 lớp bảo vệ 2, cửa sổ 7 ngày (AC-C6)
--   - KT B7:378-384 báo cáo theo tuần
-- Ghi rõ giới hạn: cả hai đều là truy vấn GỘP trên cửa sổ rộng; nếu cửa sổ
-- phủ phần lớn bảng thì planner chọn Seq Scan và index này không được dùng.
-- Kết quả EXPLAIN thật ghi trong schema-notes.md — không phỏng đoán.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_alerts_received_at ON alerts (received_at);

-- ---------------------------------------------------------------------------
-- KHÔNG tạo index trên `event_bucket_hash`.
-- P2:502 (Việc còn lại #2): "Bỏ index cũ theo cột băm — không còn truy vấn nào
-- dùng". D8 (P2:403) cấm mọi truy vấn đếm cụm bằng cột này. Tạo index sẽ mời
-- gọi đúng thứ D8 cấm.
-- ---------------------------------------------------------------------------

INSERT INTO schema_migrations (version) VALUES ('004_indexes_alerts');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/005_index_lop_bao_ve_2.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 005_index_lop_bao_ve_2.sql
-- Index này KHÔNG có trong đợt 004. Nó được tìm ra bằng EXPLAIN sau khi nạp
-- 500.000 dòng, nên đi thành một migration riêng thay vì sửa 004 — 004 đã áp.
--
-- Phục vụ: P3:277-288 · lớp bảo vệ 2 (AC-C6) "cảnh báo khi một rule vượt 30%
-- tổng alert trên cửa sổ 7 ngày".
--
-- ĐO ĐƯỢC trên 500.000 dòng, PostgreSQL 16.15:
--   chỉ có ix_alerts_received_at : 117,5 ms · 21.095 buffer · loại bỏ 120.406 dòng ở Filter
--   thêm index này               :  11,4 ms ·  2.905 buffer · không dòng nào bị loại
--   kích thước index             : 400 kB
-- Lý do chênh lệch: nửa `auto_closed` chỉ chiếm 3.888/124.295 dòng của cửa sổ
-- 7 ngày, nên quét theo received_at rồi lọc status là đọc thừa 32 lần.
--
-- GIỚI HẠN — giống hệt giới hạn đã ghi ở KT:455 cho ix_alerts_dedup:
-- `auto_closed` là trạng thái terminal (M3), dòng KHÔNG BAO GIỜ rời khỏi vị từ,
-- nên index này tăng đơn điệu. Ở quy mô sản xuất phải partition `alerts` theo
-- tháng; khi đó index bị cắt theo partition.
-- ============================================================================


CREATE INDEX ix_alerts_autoclose_7ngay
  ON alerts (received_at)
  WHERE status = 'auto_closed';

INSERT INTO schema_migrations (version) VALUES ('005_index_lop_bao_ve_2');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/006_chot_hop_dong.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 006_chot_hop_dong.sql — AI Support SOC
-- Hệ quả DDL của vòng chốt hợp đồng trước khi viết `domain/transitions.py`.
-- Chạy sau 005. KHÔNG sửa 001-005: chúng đã áp.
--
-- Mã quyết định tham chiếu bảng "Vòng chốt hợp đồng" trong schema-notes.md §10.
--   S1  jobs.status có giá trị cho job chạy xong
--   S6  resolved_by: 6 giá trị, một cho mỗi tầng của thang 5 tầng
--   S9c alert_user chỉ NULL, không bao giờ ''
--   S5  iocs: một giá trị, nhiều nguồn, nhiều mức uy tín
--   S7  gỡ bẫy JOIN … USING (rule_id)
--   B   một alert thuộc tối đa một case
-- ============================================================================

-- ---------------------------------------------------------------------------
-- S1 · jobs.status có giá trị cho job chạy xong
-- Đặc tả nêu 'pending' (P4:44), 'running' (P4:49), 'failed' (P4:68) và KHÔNG nêu
-- giá trị cho job thành công — khoảng trống có thật, xem schema-notes §7①.
-- 'succeeded' là phản nghĩa của 'failed', cặp duy nhất không nhập nhằng.
-- Dòng job xong ĐƯỢC GIỮ LẠI: xoá là mất dữ liệu đo độ trễ job và số lần retry.
-- ---------------------------------------------------------------------------
ALTER TABLE jobs ADD CONSTRAINT ck_jobs_status
  CHECK (status IN ('pending','running','succeeded','failed'));

-- ---------------------------------------------------------------------------
-- S6 · resolved_by — 6 giá trị, một cho mỗi tầng của thang 5 tầng P1:160-166
-- Ngữ nghĩa 5 tầng đã đặc tả đầy đủ; thứ duy nhất còn trống là CHÍNH TẢ.
-- Không chốt chính tả = tỉ lệ `unknown` sai âm thầm, không ai thấy.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_resolved_by
  CHECK (resolved_by IN ('mitre','mitre_parent','rule_groups','decoder','dst_port','none'));

-- ---------------------------------------------------------------------------
-- S9c · alert_user chỉ NULL, không bao giờ ''
-- P2:299 lọc `alert_user IS NOT NULL`. Nếu '' lọt vào, `SELECT DISTINCT alert_user`
-- trả '' như một "tài khoản bị nhắm" — sai kiểu im lặng. CHECK biến nó thành
-- sai-thì-nổ. NULL <> '' trả NULL nên CHECK vẫn qua: chặn ĐÚNG một ca, chuỗi rỗng.
-- ĐIỀU KIỆN: P4:99 và gen_data.py phải đổi '' → NULL TRƯỚC khi chạy lệnh này.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD CONSTRAINT ck_alerts_alert_user_khong_rong
  CHECK (alert_user <> '');

-- ---------------------------------------------------------------------------
-- S5 · iocs — một giá trị, nhiều nguồn, nhiều mức uy tín
-- `value` là PRIMARY KEY nên một IP chỉ nằm được trong MỘT dòng: không biểu diễn
-- được ca "cùng một IP bị hai nguồn bêu tên với hai mức uy tín" (schema-notes §7⑤).
-- Đổi PK sau khi đã có dữ liệu là migration, nên làm bây giờ.
-- P4:86 vốn đã là `value IN (…)` nên trả TẬP DÒNG — hình dạng truy vấn không đổi,
-- tầng ứng dụng không phải sửa.
-- Luật chấm điểm: lấy uy tín XẤU NHẤT (malicious > suspicious > clean) trong các
-- dòng CÒN HẠN. Giữ `risk_score` tất định (V1).
-- ---------------------------------------------------------------------------
ALTER TABLE iocs ADD COLUMN source text NOT NULL DEFAULT 'internal';
ALTER TABLE iocs DROP CONSTRAINT iocs_pkey;
ALTER TABLE iocs ADD CONSTRAINT iocs_pkey PRIMARY KEY (value, source);

-- ---------------------------------------------------------------------------
-- S7 · gỡ bẫy JOIN … USING (rule_id)
-- `autoclose_rules.rule_id` là uuid của rule auto-close; `alerts.rule_id` là id
-- rule Wazuh dạng text ("40112"). Trùng tên, khác nghĩa, khác kiểu. Một câu
-- `JOIN … USING (rule_id)` viết vô ý sẽ hoặc lỗi kiểu, hoặc — tệ hơn — nối sai
-- im lặng. Đổi bây giờ khi CHƯA dòng code nào tham chiếu là một lệnh; đổi sau là
-- sửa ingest/ + soar/ + mọi truy vấn báo cáo.
-- PostgreSQL tự cập nhật FK `alerts.autoclose_rule_id` và index
-- `ix_autoclose_rules_enabled`. Sau lệnh này, `USING (rule_id)` giữa `alerts` và
-- `autoclose_rules` KHÔNG biên dịch được — đó chính là mục đích.
-- Lệch một chữ so với DDL nguyên văn P3:84, có chủ đích.
-- ---------------------------------------------------------------------------
ALTER TABLE autoclose_rules RENAME COLUMN rule_id TO autoclose_rule_id;

-- ---------------------------------------------------------------------------
-- B · một alert thuộc TỐI ĐA một case
-- `alerts.case_id` vốn là một cột uuid đơn → mô hình đã là 1:1. Index này chỉ ép
-- `case_alerts` đồng ý với nó, và là nơi hai transaction escalate chồng nhau nổ
-- ra thay vì âm thầm cướp `case_id` của case đã commit trước.
-- Vi phạm → unique violation → tầng gọi trả 409, đúng quy ước sẵn có (P6-1, P6-2).
-- Cưỡng chế ở DB, KHÔNG bằng `if` trong Python: `if` không sống sót qua hai
-- transaction đồng thời dưới READ COMMITTED.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX ux_case_alerts_mot_alert_mot_case ON case_alerts (alert_id);

INSERT INTO schema_migrations (version) VALUES ('006_chot_hop_dong');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/007_users.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 007_users.sql — AI Support SOC · quyết định S8
-- Tách riêng khỏi 006 vì nó THÊM BẢNG, không chỉ thêm ràng buộc.
--
-- Đóng lại schema-notes §7⑧: sáu cột uuid trỏ tới người mà không cột nào có FK,
-- vì không có bảng đích. Hệ quả cũ: DB không chặn được uuid mồ côi, và báo cáo
-- không hiển thị được TÊN người quyết.
--
-- Thêm FK sau khi đã có dòng mồ côi là migration có thể thất bại — nên làm bây giờ.
-- GIẢ ĐỊNH đã ghi nhận: < 50 analyst, vai trò phẳng, không phân quyền theo nhóm.
-- ============================================================================

CREATE TABLE users (
  user_id       uuid        PRIMARY KEY,
  username      text        NOT NULL UNIQUE,
  display_name  text        NOT NULL,
  role          text        NOT NULL,
  is_active     boolean     NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_users_role CHECK (role IN ('tier1','tier2','admin'))
);

-- ---------------------------------------------------------------------------
-- FK cho 4 cột TRẠNG THÁI SỐNG trên bảng nhỏ — validate ngay.
-- ---------------------------------------------------------------------------
ALTER TABLE cases           ADD CONSTRAINT fk_cases_created_by
  FOREIGN KEY (created_by)   REFERENCES users(user_id);
ALTER TABLE cases           ADD CONSTRAINT fk_cases_concluded_by
  FOREIGN KEY (concluded_by) REFERENCES users(user_id);
ALTER TABLE case_alerts     ADD CONSTRAINT fk_case_alerts_added_by
  FOREIGN KEY (added_by)     REFERENCES users(user_id);
ALTER TABLE autoclose_rules ADD CONSTRAINT fk_autoclose_created_by
  FOREIGN KEY (created_by)   REFERENCES users(user_id);

-- ---------------------------------------------------------------------------
-- `alerts` có 500.000 dòng thử → NOT VALID để nạp được dữ liệu cũ, VALIDATE sau.
-- Từ khi gen_data.py sinh users.tsv và bốc `acknowledged_by` từ tập analyst cố
-- định (thay vì uuid ngẫu nhiên mỗi dòng), lệnh VALIDATE dưới đây CHẠY ĐƯỢC:
--
--     ALTER TABLE alerts VALIDATE CONSTRAINT fk_alerts_acknowledged_by;
--
-- Chạy nó SAU khi đã COPY users.tsv và alerts. Để ở dạng NOT VALID trong migration
-- vì migration không được giả định dữ liệu nào đã có sẵn.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD CONSTRAINT fk_alerts_acknowledged_by
  FOREIGN KEY (acknowledged_by) REFERENCES users(user_id) NOT VALID;

-- ---------------------------------------------------------------------------
-- `audit_events.actor_id` CỐ Ý KHÔNG CÓ FK.
-- Vết là append-only và phải sống sót kể cả khi người dùng bị dọn khỏi `users`.
-- FK ở đây biến "dọn dữ liệu người dùng" thành "mất vết" — đổi một bài toán
-- vận hành lấy một lỗ hổng kiểm toán.
-- ---------------------------------------------------------------------------

INSERT INTO schema_migrations (version) VALUES ('007_users');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/008_audit_event_type.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 008_audit_event_type.sql — AI Support SOC
-- Cưỡng chế tập `event_type` ở DB. Đề nghị `R-D5-1`, người chủ trì duyệt 28/08/2026.
-- Chạy sau 007. KHÔNG sửa 001-007: chúng đã áp.
--
-- VÌ SAO: audit_events KHÔNG có CHECK nào trên `event_type` (chỉ có ck_audit_actor_role),
-- nên `'tier1.decidedd'` INSERT được. Ba phép đo của báo cáo lọc theo CHUỖI CHÍNH XÁC,
-- nên một ký tự thừa làm truy vấn trả RỖNG mà không báo lỗi — số liệu im lặng biến mất.
-- Đo được ở audit-catalog.md ca `3a`,`3b`.
--
-- KHI NÓ NỔ: để giao dịch ABORT, không nuốt lỗi. Nuốt lỗi là phá đúng thứ bảng audit
-- tồn tại vì nó (tính đầy đủ). Nguy hiểm của abort chỉ có thật NẾU chuỗi gõ sai tới được
-- lúc chạy — cửa đó đóng bằng module hằng EV_* + quét AST cấm chuỗi trực tiếp.
-- CHECK này là LƯỚI CUỐI, và lưới cuối thì nên nổ to.  (audit-payload.md §3.1)
--
-- 21 chuỗi = 16 hằng của danh mục D5 + `alert.reopened` + 4 sự kiện admin.
-- `alert.received` và `alert.enrich_started` GIỮ trong tập cho phép dù chốt C nói không
-- phát: CHECK canh CHUỖI HỢP LỆ, không canh CHÍNH SÁCH PHÁT. Trộn hai việc vào một ràng
-- buộc là để lần sau ai đó cần phát chúng thì phải sửa migration vì một lý do sai.
-- ============================================================================

ALTER TABLE audit_events ADD CONSTRAINT ck_audit_event_type CHECK (event_type IN (
  'alert.received','alert.duplicate_merged','alert.auto_closed',
  'alert.autoclose_blocked_critical','alert.enrich_started','alert.enriched',
  'alert.reopened',
  'job.exhausted','triage.suggested','alert.acknowledged','tier1.decided',
  'tier1.escalated','case.opened','case.truncated','case.analyzed',
  'tier2.concluded','authz.denied',
  'admin.user_created','admin.user_updated','admin.job_retried',
  'admin.autoclose_rule_toggled'));

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/009_audit_actor.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 009_audit_actor.sql — AI Support SOC
-- `actor_role` thêm 'admin', và `actor_id` bị ràng buộc theo vai.
-- Chạy sau 008.  (audit-payload.md §3.2 · hop-dong-dang-nhap.md §6.2)
--
-- VÌ SAO THÊM 'admin' thay vì nhét admin vào 'analyst': phép đo ③ (KT §B7) nhóm theo
-- actor_role để trả lời "bao nhiêu quyết định do máy, bao nhiêu do người". Trộn một lần
-- bật/tắt rule auto-close vào cùng rổ với quyết định triage của analyst làm hỏng đúng
-- con số đó. Lý do ĐO ĐƯỢC, không phải lý do thẩm mỹ.
--
-- VÌ SAO 'llm' ĐỂ MỞ trong ràng buộc actor_id — đây là chỗ dễ làm sai nhất:
--   ① chạy tự động  → `triage.suggested` KHÔNG có người nào (actor_id NULL)
--   ② do analyst bấm → `case.analyzed` CÓ user_id  (phase-7:286 ghi rõ $user_id)
-- Cùng một actor_role, hai ca hợp lệ NGƯỢC NHAU. Bất kỳ ràng buộc nào bắt 'llm' phải
-- NULL hoặc phải NOT NULL đều sai đúng MỘT NỬA số ca.
-- ============================================================================

ALTER TABLE audit_events DROP CONSTRAINT ck_audit_actor_role;
ALTER TABLE audit_events ADD  CONSTRAINT ck_audit_actor_role
  CHECK (actor_role IN ('system','llm','analyst','admin'));

-- Nhánh đầu là CỐ Ý và nó không thừa: thiếu nó thì một `actor_role` LẠ không khớp
-- nhánh nào và ràng buộc này nổ TRƯỚC ck_audit_actor_role — tức thông báo lỗi trỏ vào
-- sai quy tắc. Mỗi ràng buộc nói đúng MỘT chuyện: cái kia canh TẬP VAI, cái này canh
-- QUAN HỆ giữa vai và actor_id. (Bắt được bằng ca kiểm cũ 'actor_role lạ' đỏ sai lý do.)
ALTER TABLE audit_events ADD CONSTRAINT ck_audit_actor_id_theo_role CHECK (
     actor_role NOT IN ('system','llm','analyst','admin')
  OR (actor_role = 'system'             AND actor_id IS NULL)
  OR (actor_role IN ('analyst','admin') AND actor_id IS NOT NULL)
  OR (actor_role = 'llm')
);

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/010_enrich_cache.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 010_enrich_cache.sql — AI Support SOC
-- Cache nội dung cho tra cứu ngoài. Đề nghị `R-CHU-1`.  (hop-dong-n8n.md §4)
-- Chạy sau 009.
--
-- VÌ SAO POSTGRES CHỨ KHÔNG REDIS: thêm một hạ tầng cho một đồ án là đổi sai. Tần suất
-- và kích thước ở đây nằm gọn trong khả năng của một bảng có index.
--
-- ĐIỂM MẤU CHỐT — thiếu nó thì cache VÔ DỤNG ở đây:
--   Ghi cache trong một TRANSACTION RIÊNG, commit NGAY khi nhận trả lời n8n,
--   TRƯỚC transaction nghiệp vụ.
-- Cửa sổ hỏng (job-contract.md §2.3) là: worker chết SAU khi n8n trả lời, TRƯỚC COMMIT.
-- Cache ghi TRONG transaction nghiệp vụ sẽ chết cùng nó, và lần thử lại VẪN gọi n8n —
-- tức cache không đóng được gì. Ghi riêng thì lần thử lại thấy cache và không gọi lại.
-- Cái giá: một mục cache có thể tồn tại cho một job đã cuộn ngược. Vô hại — nó là kết
-- quả tra cứu, không phải trạng thái nghiệp vụ, và TTL chặn trần.
-- ============================================================================

CREATE TABLE enrich_cache (
  cache_key   text        PRIMARY KEY,   -- sha256(dich ‖ chuẩn_hoá(giá trị tra cứu))
  dich        text        NOT NULL,      -- cmdb · ad · virustotal · misp
  ket_qua     jsonb       NOT NULL,
  trang_thai  text        NOT NULL,
  expires_at  timestamptz NOT NULL,      -- 3600s cho found · 300s cho not_found
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT ck_enrich_cache_trang_thai CHECK (trang_thai IN ('found','not_found')),
  CONSTRAINT ck_enrich_cache_dich       CHECK (dich IN ('cmdb','ad','virustotal','misp'))
);

CREATE INDEX ix_enrich_cache_het_han ON enrich_cache (expires_at);

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/011_auth.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 011_auth.sql — AI Support SOC
-- Mật khẩu cho `users`.  (hop-dong-dang-nhap.md §3.1)
-- Chạy sau 010.
--
-- argon2id, tham số khởi điểm time_cost=3 · memory_cost=64MiB · parallelism=4.
-- KHÔNG bcrypt (giới hạn 72 byte), KHÔNG PBKDF2 (yếu hơn trước GPU ở cùng ngân sách).
--
-- HAI BƯỚC LÀ CỐ Ý: bảng users đã có dữ liệu (fixture của gen_data.py), nên
-- `ADD COLUMN ... NOT NULL` không kèm DEFAULT sẽ hỏng ngay. Thêm cho phép NULL,
-- backfill, rồi mới siết.
--
-- Giá trị backfill là một hash argon2id KHÔNG khớp mật khẩu nào (khoá tài khoản fixture
-- cho tới khi admin đặt lại) — KHÔNG dùng chuỗi rỗng hay một mật khẩu mặc định đoán được.
-- ============================================================================

ALTER TABLE users ADD COLUMN password_hash text;

UPDATE users SET password_hash = '$argon2id$v=19$m=65536,t=3,p=4$CHUA_DAT$CHUA_DAT'
 WHERE password_hash IS NULL;

ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/012_hop_dong_job_llm.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 012_hop_dong_job_llm.sql — AI Support SOC
-- Hai đề nghị đã duyệt, gộp một lượt vì cùng chạm `jobs` và `llm_runs`.
-- Chạy sau 011.
--
--   (1) ĐÃ RÚT — ck_jobs_status có sẵn ở 006 (chốt S1, giá trị 'succeeded')
--   (2) R-D7-1 · một job SỐNG mỗi (loại, chủ thể) — job-contract.md §2.4
--   (3) R-D0-1 · ① không được có vòng tool     — D0 §3④, chốt P5-6
-- ============================================================================

-- ── (1) ĐÃ RÚT ───────────────────────────────────────────────────────────────
-- Vòng đầu định thêm ck_jobs_status với giá trị 'done'. RÚT: `006_chot_hop_dong.sql`
-- đã chốt cột này từ 25/08 (chốt S1) với giá trị **'succeeded'**. Postgres từ chối
-- đúng lúc áp — "constraint ck_jobs_status already exists" — và đó là hàng rào làm
-- việc của nó. Giữ ghi chú này thay vì xoá lặng, để không ai đề nghị lại lần ba.

-- ── (2) · R-D7-1 ────────────────────────────────────────────────────────────
-- PARTIAL, không phải unique toàn bảng. Unique toàn bảng cấm luôn cả job ĐÃ XONG,
-- nghĩa là một alert vĩnh viễn không bao giờ được xếp lại loại job đó — mà S1 chốt
-- GIỮ LẠI dòng job xong, nên bảng luôn còn dòng cũ. Partial cấm đúng thứ cần cấm:
-- hai job cùng loại cùng chủ thể cùng SỐNG một lúc.
CREATE UNIQUE INDEX ux_jobs_mot_job_song_moi_subject
  ON jobs (job_type, subject_id) WHERE status IN ('pending','running');

-- ── (3) · R-D0-1 ────────────────────────────────────────────────────────────
-- Cưỡng chế chốt P5-6: pipeline ① KHÔNG gọi tool. Đây là ràng buộc bảo vệ một CHỐT,
-- không phải bảo vệ hình dạng một hiện vật chẩn đoán — nếu nó bị vi phạm thì phép đo
-- ③ của báo cáo sai mà không ai biết. ② (investigate) vẫn được có `rounds` đầy đủ.
-- Kiểu `jsonb` của agent_trace GIỮ NGUYÊN, không đổi.
ALTER TABLE llm_runs ADD CONSTRAINT ck_llm_runs_v1_mot_pipeline_khong_tool CHECK (
  pipeline <> 'triage' OR agent_trace IS NULL OR agent_trace->'rounds' IS NULL
  OR jsonb_array_length(agent_trace->'rounds') = 0);

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/013_assets_enrichment.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 013_assets_enrichment.sql — AI Support SOC
-- Ba bảng làm giàu (`assets`, `identities`, `iocs`) chuyển sang từ vựng của
-- §6.2 và nhận ba cột xuất xứ mà bộ nạp inventory của P2 upsert.
-- Chạy sau 012. KHÔNG sửa 001-012: chúng đã áp.
--
-- (1) VÌ SAO ĐỔI CHECK — DEC-004: `assets.criticality` bị CHECK theo
--     `crown_jewel|high|normal|low` trong khi §6.2 `structured_basis.asset_criticality`
--     là `high|medium|low|unknown`. Bước 2 của cổng (§7.3) so `structured_basis` với
--     dữ kiện CSDL theo từng trường, nên hai từ vựng nghĩa là trường ấy LUÔN lệch và
--     mọi phán quyết tụt xuống `needs_review`. CSDL đổi theo §6.2, không bao giờ ngược lại.
--     KHÔNG cần chuyển dữ liệu: `assets`, `identities`, `iocs` đều RỖNG trên `soc_dev`,
--     `soc_test` và `soc` — đo ngày 05/09/2026. Nếu một CSDL nào đó còn dòng
--     `crown_jewel`/`normal` thì ADD CONSTRAINT hỏng ngay, và đó là hành vi ĐÚNG.
--
-- (2) `owner`, `role` — §7.1 liệt "inventory lookup values (owner, role text)" vào
--     nhóm LUÔN nằm trong khối <untrusted_data>, nhưng chưa cột nào giữ chúng.
--     text NULL: một asset không có trong inventory thì không có cả hai.
--
-- (3) `source`, `loaded_at`, `active` — inventory-format.md §4: mỗi dòng được upsert
--     kèm tên tệp, thời điểm nạp và `active = true`; dòng BIẾN MẤT khỏi tệp bị đánh
--     `active = false`, KHÔNG xoá, để lịch sử làm giàu của cảnh báo cũ vẫn truy được.
--     `active` NOT NULL DEFAULT true — mọi tra cứu lọc theo nó. `source`/`loaded_at`
--     GIỮ NULL: NULL nghĩa là "dòng này không đến từ tệp inventory". KHÔNG đặt
--     DEFAULT 'inventory' — một chuỗi xuất xứ SAI tệ hơn một NULL thành thật, và P2
--     luôn ghi giá trị thật.
--
-- (4) `iocs.source` KHÔNG thêm ở đây. `006_chot_hop_dong.sql:54` đã thêm
--     `source text NOT NULL DEFAULT 'internal'` và dòng 56 đổi khoá chính thành
--     `iocs_pkey PRIMARY KEY (value, source)`. ADD COLUMN lần nữa sẽ hỏng với
--     "column \"source\" of relation \"iocs\" already exists". Yêu cầu
--     "`assets/identities/iocs` + `source`" của §6.1 với `iocs` đã thoả từ 006.
--
-- (5) `enrich_cache` — §6.1 "Dropped from v3", giao cho 013 (DEC-004/DEC-005: DDL của
--     một bảng không bao giờ tách đôi, và 013 là migration của các bảng làm giàu).
--     Đo được: không FK nào, không view nào phụ thuộc, nên DROP TABLE trơn — hai
--     index `enrich_cache_pkey` và `ix_enrich_cache_het_han` đi theo bảng.
--     §6.1 cũng liệt `prompt_versions` là bị bỏ — bảng ấy CHƯA TỪNG TỒN TẠI, không có gì để làm.
-- ============================================================================

-- ── (1) · assets — từ vựng §6.2, DEC-004 ────────────────────────────────────
ALTER TABLE assets DROP CONSTRAINT ck_assets_criticality;
ALTER TABLE assets ADD CONSTRAINT ck_assets_criticality
  CHECK (criticality IN ('high','medium','low','unknown'));

-- ── (2) · assets — §7.1 ─────────────────────────────────────────────────────
ALTER TABLE assets ADD COLUMN owner text,
                   ADD COLUMN role  text;

-- ── (3) · ba cột xuất xứ — inventory-format.md §4 ───────────────────────────
ALTER TABLE assets ADD COLUMN source    text,
                   ADD COLUMN loaded_at timestamptz,
                   ADD COLUMN active    boolean NOT NULL DEFAULT true;

ALTER TABLE identities ADD COLUMN source    text,
                       ADD COLUMN loaded_at timestamptz,
                       ADD COLUMN active    boolean NOT NULL DEFAULT true;

-- ── (4) · iocs — `source` đã có từ 006 và là nửa khoá chính ──────────────────
ALTER TABLE iocs ADD COLUMN loaded_at timestamptz,
                 ADD COLUMN active    boolean NOT NULL DEFAULT true;

-- ── (5) · §6.1 "Dropped from v3" ────────────────────────────────────────────
DROP TABLE enrich_cache;

INSERT INTO schema_migrations (version) VALUES ('013_assets_enrichment');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/014_intake_cursor_heartbeat.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 014_intake_cursor_heartbeat.sql — the intake ledger and the puller's state
--
-- Context pack §6.1 (three new v3 tables) and §5 (the flow that writes them):
--   intake            one row per document read from a manager, plus a receipt
--   source_cursor     where the next pull resumes from, per manager
--   source_heartbeat  when a manager was last heard from, and last heard with
--
-- Append-only enforcement on `intake` is NOT here. Migration 017 owns it and
-- applies it on top of this file (DEC-023 item 1): REVOKE UPDATE, DELETE,
-- TRUNCATE, then a column-level GRANT UPDATE (processed_at, outcome, error) for
-- the G12 completion write, then the pinning triggers. This file creates the
-- three tables with their constraints and nothing else — no GRANT, no REVOKE,
-- no trigger, no index beyond the ones the keys imply.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- intake — the ledger every alert enters through, from either intake path
-- (§5: the 60 s puller, and POST /webhook/alerts as the secondary path).
--
-- G9, as re-worded by DEC-023: `raw_text` is the received document unchanged —
-- the webhook body, the hit object's bytes sliced from the pull response, or
-- the archive line for a replay row — and `raw_payload` is derived from it and
-- may be normalised. Byte identity cannot hold on jsonb: measured on this
-- cluster, '{"b":1,"a":2,  "c":3}' comes back from jsonb as
-- '{"a": 2, "b": 1, "c": 3}' — keys reordered, whitespace collapsed. So the
-- received document lives in `text` (server_encoding is UTF8 and JSON text is
-- UTF-8 by RFC 8259, so text preserves every valid input byte and rejects
-- invalid UTF-8 loudly) and the jsonb is generated from it, never inserted.
-- The generated column doubles as the well-formedness check: 'not json' fails
-- with `invalid input syntax for type json`.
--
-- No foreign key to `alerts`, in either direction. §6.1 gives `alerts` no
-- `intake_id` and `intake` no `alert_id`; the link is carried by the
-- jobs('pipeline', intake_id) row. An FK here would extend a frozen contract.
-- ---------------------------------------------------------------------------
CREATE TABLE intake (
  intake_id        bigint      GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  manager_id       text        NOT NULL,   -- §6.3 WAZUH_MANAGER_ID, e.g. 'IA1803'
  source_alert_id  text        NOT NULL,   -- the manager's own alert id, e.g. '1788340536.1509017'
  raw_text         text        NOT NULL,   -- G9: the received bytes, unchanged (DEC-023)
  raw_payload      jsonb       NOT NULL GENERATED ALWAYS AS (raw_text::jsonb) STORED,
  sort_key         bigint,                 -- indexer `sort`; computed for replay rows (DEC-019)
  via              text        NOT NULL,
  received_at      timestamptz NOT NULL DEFAULT now(),  -- §9: control time comes from the DB
  processed_at     timestamptz,            -- G12: this or `error`, within 60 s
  outcome          text,
  error            text,

  -- §5 · the puller overlaps its window by 60 s, so it re-reads rows it has
  -- already stored. This is what makes a double pull idempotent.
  CONSTRAINT uq_intake_manager_source UNIQUE (manager_id, source_alert_id),

  CONSTRAINT ck_intake_via     CHECK (via IN ('pull','webhook')),

  -- Both `outcome` and `processed_at` are nullable on purpose: a row is
  -- inserted the moment it is read and only later resolved. G12 is what forces
  -- a value within 60 s, and G12 is a health check in P5, not a DB constraint —
  -- so the CHECK has to admit NULL or it would reject every fresh row.
  CONSTRAINT ck_intake_outcome CHECK (outcome IS NULL
    OR outcome IN ('alert','duplicate','auto_closed','heartbeat','rejected'))
);

-- ---------------------------------------------------------------------------
-- source_cursor — the persistent `search_after` cursor, one row per manager.
-- Everything but the key is nullable: a manager is registered before its first
-- pull has produced anything to resume from, and `last_error` holds the last
-- failure without stopping the next attempt.
-- ---------------------------------------------------------------------------
CREATE TABLE source_cursor (
  manager_id   text PRIMARY KEY,
  last_sort    bigint,       -- the `sort` value of the last hit consumed
  last_pull_at timestamptz,
  last_error   text
);

-- ---------------------------------------------------------------------------
-- source_heartbeat — `last_seen_at` is when the manager answered at all,
-- `last_alert_at` is when it last answered with an alert. The gap between the
-- two is what heartbeat detection reads in P2; a quiet manager is not a dead
-- one (DEC-014: the median day is 592 alerts, but the distribution is spiky).
-- ---------------------------------------------------------------------------
CREATE TABLE source_heartbeat (
  manager_id    text PRIMARY KEY,
  last_seen_at  timestamptz,
  last_alert_at timestamptz
);

INSERT INTO schema_migrations (version) VALUES ('014_intake_cursor_heartbeat');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/015_labels_reviews_notes_eval_health.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 015_labels_reviews_notes_eval_health.sql — AI Support SOC
--
-- Context pack §6.1, "v3 new": the five tables P5 (digest, health), P6 (blind
-- labelling) and P7 (evaluation) write to. Transcribed verbatim from the DDL
-- in P1-T04's task card, which is itself §6.1 spelled out — this file does not
-- extend the contract, only implements it. Runs after 014; does not depend on
-- 016 (another P1 task owns it, in parallel): the two files touch no common
-- table, so either merge order works.
--
-- ── Two places §6.1 deliberately gives no CHECK ─────────────────────────────
--
-- (1) `triage_labels.confidence` — §6.2's `triage_v2.confidence` is
--     `low|medium|high`, but that is the MODEL's confidence. This column is a
--     human labeller's, and §6.1 gives it no closed set. Constraining it would
--     be extending §6.1, which rule 4 forbids. Left `text`. If P6 wants it
--     closed, that is a P6 DECISION_REQUEST and a one-line migration, not this
--     one.
--
-- (2) `eval_runs.gold_set` — §13 names G1/G2/G3 today, but P7 may run a
--     combined or a sliced set and §6.1 lists no closed set for it. `config`
--     DOES get one: §6.1 writes `config ∈ B0..B4` explicitly.
--
-- ── Two places measured on this cluster, not read off a document ───────────
--
-- (3) `eval_run_id` is `uuid` with NO DEFAULT, matching `llm_runs.run_id`
--     (`schema.sql:392`: app-assigned, no DEFAULT) — the application generates
--     it, the same way it generates a ① run's `run_id`.
--
-- (4) `case_notes.note_id` is `bigint GENERATED BY DEFAULT AS IDENTITY` — the
--     v1 convention for a new surrogate key, and deliberately not the older
--     auto-increment column type that IDENTITY replaces. Measured on this
--     cluster: with the grants migration 017 issues, `INSERT` as `app_rw` into
--     an IDENTITY table succeeds and into the older type fails with
--     `permission denied for sequence …_id_seq`. Every P1 test runs as the
--     owner, so the older type would pass this migration's own tests and
--     break the application the moment P2 runs as `app_rw`.
--
-- ── One place the contract's choice is noted, not improved ─────────────────
--
-- (5) `system_health.checked_at` is the primary key, exactly as §6.1 writes
--     it. Two health checks landing in the same microsecond would collide on
--     insert; that is the contract's choice to make, not this migration's to
--     fix. Flagged for P5 in the task report.
-- ============================================================================

-- ── triage_labels — P6 blind labelling, one row per (alert, labeler, source) ─
CREATE TABLE triage_labels (
  alert_id    text        NOT NULL,
  labeler_id  uuid        NOT NULL,
  source      text        NOT NULL,
  label       text        NOT NULL,
  confidence  text,                      -- human labeller's; no closed set, see note (1)
  note        text,
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pk_triage_labels PRIMARY KEY (alert_id, labeler_id, source),
  CONSTRAINT fk_triage_labels_alert   FOREIGN KEY (alert_id)   REFERENCES alerts(alert_id),
  CONSTRAINT fk_triage_labels_labeler FOREIGN KEY (labeler_id) REFERENCES users(user_id),
  CONSTRAINT ck_triage_labels_source
    CHECK (source IN ('gold_offline','digest','disagreement','lab')),
  CONSTRAINT ck_triage_labels_label
    CHECK (label IN ('false_positive','benign','escalate'))
);

-- ── autoclose_reviews — P5 digest: one human review per auto-closed alert ───
CREATE TABLE autoclose_reviews (
  alert_id     text        NOT NULL,
  reviewer_id  uuid        NOT NULL,
  verdict      text        NOT NULL,
  reviewed_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pk_autoclose_reviews PRIMARY KEY (alert_id),
  CONSTRAINT fk_autoclose_reviews_alert    FOREIGN KEY (alert_id)    REFERENCES alerts(alert_id),
  CONSTRAINT fk_autoclose_reviews_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(user_id),
  CONSTRAINT ck_autoclose_reviews_verdict
    CHECK (verdict IN ('correct','wrong','unsure'))
);

-- ── case_notes — tier2 free-text notes on a case; see note (4) on note_id ───
CREATE TABLE case_notes (
  note_id     bigint      GENERATED BY DEFAULT AS IDENTITY,
  case_id     uuid        NOT NULL,
  author_id   uuid        NOT NULL,
  body        text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pk_case_notes PRIMARY KEY (note_id),
  CONSTRAINT fk_case_notes_case   FOREIGN KEY (case_id)   REFERENCES cases(case_id),
  CONSTRAINT fk_case_notes_author FOREIGN KEY (author_id) REFERENCES users(user_id)
);

-- ── eval_runs — P7 evaluation; see note (3) on eval_run_id, note (2) on gold_set ─
CREATE TABLE eval_runs (
  eval_run_id     uuid        NOT NULL,   -- application-assigned, like llm_runs.run_id
  prompt_version  text        NOT NULL,
  model_id        text        NOT NULL,
  gold_set        text        NOT NULL,   -- G1/G2/G3 today (§13); no closed set, see note (2)
  config          text        NOT NULL,
  metrics         jsonb       NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pk_eval_runs PRIMARY KEY (eval_run_id),
  CONSTRAINT ck_eval_runs_config CHECK (config IN ('B0','B1','B2','B3','B4'))
);

-- ── system_health — P5 health job; see note (5) on checked_at as the PK ─────
CREATE TABLE system_health (
  checked_at  timestamptz NOT NULL,
  checks      jsonb       NOT NULL,
  ok          boolean     NOT NULL,

  CONSTRAINT pk_system_health PRIMARY KEY (checked_at)
);

INSERT INTO schema_migrations (version) VALUES ('015_labels_reviews_notes_eval_health');

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/016_alter_alerts_jobs_llm_runs_users.sql
-- └──────────────────────────────────────────────────────────────────────────┘
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

-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/017_append_only_and_roles.sql
-- └──────────────────────────────────────────────────────────────────────────┘
-- ============================================================================
-- 017_append_only_and_roles.sql — AI Support SOC
-- §6.1 "Append-only enforcement", as amended by DEC-023 and DEC-024(a).
-- Runs after 016, as the database owner. KHÔNG sửa 001-016: chúng đã áp.
--
-- `audit_events`, `llm_runs` and `intake` become append-only against TWO layers,
-- because neither one alone covers everyone who can reach the database:
--
--   Layer 1 — privileges. Binds the application role `app_rw`, and answers
--     before any trigger runs. It does NOT bind the owner, who is the grantor.
--   Layer 2 — triggers. Bind everyone the privilege layer does not, the owner
--     included. A row trigger does not fire on TRUNCATE (DEC-016, measured), so
--     each table also carries a BEFORE TRUNCATE ... FOR EACH STATEMENT trigger.
--
-- The one write that must survive both layers is G12's: every `intake` row gets
-- `processed_at` or `error` within 60 s, which is one UPDATE on a row that was
-- INSERTed on arrival. Layer 1 admits it as a column-level grant, layer 2 as the
-- only shape `intake_pin_receipt()` lets through.
--
-- `app_rw` is cluster-global, not per-database. This file creates it when it is
-- absent, so migrations 013-017 are one repeatable command on any cluster whose
-- migrator can create roles (DEC-024(a)). It is created NOLOGIN deliberately:
-- the role authenticates over TCP with a SCRAM password, a passwordless LOGIN
-- role cannot connect at all, and a password must never enter a migration on a
-- public remote (DEC-022). Granting LOGIN and a password stays a one-off
-- out-of-band step per cluster — HUONG-DAN-VAN-HANH.md §0. NOLOGIN is enough
-- here: every GRANT/REVOKE and both append-only layers bind a NOLOGIN role
-- exactly as they bind a LOGIN one.
--
-- `domain_rw` is a v1 role on the legacy `soc` database and holds nothing on
-- `soc_dev` (DEC-024(d)). This migration names `app_rw` only.
-- ============================================================================

-- The role must exist before anything below can bind it. Create it when absent;
-- fail loudly, never silently, when this migrator is not allowed to — a REVOKE
-- that binds nothing is the one outcome that must not be reachable.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
    BEGIN
      CREATE ROLE app_rw NOLOGIN;
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE EXCEPTION USING
        MESSAGE = 'migration 017: role app_rw does not exist and this migrator cannot create it',
        HINT    = 'one-off superuser step, see docs/plan/HUONG-DAN-VAN-HANH.md §0 "Prerequisites"';
    END;
  END IF;
END
$$;

-- Application privileges: an explicit list, so TRUNCATE is never granted.
-- `GRANT ALL PRIVILEGES` would carry TRUNCATE and quietly undo half of this file.
GRANT USAGE ON SCHEMA public TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rw;
-- v1 uses GENERATED BY DEFAULT AS IDENTITY, which needs no sequence grant; the
-- line above closes the gap if anyone ever adds a `serial`. The two lines below
-- cover tables created after 017, so P2 needs no grants migration of its own.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_rw;

-- Bookkeeping table is the migrator's alone.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON schema_migrations FROM app_rw, PUBLIC;

-- Layer 1 — privileges. Table-level REVOKE first: a table-level REVOKE also
-- removes column-level grants of the same kind, so the column GRANT must follow
-- it. Measured the other way round, has_column_privilege(...) came back false.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, llm_runs, intake FROM app_rw, PUBLIC;
GRANT  UPDATE (processed_at, outcome, error) ON intake TO app_rw;   -- G12 completion write

-- Layer 2 — triggers, which also bind the owner.
CREATE FUNCTION raise_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION 'append-only table: % is immutable', TG_TABLE_NAME;
END
$fn$;

-- `intake` is the one append-only table with a legitimate second write. Payload
-- columns never change; the three receipt columns may each be written once.
CREATE FUNCTION intake_pin_receipt() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF NEW.intake_id       IS DISTINCT FROM OLD.intake_id
  OR NEW.manager_id      IS DISTINCT FROM OLD.manager_id
  OR NEW.source_alert_id IS DISTINCT FROM OLD.source_alert_id
  OR NEW.raw_text        IS DISTINCT FROM OLD.raw_text
  OR NEW.sort_key        IS DISTINCT FROM OLD.sort_key
  OR NEW.via             IS DISTINCT FROM OLD.via
  OR NEW.received_at     IS DISTINCT FROM OLD.received_at THEN
    RAISE EXCEPTION 'append-only table: intake row % payload columns are immutable', OLD.intake_id;
  END IF;
  IF (OLD.processed_at IS NOT NULL AND NEW.processed_at IS DISTINCT FROM OLD.processed_at)
  OR (OLD.outcome      IS NOT NULL AND NEW.outcome      IS DISTINCT FROM OLD.outcome)
  OR (OLD.error        IS NOT NULL AND NEW.error        IS DISTINCT FROM OLD.error) THEN
    RAISE EXCEPTION 'append-only table: intake row % receipt columns are pinned once set', OLD.intake_id;
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER trg_audit_events_immutable   BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW       EXECUTE FUNCTION raise_immutable();
CREATE TRIGGER trg_llm_runs_immutable       BEFORE UPDATE OR DELETE ON llm_runs     FOR EACH ROW       EXECUTE FUNCTION raise_immutable();
CREATE TRIGGER trg_intake_pin_receipt       BEFORE UPDATE           ON intake       FOR EACH ROW       EXECUTE FUNCTION intake_pin_receipt();
CREATE TRIGGER trg_intake_immutable         BEFORE DELETE           ON intake       FOR EACH ROW       EXECUTE FUNCTION raise_immutable();
-- A row trigger does not fire on TRUNCATE (DEC-016, kept by DEC-020).
CREATE TRIGGER trg_audit_events_no_truncate BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION raise_immutable();
CREATE TRIGGER trg_llm_runs_no_truncate     BEFORE TRUNCATE ON llm_runs     FOR EACH STATEMENT EXECUTE FUNCTION raise_immutable();
CREATE TRIGGER trg_intake_no_truncate       BEFORE TRUNCATE ON intake       FOR EACH STATEMENT EXECUTE FUNCTION raise_immutable();

INSERT INTO schema_migrations (version) VALUES ('017_append_only_and_roles');

COMMIT;
