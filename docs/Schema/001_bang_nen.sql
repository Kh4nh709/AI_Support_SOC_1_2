-- ============================================================================
-- 001_bang_nen.sql — AI Support SOC
-- Các bảng KHÔNG phụ thuộc `alerts`. Phải chạy trước 002.
--   assets · identities · iocs      (enrichment/ · Phase 4)
--   autoclose_rules                 (ingest/     · Phase 3)
--   cases                           (tier2/      · Phase 6, 7)
--   rejected_alerts                 (ingest/     · Phase 1)
-- Mọi giá trị đều truy được về đặc tả; xem bảng truy vết trong schema-notes.md.
-- ============================================================================

BEGIN;

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

COMMIT;
