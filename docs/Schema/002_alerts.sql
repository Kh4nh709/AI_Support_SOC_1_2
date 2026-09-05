-- ============================================================================
-- 002_alerts.sql — bảng trung tâm, 51 cột + case_alerts
-- Phụ thuộc 001 (cases, autoclose_rules).
-- Mỗi cột có chú thích <TỆP>:<DÒNG> trỏ về nguồn trong đặc tả.
--   KT=kien-truc  P1..P7=phase-1..phase-7
-- ============================================================================

BEGIN;

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

COMMIT;
