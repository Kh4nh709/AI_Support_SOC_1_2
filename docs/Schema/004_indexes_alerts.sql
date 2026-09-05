-- ============================================================================
-- 004_indexes_alerts.sql
-- Mỗi index kèm TRUY VẤN nó phục vụ và VỊ TRÍ truy vấn đó trong đặc tả.
-- Không có index nào ở đây là "phòng xa" — cái nào không truy được về một câu
-- SQL trong đặc tả thì không tạo.
-- ============================================================================

BEGIN;

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

COMMIT;
