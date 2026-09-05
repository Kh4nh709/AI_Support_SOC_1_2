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
BEGIN;

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

COMMIT;
