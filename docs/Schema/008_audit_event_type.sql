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
BEGIN;

ALTER TABLE audit_events ADD CONSTRAINT ck_audit_event_type CHECK (event_type IN (
  'alert.received','alert.duplicate_merged','alert.auto_closed',
  'alert.autoclose_blocked_critical','alert.enrich_started','alert.enriched',
  'alert.reopened',
  'job.exhausted','triage.suggested','alert.acknowledged','tier1.decided',
  'tier1.escalated','case.opened','case.truncated','case.analyzed',
  'tier2.concluded','authz.denied',
  'admin.user_created','admin.user_updated','admin.job_retried',
  'admin.autoclose_rule_toggled'));

COMMIT;
