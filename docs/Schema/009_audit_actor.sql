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
BEGIN;

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

COMMIT;
