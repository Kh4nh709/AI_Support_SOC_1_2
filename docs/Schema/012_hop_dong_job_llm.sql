-- ============================================================================
-- 012_hop_dong_job_llm.sql — AI Support SOC
-- Hai đề nghị đã duyệt, gộp một lượt vì cùng chạm `jobs` và `llm_runs`.
-- Chạy sau 011.
--
--   (1) ĐÃ RÚT — ck_jobs_status có sẵn ở 006 (chốt S1, giá trị 'succeeded')
--   (2) R-D7-1 · một job SỐNG mỗi (loại, chủ thể) — job-contract.md §2.4
--   (3) R-D0-1 · ① không được có vòng tool     — D0 §3④, chốt P5-6
-- ============================================================================
BEGIN;

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

COMMIT;
