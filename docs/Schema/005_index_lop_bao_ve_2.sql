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

BEGIN;

CREATE INDEX ix_alerts_autoclose_7ngay
  ON alerts (received_at)
  WHERE status = 'auto_closed';

INSERT INTO schema_migrations (version) VALUES ('005_index_lop_bao_ve_2');

COMMIT;
