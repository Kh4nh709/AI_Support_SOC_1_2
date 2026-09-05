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
BEGIN;

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

COMMIT;
