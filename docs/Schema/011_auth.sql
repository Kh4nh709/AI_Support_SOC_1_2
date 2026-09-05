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
BEGIN;

ALTER TABLE users ADD COLUMN password_hash text;

UPDATE users SET password_hash = '$argon2id$v=19$m=65536,t=3,p=4$CHUA_DAT$CHUA_DAT'
 WHERE password_hash IS NULL;

ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

COMMIT;
