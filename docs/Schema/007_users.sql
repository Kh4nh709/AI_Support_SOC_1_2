-- ============================================================================
-- 007_users.sql — AI Support SOC · quyết định S8
-- Tách riêng khỏi 006 vì nó THÊM BẢNG, không chỉ thêm ràng buộc.
--
-- Đóng lại schema-notes §7⑧: sáu cột uuid trỏ tới người mà không cột nào có FK,
-- vì không có bảng đích. Hệ quả cũ: DB không chặn được uuid mồ côi, và báo cáo
-- không hiển thị được TÊN người quyết.
--
-- Thêm FK sau khi đã có dòng mồ côi là migration có thể thất bại — nên làm bây giờ.
-- GIẢ ĐỊNH đã ghi nhận: < 50 analyst, vai trò phẳng, không phân quyền theo nhóm.
-- ============================================================================
BEGIN;

CREATE TABLE users (
  user_id       uuid        PRIMARY KEY,
  username      text        NOT NULL UNIQUE,
  display_name  text        NOT NULL,
  role          text        NOT NULL,
  is_active     boolean     NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_users_role CHECK (role IN ('tier1','tier2','admin'))
);

-- ---------------------------------------------------------------------------
-- FK cho 4 cột TRẠNG THÁI SỐNG trên bảng nhỏ — validate ngay.
-- ---------------------------------------------------------------------------
ALTER TABLE cases           ADD CONSTRAINT fk_cases_created_by
  FOREIGN KEY (created_by)   REFERENCES users(user_id);
ALTER TABLE cases           ADD CONSTRAINT fk_cases_concluded_by
  FOREIGN KEY (concluded_by) REFERENCES users(user_id);
ALTER TABLE case_alerts     ADD CONSTRAINT fk_case_alerts_added_by
  FOREIGN KEY (added_by)     REFERENCES users(user_id);
ALTER TABLE autoclose_rules ADD CONSTRAINT fk_autoclose_created_by
  FOREIGN KEY (created_by)   REFERENCES users(user_id);

-- ---------------------------------------------------------------------------
-- `alerts` có 500.000 dòng thử → NOT VALID để nạp được dữ liệu cũ, VALIDATE sau.
-- Từ khi gen_data.py sinh users.tsv và bốc `acknowledged_by` từ tập analyst cố
-- định (thay vì uuid ngẫu nhiên mỗi dòng), lệnh VALIDATE dưới đây CHẠY ĐƯỢC:
--
--     ALTER TABLE alerts VALIDATE CONSTRAINT fk_alerts_acknowledged_by;
--
-- Chạy nó SAU khi đã COPY users.tsv và alerts. Để ở dạng NOT VALID trong migration
-- vì migration không được giả định dữ liệu nào đã có sẵn.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD CONSTRAINT fk_alerts_acknowledged_by
  FOREIGN KEY (acknowledged_by) REFERENCES users(user_id) NOT VALID;

-- ---------------------------------------------------------------------------
-- `audit_events.actor_id` CỐ Ý KHÔNG CÓ FK.
-- Vết là append-only và phải sống sót kể cả khi người dùng bị dọn khỏi `users`.
-- FK ở đây biến "dọn dữ liệu người dùng" thành "mất vết" — đổi một bài toán
-- vận hành lấy một lỗ hổng kiểm toán.
-- ---------------------------------------------------------------------------

INSERT INTO schema_migrations (version) VALUES ('007_users');

COMMIT;
