-- ============================================================================
-- 013_assets_enrichment.sql — AI Support SOC
-- Ba bảng làm giàu (`assets`, `identities`, `iocs`) chuyển sang từ vựng của
-- §6.2 và nhận ba cột xuất xứ mà bộ nạp inventory của P2 upsert.
-- Chạy sau 012. KHÔNG sửa 001-012: chúng đã áp.
--
-- (1) VÌ SAO ĐỔI CHECK — DEC-004: `assets.criticality` bị CHECK theo
--     `crown_jewel|high|normal|low` trong khi §6.2 `structured_basis.asset_criticality`
--     là `high|medium|low|unknown`. Bước 2 của cổng (§7.3) so `structured_basis` với
--     dữ kiện CSDL theo từng trường, nên hai từ vựng nghĩa là trường ấy LUÔN lệch và
--     mọi phán quyết tụt xuống `needs_review`. CSDL đổi theo §6.2, không bao giờ ngược lại.
--     KHÔNG cần chuyển dữ liệu: `assets`, `identities`, `iocs` đều RỖNG trên `soc_dev`,
--     `soc_test` và `soc` — đo ngày 05/09/2026. Nếu một CSDL nào đó còn dòng
--     `crown_jewel`/`normal` thì ADD CONSTRAINT hỏng ngay, và đó là hành vi ĐÚNG.
--
-- (2) `owner`, `role` — §7.1 liệt "inventory lookup values (owner, role text)" vào
--     nhóm LUÔN nằm trong khối <untrusted_data>, nhưng chưa cột nào giữ chúng.
--     text NULL: một asset không có trong inventory thì không có cả hai.
--
-- (3) `source`, `loaded_at`, `active` — inventory-format.md §4: mỗi dòng được upsert
--     kèm tên tệp, thời điểm nạp và `active = true`; dòng BIẾN MẤT khỏi tệp bị đánh
--     `active = false`, KHÔNG xoá, để lịch sử làm giàu của cảnh báo cũ vẫn truy được.
--     `active` NOT NULL DEFAULT true — mọi tra cứu lọc theo nó. `source`/`loaded_at`
--     GIỮ NULL: NULL nghĩa là "dòng này không đến từ tệp inventory". KHÔNG đặt
--     DEFAULT 'inventory' — một chuỗi xuất xứ SAI tệ hơn một NULL thành thật, và P2
--     luôn ghi giá trị thật.
--
-- (4) `iocs.source` KHÔNG thêm ở đây. `006_chot_hop_dong.sql:54` đã thêm
--     `source text NOT NULL DEFAULT 'internal'` và dòng 56 đổi khoá chính thành
--     `iocs_pkey PRIMARY KEY (value, source)`. ADD COLUMN lần nữa sẽ hỏng với
--     "column \"source\" of relation \"iocs\" already exists". Yêu cầu
--     "`assets/identities/iocs` + `source`" của §6.1 với `iocs` đã thoả từ 006.
--
-- (5) `enrich_cache` — §6.1 "Dropped from v3", giao cho 013 (DEC-004/DEC-005: DDL của
--     một bảng không bao giờ tách đôi, và 013 là migration của các bảng làm giàu).
--     Đo được: không FK nào, không view nào phụ thuộc, nên DROP TABLE trơn — hai
--     index `enrich_cache_pkey` và `ix_enrich_cache_het_han` đi theo bảng.
--     §6.1 cũng liệt `prompt_versions` là bị bỏ — bảng ấy CHƯA TỪNG TỒN TẠI, không có gì để làm.
-- ============================================================================
BEGIN;

-- ── (1) · assets — từ vựng §6.2, DEC-004 ────────────────────────────────────
ALTER TABLE assets DROP CONSTRAINT ck_assets_criticality;
ALTER TABLE assets ADD CONSTRAINT ck_assets_criticality
  CHECK (criticality IN ('high','medium','low','unknown'));

-- ── (2) · assets — §7.1 ─────────────────────────────────────────────────────
ALTER TABLE assets ADD COLUMN owner text,
                   ADD COLUMN role  text;

-- ── (3) · ba cột xuất xứ — inventory-format.md §4 ───────────────────────────
ALTER TABLE assets ADD COLUMN source    text,
                   ADD COLUMN loaded_at timestamptz,
                   ADD COLUMN active    boolean NOT NULL DEFAULT true;

ALTER TABLE identities ADD COLUMN source    text,
                       ADD COLUMN loaded_at timestamptz,
                       ADD COLUMN active    boolean NOT NULL DEFAULT true;

-- ── (4) · iocs — `source` đã có từ 006 và là nửa khoá chính ──────────────────
ALTER TABLE iocs ADD COLUMN loaded_at timestamptz,
                 ADD COLUMN active    boolean NOT NULL DEFAULT true;

-- ── (5) · §6.1 "Dropped from v3" ────────────────────────────────────────────
DROP TABLE enrich_cache;

INSERT INTO schema_migrations (version) VALUES ('013_assets_enrichment');

COMMIT;
