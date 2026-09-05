-- ============================================================================
-- load.sql — nạp bộ dữ liệu thử của gen_data.py vào một DB đã có schema.sql.
--
-- §8.3 của schema-notes.md viện dẫn tệp này từ đầu nhưng nó chưa từng có trong
-- repo — nghĩa là lệnh tái lập ở đó không chạy được như đang viết. Tệp này làm
-- lệnh đó thành sự thật.
--
-- Dùng:  psql -d soc -v ON_ERROR_STOP=1 -v dir=/duong/dan/data -f load.sql
--        (dir mặc định là giá trị SOC_DATA_OUT đã dùng khi chạy gen_data.py)
--
-- THỨ TỰ QUAN TRỌNG. Sau migration 007, `cases.created_by`, `case_alerts.added_by`
-- và `autoclose_rules.created_by` đều có FK tới `users`. `users` PHẢI vào trước.
-- ============================================================================

\if :{?dir}
\else
\set dir '/tmp/socdata'
\endif

-- Dùng COPY phía SERVER, không phải \copy: `\copy` là meta-command duy nhất KHÔNG
-- nội suy biến trong tham số, nên :'dir' sẽ được truyền nguyên văn thành tên tệp.
-- COPY phía server có nội suy, đổi lại nó đòi quyền superuser (hoặc vai trò
-- pg_read_server_files) và tệp phải nằm trên MÁY CHẠY POSTGRES.
--   · chạy local  : tệp ở ngay đường dẫn đó
--   · chạy docker : docker cp <dir>/*.tsv <container>:/tmp/socdata/ trước
\set f_users     :dir '/users.tsv'
\set f_rules     :dir '/autoclose_rules.tsv'
\set f_cases     :dir '/cases.tsv'
\set f_heads     :dir '/alerts_heads.tsv'
\set f_dups      :dir '/alerts_dups.tsv'

\echo '① users — phải vào trước, mọi FK người dùng trỏ về đây'
COPY users (user_id, username, display_name, role, is_active, created_at) FROM :'f_users';

\echo '② autoclose_rules'
COPY autoclose_rules (autoclose_rule_id, name, enabled, match, reason, created_by, created_at) FROM :'f_rules';

\echo '③ cases'
COPY cases (case_id, title, status, severity, created_by, created_at, last_analyzed_at, conclusion_reason, concluded_by, concluded_at) FROM :'f_cases';

\echo '④ alerts — dòng gốc trước, bản sao sau (duplicate_of là FK tự trỏ)'
COPY alerts (alert_id, rule_id, rule_level, severity, description, agent_name, alert_time, agent_id, agent_ip, alert_user, decoder, event_time, raw_log, srcip, dstip, src_port, dst_port, mitre_ids, rule_groups, category, categories, resolved_by, mapping_version, srcip_is_private, dstip_is_private, raw_log_truncated, source, is_synthetic, status, event_bucket_hash, duplicate_of, occurrence_count, case_id, autoclose_rule_id, received_at, first_seen_at, last_seen_at, acknowledged_at, acknowledged_by, closed_at, sealed_at, close_reason, triage_status, triaged_count, risk_score, risk_score_components, asset_context, identity_context, ioc_context, lookup_status, raw_payload) FROM :'f_heads';

COPY alerts (alert_id, rule_id, rule_level, severity, description, agent_name, alert_time, agent_id, agent_ip, alert_user, decoder, event_time, raw_log, srcip, dstip, src_port, dst_port, mitre_ids, rule_groups, category, categories, resolved_by, mapping_version, srcip_is_private, dstip_is_private, raw_log_truncated, source, is_synthetic, status, event_bucket_hash, duplicate_of, occurrence_count, case_id, autoclose_rule_id, received_at, first_seen_at, last_seen_at, acknowledged_at, acknowledged_by, closed_at, sealed_at, close_reason, triage_status, triaged_count, risk_score, risk_score_components, asset_context, identity_context, ioc_context, lookup_status, raw_payload) FROM :'f_dups';

-- ---------------------------------------------------------------------------
-- S8 · giờ mới VALIDATE được ràng buộc mà 007 để ở NOT VALID.
-- Chạy được là bằng chứng `acknowledged_by` chỉ dùng tập analyst cố định của
-- gen_data.py. Nếu ai đó đưa uuid ngẫu nhiên trở lại, lệnh này sẽ nổ ở đây —
-- đúng chỗ, thay vì lặng lẽ để một ràng buộc nằm mãi ở trạng thái chưa kiểm.
-- ---------------------------------------------------------------------------
\echo '⑤ VALIDATE fk_alerts_acknowledged_by'
ALTER TABLE alerts VALIDATE CONSTRAINT fk_alerts_acknowledged_by;

\echo '⑥ VACUUM ANALYZE'
VACUUM ANALYZE users;
VACUUM ANALYZE alerts;
VACUUM ANALYZE cases;

SELECT 'users' AS bang, count(*) FROM users
UNION ALL SELECT 'autoclose_rules', count(*) FROM autoclose_rules
UNION ALL SELECT 'cases', count(*) FROM cases
UNION ALL SELECT 'alerts', count(*) FROM alerts;
