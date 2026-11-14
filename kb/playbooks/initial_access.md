# Playbook · `initial_access` · `initial_access_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Initial Access; T1566.001; tier 6 còn T1133, T1195, T1199, T1200 và các id map tương ứng. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. File macro mới tạo hay đã mở/chạy?
2. Nguồn file có hiện trong log không?
3. Có tiến trình con, tải file hoặc đăng nhập từ ngoài trong mẫu không?

## 2 · Kiểm gì — cụ thể

- Đọc file Office, nguồn tải/email nếu có, Image, ParentImage và lệnh tiếp nối. Rule Office Macro File Creation không tự chứng minh email phishing hoặc macro đã chạy.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 19 alerts: 110464 ×19 (level 5).

## 3 · Nghiêng về FALSE POSITIVE khi

- Tài liệu có macro phục vụ công việc được mô tả trong context, nguồn và hành vi phù hợp. Chỉ tạo file mà chưa thấy chạy là giới hạn bằng chứng, không đủ tự đóng.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Office sinh shell, tải payload hoặc macro ghi/chạy mã từ thư mục tạm; nguồn lạ kèm chuỗi thực thi làm mạnh giả thuyết truy cập ban đầu.
- `ioc_reputation` là `malicious`/`suspicious` → chuyển xử lý; đối chiếu IoC nào thực sự thuộc sự kiện.
- `rule_level >= 12` → chuyển xử lý; đây là ngưỡng chính sách DEC-053, không phải tỷ lệ tấn công đo được.

## 5 · Ngữ cảnh làm đổi kết luận

- `asset_criticality = high` hoặc `unknown` (chưa có kiểm kê) → xử lý như sự cố; không tự đóng. `unknown` giữ `needs_review` nếu chưa đủ chứng cứ.
- `identity_privileged = "true"` → giả định thông tin đăng nhập đã lộ; thiếu danh tính không được coi là không đặc quyền.
- Context trial đến từ SOAR enrichment (DEC-208); `ENRICHMENT_ENABLED` tắt nên IoC thường `skipped`. `skipped`, `clean`, `not_found` không chứng minh vô hại.
- Severity suy từ rule level: dưới 5 low, 5–7 medium, 8–11 high, từ 12 critical. Bảng giữ `needs_review` dưới 12 khi không có IoC xấu; không thay cho đánh giá nội dung ở §4.

## 6 · Chưa kết luận được thì cần thêm

- Ghi rõ trường còn thiếu: dòng lệnh, mục tiêu, tiến trình cha, kết quả thực thi hoặc mẫu trước/sau. Yêu cầu người phân tích bổ sung vào hồ sơ; ① không tự truy vấn hệ thống khác.
- Nếu viện dẫn bảo trì/công cụ đã biết, cần bằng chứng tương ứng được đưa vào context; không giả định có ticket hay chữ ký số khi chưa được gửi.

## 7 · Windows

- Sysmon 11 (TargetFilename), 1 (Image, CommandLine, ParentImage), 3; PowerShell 4104; Security 4624 cho nhánh remote service nếu được gửi.
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
