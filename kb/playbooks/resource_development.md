# Playbook · `resource_development` · `resource_development_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Resource Development; T1587.001, T1584; tier 6 còn T1583, T1585–T1588, T1608, T1650, T1683. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Executable được tạo bởi compiler/updater hay tiến trình lạ?
2. Có bằng chứng chuẩn bị công cụ/hạ tầng không?
3. Windows Update Error chỉ là lỗi cập nhật hay có chuỗi chiếm dụng khác?

## 2 · Kiểm gì — cụ thể

- Đọc tiến trình tạo file, đích executable, lệnh build/tải và mô tả lỗi cập nhật. Endpoint ít quan sát được chuẩn bị hạ tầng bên ngoài; tag không chứng minh nguồn gốc công cụ.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 50 alerts: 112431 ×33 (level 5), 110256 ×17 (3).

## 3 · Nghiêng về FALSE POSITIVE khi

- 110256 Windows Update Error level 3 có mã lỗi và ngữ cảnh cập nhật bình thường: T1584 không chứng minh hạ tầng bị chiếm. Compiler/updater tạo executable với lệnh và đích phù hợp ngữ cảnh công việc cũng có thể lành tính.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Tiến trình lạ tạo payload, nén/đóng gói rồi chuyển hoặc triển khai trong mẫu; bằng chứng công cụ bị sửa và dùng tiếp làm mạnh giả thuyết. Một executable mới tạo không đủ quy kết phát triển mã độc.
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

- Sysmon 1/11 (Image, CommandLine, ParentImage, TargetFilename, Hashes nếu có); Security 4688; đọc mã lỗi và provider của Windows Update trong raw_log, không suy ra Event ID từ rule 110256.
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
