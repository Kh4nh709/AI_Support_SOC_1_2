# Playbook · `lateral_movement` · `lateral_movement_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Lateral Movement; T1570, T1021.006, T1550.002, T1021.002, T1569.002. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Có bằng chứng từ máy nguồn sang máy đích không?
2. WinRM, SMB hay dịch vụ nào được dùng?
3. File được thả xuống hay đã chạy từ xa?

## 2 · Kiểm gì — cụ thể

- Đọc cặp nguồn/đích nếu có, LogonType, gói xác thực, đường dẫn file và ImagePath của dịch vụ; không suy ra nguồn từ một file nằm ở thư mục Windows.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 17 alerts: 92217 ×10 (level 6), 110814 ×3 (8), 110243 ×2 (8), 92650 ×2 (12).

## 3 · Nghiêng về FALSE POSITIVE khi

- Công cụ triển khai được mô tả trong context chạy đúng lệnh/đường dẫn và mẫu quản trị. NTLMv1 có thể là cấu hình cũ nhưng không phải bằng chứng an toàn.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- File lạ được chuyển rồi chạy qua dịch vụ từ xa; WinRM mới bật kèm đăng nhập hoặc tái dùng hash. 92650 level 12 cần chuyển xử lý ngay; chỉ bật WinRM chưa chứng minh di chuyển thành công.
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

- Security 4624 (LogonType, AuthenticationPackageName), 4648, 4697; System 7045 (ImagePath); Sysmon 1/11 (Image, CommandLine, ParentImage, TargetFilename).
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
