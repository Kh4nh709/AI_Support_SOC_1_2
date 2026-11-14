# Playbook · `collection` · `collection_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Collection; T1114.001, T1119 (kèm T1083 trong rule). Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Thu thập loại dữ liệu nào?
2. Lệnh tìm kiếm hay đã sao chép/nén dữ liệu?
3. Đích lưu và tiến trình gọi có phù hợp công việc được mô tả không?

## 2 · Kiểm gì — cụ thể

- Đọc ScriptBlock, CommandLine, bộ lọc file, đường dẫn nguồn/đích; đối chiếu mẫu tương quan về tạo archive và kết nối sau đó.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 15 alerts: 110903 ×13 (level 8), 91820 ×2 (4).

## 3 · Nghiêng về FALSE POSITIVE khi

- Sao lưu thư hoặc lập chỉ mục có nguồn, đích, lệnh và ngữ cảnh công việc khớp nhau trong dữ liệu được gửi. Tìm file đơn lẻ không chứng minh đã lấy dữ liệu.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- PowerShell đọc hàng loạt email, gom file nhạy cảm vào thư mục tạm hoặc nén để chuyển đi, nhất là sau truy cập bất thường. Thu thập chưa đồng nghĩa đã exfiltrate.
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

- PowerShell 4104 (ScriptBlockText); Sysmon 1 (Image, CommandLine, ParentImage), 11 (TargetFilename), 3 (kết nối nếu có).
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
