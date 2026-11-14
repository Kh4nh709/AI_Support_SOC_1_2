# Playbook · `execution` · `execution_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Execution; tier 6 T1047, T1106, T1127, T1129, T1203, T1559, T1569, T1609, T1610, T1648, T1651; các id mới/cũ theo category.py. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Lệnh nào thực sự được chạy?
2. Tiến trình gọi và module có được cung cấp không?
3. Có tải payload, tạo dịch vụ hoặc kết nối sau chạy trong mẫu không?

## 2 · Kiểm gì — cụ thể

- Đọc lệnh WMI, service ImagePath, module và tiến trình cha nếu raw_log có. Đây là bản suy từ ATT&CK và chuỗi chạy mã của lab; WMI/scripting thường đã tới malware ở tier trước.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 0 alerts (no trial alert — ATT&CK only); lab-scenarios.md:476-527 describes malware execution, not an execution-labelled measurement.

## 3 · Nghiêng về FALSE POSITIVE khi

- WMI kiểm kê, build tool hoặc dịch vụ chạy lệnh phù hợp ngữ cảnh quản trị được gửi. Một module được nạp chưa chứng minh mã độc; không có mẫu tấn công/benign đo riêng cho category này.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Ứng dụng văn phòng sinh shell rồi tải/chạy payload; WMI/service chạy lệnh encoded hoặc file lạ và có dấu vết tiếp nối. Chuỗi chỉ được viện dẫn khi các mắt xích có trong raw_log hoặc mẫu tương quan.
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

- Sysmon 1/7 (Image, CommandLine, ParentImage, ImageLoaded); Security 4688 (NewProcessName, ProcessCommandLine nếu bật), 4697; System 7045 (ImagePath); PowerShell 4104 nếu được gửi.
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
