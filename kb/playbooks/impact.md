# Playbook · `impact` · `impact_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Impact; T1531, T1489, T1485, T1112, T1070.004. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Đăng xuất bình thường hay tài khoản bị tước quyền?
2. Dừng tiến trình nào, có ảnh hưởng dịch vụ không?
3. Có xoá dữ liệu hoặc chuỗi phá hoại trong mẫu tương quan không?

## 2 · Kiểm gì — cụ thể

- Đọc mục tiêu taskkill, mã thoát, đối tượng registry bị xoá và thời điểm logoff; tên category không chứng minh có phá hoại.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 41 alerts: 110229 ×20 (level 3), 112524 ×15 (5), 751 ×2 (5), 597 ×2 (5), 60778 ×2 (5).

## 3 · Nghiêng về FALSE POSITIVE khi

- 110229 User Logoff Event chỉ ghi đăng xuất thông thường nếu raw_log và mẫu tương quan phù hợp; T1531 không tự chứng minh mất quyền. Dừng ứng dụng hoặc xoá registry khi gỡ phần mềm chỉ nghiêng vô hại khi có ngữ cảnh tương ứng được cung cấp.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Lệnh dừng dịch vụ hàng loạt, xoá dữ liệu hoặc tước quyền kèm thất bại truy cập trong mẫu là dấu hiệu thật; 751/597 mang nhiều tag, phải đọc đối tượng thay vì suy diễn từ T1485.
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

- Sysmon 1 (Image, CommandLine, ParentImage), 5 (kết thúc tiến trình), 12/13 (TargetObject); Security 4634/4647 (logoff), 4725 (vô hiệu hoá tài khoản).
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
