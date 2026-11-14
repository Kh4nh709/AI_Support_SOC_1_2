# Playbook · `persistence` · `persistence_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Persistence; T1197, T1053.005, T1574.001. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Task/BITS chỉ được tạo hay đã thực thi?
2. Action, trigger và đường dẫn DLL trỏ đi đâu?
3. Updater/agent quản trị đã biết có được chứng thực trong ngữ cảnh gửi kèm không?

## 2 · Kiểm gì — cụ thể

- Đọc TaskName, nội dung task, action/arguments, trigger, BITS job và tiến trình nạp DLL. taskschd.dll hoặc BitsProxy được nạp chưa đủ chứng minh persistence.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 1,119 alerts: 112438 ×496 (level 5), 112533 ×201 (5), 92154 ×124 (4), 111810 ×56 (5), 111828 ×56 (12), 112430 ×50 (5), 110798 ×41 (8), 110437 ×22 (12); 11 other rules ×73, unspecified.

## 3 · Nghiêng về FALSE POSITIVE khi

- Updater hoặc agent quản trị đã biết chạy từ đường dẫn cài đặt phù hợp, action/trigger và ngữ cảnh quản trị khớp nhau. Khoảng 1,000 alert task/BITS là tín hiệu cần phân biệt, không phải 1,000 tấn công; tên quen không đủ.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Task trỏ thư mục người dùng ghi được, lệnh encoded, script host hoặc DLL hijack có nội dung đáng ngờ; đặc biệt 111828/110437 level 12. Đường dẫn ghi được là dấu hiệu cần đối chiếu, không tự nó xác nhận.
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

- Security 4698/4702 (TaskName, TaskContent); Sysmon 1 (Image, CommandLine, ParentImage), 7 (ImageLoaded nếu được gửi), 11, 12/13 (TargetObject).
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
