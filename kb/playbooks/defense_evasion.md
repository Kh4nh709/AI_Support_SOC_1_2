# Playbook · `defense_evasion` · `defense_evasion_v1`

> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — bản nháp chờ Chủ đồ án và giảng viên xét, sửa và ký. implemented, not measured; chưa có gold của category này.

> MITRE ATT&CK Defense Evasion; T1220, T1222.001, T1140, T1070.004, T1620, T1036.003, T1564.004. Tag định tuyến không phải kết luận hành vi; số liệu dưới đây chỉ là alert đã phát.

## 1 · Ba câu phân định

1. Đang xoá gì hoặc đổi quyền cho ai?
2. Giải nén/thực thi trong bộ nhớ phục vụ lệnh nào?
3. Có che dấu, giảm bảo vệ hoặc xoá dấu vết trong mẫu được gửi không?

## 2 · Kiểm gì — cụ thể

- Đọc nội dung PowerShell, XSL, lệnh WMIC, đường dẫn mục tiêu, quyền trước/sau nếu có. Tên tiến trình và short path không tự chứng minh né tránh.
- Chỉ đối chiếu `raw_log`, mô tả rule, mẫu tương quan, `context`, `siem_context` đã được gửi. Không có trường thì ghi thiếu, không dựng cây tiến trình hay lịch sử ngoài mẫu.
- Nguồn trial §3: 370 alerts: 110665 ×152 (level 8), 112519 ×50 (8), 110753 ×49 (3), 112466 ×34 (5), 110810 ×25 (8), 110915 ×22 (8), 92021 ×11 (3), 112520 ×6 (8); 6 other rules ×21, unspecified.

## 3 · Nghiêng về FALSE POSITIVE khi

- Giải nén, dọn file tạm hoặc đổi quyền theo tác vụ quản trị phù hợp với context và lệnh cụ thể. Remove-Item và Decompress có cả công dụng thường ngày; thiếu lookup không chứng minh lành tính.
- Các dấu hiệu này cần nội dung lệnh và ngữ cảnh; bảng không có rule `false_positive` vì bốn fact phân loại không phân biệt được chúng với tấn công.

## 4 · Nghiêng về THẬT khi

- Xoá dấu vết sau lệnh đáng ngờ, cấp quyền rộng cho payload, reflection nạp mã lạ hoặc giả tên dịch vụ hệ thống. WMIC nạp thư viện script phải đối chiếu CommandLine, không kết luận chỉ vì tag T1220.
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

- PowerShell 4104; Sysmon 1/7/11/23/26 (Image, CommandLine, ParentImage, ImageLoaded, TargetFilename khi có); Security 4670 (đổi quyền), 1102 (xoá audit log).
- Event ID trên chỉ đọc khi có trong dữ liệu gửi kèm; Wazuh rule id không phải Windows Event ID.
