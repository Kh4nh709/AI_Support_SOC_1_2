# Playbook · `brute_force` · `brute_force_v1`

> **agent-drafted 29/09 (P9-T02), not reviewed** — bản nháp cho alert Windows (DEC-149). Chưa có chữ ký của Chủ đồ án và giảng viên; bảng `brute_force.yaml` vẫn `reviewed_by: null`.

> Nhiều lần xác thực hỏng vào tài khoản Windows — MITRE ATT&CK **T1110 Brute Force**. Câu hỏi thật không phải *«có đăng nhập hỏng không»* mà **có ai vào được không**, và **một tài khoản bị thử nhiều lần hay nhiều tài khoản bị thử từ một nguồn**.

## 1 · Ba câu phân định

1. Sau chuỗi hỏng, có **4624 thành công** nào cho cùng tài khoản hoặc từ cùng nguồn không? Đó là ranh giới giữa nhiễu và sự cố.
2. Đây là **brute force** (một tài khoản, nhiều lần thử — T1110.001) hay **password spraying** (nhiều tài khoản, mỗi tài khoản vài lần, từ một nguồn — T1110.003)?
3. `Logon Type` là gì, và nguồn là **nội bộ** hay ngoài? Gõ sai tại bàn phím (type 2) khác hẳn thử qua mạng (type 3) hay qua RDP (type 10).

## 2 · Kiểm gì — cụ thể

- `raw_log` là thông điệp sự kiện Windows: đọc `Status`/`Sub Status`, `Logon Type`, `Workstation Name`, `Source Network Address`.
- 4625 — mã NTSTATUS trong `Sub Status` (hoặc `Status`):
  - `0xC000006A` — tài khoản **có thật**, sai mật khẩu.
  - `0xC0000064` — tài khoản **không tồn tại**: dò tên, danh sách từ điển hoặc spraying.
  - `0xC0000234` — tài khoản **đã bị khoá**: kẻ thử vẫn tiếp tục sau ngưỡng khoá.
- Kerberos 4771 trên máy điều khiển miền — `Failure Code`:
  - `0x18` — sai mật khẩu (pre-authentication failed).
  - `0x6` — tên tài khoản không tồn tại (thường ghi ở 4768).
  - `0x12` — tài khoản bị khoá, bị vô hiệu hoá hoặc hết hạn.
- 4740 — tài khoản bị khoá; `Caller Computer Name` là **máy gây ra** lần khoá, không phải máy ghi log.
- 4776 (xác thực NTLM) và 4648 (đăng nhập bằng thông tin chỉ định) quanh cùng thời điểm, cùng tài khoản.
- `Logon Type`: 2 tại chỗ · 3 qua mạng (SMB…) · 7 mở khoá màn hình · 8 mật khẩu gửi rõ qua mạng · 10 RDP · 11 thông tin đăng nhập lưu sẵn.
- `alert_user`, `srcip` + `srcip_is_private`, `occurrence_count` và khoảng thời gian của cụm.

## 3 · Nghiêng về FALSE POSITIVE khi

- Chỉ **một** tài khoản **có thật**, `0xC000006A` vài lần, type 2 hoặc 7 — người dùng gõ sai rồi đăng nhập được.
- Nguồn nội bộ lặp đều theo nhịp cố định: dịch vụ, tác vụ định kỳ, ổ mạng ánh xạ hoặc ứng dụng thư còn giữ mật khẩu cũ sau khi đổi.
- Không có 4624 thành công bất thường nào sau chuỗi hỏng, và không có 4740.

## 4 · Nghiêng về THẬT khi

- Có **4624 thành công sau chuỗi hỏng** từ cùng nguồn — tín hiệu mạnh nhất, ưu tiên trên mọi tín hiệu khác.
- Nhiều `0xC0000064`, hoặc **nhiều tài khoản khác nhau từ một nguồn** — spraying, không phải người gõ nhầm.
- Thử qua mạng (type 3) hoặc RDP (type 10) từ `srcip` ngoài, hoặc `ioc_context` báo `malicious`/`suspicious`.
- 4740 trên nhiều tài khoản trong thời gian ngắn, hoặc vẫn thử tiếp khi đã gặp `0xC0000234`.
- Tài khoản bị nhắm là `Administrator` hoặc thành viên nhóm quản trị.

## 5 · Ngữ cảnh làm đổi kết luận

- `asset_context.criticality = high` → hạ ngưỡng; `unknown` (không có trong kiểm kê) → **không** kết luận vô hại, xử lý như `high` cho tới khi kiểm kê trả lời.
- `identity_context.is_privileged = true` cho tài khoản bị nhắm → nâng mức, kể cả khi chưa thành công.
- `lookup_status` thiếu → **không** kết luận vô hại chỉ vì thiếu ngữ cảnh.

## 6 · Chưa kết luận được thì cần thêm

- Nhật ký Security của `agent_name` trong ±1 giờ: 4624/4625/4648/4740/4776 cùng tài khoản hoặc cùng nguồn.
- Nhật ký máy điều khiển miền (4768/4771/4776) nếu tài khoản thuộc miền.
- Lịch sử đăng nhập thành công của các tài khoản bị nhắm trong 7 ngày.
