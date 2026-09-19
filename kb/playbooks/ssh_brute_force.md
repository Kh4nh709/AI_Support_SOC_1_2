# Playbook · `ssh_brute_force` · `ssh_brute_force_v1`

> Nhiều lần xác thực hỏng vào cùng một dịch vụ. Câu hỏi thật không phải *«có brute force không»* mà **có ai vào được không**, và **tài khoản nào bị nhắm**.

## 1 · Ba câu phân định

1. Sau chuỗi hỏng, có **một lần thành công** nào từ cùng `srcip` không? Đó là ranh giới giữa nhiễu và sự cố.
2. Tài khoản bị nhắm là **có thật** hay là danh sách từ điển (`admin`, `test`, `oracle`, `git`)?
3. `srcip` là **nội bộ** hay ngoài? Brute force từ nội bộ là chuyện khác hẳn — thường là script hỏng hoặc thông tin đăng nhập hết hạn.

## 2 · Kiểm gì — cụ thể

- `alert_user` — tập tài khoản bị thử. Một tài khoản lặp lại ≠ hàng chục tài khoản khác nhau.
- `occurrence_count` và khoảng thời gian: 500 lần trong 30 giây là máy quét; 20 lần trong 6 giờ là người gõ sai hoặc script cũ.
- `srcip_is_private`. Nếu `false`, tra `ioc_context` xem IP đã bị bêu tên chưa.
- Có alert xác thực **thành công** nào cùng `srcip`, cùng `agent_name`, ngay sau cửa sổ hỏng không.

## 3 · Nghiêng về FALSE POSITIVE khi

- Chỉ **một** tài khoản, và tài khoản đó **có thật** — thường là người dùng đổi mật khẩu, hoặc một dịch vụ còn giữ mật khẩu cũ.
- `srcip` nội bộ và trùng một máy chủ ứng dụng đã biết (cron, sao lưu, giám sát).
- Số lần hỏng thấp, rải đều nhiều giờ, **không** có lần thành công nào.

## 4 · Nghiêng về THẬT khi

- Có **thành công sau chuỗi hỏng** từ cùng nguồn — tín hiệu mạnh nhất, ưu tiên trên mọi tín hiệu khác.
- Nhiều tài khoản khác nhau bị thử theo thứ tự từ điển.
- `srcip` ngoài, `ioc_context` báo `malicious` hoặc `suspicious`.
- Sau khi thành công có lệnh bất thường: tạo user, sửa `authorized_keys`, cài dịch vụ.
- Cùng `srcip` đồng thời gõ nhiều `agent_name` khác nhau — quét ngang, không phải gõ nhầm.

## 5 · Ngữ cảnh làm đổi kết luận

- `asset_context.criticality = high` → hạ ngưỡng, đừng chờ đủ bằng chứng như máy thường; `unknown` (không có trong kiểm kê) → **không** kết luận vô hại, xử lý như `high` cho tới khi kiểm kê trả lời.
- `identity_context.is_privileged = true` cho tài khoản bị nhắm → nâng mức, kể cả khi chưa thành công.
- `lookup_status` thiếu → **không** kết luận vô hại chỉ vì thiếu ngữ cảnh.

## 6 · Chưa kết luận được thì cần thêm

- Log xác thực đầy đủ của `agent_name` trong ±1 giờ quanh alert.
- Lịch sử đăng nhập thành công của các tài khoản bị nhắm trong 7 ngày.
