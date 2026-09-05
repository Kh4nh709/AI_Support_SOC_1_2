# Playbook · `suspicious_login` · `suspicious_login_v1`

> Một lần đăng nhập **thành công** nhưng lệch thói quen. Tài khoản hợp lệ là công cụ tấn công phổ biến nhất — và cũng là nguồn false positive lớn nhất.

## 1 · Ba câu phân định

1. Lệch ở **chiều nào**: địa điểm, giờ giấc, máy nguồn, hay giao thức?
2. Tài khoản này có **đặc quyền** không? Cùng một lệch trên tài khoản thường và tài khoản quản trị là hai mức khác nhau.
3. Sau khi vào, phiên đó **làm gì**? Đăng nhập rồi không làm gì khác hẳn đăng nhập rồi liệt kê toàn mạng.

## 2 · Kiểm gì — cụ thể

- `alert_user` và `identity_context.is_privileged`.
- `srcip` + `srcip_is_private`: nguồn mới hay nguồn đã thấy nhiều lần.
- Giờ trong `event_time` so với giờ làm việc của đơn vị.
- Có alert nào khác **cùng tài khoản** trong 24 giờ trước không — đặc biệt `ssh_brute_force`.
- Sau alert này, cùng `agent_name` có sinh alert `recon` hoặc `privilege_escalation` không.

## 3 · Nghiêng về FALSE POSITIVE khi

- Người dùng có lịch sử đi công tác hoặc làm từ xa, IP thuộc dải nhà mạng dân dụng trong nước.
- Đăng nhập ngoài giờ nhưng trùng lịch bảo trì đã thông báo.
- Tài khoản dịch vụ đăng nhập từ chính máy chủ nó vẫn chạy.

## 4 · Nghiêng về THẬT khi

- Đăng nhập thành công từ IP có `ioc_context` xấu, hoặc từ nơi đơn vị không có hoạt động.
- Cùng tài khoản đăng nhập từ hai nơi cách nhau xa trong khoảng thời gian không thể di chuyển kịp.
- Ngay trước đó có chuỗi xác thực hỏng — đây là brute force **thành công**, không phải đăng nhập lạ đơn lẻ.
- Sau khi vào có tạo tài khoản mới, đổi mật khẩu người khác, hoặc truy cập dữ liệu ngoài phạm vi công việc.

## 5 · Ngữ cảnh làm đổi kết luận

- `identity_context.is_privileged = true` → coi như mức cao cho tới khi loại trừ được.
- `asset_context.criticality` cao → một lần đăng nhập lạ đủ để mở case.

## 6 · Chưa kết luận được thì cần thêm

- Lịch sử đăng nhập 30 ngày của tài khoản: IP, giờ, giao thức thường dùng.
- Xác nhận với chính người dùng hoặc quản lý trực tiếp — bước rẻ nhất và quyết định nhất.
