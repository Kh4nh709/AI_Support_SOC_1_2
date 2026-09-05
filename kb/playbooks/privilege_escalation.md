# Playbook · `privilege_escalation` · `privilege_escalation_v1`

> Một chủ thể có được quyền cao hơn mức đáng có. Hiếm khi là điểm bắt đầu — thường là **khúc giữa** của một chuỗi đã bắt đầu từ trước.

## 1 · Ba câu phân định

1. Leo thang **thành công** hay là một lần thử hỏng?
2. Chủ thể là **người** hay **tiến trình**? Tiến trình tự nâng quyền đáng ngờ hơn nhiều.
3. **Trước đó** có gì? Loại này gần như luôn có tiền sử — tìm nó.

## 2 · Kiểm gì — cụ thể

- `alert_user` trước và sau; nhóm quyền được thêm.
- Cơ chế: khai thác lỗ hổng, lạm dụng cấu hình sai (sudo, SUID, dịch vụ chạy quyền cao), hay dùng thông tin đăng nhập lấy được.
- Tiến trình thực hiện và tiến trình cha của nó.
- Alert của cùng `agent_name` hoặc `alert_user` trong 24 giờ **trước** — bước bắt buộc, không phải tuỳ chọn.
- Sau khi nâng quyền, chủ thể làm gì.

## 3 · Nghiêng về FALSE POSITIVE khi

- Quản trị viên thao tác đúng quy trình, đúng giờ, từ máy quản trị quen thuộc.
- Công cụ triển khai tự động chạy với quyền cao theo thiết kế.
- Cài đặt phần mềm hợp lệ cần quyền cao, có phiếu yêu cầu đi kèm.
- Rule bắt mọi lần dùng `sudo` mà không lọc — nhiễu cấu hình, nên sửa rule.

## 4 · Nghiêng về THẬT khi

- Nâng quyền bởi tiến trình không phải công cụ quản trị.
- Có khai thác lỗ hổng đã biết ngay trước đó.
- Tài khoản thường bỗng vào nhóm quản trị, không có phiếu yêu cầu.
- Ngay sau đó có tạo tài khoản mới, cài dịch vụ, hoặc chạm máy khác.
- Chuỗi đầy đủ: đăng nhập lạ → leo thang → di chuyển ngang.

## 5 · Ngữ cảnh làm đổi kết luận

- `identity_context.is_privileged` đã `true` từ trước → alert này có thể chỉ là hoạt động bình thường.
- Máy trọng yếu → giả định xấu nhất cho tới khi loại trừ.
- Có alert `malware` trước đó trên cùng máy → gần như chắc chắn là chuỗi tấn công thật.

## 6 · Chưa kết luận được thì cần thêm

- Lịch sử alert của máy và tài khoản trong 7 ngày trước.
- Phiếu yêu cầu hoặc lịch thay đổi tương ứng.
- Cây tiến trình quanh thời điểm nâng quyền.
