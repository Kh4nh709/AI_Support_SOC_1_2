# Playbook · `policy_violation` · `policy_violation_v1`

> Có người làm việc bị cấm, nhưng **không nhất thiết là tấn công**. Kết luận đúng thường là `concluded_policy_violation` — không phải sự cố, cũng không phải false positive.

## 1 · Ba câu phân định

1. Đây là **vi phạm nội quy** hay là **tấn công đang giả dạng vi phạm nội quy**?
2. Người thực hiện có biết mình đang vi phạm không — vô ý hay cố tình?
3. Vi phạm này có **mở đường** cho cái khác không (tắt bảo vệ, mở cổng, cài công cụ)?

## 2 · Kiểm gì — cụ thể

- Hành vi cụ thể: cài phần mềm cấm, tắt bộ diệt virus, dùng USB, dựng dịch vụ chưa duyệt, chia sẻ tài khoản.
- `alert_user` và vai trò của người đó.
- Hành vi lặp lại hay lần đầu.
- Đặc biệt: hành vi có **làm giảm khả năng phát hiện** không — tắt log, tắt bảo vệ, mở tường lửa.
- Có alert khác từ cùng máy hoặc cùng tài khoản sau đó không.

## 3 · Nghiêng về FALSE POSITIVE khi

- Người dùng có ngoại lệ đã được duyệt mà rule chưa cập nhật.
- Phần mềm nằm trong danh sách cấm nhưng đã được phê duyệt riêng cho bộ phận đó.
- Thay đổi do đội hạ tầng thực hiện theo phiếu yêu cầu.

> Ở đây *false positive* nghĩa là **rule sai**, không phải *không có gì xảy ra*. Nếu hành vi có thật mà được phép, hãy sửa rule chứ đừng đóng lặng lẽ.

## 4 · Nghiêng về THẬT khi

- Hành vi làm giảm khả năng phát hiện: tắt bộ diệt virus, xoá log, dừng dịch vụ giám sát.
- Cài công cụ có thể dùng để tấn công (điều khiển từ xa, dò mật khẩu).
- Lặp lại sau khi đã được nhắc.
- Đi kèm alert khác trong cùng cửa sổ thời gian — lúc đó nó không còn là vi phạm nội quy đơn thuần.

## 5 · Ngữ cảnh làm đổi kết luận

- Người có đặc quyền vi phạm → nghiêm trọng hơn, vì họ hiểu rõ hơn và làm được nhiều hơn.
- Máy trọng yếu → mọi thay đổi cấu hình bảo vệ đều phải mở case.
- Vi phạm xảy ra ngay sau một alert đăng nhập lạ → xét khả năng không phải chính chủ.

## 6 · Chưa kết luận được thì cần thêm

- Nội quy hiện hành và danh sách ngoại lệ đã duyệt.
- Xác nhận từ quản lý trực tiếp của người dùng.
- Trạng thái bảo vệ của máy trước và sau hành vi.
