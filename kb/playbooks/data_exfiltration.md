# Playbook · `data_exfiltration` · `data_exfiltration_v1`

> Dữ liệu đi ra ngoài bất thường. Khó nhất trong các loại, vì công việc bình thường cũng đẩy dữ liệu ra ngoài suốt ngày.

## 1 · Ba câu phân định

1. **Bao nhiêu**, và so với chính máy đó những ngày trước thì lệch mấy lần?
2. Đi **đâu**, và bằng **đường nào** — dịch vụ đã duyệt hay kênh lạ?
3. Ai đang đăng nhập lúc đó, và người đó có lý do nghiệp vụ để chạm dữ liệu này không?

## 2 · Kiểm gì — cụ thể

- Khối lượng đi ra so với đường nền của **chính máy đó**, không so với máy khác.
- Giao thức và cổng: DNS hoặc ICMP mang nhiều dữ liệu là bất thường theo định nghĩa.
- Đích đến: dịch vụ lưu trữ cá nhân, máy chủ lạ, hay hạ tầng công ty.
- Giờ: ngoài giờ làm việc là tín hiệu, dù yếu.
- Trước đó có `suspicious_login` hoặc `privilege_escalation` trên cùng máy hoặc cùng tài khoản không.

## 3 · Nghiêng về FALSE POSITIVE khi

- Sao lưu định kỳ ra dịch vụ đám mây đã duyệt, đúng lịch, đúng khối lượng thường lệ.
- Đồng bộ dữ liệu của phần mềm nghiệp vụ đã biết.
- Người dùng tải bộ dữ liệu lớn phục vụ công việc, có thể xác nhận được.
- Khối lượng lớn nhưng đích là hạ tầng nội bộ đặt tại nhà cung cấp đám mây.

## 4 · Nghiêng về THẬT khi

- Khối lượng lệch nhiều lần so với đường nền của chính máy đó.
- Đường đi bất thường: dữ liệu nhét trong DNS, ICMP, hoặc chia nhỏ đều đặn.
- Đích là dịch vụ lưu trữ cá nhân trong khi chính sách cấm.
- Ngay trước đó có truy cập hàng loạt vào kho dữ liệu.
- Tài khoản thực hiện vừa được nâng quyền, hoặc vừa đăng nhập từ nơi lạ.

## 5 · Ngữ cảnh làm đổi kết luận

- Dữ liệu cá nhân hoặc dữ liệu khách hàng → hệ quả pháp lý; phải mở case dù chưa chắc chắn.
- Người dùng đang trong quá trình nghỉ việc → đổi hẳn mức ưu tiên.
- `asset_context.criticality` cao → hạ ngưỡng.

## 6 · Chưa kết luận được thì cần thêm

- Đường nền lưu lượng ra của chính máy đó trong 30 ngày.
- Danh sách file được truy cập ngay trước thời điểm gửi.
- Xác nhận nghiệp vụ: dữ liệu này có lý do rời khỏi mạng không.
