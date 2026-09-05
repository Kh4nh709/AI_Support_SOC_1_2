# Playbook · `web_attack` · `web_attack_v1`

> Yêu cầu HTTP mang dấu hiệu khai thác. Phần lớn là máy quét tự động gõ mù; phần nhỏ là khai thác có chủ đích — và hai thứ đó trông giống nhau ở dòng log đầu tiên.

## 1 · Ba câu phân định

1. Máy chủ **trả về gì**? `4xx` hàng loạt là quét trượt; một `200` giữa rừng `404` là chỗ phải nhìn.
2. Payload có **nhắm đúng công nghệ** đang chạy không, hay là danh sách gõ mù mọi nền tảng?
3. Có dấu hiệu **sau khai thác** không: file mới, tiến trình mới, kết nối ra ngoài?

## 2 · Kiểm gì — cụ thể

- `raw_log`: đường dẫn, tham số, User-Agent, mã trả về.
- Tỉ lệ mã trả về trong cụm: toàn `404`/`403` ≠ có `200`/`500`.
- User-Agent: công cụ quét công khai thường khai tên mình.
- `srcip` + `ioc_context`; IP quét thường xuất hiện trong nhiều nguồn threat intel.
- Máy đích có thật sự chạy công nghệ bị nhắm không — gõ khai thác WordPress vào máy chủ Java là gõ mù.

## 3 · Nghiêng về FALSE POSITIVE khi

- Toàn bộ cụm là `404`, đường dẫn thuộc danh sách quét phổ biến (`/wp-admin`, `/.env`, `/phpmyadmin`).
- Ứng dụng đích không tồn tại hoặc đã gỡ.
- User-Agent là bot tìm kiếm hợp lệ và IP tra ngược đúng chủ.
- Đội phát triển đang chạy kiểm thử bảo mật đã báo trước.

## 4 · Nghiêng về THẬT khi

- Có mã `200` hoặc `500` ở đúng request mang payload — máy chủ **đã xử lý** cái gì đó.
- Payload khớp đúng công nghệ và đúng phiên bản có lỗ hổng.
- Sau đó xuất hiện file mới trong thư mục web, hoặc alert `malware`/`c2_beacon` từ cùng `agent_name`.
- Chuỗi request cho thấy **thăm dò rồi khai thác**: quét trước, gõ đúng một chỗ sau.

## 5 · Ngữ cảnh làm đổi kết luận

- Máy chủ đưa ra Internet + `criticality` cao → mọi `200` đáng ngờ đều phải mở case.
- Ứng dụng có xử lý dữ liệu cá nhân → hệ quả pháp lý, không chỉ hệ quả kỹ thuật.
- `lookup_status` thiếu IoC ngoài → vắng mặt **không** phải bằng chứng vô hại.

## 6 · Chưa kết luận được thì cần thêm

- Access log đầy đủ của máy chủ trong ±30 phút, không chỉ dòng khớp rule.
- Danh sách file thay đổi trong thư mục web sau thời điểm alert.
- Phiên bản thật của ứng dụng và framework.
