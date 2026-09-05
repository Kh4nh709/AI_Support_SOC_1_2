# Playbook · `recon` · `recon_v1`

> Ai đó đang vẽ bản đồ. Bản thân thăm dò không gây thiệt hại — giá trị của alert này nằm ở chỗ nó **báo trước**, và ở chỗ nguồn thăm dò là **trong hay ngoài**.

## 1 · Ba câu phân định

1. Nguồn **nội bộ** hay ngoài? Quét từ bên trong nghiêm trọng hơn hẳn — nghĩa là đã có chỗ đứng.
2. Quét **rộng** (cả dải) hay **hẹp** (đúng vài cổng trên vài máy)? Hẹp và đúng chỗ là dấu hiệu có mục tiêu.
3. Có công cụ quét hợp lệ nào đang chạy theo lịch không?

## 2 · Kiểm gì — cụ thể

- `srcip` + `srcip_is_private` — câu hỏi đầu tiên và quan trọng nhất.
- Số `agent_name` khác nhau bị chạm và số cổng khác nhau được thử.
- Thời gian: quét nhanh và ồn ào ≠ quét chậm rải nhiều giờ để né phát hiện.
- Nếu nguồn nội bộ: máy đó là gì, ai đang đăng nhập, có alert nào trước đó.
- Lịch quét lỗ hổng của đơn vị.

## 3 · Nghiêng về FALSE POSITIVE khi

- Trùng lịch quét lỗ hổng đã đăng ký, và `srcip` là máy quét đã biết.
- Công cụ giám sát hạ tầng thăm dò dịch vụ theo thiết kế.
- Quét từ Internet vào bề mặt công khai — nhiễu nền của Internet, xảy ra liên tục với mọi địa chỉ công cộng.
- Máy mới cài đang tự dò dịch vụ mạng.

## 4 · Nghiêng về THẬT khi

- Nguồn **nội bộ** mà không phải máy quét đã đăng ký.
- Quét hẹp, đúng cổng quản trị, đúng vài máy trọng yếu.
- Ngay trước đó máy nguồn có alert `malware` hoặc `suspicious_login`.
- Sau thăm dò có thử xác thực hoặc khai thác vào đúng dịch vụ vừa dò được.
- Quét chậm có chủ đích để tránh ngưỡng phát hiện.

## 5 · Ngữ cảnh làm đổi kết luận

- Nguồn nội bộ + máy nguồn là máy người dùng thường → coi như máy đã bị chiếm cho tới khi loại trừ.
- Đích là dải máy chủ trọng yếu → nâng mức dù thăm dò chưa gây hại.
- Thiếu `ioc_context` → vắng mặt không phải bằng chứng vô hại.

## 6 · Chưa kết luận được thì cần thêm

- Danh sách đầy đủ máy và cổng bị chạm, để phân biệt rộng với hẹp.
- Lịch quét lỗ hổng và danh sách máy quét hợp lệ.
- Nếu nguồn nội bộ: toàn bộ hoạt động của máy đó trong 24 giờ.
