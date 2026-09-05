# Playbook · `c2_beacon` · `c2_beacon_v1`

> Máy nội bộ đều đặn gọi ra một địa chỉ ngoài. Điểm phân định không phải *«có kết nối ra ngoài không»* — máy nào cũng có — mà là **tính đều đặn** và **đích đến**.

## 1 · Ba câu phân định

1. Nhịp gọi có **đều** không? Phần mềm hợp lệ cũng gọi về nhà, nhưng thường không đều tới mức đồng hồ.
2. Đích đến là gì: tên miền mới đăng ký, IP thô, hay dịch vụ đám mây phổ biến?
3. Tiến trình nào mở kết nối — trình duyệt, hay một tệp trong thư mục tạm?

## 2 · Kiểm gì — cụ thể

- Khoảng cách giữa các lần kết nối và độ lệch của nó. Đều đặn ±vài giây là dấu hiệu mạnh.
- Kích thước gói đi và về: beacon thường nhỏ và đồng đều cho tới khi có lệnh.
- `dstip` + `ioc_context`; tên miền mới đăng ký trong 30 ngày là tín hiệu riêng.
- Tiến trình khởi tạo và đường dẫn của nó.
- Có alert `malware` trên cùng `agent_name` trước đó không.

## 3 · Nghiêng về FALSE POSITIVE khi

- Kết nối là phần mềm hợp lệ kiểm tra cập nhật hoặc đồng bộ.
- Đích đến thuộc dải của nhà cung cấp phần mềm đang dùng.
- Nhịp đều nhưng thưa (mỗi 24 giờ) và tiến trình là dịch vụ hệ thống đã ký.
- Nhiều máy cùng gọi một đích và đích đó là dịch vụ nội bộ.

## 4 · Nghiêng về THẬT khi

- Nhịp rất đều, khoảng ngắn, kéo dài nhiều giờ.
- Đích là IP thô không có tên miền, hoặc tên miền vừa đăng ký.
- Tiến trình nằm ở thư mục tạm hoặc thư mục người dùng, không có chữ ký.
- Lượng dữ liệu đột ngột tăng sau một chuỗi beacon nhỏ — chuyển từ chờ lệnh sang lấy dữ liệu.
- Máy này trước đó có alert `malware`.

## 5 · Ngữ cảnh làm đổi kết luận

- Máy có đặc quyền hoặc chạm dữ liệu nhạy cảm → nâng mức ngay.
- `lookup_status` chưa tra được IoC ngoài → **không** kết luận vô hại vì thiếu dữ liệu.
- Nhiều máy cùng nhịp cùng đích → không còn là alert đơn lẻ.

## 6 · Chưa kết luận được thì cần thêm

- Toàn bộ kết nối ra ngoài của máy trong 24–72 giờ, để đo nhịp thật.
- Thông tin đăng ký tên miền đích.
- Cây tiến trình của tiến trình mở kết nối.
