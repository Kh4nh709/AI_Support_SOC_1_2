# Playbook · `ransomware` · `ransomware_v1`

> Mã hoá dữ liệu để tống tiền. **Đây là loại alert mà chậm một giờ là mất một hệ thống** — ngưỡng bằng chứng để hành động phải thấp hơn mọi loại khác.

## 1 · Ba câu phân định

1. Có **đang mã hoá** không, hay mới chỉ là công cụ nằm trên đĩa?
2. Đã chạm tới **ổ chia sẻ hoặc máy chủ file** chưa?
3. Bản sao lưu và bản chụp có còn nguyên không — hay đã bị xoá trước?

## 2 · Kiểm gì — cụ thể

- `raw_log`: tên file bị đổi đuôi, tốc độ đổi file, đường dẫn bị chạm.
- Lệnh xoá bản chụp và tắt khôi phục (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`) — **dấu hiệu quyết định**.
- Dịch vụ sao lưu hoặc cơ sở dữ liệu bị dừng ngay trước đó.
- Số máy cùng sinh alert tương tự trong 30 phút.
- File hướng dẫn đòi tiền chuộc xuất hiện trong thư mục.

## 3 · Nghiêng về FALSE POSITIVE khi

- Công cụ mã hoá hợp lệ được dùng đúng quy trình (mã hoá ổ đĩa theo chính sách).
- Một máy đơn lẻ, không có lệnh xoá bản chụp, không có đổi đuôi hàng loạt.
- Phần mềm sao lưu tự đổi tên file theo thiết kế và rule chưa được tinh chỉnh.

> Ngay cả khi nghiêng về false positive, **đừng đóng im lặng**: ghi rõ lý do và sửa rule, vì đóng nhầm loại này đắt hơn mọi loại khác.

## 4 · Nghiêng về THẬT khi

- Nhiều file đổi đuôi trong thời gian ngắn.
- Có lệnh xoá bản chụp hoặc tắt khôi phục.
- Có file đòi tiền chuộc.
- Nhiều máy cùng lúc — gần như chắc chắn đã lan qua tài khoản quản trị hoặc chính sách nhóm.
- Trước đó có `suspicious_login` hoặc `privilege_escalation` trên cùng đội máy.

## 5 · Ngữ cảnh làm đổi kết luận

- Bất kỳ máy chủ file hay máy chủ cơ sở dữ liệu nào dính → mức cao nhất, không tranh luận.
- `identity_context.is_privileged` cho tài khoản đang chạy tiến trình → giả định sẽ lan.
- Alert `critical` **không bao giờ** bị auto-close (`G8`) — nếu thấy cụm này đã tự đóng thì đó là lỗi cấu hình, phải nêu ra.

## 6 · Chưa kết luận được thì cần thêm

- Danh sách file bị chạm và mốc thời gian đầu tiên.
- Tình trạng bản sao lưu gần nhất và bản chụp.
- Đường lây: tài khoản nào, máy nào trước.

## 7 · Windows (added 29/09, P9-T02, not reviewed)

- Sysmon 1 chạy `vssadmin`, `wbadmin` hoặc `bcdedit` với tham số xoá bản chụp hay tắt khôi phục — dấu hiệu quyết định ở §2, nhìn qua cây tiến trình.
- Sysmon 11 (tạo file) **hàng loạt** từ một tiến trình trong thời gian ngắn, nhất là cùng một đuôi lạ, hoặc cùng một file đòi tiền chuộc ở nhiều thư mục.
- Tiến trình sinh các lệnh trên chạy từ thư mục người dùng hoặc thư mục tạm → xử lý như đang mã hoá.
