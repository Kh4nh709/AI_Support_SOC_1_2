# Thiết kế AI Support SOC

## Bố cục và thương hiệu

- Giữ nền tối, màu trạng thái và màu nhấn tím của frontend. Token nằm trong [styles.css](frontend/src/styles.css).
- Dùng IBM Plex Sans cho giao diện và IBM Plex Mono cho mã, thời gian và giá trị kỹ thuật.
- Bố cục trên màn nhỏ đưa phần xem nhanh ngay sau bản ghi đang chọn. Bố cục trên màn rộng đặt danh sách và phần xem nhanh cạnh nhau.

Người dùng chọn Sáng hoặc Tối ở thanh đầu trang. Lần đầu giao diện dùng nền tối. Trình duyệt lưu lựa chọn cho các lần mở sau.

## Phương án B

| Màn | Bố cục |
| --- | --- |
| Hàng đợi Tier 1 | Danh sách thẻ, sắp xếp, bộ lọc và xem nhanh cảnh báo |
| Chi tiết cảnh báo | Tab Bằng chứng, Phân tích AI và Quyết định xử lý theo quyền |
| Danh sách case Tier 2 | Danh sách thẻ báo trạng thái điều tra và thời gian phân tích, kèm xem nhanh |
| Chi tiết case | Tab Bằng chứng, Phân tích AI, Ghi chú và kết luận. Bản nháp giữ nguyên trong khi chuyển tab. |
| Threat Intel | Tra cứu IOC và bộ lọc ở đầu trang, mở chi tiết bên cạnh danh sách, mở rộng chỉ số và biểu đồ khi cần. |
| Phản hồi SOAR | Lọc và tìm phiếu theo trạng thái, xem danh sách thẻ và mở chi tiết phiếu để đối chiếu. |

## Danh mục để duyệt

Mở [ui-design.html](docs/ui-design.html) để xem 15 màn triển khai hoặc đề xuất, cùng các trạng thái truy cập. Hai phương án có thể so sánh trực tiếp ở Threat Intel và Phản hồi SOAR. Mỗi trang Admin có một bố cục đề xuất và menu Quản trị dẫn tới mọi trang con.

Mọi số liệu trong danh mục là dữ liệu mẫu. Các biểu mẫu và phiếu trong bản xem không gửi dữ liệu ra ngoài. Đường dẫn và quyền xem được đối chiếu với [routes.tsx](frontend/src/routes.tsx).
