# Tiến độ wireframe SOC

Bản xem độc lập nằm ở `docs/wireframe.html`. Dữ liệu và các thao tác đều được mô phỏng trong bộ nhớ của trang. Mã dựng nằm trong `frontend/wireframe`. Dựng lại bằng `node frontend/wireframe/build.mjs` từ gốc worktree trial.

| Nhóm | Tiến độ | Nhóm khoá đã nối với component |
| --- | --- | --- |
| Hàng đợi / Alert | Đã dựng | app, appearance, nav, role, live, common, forbidden, workspace, band, severity, category, confidence, status, queue, alert, ai1, analysis, rag, decision |
| Case | Đã dựng | case, caseStatus, conclusion, headStatus, ai2, analysis, rag, workspace |
| SOAR | Đã dựng | soar (bảng phiếu, chi tiết, thông báo, báo phiếu mới, đồng hồ, quyết định, phân trang và huy hiệu ở header) |
| Threat Intel | Đã dựng | ti (tra cứu, chi tiết IOC, sao chép giá trị gốc, tình trạng nạp dữ liệu, biểu đồ, phân trang và xuất dữ liệu cho admin) |
| Quản trị / Đăng nhập | Chờ | admin, login |

Các nhóm ghi “Chờ” chưa có bộ dữ liệu và phản hồi cho thao tác. Chi tiết alert có ví dụ cụm đang chờ, cụm tăng trong lúc đọc, cụm tự động đóng và hai mẫu SOAR. Quyết định đóng và mở lại yêu cầu lý do. Chuyển tier 2 dùng tiêu đề và mức độ theo hợp đồng API.
