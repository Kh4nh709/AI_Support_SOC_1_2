# Tiến độ wireframe SOC

Bản xem độc lập nằm ở `docs/wireframe.html`. Dữ liệu và các thao tác đều được mô phỏng trong bộ nhớ của trang. Mã dựng nằm trong `frontend/wireframe`. Dựng lại bằng `node frontend/wireframe/build.mjs` từ gốc worktree trial.

| Nhóm | Tiến độ | Nhóm khoá đã nối với component |
| --- | --- | --- |
| Hàng đợi / Alert | Đã dựng | app, appearance, nav, role, live, common, forbidden, workspace, band, severity, category, confidence, status, queue, alert, ai1, analysis, rag, decision |
| Case | Chờ | case, caseStatus, conclusion, headStatus, ai2 |
| SOAR | Chờ | soar |
| Threat Intel | Chờ | ti |
| Quản trị / Đăng nhập | Chờ | admin, login |

Các nhóm ghi “Chờ” chưa có bộ dữ liệu và phản hồi cho thao tác. Chi tiết alert có ví dụ cụm đang chờ, cụm tăng trong lúc đọc, cụm tự động đóng và hai mẫu SOAR. Quyết định đóng và mở lại yêu cầu lý do. Chuyển tier 2 dùng tiêu đề và mức độ theo hợp đồng API.
