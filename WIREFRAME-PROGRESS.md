# Tiến độ wireframe SOC

Bản xem độc lập nằm ở `docs/wireframe.html`. Dữ liệu và các thao tác đều được mô phỏng trong bộ nhớ của trang. Mã dựng nằm trong `frontend/wireframe`. Dựng lại bằng `node frontend/wireframe/build.mjs` từ gốc worktree trial.

| Nhóm | Tiến độ | Nhóm khoá đã nối với component |
| --- | --- | --- |
| Hàng đợi / Alert | Đã dựng | app, appearance, nav, role, live, common, forbidden, workspace, band, severity, category, confidence, status, queue, alert, ai1, analysis, rag, decision |
| Case | Đã dựng | case, caseStatus, conclusion, headStatus, ai2, analysis, rag, workspace |
| SOAR | Đã dựng | soar (bảng phiếu, chi tiết, thông báo, báo phiếu mới, đồng hồ, quyết định, phân trang và huy hiệu ở header) |
| Threat Intel | Đã dựng | ti (tra cứu, chi tiết IOC, sao chép giá trị gốc, tình trạng nạp dữ liệu, biểu đồ, phân trang và xuất dữ liệu cho admin) |
| Quản trị / Đăng nhập | Đã dựng | admin, login |

## Bảng đối chiếu từng nhóm khoá

Trong [Danh mục wireframe](docs/wireframe.html), mở **Đối chiếu strings.ts** để tra từng khoá, đọc nội dung và đi đến màn tương ứng. Các hàm định dạng có tham số minh hoạ. Bảng tra được tạo trực tiếp từ `S` trong [strings.ts](frontend/src/strings.ts). Có 28 nhóm cấp đầu và 1.994 khoá lá, gồm cả chuỗi và hàm định dạng.

| Nhóm khoá | Màn hình | Vị trí hoặc điều kiện xem |
| --- | --- | --- |
| `appearance`, `app`, `nav`, `role`, `live` | Header | Tên sản phẩm, giao diện sáng/tối, tài khoản và vai trò, điều hướng theo quyền, huy hiệu SOAR. Chọn Mất kết nối để đổi chỉ báo. |
| `forbidden` | Hàng đợi | Mở đường dẫn Case bằng Tier 1 hoặc trang Quản trị bằng Tier 2. |
| `common` | Các trang danh sách, chi tiết và form | Trạng thái tải, thử lại, dữ liệu khuyết, sao chép, đóng và chuyển trang. |
| `workspace` | Hàng đợi, Alert, Case | Khung xem nhanh, liên kết mở bản ghi, tab bằng chứng, phân tích và quyết định. |
| `band`, `category`, `status` | Hàng đợi, Alert, cụm trong Case | Bốn mức rủi ro, danh mục và trạng thái alert. |
| `severity`, `confidence` | Alert, Case, Gán nhãn và các kết quả AI có liên quan | Mức độ nghiêm trọng, độ tin cậy. |
| `queue` | Hàng đợi | Ô đếm, chín cột, bộ lọc, thứ tự, phân trang và trạng thái danh sách. |
| `alert` | Chi tiết Alert | Sự kiện, ngữ cảnh SOAR, log, tài khoản đích, làm giàu, tương quan và playbook. Mở alert loại quét cổng để xem thêm địa lý, cổng và TI. |
| `ai1` | Hàng đợi và tab Phân tích AI của Alert | TP/FP, cờ, độ tin cậy, dẫn chứng, lịch sử, kiểm chứng và trạng thái nhánh mù. |
| `decision` | Alert, vai trò Tier 1 | Nhận xử lý, đóng, chuyển tier 2, mở lại và xử lý xung đột khi cụm tăng. |
| `analysis`, `rag` | Phân tích AI của Alert và Case | Chỉ số, dẫn chứng, kết quả tra cứu tri thức, lỗi và nội dung dùng chung của ①/②. |
| `case`, `caseStatus` | Danh sách và chi tiết Case | Bảy cột, năm trạng thái, xem nhanh, bảng cụm, log, tiếp diễn, diễn biến và ghi chú. Danh sách dùng phân trang theo offset. |
| `headStatus`, `conclusion` | Chi tiết Case | Trạng thái từng cụm và ba kết luận có lý do. |
| `ai2` | Case, tab Phân tích AI | Chưa chạy, đang chạy, treo, lỗi, hết lượt, kết quả và phân tích lại. |
| `soar` | Phản hồi SOAR và header | Danh sách/chi tiết phiếu, thông báo, tín hiệu mới, đồng hồ, quyền giữ/gỡ/FP, hộp xác nhận và phân trang. |
| `ti` | Threat Intel | Tra cứu và chi tiết IOC, ngày và độ tin cậy, cột thẻ, sao chép gốc, chỉ số, biểu đồ và hai định dạng xuất cho admin. |
| `admin.nav`, `admin.title`, `admin.common` | Khung và các trang Quản trị | Điều hướng, tiêu đề, xác nhận, lưu, lỗi. Lab dùng tiêu đề riêng trong `admin.lab`. |
| `admin.range` | Tổng quan, LLM, Audit | Khoảng thời gian theo từng API. |
| `admin.reason`, `admin.bounds` | Biểu mẫu Quản trị | Thông báo từ chối và giới hạn giá trị tại trường hoặc hộp xác nhận. |
| `admin.overviewPage` | Tổng quan | Sức khoẻ, chỉ số, job lỗi và chạy lại, kiểm kê và nạp lại. |
| `admin.usersPage` | Người dùng và quyền | Bảng người dùng, menu thao tác, các hộp xác nhận, tạo tài khoản và bảng quyền. |
| `admin.llmPage` | LLM và hạn mức | Sửa ba hạn mức, pipeline, lượt ② theo người và lượt gọi gần đây. |
| `admin.labelsPage` | Gán nhãn tập vàng | Bằng chứng mù, ba nhãn, độ chắc chắn, ghi chú, tiến độ, hoàn tác và đóng băng. |
| `admin.lab` | Danh sách và chi tiết lần chạy lab | Tạo lần chạy, chọn mục đích và thời gian, xem bằng chứng, gán TP/FP hoặc bỏ nhãn. |
| `admin.knowledgePage` | Tri thức | Năm tab, đối chiếu nguồn và bản nháp, duyệt, sửa rồi duyệt, từ chối, soạn lại, gỡ. Bản nháp chưa có nội dung cho xem thao tác soạn lại. |
| `admin.auditPage`, `admin.auditGroup`, `admin.eventType`, `admin.verdict` | Audit | Lọc thời gian, nhóm, người và đối tượng. Mở dòng để đọc payload, chuyển trang bằng con trỏ. |
| `login` | Đăng nhập | Tên đăng nhập, mật khẩu, gửi form. Chọn tình huống bị khoá, đăng nhập đang tắt hoặc sai thông tin rồi gửi form để nhận thông báo. |

## Mục còn thiếu và phạm vi kiểm tra

- Không còn nhóm trang chờ thực hiện. Tất cả 1.994 khoá có mục tra trong wireframe. Một số thông báo phụ thuộc vào lỗi nhà cung cấp, phản hồi máy chủ hoặc xung đột nhiều phiên chỉ có ví dụ trong bảng tra. Bản mẫu chỉ chạy các tình huống nghiệp vụ bằng dữ liệu cục bộ.
- Quyết định đóng alert và mở lại yêu cầu lý do tối đa 500 ký tự. Form chuyển tier 2 dùng tiêu đề và mức độ theo API. Năm trạng thái Case là trạng thái bản ghi, API danh sách không cung cấp bộ lọc mức độ hay trạng thái.
- Dữ liệu mẫu được khởi tạo lại khi tải lại tài liệu. Dùng điều hướng trong header, danh sách và khung xem nhanh để theo dõi kết quả của các thao tác trong cùng phiên xem.
- Mở trực tiếp HTML hoặc chạy `node frontend/wireframe/serve.mjs` để xem trên cổng 8786. HTML đã đóng gói độc lập. Lệnh dựng lại dùng các component hiện có trong worktree `trial`, kể cả phần frontend đang chỉnh sửa.

## Kiểm tra bản giao

Edge mở đủ 15 màn ở cả 375 px và 1440 px trên cổng 8786. Mỗi màn vừa chiều rộng viewport và không phát sinh lỗi JavaScript. Đã so sánh từng tên khoá trong bảng tra với 1.994 khoá lá của `strings.ts`, kiểm tra header theo ba vai trò, mở log của cụm trong Case và quan sát cảnh báo khi số lần xuất hiện của alert tăng từ 2 lên 14.

Các checkpoint trước nhóm Quản trị là `f779b3b1` (Hàng đợi/Alert), `fb0be915` (Case), `f88dbe2b` (SOAR) và `dd1b6188` (Threat Intel). Nhóm Quản trị, Đăng nhập và bảng đối chiếu nằm trong commit chứa phần kiểm tra này.
