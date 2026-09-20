# Đọc trước buổi sitting duyệt bảng quyết định KB

**Gửi:** Mai Nam Nguyên. **Thời lượng đọc:** khoảng 10 phút. **Mục tiêu của tài liệu này:** để 90 phút của buổi sitting dùng hết cho việc quyết định, không phải để giải thích khái niệm.

## Bảng quyết định (decision table) là gì, trên hệ thống này

AI Support SOC tự động phân loại từng cụm cảnh báo (cluster — nhiều alert giống nhau gộp lại) bằng một bảng quy tắc dạng "nếu … thì …". Máy **chỉ** được nhìn thấy đúng 4 sự kiện cho mỗi cụm — không thấy tên rule, không thấy tên máy, không thấy tên tài khoản:

1. **`severity`** — suy ra từ `rule_level` của Wazuh: mức ≥12 = critical, ≥8 = high, ≥5 = medium, còn lại = low (quy ước DEC-053).
2. **`ioc_reputation`** — kết quả tra địa chỉ IP: malicious / suspicious / clean / not_found / skipped (skipped = IP nội bộ hoặc không có IP để tra — **không** có nghĩa là vô hại).
3. **`asset_criticality`** — mức quan trọng của máy bị ảnh hưởng: high / medium / low / unknown (unknown = máy chưa có trong bảng kiểm kê → hệ thống xử lý như *high* cho tới khi biết rõ hơn).
4. **`identity_privileged`** — tài khoản liên quan có phải tài khoản đặc quyền không: "true" / "false" / "unknown".

(Còn `occurrence_count` — cụm đó lặp lại bao nhiêu lần trong kỳ — nhưng đây không phải một "sự kiện phân loại" theo nghĩa trên.)

Với 4 sự kiện đó, mỗi quy tắc trả về đúng 1 trong 3 hành động:

- **`false_positive`** — đóng ngay, không cần người xem. Đây là hành động **duy nhất** không cần người can thiệp.
- **`needs_review`** — xếp vào hàng đợi cho phân tích viên (Tier-1) xem.
- **`escalate`** — mở case ngay.

Nếu không quy tắc nào khớp → mặc định `needs_review` (bảng không cần phủ hết mọi trường hợp có thể xảy ra).

**Hiện trạng.** 10 bảng (mỗi loại tấn công một bảng) hiện là **bản nháp do agent soạn** — lấy bằng chứng từ 30 ngày log thật cộng với các playbook đã có sẵn (văn bản do người viết từ trước). Bản nháp **chưa có hiệu lực**: hệ thống coi cả 10 bảng như "chưa tồn tại" (không tự đóng cụm nào qua chúng) cho tới khi thầy và chủ đồ án cùng đọc, sửa nếu cần, và **ký**. Buổi sitting chính là hành động biến bản nháp thành chính sách — không phải một buổi duyệt cho có.

## Thầy được mời quyết định gì

**3 bảng có dữ liệu thật, đáng bàn kỹ (15 phút/bảng trong buổi):** `ssh_brute_force` (968 cụm), `suspicious_login` (174 cụm), `privilege_escalation` (108 cụm). Ví dụ một câu hỏi thật sẽ được hỏi: 350 cụm dò mật khẩu SSH nhắm vào tài khoản `root` (không thể đăng nhập thành công vì mật khẩu root trên hệ thống đã bị khoá) — nên vẫn chờ người xem, hay báo động ngay vì mục tiêu là tài khoản đặc quyền?

**7 bảng còn lại** chưa có log thật trong 30 ngày đã thu thập (chỉ phục vụ kịch bản diễn tập trong lab 22–24/09 và giai đoạn thí điểm sau đó) — sitting chỉ xin thầy xác nhận nhanh, không tranh luận sâu.

## Ba đề xuất (sẽ nói kỹ hơn trong buổi — đây là bản tóm tắt)

1. **Rule `5402`** (sudo thành công lên root, 57 cụm) — hệ thống **không có cách nào** tự đóng loại cảnh báo này, kể cả khi đó là một người dùng gõ `sudo` hoàn toàn bình thường, vì tài khoản đích luôn là "root" = đặc quyền = bị chặn cứng theo thiết kế an toàn. Hỏi thầy: chấp nhận giới hạn này (ghi rõ thành một câu trong tài liệu), hay đổi cách hệ thống xác định "ai gây ra" cảnh báo (một thay đổi code riêng, không làm trong buổi này)?
2. **Rootcheck `510`/`521`** (nghi có rootkit, 21 cụm) — hiện đang tính vào loại "leo thang đặc quyền". Có nên chuyển sang loại "mã độc" cho đúng bản chất hơn không?
3. **4 loại tấn công từng bị bỏ trước đây** — 3 loại đầu (dò mật khẩu RDP, lừa đảo qua email, thực thi đáng ngờ) không có gì để bàn (hạ tầng không sinh ra log phù hợp). Riêng **`persistence`** (duy trì truy cập sau khi đã xâm nhập) có 25 cụm thật, 21 cụm trong số đó thuộc mức critical/high và hiện đang bị trộn lẫn vào loại "unknown" — không ai nhìn thấy chúng đúng bản chất. Có đáng mở lại loại này không (cần viết playbook mới), hay tạm gộp vào "leo thang đặc quyền" cho rẻ hơn?

## Chữ ký nghĩa là gì

Cuối buổi, với mỗi bảng đã thống nhất, tên thầy (cùng tên chủ đồ án) và ngày ký sẽ được ghi thẳng vào file YAML của bảng đó — ví dụ `reviewed_by: "Nguyễn Chí Khanh + Mai Nam Nguyên"`, `reviewed_at: "<ngày>"`. Từ đúng thời điểm ghi đó, bảng mới thật sự có hiệu lực trong hệ thống; trước đó nó chỉ là văn bản tham khảo, không ảnh hưởng gì tới cảnh báo thật.
