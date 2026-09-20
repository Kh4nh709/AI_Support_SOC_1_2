# Open questions — §1–§10, one row per question the draft could not settle

Nguồn: `docs/plan/kb-review-sheet-2026-09-19.md` §1–§10 (đề xuất §11–§13 không nằm ở đây — xem `agenda.md`). Dùng bảng này nếu sitting hết giờ trước khi bàn hết: ký bảng đó với mặc định ghi ở cột cuối, coi mọi câu chưa bàn là đã chọn mặc định.

| # | Bảng (category) | Câu hỏi | Mặc định nếu không kịp bàn |
|---|---|---|---|
| 1.1 | ssh_brute_force | `sbf-1` không bao giờ khớp trong G1 (0 cụm) — có thêm `ioc=skipped` vào điều kiện không? | Giữ nguyên §3.10 (draft) — B1 không bao giờ trả `false_positive` cho category này |
| 1.2 | ssh_brute_force | `sbf-5` (514/901 cụm, phần lớn tài khoản không tồn tại từ Internet) — needs_review, tách rule FP cho identity unknown, hay escalate? | needs_review (draft) |
| 1.3 | ssh_brute_force | `sbf-6` (350/901 cụm, nhắm `root`) — needs_review hay escalate? | needs_review (draft) |
| 1.4 | ssh_brute_force | `sbf-4` (39 cụm, dải high) — escalate cả dải hay chỉ khi identity "true"? | escalate cả dải (draft) |
| 2.1 | suspicious_login | `sul-1` — nhận `ioc=skipped` (48 cụm) hay chỉ ISP ngoài (16 cụm)? | giữ `skipped` (draft) |
| 2.2 | suspicious_login | `sul-4` (32 cụm, `root` qua PAM) — needs_review hay escalate? (đổi thì `sul-5` phải đổi theo, hai rule chồng nhau nếu không) | needs_review (draft) |
| 2.3 | suspicious_login | `sul-5` (93 cụm báo cáo qua rule này, 115 liên quan trên `IA1803`) — needs_review hay escalate? | needs_review (draft) |
| 2.4 | suspicious_login | Nhãn gold dùng "benign", bảng dùng "false_positive" cho cùng nhóm cụm ở `sul-1` — có cần đổi gì trong bảng không? | Không đổi bảng; chỉ là lưu ý cho khâu chấm điểm P7 |
| 3.1 | privilege_escalation | `pre-1` không bao giờ khớp được (sudo thành công → root → hard-block) — giữ làm mẫu hay xoá? | giữ làm mẫu tham chiếu (draft) |
| 3.2 | privilege_escalation | `pre-4` (18/31 cụm là rule `100205` đã lỗi thời, máy dựng lại không còn) — escalate cả dải 8–11 hay thu hẹp còn `rule_level ≥ 11`? | escalate cả dải (draft) |
| 3.3 | privilege_escalation | Kịch bản tấn công trong lab ở mức 5 (dưới ngưỡng escalate) — chấp nhận B1 bỏ lỡ, hay thêm escalate cho medium+asset-high (không cứu được lab vì máy lab là medium)? | chấp nhận, B1 bỏ lỡ theo thiết kế (draft) |
| 4.1 | ransomware | Không có rule `false_positive` nào — giữ vậy hay khôi phục theo mẫu §3.10? | không có rule FP (draft) |
| 4.2 | ransomware | Giữ hay bỏ `ran-4` (dải 8–11, hiện không rule nào chiếm)? | giữ (draft) |
| 4.3 | ransomware | Thêm escalate riêng cho asset-high không (cần thu hẹp `ran-1` trước)? | để nguyên, không thêm (draft) |
| 5.1 | data_exfiltration | Giữ mẫu FP hiện tại (loại trừ `skipped`) hay nhận `skipped`? | giữ như mẫu (draft) |
| 5.2 | data_exfiltration | `dex-4` — escalate (theo runbook) hay needs_review (theo docstring của rule)? | escalate (draft) |
| 6.1 | c2_beacon | Giữ `c2b-4` hiển thị tường minh hay bỏ (ẩn vào mặc định)? | giữ, hiển thị (draft) |
| 6.2 | c2_beacon | Thêm rule escalate cho asset-high không? | để nguyên, không thêm (draft) |
| 7.1 | malware | `mal-4` — escalate cả dải high hay needs_review (không phân biệt được cách ly vs đang chạy)? | escalate (draft) |
| 8.1 | recon | `rec-1` giữ identity "unknown" hay thu hẹp còn "false" (vô hiệu hoá FP cho cả category)? | giữ "unknown" (draft) |
| 8.2 | recon | Mức của `5731`/`40601` chưa xác nhận được trong repo — ký với giả định dải high, hay hoãn tới khi có số liệu lab? | ký với giả định viết rõ trong bảng (draft); xác nhận lại khi có số liệu lab |
| 9.1 | web_attack | `web-1` giữ "false"/"unknown" hay thu hẹp? | giữ (draft) |
| 9.2 | web_attack | `web-4` chỉ escalate khi asset-high hay cả dải? | chỉ asset-high (draft) |
| 10.1 | policy_violation | Ký như draft (giữ `pol-2`) hay bỏ `pol-2`? | ký như draft, giữ `pol-2` (vô hại, chỉ ghi rõ ý định) |
| 10.2 | policy_violation | Giữ `pol-4`/`pol-5` tách biệt hay escalate cả dải 8–11? | giữ tách biệt (draft) |

**Không nằm trong bảng này** (thuộc §11–§13, không phải §1–§10): đề xuất rule `5402`, rootcheck `510`/`521`, và 4 category đã bỏ (kể cả `persistence`) — mặc định của các mục đó nằm trong `agenda.md`, mỗi mục có phần "nếu giảng viên không đồng ý" riêng.
