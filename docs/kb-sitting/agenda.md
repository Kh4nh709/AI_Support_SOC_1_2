# Lịch trình sitting KB — 90 phút

**Nguồn:** `docs/plan/kb-review-sheet-2026-09-19.md`. **Người ký:** Nguyễn Chí Khanh (chủ đồ án) + Mai Nam Nguyên (giảng viên). **Ngày giờ:** chủ đồ án chọn 1 trong các khung ở `invite.md` — càng sớm hơn tối 23/09 càng tốt (lý do bên dưới).

**Vì sao đúng thời điểm này quan trọng.** Thí điểm (pilot) có thể bắt đầu sớm nhất tối 23/09 (khi P4-T05 merge). Từ lúc đó tới lúc 10 bảng được ký, gate bước 4 coi cả 10 bảng như "chưa tồn tại" — không cụm nào tự đóng được qua chúng. Gán nhãn chiếm 26–27/09, đóng băng gold 28/09, đánh giá P7 ngày 29/09 cần chữ ký đã nằm sẵn trong file. Sitting càng sớm, giá trị càng cao — trước pilot tốt hơn sau pilot.

**Quy ước đọc lịch này:** mỗi mục ghi **quyết định phải chốt**, không phải mô tả lại bảng. "(draft)" đứng sau một phương án nghĩa là đó là mặc định hiện có trong bản nháp — dùng nó nếu hết giờ hoặc không ai phản đối.

## Tổng quan

| Phút | Khối | Bối cảnh |
|---|---|---|
| 0:00–0:05 (5’) | Mở đầu — hợp đồng §0 | không có cụm nào, chỉ là ngôn ngữ chung |
| 0:05–0:20 (15’) | §1 `ssh_brute_force` | 968 cụm, pool G1 = 901 |
| 0:20–0:35 (15’) | §2 `suspicious_login` | 174 cụm |
| 0:35–0:50 (15’) | §3 `privilege_escalation` | 108 cụm |
| 0:50–1:10 (20’) | §4–§10, 7 bảng lab/no-signal (gộp) | 0 cụm archive/bảng — phục vụ lab 22–24/09 + pilot |
| 1:10–1:15 (5’) | §11 Đề xuất — rule `5402` | 57 cụm |
| 1:15–1:20 (5’) | §12 Đề xuất — rootcheck `510`/`521` | 21 cụm |
| 1:20–1:26 (6’) | §13 Đề xuất — 4 category đã bỏ | `persistence`: 25 cụm |
| 1:26–1:30 (4’) | Ký 10 bảng (§15) | — |

Nếu một khối xong sớm, dồn phút dư sang §11–§13 (đề xuất thường cần bàn kỹ hơn số phút cấp). Nếu một bảng ở §1–§3 chưa xong khi hết giờ của nó: ghi vào `open-questions.md` và đi tiếp — đừng giữ cả buổi lại vì một bảng; quay lại cuối giờ nếu còn phút dư trước lúc ký.

## 0:00–0:05 — Mở đầu: hợp đồng §0

Không phải để tranh luận — hợp đồng đến từ code (`backend/app/kb/lookup.py`), sitting không sửa được hôm nay. Mục tiêu duy nhất: cả hai người xác nhận cùng đọc một hợp đồng trước khi vào bảng.

1. Một cụm chỉ mang 4 sự kiện cho quy tắc (severity, ioc_reputation, asset_criticality, identity_privileged) + occurrence_count — không tên rule, không tên máy, không tên tài khoản.
2. 3 hành động: `false_positive` (hành động DUY NHẤT không cần người) · `needs_review` · `escalate`.
3. Bảng chạy theo quy tắc khớp **đầu tiên** theo thứ tự trong file; test tính nhất quán (2.520 điểm lưới) đảm bảo hai quy tắc khác hành động không bao giờ cùng khớp một điểm — nên thứ tự chỉ chọn "id nào được báo cáo", không đổi kết quả.
4. Không có quy tắc nào khớp → mặc định `needs_review`.
5. Trong 7 bảng lab/pilot (§4–§10), quy tắc `false_positive` không tự nó là "bộ phát hiện" — nó là **điều kiện cấu trúc** để playbook §3 được phép nói false_positive; đánh giá nó như tiền đề, không như detector.
6. 5 hard-block chạy **trước** bảng, không quy tắc nào thắng được: severity critical · asset high · asset unknown (không có trong kiểm kê) · identity "true" · IoC malicious/suspicious.

## 0:05–0:20 — §1 `ssh_brute_force`: 4 quyết định (968 cụm; pool G1 901; mẫu 115)

- **Q1 (`sbf-1` không bao giờ khớp trong G1 — 0 cụm).** Thêm `ioc=skipped` vào điều kiện hay giữ nguyên §3.10? ☐ giữ nguyên (draft — B1 không bao giờ trả `false_positive` cho category này trong G1) ☐ thêm `skipped` (bắt thêm 14 cụm, vẫn nhất quán lưới).
- **Q2 (`sbf-5` — nhóm lớn nhất, 514/901 cụm, phần lớn tài khoản không tồn tại gõ từ Internet).** ☐ needs_review (draft) ☐ tách một quy tắc `false_positive` cho identity "unknown" ☐ escalate.
- **Q3 (`sbf-6` — nhắm `root`, 350/901 cụm, mật khẩu root đã khoá nên không thể thành công).** ☐ needs_review (draft) ☐ escalate.
- **Q4 (`sbf-4` — cả dải high, 39 cụm toàn bộ archive, chủ yếu tấn công dồn dập trên máy lab).** ☐ escalate cả dải (draft) ☐ chỉ escalate khi identity "true".

## 0:20–0:35 — §2 `suspicious_login`: 3 quyết định + 1 lưu ý (174 cụm, toàn bộ mức low)

- **Q1 (`sul-1` — có nhận `ioc=skipped` không).** ☐ giữ `skipped` (draft, bắt 48 cụm) ☐ bỏ (chỉ còn 16 cụm từ dải ISP nước ngoài).
- **Q2 (`sul-4` — đăng nhập `root` qua PAM, 32 cụm, hình dạng giống phiên sudo/cron hơn là người).** ☐ needs_review (draft) ☐ escalate (**kéo theo Q3 cũng phải escalate — hai quy tắc chồng nhau ở (identity true, asset high) nếu chỉ đổi một**).
- **Q3 (`sul-5` — mọi lần đăng nhập trên `IA1803`, 93 cụm được báo cáo qua quy tắc này trong 115 cụm liên quan).** ☐ needs_review (draft) ☐ escalate.
- **Lưu ý, không cần chốt bảng:** nhãn gold có thể chấm các cụm `sul-1` là "benign" (đăng nhập hợp lệ) chứ không phải "false_positive" (quy tắc sai) — ghi nhận cho khâu chấm điểm P7, không đổi bảng hôm nay.

## 0:35–0:50 — §3 `privilege_escalation`: 3 quyết định (108 cụm; mẫu 40)

- **Q1 (`pre-1` không bao giờ khớp được trên hạ tầng này — mọi sudo thành công đều nhắm `root` = identity "true" = bị hard-block).** ☐ giữ làm mẫu tham chiếu (draft) ☐ xoá khỏi bảng. (Đòn bẩy thật để sửa vấn đề này nằm ở §11, không phải ở đây.)
- **Q2 (`pre-4` — rule `100205` chiếm 18/31 cụm escalate, là rule cũ thời archive; máy quản lý dựng lại không còn nó nữa).** ☐ escalate cả dải 8–11 (draft) ☐ thu hẹp còn `rule_level ≥ 11` (giữ rootkit `521` ×11, bỏ `100205`/`5404`/`513`).
- **Q3 (kịch bản tấn công trong lab ở mức 5 — dưới ngưỡng escalate của bảng).** ☐ chấp nhận B1 bỏ lỡ đòn tấn công lab theo thiết kế (draft) ☐ thêm escalate cho dải medium khi asset high (lưu ý: máy lab là *medium* — thêm quy tắc này **không** cứu được kịch bản lab).

## 0:50–1:10 — §4–§10: 7 bảng lab-only / no-signal, gộp chung (~3 phút/bảng)

Không có cụm thật nào trong kho lưu cho các bảng này hôm nay — mục tiêu là xác nhận nhanh, không tranh luận sâu như §1–§3.

- **§4 `ransomware`** (lab rule `100301`, mức 12): không có quy tắc `false_positive` nào (draft, theo playbook "không bao giờ tự đóng im lặng") — giữ vậy? Giữ hay bỏ `ran-4`? Có thêm escalate riêng cho asset-high không (cần thu hẹp `ran-1` trước)?
- **§5 `data_exfiltration`** (lab `100302`, mức 10): giữ mẫu FP hiện tại (loại trừ `skipped`) hay nhận `skipped`? `dex-4` escalate theo runbook (draft) hay needs_review theo docstring của chính rule đó (hai nguồn mâu thuẫn nhau)?
- **§6 `c2_beacon`** (lab `100303`, mức 12): giữ `c2b-4` hiển thị tường minh (draft) hay bỏ (ẩn vào mặc định, không đổi kết quả)? Có thêm quy tắc escalate cho asset-high không (chưa có quy tắc nào cho trường hợp đó)?
- **§7 `malware`** (lab `52502`, mức 8): `mal-4` escalate cả dải high (draft) hay needs_review (bảng không phân biệt được virus đang bị cách ly vs đang chạy)?
- **§8 `recon`** (lab kỳ vọng `5706`/`5731`/`40601`): `rec-1` giữ identity "unknown" (draft) hay thu hẹp còn "false" (vô hiệu hoá `false_positive` cho cả category)? Mức của `5731`/`40601` **chưa xác nhận được trong repo** — ký với giả định dải high viết rõ trong bảng, hay hoãn tới khi có số liệu lab thật (chậm nhất trước 22/09)?
- **§9 `web_attack`** (0 cụm sau DEC-055): `web-1` giữ "false"/"unknown" (draft) hay thu hẹp? `web-4` chỉ escalate khi asset high (draft) hay cả dải (ảnh hưởng mọi host bị quy tắc tần suất 31151–31153 bắt)?
- **§10 `policy_violation`** (không có tín hiệu nào trong archive): ký như draft (giữ `pol-2`, coi là vô hại) hay bỏ `pol-2`? Giữ `pol-4`/`pol-5` tách biệt (draft) hay escalate cả dải 8–11?

## 1:10–1:15 — §11 Đề xuất: rule `5402` (sudo thành công lên root, 57 cụm)

**Vấn đề:** không bảng nào có thể cho `5402` là `false_positive` trên hạ tầng này — tài khoản đích luôn là `root` (identity "true"), bị hard-block bất kể bảng nói gì.

**Quyết định:** ☐ **A — chấp nhận (sheet nghiêng về phương án này).** `pre-5` giữ nguyên needs_review; thêm đúng 1 câu vào `docs/limitations.md` giải thích giới hạn. Phí tổn: ~57 cụm needs_review mỗi 30 ngày trong pilot (~2/ngày). ☐ **B — đổi nguồn identity cho decoder sudo** (lấy từ `srcuser` thay vì `dstuser`) — thay đổi code, cần DEC + card riêng, **không sửa bảng hôm nay**. ☐ **C — chuyển nhóm sudo sang resolver của `privilege_escalation`** — sheet **không khuyến nghị** (phá kịch bản tấn công lab G2, vì `5401` cần ở lại `unknown`).

**Nếu giảng viên không đồng ý A:** ghi B thành việc theo dõi (follow-up) cho pilot — cần một DEC riêng và một card code, không đổi gì trong 10 file hôm nay.

## 1:15–1:20 — §12 Đề xuất: rootcheck `510`/`521` (nghi rootkit, 21 cụm)

**Vấn đề:** rootcheck hiện tính vào `privilege_escalation`; về ngữ nghĩa nó hợp với `malware` hơn (đã có playbook, đổi được).

**Quyết định:** ☐ **A — giữ nguyên (sheet nghiêng về phương án này).** DEC-055 đã nói: không cách nào "sai rõ ràng". ☐ **B — chuyển nhóm `rootcheck` sang `malware`.** Cần DEC mới + tăng `MAPPING_VERSION` + gắn lại `test_category.py`; phải làm **trước khi rút mẫu G1 ngày 25/09**, vì nó đổi thành phần đã ghi trong DEC-086 (`privilege_escalation` mất 21 cụm; `malware` có thêm 22 cụm sống, trong đó 11 high).

**Nếu giảng viên không đồng ý A:** ghi B thành ứng viên follow-up của DEC-055 kèm số liệu (21 cụm, +1 nếu tính cả `513`) — không đổi bảng hôm nay, nhưng cần quyết trước 25/09 nếu muốn kịp trước khi G1 được rút mẫu.

## 1:20–1:26 — §13 Đề xuất: 4 category đã bỏ ở P2-T03

**3 trong 4 loại — sheet đề xuất giữ bỏ, không cần bàn sâu:** `rdp_brute_force` (0 cụm, không có tín hiệu RDP) · `phishing` (0 cụm, hạ tầng không có đường mail) · `suspicious_execution` (44 cụm nhưng 1 rule/1 máy/dải medium, gần như chắc chắn là công cụ của chính người vận hành).

**Đáng bàn — `persistence` (25 cụm, 21 thuộc critical+high, hiện bị trộn vào `unknown`):** sheet **không nghiêng** về phương án nào ở đây — đây là lựa chọn duy nhất của cả §13 mà sitting thật sự cần quyết định. ☐ **(i)** mở lại category — Owner + advisor tự viết `kb/playbooks/persistence.md`, thêm ánh xạ nhóm mới, rồi mới có bảng — thu hồi 21 cụm crit+high khỏi `unknown`, nhưng tốn công viết playbook (hôm nay hoặc sau). ☐ **(ii)** map `adduser`/`account_changed` → `privilege_escalation` — rẻ, hợp R5, nhưng "thêm user mới" về bản chất là persistence chứ không phải leo thang quyền, nên không đúng ngữ nghĩa. ☐ **giữ bỏ cả 4** (mặc định nếu hết giờ — không đổi gì, 21 cụm crit+high vẫn nằm trong `unknown`).

## 1:26–1:30 — Ký (§15)

Chạy `signing-checklist.md` cho từng bảng **đã có quyết định rõ** ở trên (kể cả khi quyết định là "giữ nguyên draft" — vẫn cần ký để có hiệu lực). Bảng nào còn treo: để `reviewed_by`/`reviewed_at` là `null` và ghi câu hỏi còn treo vào `open-questions.md` — đừng ký một quyết định chưa thật sự chốt chỉ vì hết giờ.
