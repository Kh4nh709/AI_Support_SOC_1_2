# Phase 6 — Hàng đợi và quyết định Tier 1

`tier1/queue.py` · `tier1/decide.py` · `domain/` · `audit/`

> **Chặng đầu tiên có con người.** Đồng bộ, do thao tác của analyst kích hoạt.
> **Vào:** alert ở `queued_tier1` · **Ra:** đóng cả cụm, hoặc mở một `Case`.

---

## Mục tiêu

Đưa alert tới mắt người, kèm đủ ngữ cảnh để quyết trong vài chục giây thay vì vài phút. Rồi ghi lại quyết định đó **cùng chỗ** với đề xuất của model, để so được.

Ba việc phase này phải làm đúng:

1. **Xếp thứ tự hàng đợi** sao cho thứ đáng xem nhất nằm trên.
2. **Quyết một lần cho cả cụm** — analyst không bấm 500 lần cho 500 bản sao.
3. **Ghi mốc SLA** để đo được thời gian triage giảm bao nhiêu.

---

## Hàng đợi

```sql
SELECT a.alert_id, a.rule_id, a.category, a.severity, a.risk_score,
       a.occurrence_count, a.triaged_count, a.first_seen_at, a.last_seen_at,
       r.result->>'suggested_action' AS goi_y,
       r.result->>'confidence'       AS do_tin_cay,
       (a.triaged_count > 0 AND
        (a.occurrence_count >= a.triaged_count * $RETRIAGE_FACTOR
         OR a.occurrence_count - a.triaged_count >= $RETRIAGE_ABS_DELTA)
       ) AS needs_retriage
FROM alerts a
LEFT JOIN llm_runs r
       ON r.subject_id = a.alert_id AND r.pipeline = 'triage'
WHERE a.status = 'queued_tier1'
  AND NOT a.is_synthetic
ORDER BY needs_retriage DESC, a.risk_score DESC NULLS LAST, a.first_seen_at ASC
LIMIT $page_size OFFSET $offset;
```

**Bốn điểm trong câu này đáng nói:**

- **`LEFT JOIN`, không phải `JOIN`.** Alert có `triage_status = 'unavailable'` vẫn phải hiện — chỉ là cột gợi ý rỗng. `JOIN` thường sẽ **giấu mất** đúng những alert mà model không xử lý được, tức là những alert có khả năng bất thường nhất.
- **`needs_retriage` tính lúc truy vấn**, không lưu cột. Lưu thì phải cập nhật; cập nhật thì có lúc quên.
- **`risk_score DESC NULLS LAST`** — alert chưa enrich xong (hoặc enrich thất bại) không bị đẩy lên đầu vì `NULL`.
- **`first_seen_at ASC`** làm khóa phụ, để alert cũ không bị bỏ đói vô hạn bởi alert mới điểm cao.

**Không có timer nền nào.** Trạng thái SLA tính khi truy vấn:

```sql
now() - first_seen_at > $SLA_ACK_MINUTES   -- đã quá hạn tiếp nhận chưa
```

---

## P6‑1 · Cụm phình giữa lúc hiển thị và lúc bấm

Analyst mở alert lúc `occurrence_count = 3`, đọc, suy nghĩ, bấm "đóng" lúc `occurrence_count = 240`. Quyết định vừa ghi áp cho một cụm **khác hẳn** cụm analyst đã xem.

Đây không phải giả thuyết: Phase 2 cho cụm hút bản sao liên tục trong 15 phút không hoạt động, và một đợt brute-force sinh hàng trăm alert trong khoảng đó.

| | Cách | Vấn đề |
|---|---|---|
| (a) | Bỏ qua — quyết định áp cho cụm hiện tại | Analyst ký vào thứ mình chưa đọc |
| (b) | Khóa cụm khi analyst mở | Analyst bỏ đi ăn trưa thì cụm ngừng gộp; cần timeout, thêm trạng thái |
| **(c)** | **Khóa lạc quan** — gửi kèm `occurrence_count` lúc hiển thị, so lúc ghi | Analyst phải xác nhận lại khi cụm đổi nhiều |

> **Chốt (c).** Giao diện gửi kèm `seen_occurrence_count`. Khi ghi quyết định:

```
delta = occurrence_count_hiện_tại − seen_occurrence_count

delta ≤ REVIEW_DELTA_TOLERANCE (20)  → ghi bình thường
delta >  REVIEW_DELTA_TOLERANCE      → từ chối, trả 409 kèm số liệu mới
```

**Vì sao có dung sai chứ không phải so bằng tuyệt đối:** cụm tăng từ 3 lên 5 trong lúc analyst đọc là bình thường và không đổi bản chất quyết định. Bắt xác nhận lại mỗi lần tăng một đơn vị sẽ khiến analyst bấm mù — phản tác dụng.

**Vì sao không chọn (b):** khóa bi quan tạo một trạng thái mới (`đang bị giữ`), cần timeout, cần dọn khóa mồ côi, và làm cụm ngừng gộp trong lúc bị giữ — tức là đợt tấn công đang diễn ra bị chia nhỏ vì lý do giao diện. Cái giá lớn hơn vấn đề nó giải quyết.

`REVIEW_DELTA_TOLERANCE = 20` **chưa được kiểm chứng** — cần đo tỉ lệ `409` thực tế rồi chỉnh.

---

## P6‑2 · Hai analyst cùng mở một alert

Không cấm được, và không nên cấm — SOC thật có người bàn giao ca, có người xem cùng lúc.

> **Chốt:** không khóa. `acknowledged_at` và `acknowledged_by` ghi **người đầu tiên** (`UPDATE … WHERE acknowledged_at IS NULL`); người thứ hai vẫn xem được, và nếu bấm quyết định thì khóa lạc quan ở P6‑1 xử lý phần còn lại.

Thêm một lớp: nếu alert đã rời `queued_tier1`/`tier1_active` (người kia đã quyết xong), lời ghi thứ hai nhận `409` kèm thông tin ai đã quyết và quyết gì. Không im lặng ghi đè.

---

## Mở alert

```sql
UPDATE alerts
SET status = 'tier1_active',
    acknowledged_at = now(),          -- mốc SLA, đồng hồ DB (G5)
    acknowledged_by = $user_id
WHERE alert_id = $1 AND acknowledged_at IS NULL;

INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role)
VALUES ('alert.acknowledged', $1, $user_id, 'analyst');
```

Đồng thời **hiển thị** (không ghi gì):

| Khối | Nguồn | Ghi chú |
|---|---|---|
| Tương quan ±2h | `domain/correlation.py` | Tính **lúc này**, chỉ đọc |
| Gợi ý ① | `llm_runs` | `LEFT JOIN`, có thể rỗng |
| Tài khoản bị nhắm trong cụm | `SELECT DISTINCT alert_user …` | Vì khóa cụm không chứa `alert_user` |
| Playbook | `kb/` theo `category` | Cùng playbook model đã đọc |

> **Cụm analyst thấy có thể lớn hơn cụm mà ① từng thấy.** Đây là **trung thực, không phải lỗi**: ① chạy ngay sau enrichment, nhánh `+2h` của cửa sổ tương quan khi đó gần như rỗng. Giao diện nên nói rõ *"gợi ý dựa trên N cụm liên quan tại thời điểm phân tích; hiện có M"* khi hai số khác nhau.

---

## Quyết định — fan-out cả cụm

```sql
BEGIN;
SET LOCAL statement_timeout = '3s';

-- ① Kiểm tra khóa lạc quan (P6-1)
SELECT occurrence_count, status FROM alerts WHERE alert_id = $1 FOR UPDATE;
--    lệch quá dung sai, hoặc status đã rời tier1_active → ROLLBACK, trả 409

-- ② Alert gốc
UPDATE alerts
SET status = $decision,           -- closed_fp | closed_benign
    closed_at = now(), sealed_at = now(),
    close_reason = $reason,
    triaged_count = occurrence_count      -- mốc cho needs_retriage lần sau
WHERE alert_id = $1;

-- ③ Fan-out: mọi bản sao trong cụm
UPDATE alerts
SET status = $decision, closed_at = now(), sealed_at = now(), close_reason = $reason
WHERE duplicate_of = $1;

-- ④ Vết — MỘT dòng cho cả cụm, kèm đề xuất LLM
INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload)
VALUES ('tier1.decided', $1, $user_id, 'analyst',
        jsonb_build_object('decision', $decision, 'reason', $reason,
                           'occurrence_count', $n,
                           'llm_suggestion', $llm_suggestion,
                           'llm_confidence', $llm_confidence));
COMMIT;
```

**Bốn chi tiết dễ sai:**

1. **`sealed_at = now()` ở cả ② và ③.** Thiếu nó thì cụm vừa đóng vẫn thoả nhánh `sealed_at IS NULL` của vị từ Phase 2 và tiếp tục hút bản sao — alert mới bị nuốt vào một cụm đã có kết luận.
2. **`triaged_count = occurrence_count`** phải đặt ở đây, không đặt lúc mở alert. Đặt lúc mở thì `needs_retriage` đo từ mốc sai.
3. **Một dòng audit cho cả cụm**, không phải một dòng cho mỗi bản sao. `subject_id` là alert gốc; phép đo độ khớp `JOIN` đúng theo khóa đó.
4. **Ghi `llm_suggestion` vào payload ngay tại đây**, không dựa vào việc `JOIN` lại sau. Nếu `llm_runs` bị dọn hoặc pipeline đổi, số liệu so sánh vẫn còn.

---

## Escalate

```sql
BEGIN;
-- ① Mở case
INSERT INTO cases (case_id, title, status, severity, created_by, created_at)
VALUES ($uuid, $title, 'investigating', $severity, $user_id, now());

-- ② Cố định hóa cụm tương quan — đây là lúc DUY NHẤT correlation được lưu
-- CHỈ CHÈN ALERT GỐC (DEC-036, 06/09). Mỗi nhánh UNION phải lọc `duplicate_of IS NULL`.
--   Đo trên DB đã migrate: `ck_alerts_ban_sao_phai_seal_va_tro_goc` buộc mọi dòng `duplicate`
--   có `sealed_at`, và CHECK trạng thái cấm dòng đã seal sang 'escalated_tier2' — nên nếu ②
--   chèn bản sao thì ③a (chạm MỌI dòng case_alerts có case_id IS NULL) vi phạm CHECK, và phép
--   so số dòng của chính ③a cũng lệch. ③b bên dưới đã xử lý bản sao đúng cách (chỉ gắn
--   case_id), và ghi chú cuối mục này đã nói tư cách thành viên tính được bằng
--   `duplicate_of IN (case_alerts)` — nên heads-only KHÔNG mất thông tin nào.
INSERT INTO case_alerts (case_id, alert_id, added_by, added_at)
SELECT $uuid, alert_id, $user_id, now()
FROM (
  SELECT $1 AS alert_id
  UNION
  SELECT alert_id FROM alerts WHERE duplicate_of = $1
  UNION
  SELECT alert_id FROM domain.correlated_cluster_ids($1)   -- ±2h · vị từ đầy đủ ở dưới
) x;

-- ③a Mọi alert GỐC trong case rời hàng đợi.
--    `AND case_id IS NULL` là lớp chống đua: xem ghi chú N2 dưới.
--    Số dòng chạm phải BẰNG số dòng case_alerts vừa chèn, lệch → ROLLBACK + 409.
UPDATE alerts SET status = 'escalated_tier2', case_id = $uuid
WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = $uuid)
  AND case_id IS NULL;

-- ③b Bản sao của chúng: CHỈ gắn case_id, KHÔNG đổi status.
--    Bản sao luôn có sealed_at (P2:236) nên đổi status sẽ vi phạm H3;
--    và giữ 'duplicate' là giữ lớp chặn thứ hai của D2 (P2:213-214).
UPDATE alerts SET case_id = $uuid
WHERE duplicate_of IN (SELECT alert_id FROM case_alerts WHERE case_id = $uuid);

-- ④ HAI dòng audit — hai sự kiện khác nhau, không phải một sự kiện ghi hai lần.
INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload)
VALUES ('tier1.escalated', $1,     $user_id, 'analyst',
        jsonb_build_object('case_id', $uuid, 'alert_ids', $alert_ids,
                           'llm_suggestion', $llm_suggestion)),
       ('case.opened',     $uuid,  $user_id, 'analyst',
        jsonb_build_object('trigger_alert_id', $1, 'alert_count', $n,
                           'correlated_count', $n_corr));
COMMIT;
```

**Correlation chỉ được lưu tại đây** — khi đã có người xác nhận nó đáng lưu. Trước đó nó là truy vấn, sau đó nó là `case_alerts`.

> **Vì sao ③ phải là HAI câu.** Câu gộp `WHERE alert_id = $1 OR duplicate_of = $1` **không chạy được**
> trên PostgreSQL: bản sao bắt buộc có `sealed_at` ngay lúc `INSERT` (P2:236,
> `ck_alerts_ban_sao_phai_seal_va_tro_goc`), còn H3 cấm `escalated_tier2` có `sealed_at`
> (`ck_alerts_h3_escalate_khong_seal`). Hai ràng buộc cộng lại làm mọi cụm có ≥ 1 bản sao
> rollback cả transaction escalate. Tách ra: gốc đổi `status`, bản sao **chỉ** nhận `case_id`.
> Tư cách thành viên case vẫn tính được bằng `duplicate_of IN (case_alerts)`, đúng như P7 đang làm.

> **N2 · `AND case_id IS NULL` là lớp chống đua, không phải trang trí.**
> `WHERE alert_id IN (case_alerts)` **không nhắc tới `status`**, nên nó KHÔNG được bảo vệ bởi
> bộ lọc `status IN ('queued_tier1','tier1_active')` của `correlated_cluster_ids()`. Dưới
> `READ COMMITTED`, hai transaction escalate chồng nhau có thể cùng đọc một alert là ứng viên,
> và transaction sau sẽ **cướp `case_id`** của case mà transaction trước đã commit — im lặng.
> Vế `AND case_id IS NULL` cộng với việc **so số dòng chạm với số dòng `case_alerts` vừa chèn**
> biến ca đó thành `ROLLBACK` + `409`.
>
> Lớp thứ hai nằm ở DB: `ux_case_alerts_mot_alert_mot_case` (migration 006) là `UNIQUE` trên
> `case_alerts(alert_id)`. Một `if` trong Python không sống sót qua hai transaction đồng thời;
> một unique index thì có. Hai lớp này là cưỡng chế của quyết định **B — một alert thuộc tối đa
> một case, escalate lên alert đã có case luôn trả `409`, không bao giờ gộp case.**
> Gộp case là gộp hai kết luận và hai vết audit — một tính năng Tier 2 ngoài phạm vi đồ án.

> **D · escalate ghi HAI dòng audit, không phải một.**
> `tier1.escalated` (`subject_id = alert_id`) và `case.opened` (`subject_id = case_id`).
> Không đổi hẳn sang `case_id`: phép đo ③ *"độ khớp đề xuất ① với quyết định người"* nối
> `llm_runs.subject_id = alert_id`, mà `escalate` là **một trong ba** giá trị của
> `suggested_action` — mất `alert_id` là mất một phần ba phép đo đó.
> Hai dòng vì đây là **hai sự kiện khác nhau**: một alert được bấm, và một case được mở.
> Payload của mỗi dòng chứa đủ khoá của bên kia nên truy vấn không cần `JOIN`.
>
> Quy ước chung, áp cho mọi event về sau: **`subject_id` là định danh mà truy vấn báo cáo sẽ
> dùng để nhóm sự kiện đó.** So được với một đề xuất của ① → `alert_id`. Thuộc vòng đời case →
> `case_id`. Chạm cả hai → **ghi hai dòng, không chọn một bên.**

> **③a lấy phạm vi `case_alerts`, không phải `$1`.** Mọi thành viên của case — kể cả cụm tương
> quan được ② gom vào — đều rời hàng đợi Tier 1 ngay lúc escalate. Thiếu điều này, cụm tương quan
> ở lại `queued_tier1` trong khi đã thuộc case: analyst khác vẫn thấy nó trong hàng đợi và làm
> việc thừa trên thứ đã có chủ, rồi bị Tier 2 ghi đè lúc kết luận.
>
> **Đánh đổi phải biết:** alert bị kéo khỏi hàng đợi theo cách này **chưa từng được acknowledge**,
> nên `acknowledged_at` của chúng ở lại `NULL`. Phép đo ② của báo cáo (`acknowledged_at → closed_at`)
> vì thế **phải lọc `acknowledged_at IS NOT NULL`** — xem kien-truc B7.

**Vị từ của `domain.correlated_cluster_ids()`** — hàm này quyết định `UPDATE` ở ③ chạm vào đâu,
nên nó phải được viết ra, không để ngầm:

```sql
-- domain/correlation.py · correlated_cluster_ids()
-- Trả các CỤM sẽ bị kết luận của case áp lên. KHÁC summarize_for_prompt(): hàm kia chỉ
-- ĐỌC để dựng prompt nên không cần lọc; hàm này quyết định UPDATE sẽ chạm vào đâu.
SELECT alert_id
FROM alerts
WHERE (agent_name = $1 OR alert_user = $2 OR srcip = ANY($3))
  AND alert_time BETWEEN $t - interval '2 hours' AND $t + interval '2 hours'
  AND duplicate_of IS NULL                          -- chỉ cụm, theo D‑C4
  AND alert_id <> $self
  AND status IN ('queued_tier1', 'tier1_active')    -- xem bảng dưới
ORDER BY occurrence_count DESC
LIMIT 200;                                          -- MAX_ALERTS_PER_CASE
```

Một vế `status IN (…)` giữ được **bốn** thứ cùng lúc:

| Loại bỏ | Giữ được gì |
|---|---|
| `auto_closed` | M3 (terminal) · tử số phép đo giảm FP · và **luật cắt thôi ưu tiên nhiễu** — sau M4 một cụm máy quét có `occurrence_count` 5.000, đứng trên mọi alert thật ở `ORDER BY` |
| `closed_*` | Kết luận cũ của analyst khác không bị ghi đè |
| `received`, `enriching` | `enriching` chỉ còn một lối ra (kien-truc A5) — không nhảy cóc |
| `escalated_tier2` | Alert đang thuộc case khác không bị cướp `case_id` |

> **`escalated_tier2` KHÔNG set `sealed_at`.** Cụm đang điều tra vẫn hút bản sao (D‑C5): đợt tấn công còn diễn ra là thông tin Tier 2 cần. Giao diện Tier 2 phải hiển thị được rằng `occurrence_count` đang thay đổi, nếu không analyst sẽ nghi ngờ dữ liệu.

**Trần khi cố định hóa:** `LIMIT` ở vị từ trên là bắt buộc — một agent bận cho 1.792 alert trong cửa sổ ±2h (đo được ở Phase 4). Gom hết vào một case là tạo ra một case không ai điều tra nổi, và làm vỡ prompt ② ở Phase 7.

```python
MAX_ALERTS_PER_CASE = 200
```

Vượt trần: lấy 200 cụm có `occurrence_count` cao nhất, ghi audit `case.truncated` kèm số bị bỏ, và hiển thị cảnh báo cho analyst.

> **Đừng trích con số 200 như một ràng buộc đang hoạt động.** Nó được chọn dựa trên *"agent bận cho
> 1.792 alert trong ±2h"*, tức là trên tập **chưa lọc** `status`. Sau khi vị từ lọc còn
> `queued_tier1 | tier1_active`, tập ứng viên đo được chỉ còn 127/364 — trần 200 gần như không bao
> giờ chạm tới nữa. Giữ nó làm hàng rào chống ca xấu thì đúng; trích nó trong báo cáo như một giới
> hạn thường xuyên có hiệu lực thì sai.

---

## Xử lý lỗi

| Tình huống | Mã | Hành động |
|---|---|---|
| Cụm phình quá dung sai | `409` | Trả số liệu mới, yêu cầu xem lại |
| Alert đã bị người khác quyết | `409` | Trả ai quyết, quyết gì, lúc nào |
| Alert đã bị đóng bởi luồng khác | `409` | Không ghi đè |
| Analyst không có vai trò Tier 1 | `403` | Ghi audit `authz.denied` |
| Correlation vượt `MAX_ALERTS_PER_CASE` | — | Cắt + audit + cảnh báo, **không** chặn escalate |
| `statement_timeout` khi fan-out cụm lớn | `503` | Rollback toàn bộ; cụm không được đóng một nửa |

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng |
|---|---|---|
| H1 | Quyết định áp cho **toàn cụm** trong một transaction | Test kill giữa chừng → không có cụm đóng một nửa |
| H2 | Mọi đường đóng đều set `closed_at` **và** `sealed_at` | `CHECK` hoặc trigger |
| H3 | `escalated_tier2` **không** set `sealed_at` | Test bản sao vẫn gộp được |
| H4 | Audit ghi **cả** quyết định người **lẫn** đề xuất LLM | Test đọc payload |
| H5 | Một dòng audit cho một cụm, `subject_id` = alert gốc | Test đếm |
| H6 | Alert `unavailable` vẫn hiện trong hàng đợi | Test `LEFT JOIN` |
| H7 | `triaged_count` đặt lúc **quyết định**, không lúc mở | Test |
| H8 | Correlation chỉ ghi xuống ở bước escalate | Review |
| H9 | Mốc thời gian lấy `now()` của DB (G5) | Review |

---

## Test bắt buộc

```
# Hàng đợi
test_alert_unavailable_van_hien_trong_hang_doi      # H6
test_risk_score_null_khong_bi_day_len_dau
test_alert_cu_khong_bi_bo_doi
test_needs_retriage_len_dau_hang_doi
test_sla_tinh_luc_truy_van_khong_co_timer_nen

# Khóa lạc quan — P6-1
test_cum_phinh_trong_dung_sai_van_ghi_duoc
test_cum_phinh_vuot_dung_sai_tra_409
test_409_tra_kem_so_lieu_moi

# Đồng thời — P6-2
test_hai_analyst_cung_mo_acknowledged_by_la_nguoi_dau
test_nguoi_thu_hai_quyet_sau_nhan_409_khong_ghi_de

# Fan-out
test_dong_cum_500_ban_sao_trong_mot_transaction     # H1
test_kill_giua_fan_out_khong_co_cum_dong_mot_nua
test_dong_cum_set_ca_closed_at_va_sealed_at         # H2
test_cum_da_dong_khong_hut_ban_sao_nua
test_triaged_count_dat_luc_quyet_dinh               # H7

# Escalate
test_escalate_khong_set_sealed_at                   # H3
test_ban_sao_van_gop_vao_cum_dang_dieu_tra
test_case_alerts_cat_o_200_va_ghi_audit
test_correlation_chi_ghi_xuong_o_buoc_escalate      # H8
test_escalate_cum_CO_BAN_SAO_khong_vi_pham_h3      # ③ · ca mà bộ test cũ bỏ sót
test_ban_sao_giu_status_duplicate_sau_escalate     # ③b
test_ban_sao_nhan_case_id_sau_escalate             # ③b
test_cum_tuong_quan_roi_hang_doi_ngay_luc_escalate # ③a
test_correlated_cluster_ids_khong_tra_auto_closed
test_correlated_cluster_ids_khong_tra_alert_da_ket_luan
test_correlated_cluster_ids_khong_tra_alert_dang_o_case_khac
test_may_quet_5000_alert_khong_lot_vao_case        # luật cắt ưu tiên nhiễu
test_alert_that_khong_bi_cat_boi_nhieu_o_tran_200

# Truy vết
test_audit_ghi_ca_quyet_dinh_va_de_xuat_llm         # H4
test_mot_dong_audit_cho_mot_cum                     # H5
test_do_khop_join_duoc_theo_subject_id
```

---

## Quyết định đã chốt

| # | Vấn đề | Chốt | Căn cứ |
|---|---|---|---|
| **P6‑1** | Cụm phình giữa lúc xem và lúc bấm | **Khóa lạc quan**, dung sai 20 | Khóa bi quan làm cụm ngừng gộp vì lý do giao diện |
| **P6‑2** | Hai analyst cùng mở | Không khóa; ghi người đầu; `409` cho lượt ghi sau | SOC thật có bàn giao ca |
| **P6‑3** | `sealed_at` khi đóng | **Có** khi đóng, **không** khi escalate | Cụm đã kết luận không được nuốt thêm; cụm đang điều tra thì cần |
| **P6‑4** | Trần alert trong một case | 200, cắt theo `occurrence_count` | Đo: agent bận cho 1.792 alert trong ±2h |
| **P6‑5** | `triaged_count` đặt khi nào | Lúc **quyết định** | Đặt lúc mở thì `needs_retriage` đo từ mốc sai |
| **P6‑6** | Ghi đề xuất LLM ở đâu | **Cả** `llm_runs` **và** payload audit | Số liệu so sánh không phụ thuộc `JOIN` còn nguyên |

### Việc còn lại

1. **`REVIEW_DELTA_TOLERANCE = 20` chưa kiểm chứng** — đo tỉ lệ `409` thật rồi chỉnh. Quá chặt thì analyst bấm mù, quá lỏng thì mất ý nghĩa.
2. **`SLA_ACK_MINUTES` chưa đặt** — cần thống nhất với quy trình SOC của đơn vị.
3. **Giao diện phải hiện chênh lệch cụm** giữa lúc ① phân tích và lúc analyst xem.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `domain/` | Chuyển trạng thái, `escalate()`, `correlation` | `tier1/` → `domain/` ✅ |
| `infra/` | DB, auth, phân quyền, config | `tier1/` → `infra/` ✅ |
| `audit/` | `alert.acknowledged`, `tier1.decided`, `tier1.escalated` | `tier1/` → `audit/` ✅ |
| `kb/` | Hiển thị playbook cho analyst | `tier1/` → `kb/` ✅ |

Phase này **không** import `ingest/`, `soar/`, `tier2/` — bàn giao lên Tier 2 đi qua `domain.escalate()` và hàng đợi job.

---

*Đặc tả Phase 6 · Hàng đợi và quyết định Tier 1 · 6 điểm chốt (P6‑1…P6‑6)*
