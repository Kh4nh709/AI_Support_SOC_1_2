# Phase 2 — Chống trùng lặp (Dedup)

`ingest/dedup.py` · `domain/transitions.py` · `infra/db.py`

> **Vị trí:** ngay sau Phase 1, vẫn trong cùng một request webhook. Đây là **bước đầu tiên chạm database**.
> **Bản này đã áp Đề xuất 1** — khóa cụm là 4 cột trực tiếp, không phải cột băm.
> **Đã áp B1, B2, B4** — so sánh IP bằng `=`, `last_seen_at` dùng `now()`, thêm cột `sealed_at`.
> **Cập nhật M4** — cụm `auto_closed` vẫn hút bản sao. Xem mục *"Cụm còn hút"*.

---

## Mục tiêu

Một đợt tấn công sinh hàng nghìn alert giống nhau. Phase này gộp chúng lại để đạt hai mục đích:

1. **Analyst nhìn một dòng có bộ đếm**, không phải cuộn qua 5.000 dòng giống hệt nhau.
2. **Không tốn một lần gọi model cho mỗi bản sao** — 4.999 alert chỉ tăng bộ đếm, không sinh job, không vào prompt.

Và một mục tiêu ẩn quan trọng không kém:

3. **Chống ngập hàng đợi job.** Đây là lý do quyết định đặt dedup ở đây thay vì trong worker.

---

## Vì sao dedup chạy đồng bộ trong webhook

> **Chốt:** dedup chạy **đồng bộ, trong transaction của webhook**, trước khi trả `201`.

Nếu để dedup ở worker: một đợt 50.000 bản sao tạo ra 50.000 job. Worker bận rộn phát hiện trùng lặp trong khi alert mới **thật sự** xếp hàng phía sau. Dedup đồng bộ thì 49.999 cái chỉ tăng bộ đếm và **không đẩy job nào** — hàng đợi chỉ chứa việc thật.

Đây cũng là lý do auto-close (Phase 3) phải nằm cùng lớp này chứ không ở `soar/`: nhiễu đã biết không được tiêu tốn hạn ngạch API bên ngoài, mà muốn chạy trước enrichment thì phải chạy trong webhook.

> ⚠️ **Mâu thuẫn trong hồ sơ gốc cần sửa:** mục *"Dòng đời một bản ghi"* (Phần II‑05) mô tả dedup chạy **ở worker, sau khi đã trả 201**, và đặt nó **sau** bước enrichment. Bản này chốt theo Phần III (đồng bộ, trước enrichment). **Mục II‑05 cần sửa lại cho khớp.**

### Thứ tự trong transaction

```
xác thực → chặn kích thước → parse + chuẩn hóa → phân loại → event_bucket_hash
   └─ Phase 1: ba bước này là HÀM THUẦN, nằm NGOÀI khóa ─┘

→ BEGIN
→ SET LOCAL statement_timeout = '3s'
→ pg_advisory_xact_lock(hashtext(cluster_key))     ← Phase 2 bắt đầu
→ tra cụm đang mở
→ [trùng]     UPDATE gốc + INSERT bản sao → COMMIT → 201
→ [không]     rule auto-close (Phase 3)
→             INSERT alerts + INSERT jobs + INSERT audit_events
→ COMMIT → 201
```

**Vùng bị tuần tự hóa chỉ gồm một câu `SELECT` và một, hai câu ghi.** Mọi việc nặng (parse, phân loại, băm) đã xong trước khi vào khóa.

---

## Khóa cụm — 4 cột, không phải cột băm

### Vì sao không dùng `event_bucket_hash`

`event_bucket_hash` (Phase 1, chốt C1 — trước gọi là `fingerprint`) chứa bucket 5 phút. Dùng nó làm khóa cụm gây bốn hậu quả: đợt tấn công dài vỡ thành nhiều cụm, hiệu ứng biên ở mốc 5 phút, cửa sổ trượt mất tác dụng, và không phân biệt được đợt đã dừng hay chưa.

Dedup **không cần một cột băm** để tìm cụm — nó chỉ cần biết "alert nào đang mở, cùng rule, cùng nguồn, cùng đích, cùng agent". Bốn thứ đó **đã là cột riêng trong bảng**.

> **Cột giữ nguyên trong Phase 1**, chỉ đổi tên và vai trò: đối chiếu và audit, không phải khóa cụm.

### Định nghĩa cụm

> **Cụm = dòng có `duplicate_of IS NULL`.** Mỗi cụm có đúng một dòng gốc; mọi bản sao trỏ về nó.

Đây là định nghĩa duy nhất dùng cho mọi truy vấn đếm cụm. **Không** dùng `COUNT(DISTINCT event_bucket_hash)` — con số đó đếm theo ô 5 phút, cao gấp nhiều lần thực tế.

---

## Ba ranh giới cụm

Ô 5 phút trong bản C1 nguyên bản âm thầm làm **ba việc**. Đề xuất 1 chỉ thay việc thứ nhất, nên hai việc còn lại cần hằng số riêng — tường minh và chỉnh được độc lập:

```python
DEDUP_IDLE_GAP_MINUTES      = 15    # đợt tấn công im lặng bao lâu thì coi là đợt mới
MAX_CLUSTER_AGE_HOURS       = 4     # cụm thường sống tối đa bao lâu
MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES = 30   # cụm auto-closed sống tối đa bao lâu (B4)
MAX_CLUSTER_SIZE            = 1000  # một cụm chứa tối đa bao nhiêu alert
```

| Hằng số | Trả lời câu hỏi | Nếu thiếu thì sao |
|---|---|---|
| `DEDUP_IDLE_GAP_MINUTES` | Đợt tấn công đã dừng chưa? | Đợt mới sau 2 giờ vẫn gộp vào cụm cũ |
| `MAX_CLUSTER_AGE_HOURS` | Cụm sống quá lâu chưa? | Tấn công liên tục 6 giờ → 1 cụm không bao giờ đóng |
| `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES` | Cụm **nhiễu** sống quá lâu chưa? | Tắt rule mà alert vẫn bị nuốt tới 4 giờ |
| `MAX_CLUSTER_SIZE` | Cụm to quá chưa? | Cụm FIM không có `srcip` phình vô hạn |

**Vì sao cụm auto-closed cần trần ngắn hơn (B4):** cụm thường có analyst đang nhìn nên gộp lâu có ích; cụm auto-closed **không ai theo dõi**, nên giá trị của việc kéo dài bằng 0, trong khi cái giá là độ trễ khi analyst tắt một rule đóng nhầm.

---

## Thuật toán

### Bước 1 — Lấy khóa tư vấn

```sql
SET LOCAL statement_timeout = '3s';
SELECT pg_advisory_xact_lock(hashtext(
  $1 || '|' || coalesce($2,'') || '|' || coalesce($3,'') || '|' || $4
));   -- rule_id | srcip | dstip | agent_name
```

Ngay đầu transaction, **trước** mọi câu đọc. Khóa tự nhả khi transaction kết thúc, và chỉ chặn alert **cùng khóa cụm** — alert khác chạy song song bình thường.

> ⚠️ **Khóa phải tính trên khóa cụm, KHÔNG phải trên `event_bucket_hash`.** Nếu vẫn khóa theo cột băm, hai alert cùng cụm nhưng khác bucket 5 phút sẽ không bị tuần tự hóa → race condition quay lại nguyên vẹn. Đây là lỗi dễ sót nhất khi áp Đề xuất 1.

**Chuỗi khóa ráp trong SQL, không ráp trong Python** — để hai phiên bản ứng dụng chạy song song vẫn sinh cùng một khóa từ cùng bộ tham số.

**`statement_timeout` bắt buộc**, nhưng **không đủ**: nó chặn từng câu lệnh, không chặn tổng thời gian transaction. Xem mục *Ngân sách transaction* bên dưới.

### Bước 2 — Tra cụm đang mở

```sql
SELECT alert_id, occurrence_count, triaged_count, status
FROM alerts
WHERE rule_id     = $1
  AND srcip       = $2                                        -- B1 · = thuần
  AND agent_name  = $4
  AND dstip       = $3
  AND (closed_at IS NULL OR sealed_at IS NULL)                -- cụm còn hút
  AND status <> 'duplicate'
  AND last_seen_at >= now() - ($5 || ' minutes')::interval     -- IDLE_GAP
  AND first_seen_at >= now() - (CASE WHEN status = 'auto_closed'
                                THEN ($6 || ' minutes')::interval    -- MAX_AGE_AUTOCLOSED
                                ELSE ($7 || ' hours')::interval END) -- MAX_AGE
  AND occurrence_count < $8                                   -- MAX_SIZE
ORDER BY last_seen_at DESC
LIMIT 1
FOR UPDATE;
```

```sql
CREATE INDEX ON alerts (rule_id, srcip, agent_name, dstip, last_seen_at DESC)
  WHERE (closed_at IS NULL OR sealed_at IS NULL) AND status <> 'duplicate';
```

Từng điều kiện và lý do:

| Điều kiện | Lý do |
|---|---|
| 4 cột định danh, dùng `=` thuần | Khóa cụm. `srcip`/`dstip` là `NOT NULL DEFAULT ''` sau B1 nên không cần `IS NOT DISTINCT FROM` |
| `closed_at IS NULL OR sealed_at IS NULL` | **Cụm còn hút bản sao** — xem mục dưới |
| `status <> 'duplicate'` | Chặn chuỗi duplicate: bản sao không được làm gốc |
| `last_seen_at >= …` | **Cửa sổ trượt** — neo vào lần gộp gần nhất (đồng hồ DB) |
| `first_seen_at >= …` | Trần tuổi cụm — **hai giá trị**, cụm auto-closed ngắn hơn |
| `occurrence_count < …` | Trần kích thước cụm |
| `ORDER BY last_seen_at DESC` | Cụm còn sống gần đây nhất |
| `FOR UPDATE` | Khóa dòng gốc để `UPDATE` ở bước 3 không mất cập nhật |

#### Vì sao dùng `=` chứ không phải `IS NOT DISTINCT FROM` — B1

Bản trước dùng `IS NOT DISTINCT FROM` để xử lý `srcip`/`dstip` có thể là `NULL`. **Đo trên PostgreSQL 16.15, bảng 500.000 dòng:**

| Vị từ | Vào `Index Cond`? | Buffers | Sort? | Thời gian |
|---|---|---|---|---|
| `srcip IS NOT DISTINCT FROM $2` | **Không** — rơi xuống `Filter` | 154 | Có | 0,820 ms |
| `srcip = $2` (sau B1) | Có | **4** | Không | **0,030 ms** |

Gấp **38,5 lần** số buffer, trong đúng vùng advisory lock.

Chi tiết đáng nhớ: Postgres rút gọn `x IS NOT DISTINCT FROM NULL` thành `x IS NULL` — **có** dùng index. Nghĩa là toán tử đó chạy tốt ở ca `srcip` rỗng (ca hiếm) và tệ ở ca `srcip` có giá trị (ca chiếm gần hết lưu lượng). Nó trả giá ở đúng chỗ không cần.

Phase 1 chốt **B1**: `srcip`/`dstip` là `TEXT NOT NULL DEFAULT ''`. Truy vấn dùng `=`, và DB tự cưỡng chế bằng `NOT NULL` — không dựa vào việc người viết truy vấn nhớ gọi `coalesce()`.

**Vì sao neo vào `last_seen_at` chứ không phải `alert_time`:** đây là kỹ thuật *sessionization* — một phiên kết thúc khi im lặng đủ lâu, không phải khi hết giờ. Neo vào `alert_time` của alert gốc thì cụm hết hạn 15 phút sau alert **đầu tiên** bất kể đợt còn tiếp diễn, và brute-force 1 giờ vẫn ra 4 cụm.

**Khi chạm bất kỳ trần nào:** truy vấn không tìm thấy gốc → alert mới mở cụm mới. Không cần code xử lý riêng, không cần trạng thái mới.

> **Chi phí phải nói rõ:** `last_seen_at` nằm trong index và được `UPDATE` mỗi lần gộp → mất khả năng HOT update, index có churn.

#### Index tăng đơn điệu — hệ quả của M4 (P3)

Câu bảo vệ trước đây — *"partial index chỉ phủ cụm còn hút nên tập này nhỏ"* — **không còn đúng sau M4**, và cần nói thẳng:

| Loại dòng trong vị từ index | Rời index khi nào |
|---|---|
| `closed_at IS NULL` | Khi cụm bị đóng — **có rời** |
| `status = 'auto_closed'` | **Không bao giờ** — M3 đã chốt đây là trạng thái terminal |

Ba trần (`IDLE_GAP`, `MAX_AGE`, `MAX_SIZE`) chỉ quyết định cụm còn **hút** hay không. Chúng **không** đưa dòng ra khỏi index. Nghĩa là index tăng đơn điệu theo tổng số cụm auto-closed từng tồn tại — mà auto-close chính là cơ chế xử lý khối lượng lớn nhất trong hệ thống.

**Chi phí truy vấn không tăng nhiều:** index sắp theo `(…, last_seen_at DESC)` nên với mỗi khóa cụm, dòng gần đây nằm đầu, và điều kiện `last_seen_at >= now() - IDLE_GAP` cắt sớm.

**Chi phí bảo trì thì tăng thật:** kích thước index, thời gian `VACUUM`, thời gian dựng lại.

> **Chốt cho phạm vi đồ án:** chấp nhận, không thêm cột. Ở quy mô sản xuất cần **partition bảng `alerts` theo tháng** và drop partition cũ — khi đó index cũng bị cắt theo. Ghi rõ giới hạn này trong tài liệu triển khai thay vì để người đọc tự phát hiện.

#### Ngân sách transaction (P4)

`statement_timeout` chặn **từng câu lệnh**, **không** chặn tổng thời gian transaction. Sáu câu × 2,9 giây = 17 giây giữ khóa mà không câu nào bị cắt.

Ba lớp cần có đủ:

```
SET LOCAL statement_timeout = '3s'                  -- từng câu
idle_in_transaction_session_timeout = '10s'         -- ứng dụng treo giữa hai câu
TXN_BUDGET_MS = 5000                                -- tầng ứng dụng, đo từ BEGIN
```

Vượt `TXN_BUDGET_MS` → rollback, trả `503` + `Retry-After`. Không trả `201`, vì Wazuh cần biết alert chưa được nhận.

### "Cụm còn hút" — vì sao không phải "đã đóng"

Hai câu hỏi khác nhau, trước đây dùng chung một vị từ:

| Câu hỏi | Vị từ |
|---|---|
| Alert này đã kết thúc vòng đời chưa? | `closed_at IS NOT NULL` |
| **Cụm này còn hút bản sao không?** | `closed_at IS NULL OR sealed_at IS NULL` |

`sealed_at` là cột `timestamptz` nullable, mặc định `NULL`. Nó được đặt trong hai trường hợp:

| Khi nào | Ai đặt |
|---|---|
| Alert bị đóng bởi **người** (`closed_fp`, `closed_benign`, `closed_confirmed`) | `domain/` đặt cùng lúc với `closed_at` |
| Analyst **tắt một rule auto-close** | Sweeper của Phase 3 đặt cho mọi cụm do rule đó mở |

Alert `auto_closed` bình thường có `closed_at` đã đặt nhưng `sealed_at` vẫn `NULL` → **còn hút**.

Luật *"chỉ gộp vào alert đang mở"* ra đời vì **"kẻ tấn công quay lại sau khi ta đóng ca" là thông tin analyst cần biết** — lập luận đó nói về **quyết định của con người** (`closed_fp`, `closed_benign`, `closed_confirmed`). Không ai muốn biết máy quét lỗ hổng vừa chạy lại: auto-close là lọc nhiễu của máy, không phải phán quyết của người.

Hệ quả: một máy quét sinh 5.000 alert nhiễu ra **1 dòng `auto_closed` với `occurrence_count = 5000`**, thay vì 5.000 dòng. Ba trần cụm áp dụng bình thường cho cụm auto-closed.

**Bản sao vẫn bị loại:** dòng `duplicate` được đặt **cả** `closed_at` **và** `sealed_at` lúc `INSERT` → trượt cả hai nhánh. Điều kiện `status <> 'duplicate'` giữ nguyên làm lớp chặn thứ hai.

> **Vì sao dùng cột `sealed_at` chứ không phải một trạng thái mới như `auto_closed_sealed`:** thêm trạng thái sẽ làm hỏng **âm thầm** bốn truy vấn đo lường đang lọc `status = 'auto_closed'` — chúng sẽ bỏ sót các cụm đã bị niêm. Một cột riêng giữ `status` nguyên vẹn (M3 vừa chốt `auto_closed` là terminal) và tách đúng hai ý nghĩa: `status` là **vị trí trong quy trình**, `sealed_at` là **còn hút hay không**.

### Bước 3a — Có cụm đang mở

```sql
-- ① Alert mới: đánh dấu là bản sao, KHÔNG sinh job
INSERT INTO alerts (alert_id, ..., event_bucket_hash, status, duplicate_of, closed_at, sealed_at)
VALUES ($new_id, ..., $hash, 'duplicate', $parent_id, now(), now());

-- ② Alert gốc: tăng bộ đếm, đẩy mốc thời gian
UPDATE alerts
SET occurrence_count = occurrence_count + 1,
    last_seen_at     = now()          -- B2 · đồng hồ DB, KHÔNG phải alert_time
WHERE alert_id = $parent_id;

-- ③ Vết
INSERT INTO audit_events (event_type, subject_id, actor_role, payload)
VALUES ('alert.duplicate_merged', $new_id, 'system',
        jsonb_build_object('parent', $parent_id, 'occurrence', $n));
```

Rồi **`COMMIT` và dừng**. Không `INSERT jobs`. Không enrichment. Không gọi model.

**Ba chi tiết dễ sai:**

1. **Vẫn `INSERT` bản sao xuống bảng, không vứt đi.** `occurrence_count` cho biết *bao nhiêu*, nhưng bản sao giữ `raw_payload` riêng — hai lần brute-force cùng cụm vẫn có `full_log` khác nhau (số cổng nguồn, PID). Tier 2 cần dữ liệu này để dựng timeline.
2. **Đặt `closed_at` **và** `sealed_at` ngay khi tạo bản sao.** Thiếu `sealed_at` thì bản sao vẫn thoả nhánh thứ hai của vị từ và trở thành ứng viên gốc cho lần tra sau. Điều kiện `status <> 'duplicate'` là lớp chặn thứ hai; hai cột này là lớp thứ nhất và là cái làm partial index nhỏ lại.
3. **`last_seen_at = now()`, không dùng `alert_time` của SIEM (B2).** Đây là sửa lỗi, không phải tinh chỉnh — xem mục dưới.

#### `last_seen_at` phải dùng đồng hồ DB — B2

Bản trước ghi `GREATEST(last_seen_at, $new_alert_time)`, tức là đưa **`alert_time` của Wazuh** — đồng hồ **agent** — vào một cột rồi đem so với `now()` của **DB**. Hai đồng hồ khác nhau trong cùng một phép so sánh.

Điều này vi phạm ràng buộc **R7** của Phase 1 (*"mốc thời gian do DB sinh, Python chỉ đọc"*), vốn sinh ra vì container ứng dụng và container DB có thể lệch giờ. Ở bản C1 gốc thì vô hại vì `last_seen_at` chỉ để hiển thị; sau Đề xuất 1 nó **điều khiển vòng đời cụm**.

**Đo được (PostgreSQL 16.15):**

| Kịch bản | Kết quả |
|---|---|
| Agent **nhanh** 1 giờ | Cụm hết hạn **muộn đúng 1 giờ** |
| Agent **chậm** 1 giờ | Cụm **vừa lập đã ngoài cửa sổ** → mỗi alert một cụm, **dedup chết 100%** |
| Dùng `now()` của DB | Đúng trong mọi ca |

Ca agent chậm nguy hiểm nhất vì hệ thống **không báo lỗi gì** — chỉ là mọi `occurrence_count` đều bằng 1.

**Vì sao không cần cột `last_alert_time`:** rà lại mọi consumer của `last_seen_at` —

| Người dùng | Cần đồng hồ nào |
|---|---|
| Cửa sổ trượt `IDLE_GAP` | DB, vì so với `now()` |
| Hiển thị "đợt còn diễn ra không" | DB, vì so với hiện tại |
| Dựng timeline ở Tier 2 | `alert_time` **của từng alert con**, đã lưu riêng từng dòng |

Không ai cần `last_seen_at` mang giờ SIEM. Nếu Tier 2 cần mốc SIEM mới nhất của cụm thì tính `MAX(alert_time)` trên các alert con.

**Và `GREATEST` trở thành thừa:** `now()` luôn tăng, nên không có khả năng lùi về quá khứ để phải chặn. Ít code hơn bản trước.

### Bước 3b — Không có cụm đang mở

Alert đi tiếp sang **Phase 3 (auto-close)** trong cùng transaction.

---

## Danh sách tài khoản bị nhắm

Khóa cụm không chứa `alert_user`, nên một IP quét qua `user1`, `user2`, `user3` gộp thành **một cụm** — đúng, vì đó là **một chiến dịch**. Nhưng dòng đại diện chỉ hiện `user1`.

Bù lại ở tầng đọc, không đổi cách gộp:

```sql
SELECT DISTINCT alert_user
FROM alerts
WHERE (alert_id = $parent OR duplicate_of = $parent)
  AND alert_user IS NOT NULL;
```

Giao diện Tier 1 hiển thị dạng nhãn (`user1, user2, +3`); prompt ① nhận dạng danh sách. `duplicate_of` đã có index.

---

## Cờ `needs_retriage`

Alert được triage lúc `occurrence_count = 3`, sau đó cụm phình lên 500. Kết luận cũ không còn đúng nhưng không ai biết để xem lại.

Cột `triaged_count` ghi `occurrence_count` **tại thời điểm triage gần nhất**:

```
needs_retriage  ⟺  triaged_count > 0
                   AND ( occurrence_count >= triaged_count * RETRIAGE_FACTOR
                      OR occurrence_count -  triaged_count >= RETRIAGE_ABS_DELTA )
```

Với `RETRIAGE_FACTOR = 10` và `RETRIAGE_ABS_DELTA = 200` (config). **Thuộc tính suy ra**, tính lúc hiển thị, không lưu thành cột — lưu thì phải cập nhật, cập nhật thì có lúc quên.

Alert bật cờ hiện lên đầu hàng đợi Tier 1 với nhãn riêng, không phải một dòng mới.

**Vì sao cần nhánh tuyệt đối (P6):** chỉ có nhánh tỉ lệ thì cụm lớn rơi vào vùng chết. `occurrence_count < MAX_CLUSTER_SIZE = 1000`, nên với `triaged_count ≥ 100` ngưỡng tỉ lệ là `≥ 1000` — **không bao giờ đạt được**. Đúng những cụm cần theo dõi nhất lại không bao giờ bật cờ.

| `triaged_count` | Ngưỡng tỉ lệ (×10) | Ngưỡng tuyệt đối (+200) | Bật cờ ở |
|---|---|---|---|
| 3 | 30 | 203 | **30** |
| 20 | 200 | 220 | **200** |
| 150 | 1500 — *không đạt được* | 350 | **350** ✅ |

---

## Trạng thái gốc và các ca biên

> **Chốt:** chỉ gộp vào cụm **còn hút** — đang mở, **hoặc** đã `auto_closed`.

Gốc đã `closed_fp` / `closed_benign` / `closed_confirmed` (người quyết) thì bản sao mở cụm mới: "kẻ tấn công quay lại sau khi ta đóng ca" là thông tin analyst **cần biết**.

Gốc `auto_closed` (máy lọc nhiễu) thì bản sao **gộp vào** — không ai cần biết máy quét chạy lại lần thứ 5.000. Đây cũng là điều kiện để mẫu đối chứng của Phase 3 lấy **một mẫu trên một cụm**, không phải 5% của 5.000 alert.

**Gốc đang ở Tier 2** (`status = 'escalated_tier2'`): vẫn `closed_at IS NULL` → bản sao **gộp vào**. `occurrence_count` của một case đang điều tra tiếp tục nhảy số. Đúng về dữ liệu (đợt tấn công vẫn diễn ra), nhưng giao diện Tier 2 phải hiển thị được rằng con số đang thay đổi.

**Cụm không có `srcip`** (rule FIM, rootcheck, syscollector): sau B1 các alert này mang `srcip = ''`, nên chúng gộp với nhau bình thường qua `srcip = ''`. Cụm có thể to — `MAX_CLUSTER_SIZE` chặn, không cần luật riêng.

---

## Ví dụ trên mẫu thật

Alert gốc A1 từ Phase 1: `rule_id=40112`, `srcip=127.0.0.1`, `dstip=NULL`, `agent_name=user1-IA1803`, `alert_time=17:56:56 UTC`.

| Alert | Thời điểm (UTC) | Khác biệt so với A1 | Kết quả |
|---|---|---|---|
| **A1** | 17:56:56 | — (gốc) | `received`, `occurrence_count=1` |
| **A2** | 17:58:30 | chỉ khác thời gian | `duplicate` → gốc lên `2` |
| **A3** | 18:01:10 | chỉ khác thời gian | **`duplicate`** → gốc lên `3` ✅ *(bản C1 cũ: tách cụm)* |
| **A4** | 17:57:40 | `dstuser = user2` | `duplicate` — `alert_user` không nằm trong khóa cụm |
| **A5** | 17:57:40 | `srcip = 10.0.0.5` | Cụm mới — khác khóa |
| **A6** | 18:25:00 | im lặng 24 phút | Cụm mới — vượt `IDLE_GAP` 15 phút |
| **A7** | 18:40:00 | tấn công liên tục, alert thứ 1001 | Cụm mới — chạm `MAX_CLUSTER_SIZE` |
| **A8** | 21:57:00 | tấn công **thưa**, mỗi 10 phút | Cụm mới — vượt `MAX_CLUSTER_AGE_HOURS` 4 giờ |

**A3 là ca minh họa rõ nhất giá trị của Đề xuất 1:** cách A1 đúng 4 phút 14 giây, cùng một đợt tấn công. Bản C1 nguyên bản tách nó thành cụm mới vì rơi sang ô 5 phút khác; bản này gộp đúng.

**A6 chứng minh cửa sổ trượt đã lấy lại ý nghĩa:** đợt thứ hai sau 24 phút im lặng tách cụm — đúng theo luật, không phải tình cờ.

**A7 và A8 là hai trần khác nhau, không thay thế nhau.** Tấn công **dày** chạm `MAX_CLUSTER_SIZE` trước — 1000 alert đến rất nhanh, cụm vỡ trong vài phút. Tấn công **thưa** (mỗi 10 phút một alert, không đủ 15 phút để `IDLE_GAP` cắt) thì `MAX_CLUSTER_AGE_HOURS` mới là trần chạm. Một hệ thống chỉ có `MAX_AGE` sẽ để cụm dày phình vô hạn; chỉ có `MAX_SIZE` sẽ để cụm thưa sống nhiều ngày.

---

## Xử lý lỗi

| Tình huống | Hành động |
|---|---|
| `statement_timeout` khi chờ advisory lock | Rollback, trả `503` + `Retry-After`. **Không** trả `201` |
| `SELECT` cụm thất bại | Rollback toàn bộ; alert không nằm nửa vời trong DB |
| `UPDATE` gốc thất bại sau `INSERT` bản sao | Cùng transaction → rollback cả hai |
| Gốc bị đóng bởi transaction khác giữa `SELECT` và `UPDATE` | Không xảy ra — `FOR UPDATE` đã khóa dòng |
| Hai phiên bản ứng dụng chạy song song lúc deploy | Xem mục dưới |

### Cửa sổ deploy

Khóa advisory đổi từ `hashtext(event_bucket_hash)` sang `hashtext(cluster_key)`. Rolling update với hai phiên bản chạy song song sẽ khóa trên hai không gian khác nhau → **không chặn nhau**.

**Giải pháp:** dừng hẳn rồi khởi động lại, không rolling update.

**Mức độ nghiêm trọng thật:** kể cả khi race xảy ra, hậu quả là **2 cụm thay vì 1** — dữ liệu suy giảm, không hỏng. Không alert nào mất, không bộ đếm nào sai.

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng bằng |
|---|---|---|
| D1 | Bản sao **không bao giờ** sinh job | Gửi 10 bản sao → đúng 1 dòng `jobs` |
| D2 | Bản sao **không bao giờ** làm gốc | `duplicate_of` mọi dòng trỏ tới alert có `status <> 'duplicate'` |
| D3 | `occurrence_count` của gốc = số alert trỏ về + 1 | Đối chiếu `COUNT(*)` với cột |
| D4 | Advisory lock lấy **trước** mọi câu đọc, và tính trên **khóa cụm** | Review code |
| D5 | Vùng khóa không chứa I/O ngoài DB | Review code |
| D6 | `last_seen_at` không bao giờ lùi về quá khứ | Gửi alert cũ hơn sau alert mới |
| D7 | Vị từ truy vấn khớp **cú pháp** với vị từ partial index | `EXPLAIN` xác nhận index được dùng |

> **D7 · đọc `EXPLAIN` cho đúng.** Truy vấn dedup dùng `FOR UPDATE`, và rowmark do `FOR UPDATE` tạo ra làm PostgreSQL **luôn** lặp lại vị từ partial ở dòng `Filter` — kể cả khi index partial đã được dùng đúng. Thấy vị từ ở `Filter` **không** phải dấu hiệu index không khớp; dấu hiệu cần nhìn là tên index ở `Index Scan`.
| D8 | Không truy vấn nào đếm cụm bằng `event_bucket_hash` | Quét mã nguồn tìm `DISTINCT event_bucket_hash` |
| D11 | Không truy vấn đo lường nào đếm alert đã gộp bằng `status = 'duplicate'` | Quét mã nguồn tìm `status = 'duplicate'` trong thư mục truy vấn đo lường |
| D9 | `last_seen_at` luôn lấy từ `now()` của DB, không từ `alert_time` | Review code — cấm truyền tham số thời gian vào `UPDATE` |
| D10 | `srcip`/`dstip` không bao giờ `NULL` | Ràng buộc `NOT NULL` |

---

## Test bắt buộc

Nhóm này **cần DB thật**:

```
# Gộp cơ bản
test_hai_alert_cach_2_phut_thi_gop
test_alert_cach_4_phut_qua_moc_5_phut_van_gop    # A3 · Đề xuất 1
test_khac_srcip_thi_khong_gop                    # A5
test_khac_user_van_gop                           # A4 · có chủ đích
test_alert_srcip_rong_van_gop_duoc_voi_nhau      # B1 · srcip = ''

# B1 · hiệu năng
test_explain_ca_bon_cot_vao_index_cond           # KHÔNG có cột nào rơi xuống Filter
test_explain_khong_co_node_sort
test_srcip_khong_bao_gio_null                    # D10

# B2 · đồng hồ
test_last_seen_at_luon_bang_now_cua_db           # D9
test_agent_lech_gio_nhanh_khong_keo_dai_cum
test_agent_lech_gio_cham_van_dedup_binh_thuong   # ca dedup chết ở bản cũ

# Ba ranh giới
test_tan_cong_lien_tuc_1_gio_ra_1_cum
test_im_lang_20_phut_roi_tan_cong_lai_ra_2_cum   # A6 · IDLE_GAP
test_cum_cham_tran_4_gio_thi_mo_cum_moi          # A7 · MAX_AGE
test_cum_auto_closed_cham_tran_30_phut           # B4 · trần riêng
test_cum_bi_niem_sealed_at_thi_ngung_hut         # B4 · sweeper
test_cum_cham_1000_alert_thi_mo_cum_moi          # MAX_SIZE
test_cum_khong_co_srcip_van_bi_tran_chan
test_last_seen_at_duoc_day_moi_lan_gop

# Trạng thái gốc
test_goc_closed_fp_thi_khong_gop_mo_cum_moi
test_goc_auto_closed_THI_GOP                     # D‑C6 · đảo so với bản trước
test_goc_closed_confirmed_thi_khong_gop
test_goc_escalated_tier2_van_gop
test_5000_alert_nhieu_ra_1_dong_occurrence_5000
test_ban_sao_khong_the_lam_goc                   # D2

# Không sinh job
test_ban_sao_khong_sinh_job                      # D1
test_10_ban_sao_chi_1_job

# Đồng thời
test_10_luong_song_song_cung_payload             # đúng 1 gốc, 9 duplicate
test_advisory_lock_tinh_tren_cluster_key         # D4 · KHÔNG phải cột băm
test_hai_alert_khac_bucket_cung_cum_van_bi_khoa  # bẫy của Đề xuất 1
test_statement_timeout_tra_503_khong_tra_201

# Toàn vẹn
test_last_seen_at_khong_lui_ve_qua_khu           # D6
test_occurrence_count_khop_so_ban_sao            # D3
test_update_goc_that_bai_thi_rollback_ca_hai
test_ban_sao_van_giu_raw_payload_rieng

# Đếm cụm
test_dem_cum_theo_duplicate_of_null              # D8
test_khong_truy_van_nao_dung_distinct_event_bucket_hash

# needs_retriage
test_cum_phinh_10_lan_thi_bat_co
test_cum_phinh_4_lan_thi_chua_bat_co
test_chua_triage_thi_khong_bat_co

# Tài khoản bị nhắm
test_truy_van_tra_du_danh_sach_user_trong_cum

# Index
test_explain_dung_partial_index                  # D7
```

---

## Quyết định đã chốt

| # | Vấn đề | Quyết định |
|---|---|---|
| **D‑C1** | Khóa cụm là gì | **4 cột trực tiếp** (`rule_id`, `srcip`, `dstip`, `agent_name`), không phải `fingerprint` |
| **D‑C2** | Cửa sổ neo vào đâu | **`last_seen_at`** (cửa sổ trượt), `IDLE_GAP = 15 phút` |
| **D‑C3** | Trần cụm | `MAX_CLUSTER_AGE_HOURS = 4 giờ` + `MAX_CLUSTER_SIZE = 1000` |
| **D‑C4** | Định nghĩa cụm cho đo lường | `duplicate_of IS NULL` |
| **D‑C5** | Gốc đang ở Tier 2 | **Vẫn gộp**; giao diện phải hiện bộ đếm đang thay đổi |
| **D‑C6** | Vị từ "cụm còn hút" | **`closed_at IS NULL OR sealed_at IS NULL`** — khớp cú pháp ở cả truy vấn lẫn index |
| **D‑C7** | Deploy | Restart thẳng, không rolling |
| **B1** | So sánh IP trong khóa cụm | **`=` thuần** trên cột `NOT NULL DEFAULT ''` — đo: 154 → 4 buffer |
| **B2** | Nguồn của `last_seen_at` | **`now()` của DB**, bỏ `GREATEST` — đo: đồng hồ SIEM làm dedup chết |
| **B4** | Trần tuổi cụm auto-closed | **30 phút** + cột `sealed_at` cho sweeper |

### Việc còn lại

1. **Mọi trạng thái kết thúc bắt buộc set `closed_at`** — `auto_closed`, `duplicate`, `closed_fp`, `closed_benign`, `closed_confirmed`. Nên thêm `CHECK` hoặc trigger để DB tự chặn. `auto_closed` vẫn set `closed_at` dù còn hút bản sao — `sealed_at` mới là cột quyết định việc hút.
2. **Thêm cột `sealed_at timestamptz`** (nullable) và **đổi tên `fingerprint` → `event_bucket_hash`**. Đây là hai thay đổi schema duy nhất của đợt này.
2. **Bỏ index cũ theo cột băm** nếu đã tạo — không còn truy vấn nào dùng.
3. **`RETRIAGE_FACTOR = 10` chưa được kiểm chứng** — đo sau vài tuần: bao nhiêu alert bật cờ, bao nhiêu thực sự đổi kết luận khi triage lại.
4. **Ba hằng số ranh giới cũng chưa kiểm chứng** — `15 phút / 4 giờ / 1000` là điểm khởi đầu hợp lý, cần đo phân bố kích thước cụm thật để chỉnh.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `domain/alert.py` | Kiểu `Alert` từ Phase 1 | `ingest/` → `domain/` ✅ |
| `domain/transitions.py` | Chuyển `received` → `duplicate` kèm audit | `ingest/` → `domain/` ✅ |
| `infra/db.py` | Connection, transaction, advisory lock | `ingest/` → `infra/` ✅ |
| `infra/config.py` | `DEDUP_IDLE_GAP_MINUTES`, `MAX_CLUSTER_AGE_HOURS`, `MAX_CLUSTER_SIZE`, `RETRIAGE_FACTOR` | `ingest/` → `infra/` ✅ |
| `audit/` | Ghi `alert.duplicate_merged` | `ingest/` → `audit/` ✅ |

Phase này **không** import `soar/`, `tier1/`, `tier2/`, `llm/`, `kb/`, `enrichment/`.

---

*Đặc tả Phase 2 · Chống trùng lặp · AI Support SOC · đã áp Đề xuất 1 · không migration, không đổi schema*
