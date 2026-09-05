# Phase 4 — Làm giàu ngữ cảnh và tương quan

`soar/` · `enrichment/` · `domain/correlation.py` · `infra/worker.py`

> **Vị trí:** chặng đầu tiên chạy ở **worker**, sau khi webhook đã trả `201`.
> **Vào:** job `enrich` · **Ra:** `status = queued_tier1` + `risk_score` + ngữ cảnh.

---

## Mục tiêu

Bổ sung cho alert những thứ Wazuh không biết: **máy này của ai, quan trọng đến đâu; tài khoản này có đặc quyền không; địa chỉ này đã bị bêu tên chưa**. Rồi quy tất cả thành một con số để xếp thứ tự hàng đợi.

Ba mục tiêu con:

1. **Tất định.** Ba tra cứu nội bộ **luôn chạy đủ**, không phụ thuộc LLM có muốn gọi hay không — nếu để model tự chọn tool thì hai lần chạy trên cùng một alert cho hai ngữ cảnh khác nhau, và phép đo độ khớp mất ý nghĩa (ràng buộc V1).

   > `V1` ràng buộc **pipeline ①**, nơi phép đo độ khớp diễn ra. Pipeline ② (Tier 2) **được** gọi tool đọc trên chính ba bảng này — `lookup_ioc` · `lookup_asset` · `lookup_identity` — xem **P7‑8**. Phase 4 vẫn chạy đủ ba tra cứu cho mọi alert như cũ; tool của ② là đường đọc **thêm**, không thay thế.
2. **Không chặn.** Mọi nguồn ngoài đều có thể hỏng. Hỏng thì bỏ qua, ghi audit, đi tiếp — **thiếu ngữ cảnh không được chặn triage**.
3. **Bó gọn đầu ra.** Ngữ cảnh và tương quan là đầu vào prompt, nên chúng phải có trần — xem P4‑2.

---

## Ranh giới

| Làm | Không làm |
|---|---|
| Gọi n8n lấy asset · identity · IoC | Quyết định alert có phải nhiễu không (Phase 3 đã xong) |
| 3 tra cứu tất định trên DB nội bộ | Gọi model |
| Chấm `risk_score` | Ghi `case_alerts` (Tier 1 mới cố định hóa) |
| Tính **tóm tắt tương quan** | Đổi `triage_status` (Phase 5) |
| Đẩy `status = queued_tier1` | Xếp lịch retry của chính nó (việc của `infra/`) |

**Tính chất:** chạy nền · ngoài transaction webhook · **ngoài advisory lock** · có gọi mạng.

---

## Vòng lặp worker

```sql
-- infra/worker.py · nhiều worker chạy song song an toàn, không cần Redis
SELECT job_id, job_type, subject_id
FROM jobs
WHERE status = 'pending' AND scheduled_at <= now()
ORDER BY scheduled_at
FOR UPDATE SKIP LOCKED
LIMIT 1;

UPDATE jobs SET status='running', locked_at=now(), attempts=attempts+1
WHERE job_id = $1;
```

`SKIP LOCKED` là lý do không cần Redis: Postgres tự lo phần khóa hàng đợi.

### Chính sách retry — P4‑7

Tài liệu gốc có cột `attempts` và `last_error` nhưng **không nói khi nào retry, giãn bao lâu, bỏ cuộc lúc nào**. Chốt:

```python
JOB_MAX_ATTEMPTS   = 3
JOB_BACKOFF        = [10, 60, 300]      # giây, theo lần thất bại
JOB_LOCK_TIMEOUT_S = 300                # worker chết → job được nhặt lại
```

| Tình huống | Xử lý |
|---|---|
| Lỗi tạm (timeout, `5xx`, mạng) | `status='pending'`, `scheduled_at = now() + backoff[attempts]` |
| Lỗi vĩnh viễn (`4xx`, payload sai) | `status='failed'` ngay, không retry |
| Hết `JOB_MAX_ATTEMPTS` | `status='failed'` + audit `job.exhausted` |
| Worker chết giữa chừng | `locked_at < now() - JOB_LOCK_TIMEOUT_S` → nhặt lại |

> **Job `enrich` thất bại KHÔNG được giữ alert lại.** Hết retry thì vẫn đẩy `status = queued_tier1` với ngữ cảnh rỗng. Alert thiếu ngữ cảnh vẫn tốt hơn alert không ai thấy. Đây là hệ quả trực tiếp của mục tiêu 2.

---

## Hai nửa enrichment

| Nửa | Package | Nguồn | Chi phí | Hỏng thì |
|---|---|---|---|---|
| **Trong** | `enrichment/` | `assets` · `identities` · `iocs` | 3 SELECT có index | Hầu như không hỏng; hỏng = lỗi DB, job retry |
| **Ngoài** | `soar/` → n8n | CMDB · AD · VirusTotal · MISP | Hạn ngạch API, mạng | Bỏ qua, ghi `skipped`, đi tiếp |

```sql
SELECT * FROM assets     WHERE hostname = $agent_name;
SELECT * FROM identities WHERE username = $alert_user;
SELECT * FROM iocs       WHERE value IN ($srcip, $dstip) AND expires_at > now();
```

Ba câu này **luôn chạy đủ**. Nối theo **giá trị**, không phải khóa ngoại — alert trỏ tới host chưa có trong `assets` vẫn hợp lệ, chỉ là thiếu ngữ cảnh.

### Ba trạng thái kết quả — không phải hai

```
found      → đã tra, có kết quả
not_found  → đã tra, không có kết quả    ← tín hiệu an ninh
skipped    → KHÔNG tra                   ← KHÔNG phải tín hiệu an ninh
```

`skipped` xảy ra khi: IP nội bộ (C4), n8n hỏng, hết hạn ngạch, hoặc alert không có trường để tra (`alert_user IS NULL`).

> **`alert_user` chỉ nhận `NULL`, không bao giờ `''`** — cưỡng chế bằng
> `ck_alerts_alert_user_khong_rong` (migration 006). Bản trước của dòng này viết `alert_user = ''`,
> lệch với `phase-1:63` vốn đặt mặc định là `NULL`. Hệ quả nếu để lệch: `phase-2:299` lọc
> `alert_user IS NOT NULL`, nên một chuỗi rỗng lọt qua sẽ hiện trong `SELECT DISTINCT alert_user`
> như một *"tài khoản bị nhắm"* — sai kiểu im lặng. `CHECK` biến nó thành sai-thì-nổ.
> (`NULL <> ''` trả `NULL` nên `CHECK` vẫn cho `NULL` qua: nó chặn đúng một ca, chuỗi rỗng.)

**Hai luật cứng:** `risk_score` **không trừ điểm** cho `skipped`; prompt ghi *"chưa tra cứu"*, không ghi *"không tìm thấy"*.

### Hợp đồng với n8n — P4‑4

Tài liệu gốc để ngỏ ("cần chốt tiếp: hợp đồng API giữa app và n8n · hành vi khi n8n timeout"). Chốt:

```
POST  {N8N_BASE}/webhook/enrich
Body  { alert_id, agent_name, alert_user, srcip, dstip, category }
200   { asset: {...}|null, identity: {...}|null, iocs: [...],
        partial: ["virustotal"],        # nguồn nào không tra được
        took_ms: 812 }
```

| Hằng số | Giá trị |
|---|---|
| `N8N_TIMEOUT_S` | 10 |
| `N8N_RETRY` | 0 — **không retry ở tầng này**, job retry lo phần đó |
| `N8N_CIRCUIT_FAIL_THRESHOLD` | 5 lỗi liên tiếp → mở mạch 60 giây |

**Vì sao không retry trong lời gọi:** retry lồng trong retry nhân thời gian chờ lên bội số và giữ worker vô ích. Một tầng retry duy nhất, ở hàng đợi job.

**Mạch ngắt** để n8n chết không kéo mọi worker vào chờ 10 giây mỗi alert. Mạch mở thì mọi lookup ngoài là `skipped`, alert vẫn đi tiếp.

---

## `risk_score` — P4‑3

Tài liệu gốc chỉ ghi `UPDATE alerts SET risk_score=$3`, **không có công thức**. Chốt một công thức cộng điểm, có trần, và **tất định**:

### Bản đầu tiên và ba lỗi đo được

Bản nháp dùng `RISK_BASE = {critical: 40, high: 25, medium: 10, low: 0}` rồi cộng thẳng bốn khoản thưởng không giới hạn. **Chạy thử trên chính điều kiện phòng lab** (bảng `assets`/`identities` chỉ seed 10–20 host, phần lớn alert không khớp) cho ba kết quả sai:

| # | Triệu chứng | Số đo |
|---|---|---|
| 1 | **Mẫu thật trông không khẩn cấp** | Brute-force **thành công** từ localhost, `severity=critical` → `risk_score = 40/100` |
| 2 | **Nghịch đảo không giới hạn** | `low` + crown_jewel + privileged + malicious = **80** > `critical` trần trụi = **40** |
| 3 | **Nửa thang điểm chết** | Khi enrichment thưa, mọi giá trị rơi vào `0–50` → **50% thang không bao giờ đạt tới** |

Lỗi 1 và 3 là cùng một gốc: thang 0–100 nhưng phần thực sự dùng bị nén xuống nửa dưới, nên con số hiển thị **nói dối** về mức khẩn cấp.

Lỗi 2 tinh tế hơn. Ngữ cảnh **nên** ảnh hưởng tới thứ tự — M5 đã lập luận đúng điều đó. Nhưng ảnh hưởng **không có trần** thì severity của SIEM trở nên gần như vô nghĩa: một alert `low` với đủ ngữ cảnh vượt qua **hai bậc**.

### Ba phương án

| | Cách | Kết quả đo |
|---|---|---|
| (a) | Giãn `RISK_BASE` lên `60/40/20/5`, giữ nguyên cấu trúc | Mẫu thật lên `60`; nghịch đảo **vẫn còn** (`low` đủ ngữ cảnh = 85 > 60) |
| **(b)** | **Severity trội + trần ngữ cảnh** `CONTEXT_CAP` | Mẫu thật `70`; nghịch đảo bị **giới hạn còn một bậc** |
| (c) | Chuẩn hóa theo phân vị hàng đợi hiện tại | Không tất định giữa hai lần chạy — phá V1 |

**Loại (c) trước:** điểm phụ thuộc tập alert đang có trong hàng đợi thì hai lần chạy trên cùng một alert cho hai kết quả — vi phạm ràng buộc tất định, và phá luôn khả năng so sánh trong báo cáo.

**Loại (a):** nó chỉ chữa lỗi 1 và 3, để nguyên lỗi 2.

### Công thức chốt — phương án (b)

```python
RISK_BASE   = {"critical": 70, "high": 50, "medium": 28, "low": 10}
CONTEXT_CAP = 25          # trần TỔNG cho mọi khoản thưởng ngữ cảnh

context  = {"crown_jewel": 30, "high": 20, "normal": 5, "low": 0}.get(asset.criticality, 0)
context += 15 if identity.is_privileged else 0
context += {"malicious": 25, "suspicious": 10, "clean": 0}.get(ioc.reputation, 0)
context += 10 if occurrence_count >= 100 else (5 if occurrence_count >= 10 else 0)

risk_score = min(100, RISK_BASE[alert.severity] + min(CONTEXT_CAP, context))
```

**Ngữ nghĩa một câu:** *severity quyết định, ngữ cảnh điều chỉnh — tối đa một bậc.*

| Ca | Điểm | Nhận xét |
|---|---|---|
| `critical` trần trụi (**mẫu thật**) | **70** | Nằm ở nửa trên thang — nhìn đúng mức |
| `critical` + crown_jewel + malicious | 95 | Cao nhất thực tế |
| `high` + đủ ngữ cảnh | 75 | Vượt `critical` trần trụi — **có chủ đích**, đúng một bậc |
| `medium` + đủ ngữ cảnh | 53 | Vượt `high` trần trụi (50) — một bậc |
| `low` + đủ ngữ cảnh | 35 | Vượt `medium` trần trụi (28) — một bậc, **không** với tới `high` |
| `low` trần trụi | 10 | Không còn bằng `0` |

Phần thang dùng được khi enrichment thưa: **10–80 (70%)**, so với 0–50 (50%) của bản nháp.

**Bốn ràng buộc giữ nguyên từ bản nháp:**

1. **Chỉ cộng, không trừ** — `skipped` và `not_found` cùng đóng góp `0`, không cần luật riêng.
2. **Tất định** — không `random`, không hỏi model.
3. **Trần 100**.
4. **Là gợi ý sắp xếp, không phải phán quyết** — không tự đóng hay tự escalate alert nào.

**Ràng buộc mới thứ năm — không hiển thị số trần:** giao diện và prompt hiển thị **dải** kèm severity gốc, không phải con số 0–100 trần trụi.

| Dải | Nhãn |
|---|---|
| 0–24 | Thấp |
| 25–49 | Vừa |
| 50–74 | Cao |
| 75–100 | Rất cao |

Lý do: `risk_score` được thiết kế cho **thứ tự**, không phải cho **mức tuyệt đối**. Một con số như "70" mời gọi người đọc diễn giải nó như phần trăm rủi ro — thứ nó không phải. Dải kèm severity gốc nói đúng thứ nó biết.

> **Phản biện phương án đã chọn.** `CONTEXT_CAP = 25` **không** loại bỏ nghịch đảo, nó chỉ **giới hạn** nghịch đảo còn đúng một bậc: `high` + đủ ngữ cảnh (75) vẫn vượt `critical` trần trụi (70). Đây là hành vi cố ý — một alert `high` trên crown jewel với IoC độc hại **nên** xếp trên một alert `critical` chưa rõ ngữ cảnh. Nhưng phải nói rõ là *cố ý*, vì nếu không, người đọc báo cáo gặp ca đó sẽ tưởng là bug.
>
> Điểm yếu thứ hai: cả `RISK_BASE` lẫn `CONTEXT_CAP` **chưa được kiểm chứng bằng dữ liệu thật**. Chúng được chọn để đạt ba tính chất kiểm được (mẫu thật nằm nửa trên · nghịch đảo tối đa một bậc · dùng ≥70% thang), chứ không phải từ hiệu chỉnh trên quyết định của analyst. Việc hiệu chỉnh chỉ làm được sau vài tuần chạy.
>
> Điểm yếu thứ ba: công thức **không có thành phần `category`**. Một `ransomware` mức `medium` đáng lo hơn một `recon` mức `medium`. Cố ý bỏ qua để không thêm một bảng trọng số nữa cũng chưa có căn cứ — thà thiếu một yếu tố còn hơn nhân đôi số tham số đoán mò. Ghi vào việc còn lại.
>
> **Bằng chứng cho phép đổi trọng số an toàn:** rà cả bảy đặc tả và hai tài liệu kiến trúc, **không có một ngưỡng nào đặt trên `risk_score`** — không `>= 80`, không "tự escalate nếu vượt". Nó chỉ dùng để `ORDER BY` và để đưa vào prompt. Nên đổi trọng số không làm gãy hành vi nào ở hạ nguồn.

---

## Tương quan — ba vấn đề, ba chốt

### P4‑1 · Correlation thuộc package nào

Tài liệu gốc mâu thuẫn: mục 05 đặt correlation ở `soar/`, mục 02–03 nói đã chuyển sang `domain/`.

> **Chốt: `domain/correlation.py`.** Có **ba** nơi dùng — Phase 5 (dựng prompt ①), Tier 1 (hiển thị lúc mở alert), Tier 2 (gom case). Để ở `soar/` thì `tier1/` và `tier2/` phải import chéo, vi phạm luật tầng. **Mục 05 cần sửa.**

### P4‑2 · Kết quả tương quan không có trần — vấn đề nghiêm trọng nhất của phase này

Truy vấn gốc không có `LIMIT`, và kết quả đi thẳng vào prompt.

**Đo trên PostgreSQL 16.15** — một agent bận với 3.000 alert trong 4 giờ:

| Cách | Số dòng | Ước token | Thời gian truy vấn |
|---|---|---|---|
| Danh sách thô (như tài liệu gốc) | **1.792** | **~44.800** | 0,68 ms |
| **Tóm tắt gộp** theo `rule_id` × `status` | **6** | **~210** | 3,47 ms |

**Giảm 213 lần.** Truy vấn chậm hơn 5 lần nhưng đó là 2,8 mili giây — không đáng kể so với việc tiết kiệm 44.000 token mỗi alert.

Ba phương án đã cân nhắc:

| | Cách | Nhược điểm |
|---|---|---|
| (a) | Thêm `LIMIT 50` vào danh sách thô | Cắt tùy tiện — 50 dòng đầu không đại diện cho 1.792 dòng |
| (b) | Chỉ lấy dòng gốc (`duplicate_of IS NULL`) | Vẫn không có trần; agent bận vẫn ra hàng trăm cụm |
| **(c)** | **Tóm tắt gộp + top‑N đại diện** | Mất chi tiết từng dòng — nhưng prompt không cần chi tiết đó |

> **Chốt (c).** Prompt nhận **tóm tắt gộp**, không nhận danh sách thô.

```sql
-- domain/correlation.py · summarize_for_prompt()
SELECT rule_id, category, status,
       count(*)              AS so_cum,
       sum(occurrence_count) AS so_alert,
       min(alert_time)       AS tu,
       max(alert_time)       AS den,
       count(DISTINCT srcip) AS so_ip_nguon
FROM alerts
WHERE (agent_name = $1 OR alert_user = $2 OR srcip = ANY($3))
  AND alert_time BETWEEN $t - interval '2 hours' AND $t + interval '2 hours'
  AND duplicate_of IS NULL
  AND status <> 'duplicate'
  AND alert_id <> $self
GROUP BY rule_id, category, status
ORDER BY so_alert DESC
LIMIT 20;
```

Kèm **tối đa 5 alert đại diện** (mới nhất, `occurrence_count` cao nhất) để model có ví dụ cụ thể.

**Index bắt buộc** — thiếu thì truy vấn thành quét toàn bảng:

```sql
CREATE INDEX ON alerts (agent_name, alert_time);
CREATE INDEX ON alerts (alert_user, alert_time);
CREATE INDEX ON alerts (srcip,      alert_time);
```

Đo được: với ba index này Postgres dựng **BitmapOr** trên cả ba nhánh — `OR` nhiều cột **không** phải vấn đề như thường lo, miễn là mỗi cột có index riêng.

### P4‑3 · Cửa sổ `±2h` và đồng hồ SIEM

Hai điểm cần nói thẳng, cả hai là **giới hạn được chấp nhận**, không phải lỗi cần sửa:

**Nhánh `+2h` gần như rỗng ở Phase 4.** Alert tương lai chưa tồn tại lúc enrichment chạy. Nên cụm mà ① thấy **luôn nhỏ hơn hoặc bằng** cụm mà analyst thấy khi mở alert. Đây là điều đã ghi nhận là *trung thực chứ không phải lỗi*, và là lý do có cờ `needs_retriage`.

**Correlation dùng `alert_time` — đồng hồ SIEM.** Sau B2 ta đã biết đồng hồ agent trôi được. Nhưng khác với cửa sổ dedup, correlation hỏi *"những sự việc nào xảy ra gần nhau"* — đó là **ngữ nghĩa thời điểm sự kiện**, nên `alert_time` là cột đúng. Dùng `received_at` sẽ gom sai khi có lô alert tới trễ.

> Hệ quả: agent lệch giờ nặng sẽ **không** tương quan được với agent khác. Cần một cảnh báo vận hành khi `|alert_time − received_at|` vượt ngưỡng, chứ không sửa bằng cách đổi cột.

```python
CLOCK_SKEW_WARN_SECONDS = 300
```

---

## Trình tự ghi

```sql
UPDATE alerts SET status = 'enriching' WHERE alert_id = $1;   -- ①

-- ② 3 tra cứu nội bộ + 1 lời gọi n8n (song song được)
-- ③ tính risk_score, tóm tắt tương quan (chỉ trong bộ nhớ job)

UPDATE alerts
SET asset_context = $2, identity_context = $3, ioc_context = $4,
    lookup_status = $5,          -- jsonb: {"asset":"found","ioc":"skipped",...}
    risk_score    = $6,
    status        = 'queued_tier1'
WHERE alert_id = $1;                                          -- ④

INSERT INTO jobs (job_type, subject_id, status)
VALUES ('triage', $1, 'pending');                             -- ⑤ Phase 5

INSERT INTO audit_events (event_type, subject_id, actor_role, payload)
VALUES ('alert.enriched', $1, 'system', $7);                  -- ⑥
```

**Chuỗi tương quan KHÔNG được ghi xuống ở bước này** — nó chỉ sống trong bộ nhớ job và đi vào prompt. Lưu thì phải cập nhật; cập nhật thì có lúc quên.

> **Bước ④ và ⑤ trong cùng một transaction.** Nếu tách, worker chết giữa hai bước sẽ để alert ở `queued_tier1` mà không bao giờ có job triage — alert vào hàng đợi nhưng vĩnh viễn không có gợi ý, và không ai biết.

---

## Xử lý lỗi

| Tình huống | Hành động |
|---|---|
| `assets`/`identities`/`iocs` SELECT lỗi | Lỗi DB thật → job retry. Không phải "không tìm thấy" |
| n8n timeout / `5xx` | `skipped`, ghi audit, **đi tiếp** |
| n8n trả JSON sai hợp đồng | `skipped` + audit mức cảnh báo. Không cố đoán |
| Mạch ngắt đang mở | Mọi lookup ngoài `skipped` ngay, không gọi |
| Alert đã bị đóng bởi luồng khác | Kiểm tra lại `status` trước `UPDATE`; nếu đã đóng thì bỏ job, ghi audit |
| Hết retry của job `enrich` | Vẫn đẩy `queued_tier1` với ngữ cảnh rỗng + audit `job.exhausted` |

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng |
|---|---|---|
| E1 | Ba tra cứu nội bộ **luôn chạy**, không do model quyết | Review + test đếm truy vấn |
| E2 | `risk_score` tất định, chỉ cộng, trần 100 | Test chạy 100 lần cùng đầu vào |
| E3 | `skipped` không làm giảm `risk_score` | Test so hai alert giống nhau, một cái mạch ngắt mở |
| E4 | Chuỗi tương quan không được ghi vào bảng nào | Review |
| E5 | Prompt nhận **tóm tắt gộp**, không nhận danh sách thô | Test đếm dòng đưa vào prompt |
| E6 | `queued_tier1` và job `triage` trong cùng transaction | Test kill worker giữa chừng |
| E7 | Lỗi enrichment không bao giờ chặn alert vào hàng đợi | Test tắt n8n, chạy hết luồng |

---

## Test bắt buộc

```
# Tất định
test_ba_tra_cuu_noi_bo_luon_chay
test_risk_score_tat_dinh_100_lan
test_risk_score_co_tran_100
test_skipped_khong_giam_risk_score            # E3

# Không chặn
test_n8n_timeout_van_vao_hang_doi
test_n8n_tra_json_sai_van_vao_hang_doi
test_het_retry_van_vao_hang_doi_voi_ngu_canh_rong
test_mach_ngat_mo_thi_khong_goi_n8n

# Tương quan
test_tom_tat_gop_khong_qua_20_dong
test_agent_ban_1800_alert_prompt_van_duoi_nguong
test_correlation_khong_ghi_xuong_bang_nao      # E4
test_explain_dung_bitmapor_ba_index
test_correlation_loai_chinh_alert_dang_xet

# Hàng đợi
test_skip_locked_hai_worker_khong_nhan_trung_job
test_worker_chet_thi_job_duoc_nhat_lai_sau_timeout
test_backoff_tang_dan_10_60_300
test_loi_4xx_khong_retry
test_queued_tier1_va_job_triage_cung_transaction   # E6

# Đồng hồ
test_canh_bao_khi_lech_gio_vuot_300s
```

---

## Quyết định đã chốt

| # | Vấn đề | Chốt | Căn cứ |
|---|---|---|---|
| **P4‑1** | Correlation thuộc package nào | `domain/` | Ba nơi dùng; để ở `soar/` thì import chéo |
| **P4‑2** | Trần kết quả tương quan | **Tóm tắt gộp** + 5 alert đại diện | Đo: 44.800 → 210 token, giảm 213× |
| **P4‑3** | Công thức `risk_score` | Cộng điểm, chỉ cộng, trần 100 | Tất định là điều kiện của phép đo độ khớp |
| **P4‑4** | Hợp đồng n8n | `POST /webhook/enrich`, timeout 10s, **không retry tại chỗ**, mạch ngắt 5/60s | Retry lồng retry nhân thời gian chờ |
| **P4‑5** | Cột thời gian cho correlation | `alert_time` (giờ sự kiện), kèm cảnh báo lệch giờ | Correlation hỏi về thời điểm sự kiện, không phải thời điểm nhận |
| **P4‑6** | Job `enrich` thất bại | Vẫn đẩy vào hàng đợi với ngữ cảnh rỗng | Alert thiếu ngữ cảnh > alert không ai thấy |
| **P4‑7** | Retry/backoff | 3 lần · 10/60/300 giây · lock timeout 300 giây | Chưa có trong tài liệu gốc |

### Việc còn lại

1. **Trọng số `risk_score` chưa kiểm chứng** — đo tương quan với quyết định thật của analyst sau vài tuần.
2. **Ba index correlation phải có trước khi chạy thật** — thiếu là quét toàn bảng cho mọi alert.
3. **Sửa mục 05** của `Kiến_trúc.html`: correlation thuộc `domain/`, và auto-close **không** nằm ở bước này.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `enrichment/` | 3 tra cứu nội bộ | `soar/` → `enrichment/` ✅ |
| `domain/` | `correlation.py`, chuyển trạng thái | `soar/` → `domain/` ✅ |
| `infra/` | DB, hàng đợi, HTTP client, config | `soar/` → `infra/` ✅ |
| `audit/` | `alert.enriched`, `job.exhausted` | `soar/` → `audit/` ✅ |

Phase này **không** import `ingest/`, `tier1/`, `tier2/`, `llm/`, `kb/`.

---

*Đặc tả Phase 4 · Làm giàu ngữ cảnh và tương quan · 7 điểm chốt (P4‑1…P4‑7)*
