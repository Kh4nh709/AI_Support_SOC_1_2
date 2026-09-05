# Phase 3 — Tự động đóng nhiễu (Auto-close)

`ingest/autoclose.py` · `domain/transitions.py` · `audit/`

> **Vị trí:** ngay sau Phase 2, vẫn trong cùng transaction webhook. Chỉ alert **không phải bản sao** mới tới được đây.
> **Đã chuyển lớp:** `soar/autoclose.py` → `ingest/autoclose.py`.
> **Đã áp M1–M5** — enrichment nội bộ cho alert auto-close · mẫu đối chứng đi đường bình thường · tách trục `status` · cụm auto-closed hút bản sao · `NEVER_AUTOCLOSE_AGENTS`.

---

## Mục tiêu

Đóng những alert mà tổ chức **đã biết chắc** là nhiễu, trước khi tốn một lần gọi model và trước khi chiếm chỗ trong hàng đợi Tier 1.

Ba mục tiêu con:

1. **Chặn trước khi tốn tiền.** Nhiễu đã biết không được tiêu tốn hạn ngạch VirusTotal/MISP hay một lời gọi LLM nào.
2. **Không làm câm hệ thống.** Một rule quá rộng có thể nuốt cả một loại tấn công — ba lớp bảo vệ tồn tại vì lý do này.
3. **Giữ được số liệu.** Alert auto-close chính là **tử số** của phép đo "giảm false positive" trong báo cáo. Đóng mà không lưu vết thì không chứng minh được gì.

---

## Vì sao auto-close nằm ở `ingest/` chứ không phải `soar/`

Đây là **hệ quả bắt buộc của luật tầng không import tầng**, không phải lựa chọn thẩm mỹ:

```
Muốn tiết kiệm hạn ngạch API  →  phải chạy TRƯỚC enrichment
Chạy trước enrichment          →  phải chạy trong webhook
Chạy trong webhook             →  nếu để ở soar/ thì ingest/ phải import soar/
                                  ✗ vi phạm luật tầng
```

Và xét bản chất, auto-close **là lọc trên alert thô, không cần một chút ngữ cảnh nào** — nó khớp trên `rule_id`, `srcip`, `category`, tất cả đã có sau Phase 1. Đó chính là định nghĩa của việc ở biên.

### Enrichment không phải một khối — M1

Điểm dễ bỏ sót: enrichment gồm **hai nửa có chi phí hoàn toàn khác nhau**.

| Nửa | Package | Nội dung | Chi phí |
|---|---|---|---|
| **Ngoài** | `soar/` → n8n | CMDB · AD · VirusTotal · MISP | **Tốn hạn ngạch API**, chậm, có thể lỗi |
| **Trong** | `enrichment/` | 3 câu SELECT lên `assets`, `identities`, `iocs` | **Miễn phí**, vài mili giây, DB nội bộ |

Lý do chuyển auto-close lên trước enrichment — *"để nhiễu đã biết không tiêu tốn hạn ngạch API bên ngoài"* — chỉ áp cho **nửa ngoài**. Nửa trong không tốn gì.

Và `enrichment/` là **hạ tầng**, không phải tầng nghiệp vụ, nên `ingest/` → `enrichment/` là import **xuống**, hợp lệ.

> **Chốt M1:** alert auto-close **vẫn được làm giàu nội bộ**, chỉ bỏ qua nửa ngoài.
>
> Câu VI‑08 sửa thành: *"alert auto-close vẫn nằm nguyên trong bảng **với ngữ cảnh nội bộ đầy đủ** (asset, identity, IoC đã biết), chỉ thiếu phần tra cứu bên ngoài — và chỉ khác `status`."*

| | Alert thường | Alert auto-close | Mẫu đối chứng 5% |
|---|---|---|---|
| Enrichment **trong** (`enrichment/`) | ✅ | ✅ | ✅ |
| Enrichment **ngoài** (n8n) | ✅ | ❌ | ✅ |
| Vào hàng đợi Tier 1 | ✅ | ❌ | ❌ |

**Đã cân nhắc dời M1 ra sau `COMMIT`, và quyết định giữ trong transaction (B3).** Căn cứ: sau khi áp B1, câu `SELECT` dedup của Phase 2 chỉ còn **4 buffer / 0,030 ms** (đo trên 500.000 dòng). Ba câu enrichment nội bộ là tra cứu theo khóa chính, cùng cỡ. Không có bằng chứng nào cho thấy M1 là nút thắt, nên dời nó là tối ưu hóa sớm dựa trên phỏng đoán — trong khi cái giá là một loại job mới và một khoảng thời gian alert auto-close chưa có ngữ cảnh.

**Đường lùi nếu `TXN_BUDGET_MS` bắt đầu nổ:** chỉ làm giàu nội bộ cho **mẫu đối chứng**, bỏ qua cho alert auto-close thường. Đo lại trước khi đổi.

---

## Ranh giới

| Làm | Không làm |
|---|---|
| Khớp alert với `autoclose_rules` | Tra bản sao (Phase 2 đã làm) |
| Đặt `status='auto_closed'`, `close_reason` | Gọi n8n / tra cứu bên ngoài |
| Làm giàu **nội bộ** qua `enrichment/` (M1) | Chấm `risk_score` đầy đủ |
| Ghi `rule_id` đã khớp vào audit | Sinh job cho alert bị đóng (trừ mẫu) |
| Chọn mẫu đối chứng chạy qua ① | Gọi model cho alert thường |
| Chặn cứng alert `severity=critical` | Sinh job cho alert bị đóng |

**Chỉ alert đã qua Phase 2 và không phải bản sao mới tới đây.** Bản sao được quyết định bởi alert gốc của cụm — nếu gốc không bị auto-close thì cả cụm không bị, kể cả khi một bản sao về sau khớp rule. **Quyết định cụm ra một lần, do alert gốc.**

---

## Lưu rule ở đâu

```sql
CREATE TABLE autoclose_rules (
  rule_id     uuid PRIMARY KEY,
  name        text NOT NULL,          -- "Máy quét lỗ hổng nội bộ"
  enabled     bool NOT NULL DEFAULT true,
  match       jsonb NOT NULL,         -- [{field, op, value}, ...] AND với nhau
  reason      text NOT NULL,          -- ghi vào alerts.close_reason
  created_by  uuid NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
```

**Để trong bảng chứ không phải file config**, vì rule là thứ analyst thêm bớt thường xuyên — và mỗi lần thêm phải có người chịu trách nhiệm (`created_by`). Đây cũng là điều kiện để lớp bảo vệ thứ hai hoạt động: đếm được rule nào đang đóng bao nhiêu alert thì phải biết rule nào là của ai.

### Danh sách trường được phép khớp

`match` **không** được nhận tên trường tùy ý. Danh sách trắng, khai báo trong code:

| Trường | Toán tử cho phép | Ghi chú |
|---|---|---|
| `rule_id` | `eq`, `in` | Rule Wazuh |
| `category` | `eq`, `in` | Sau phân giải Phase 1 |
| `srcip` / `dstip` | `eq`, `in`, `cidr` | `cidr` dùng toán tử `<<` của Postgres |
| `agent_name` / `agent_id` | `eq`, `in`, `prefix` | |
| `alert_user` | `eq`, `in` | |
| `decoder` | `eq`, `in` | |
| `dst_port` / `src_port` | `eq`, `in` | Nhớ `0` nghĩa là "không có dữ liệu" (C2) |
| `rule_level` | `eq`, `lte` | |

**Ba thứ cố ý không có trong danh sách:**

- **Mọi trường enrichment** (`risk_score`, độ trọng yếu tài sản, kết quả IoC) — **chưa tồn tại** ở thời điểm này. Cho phép sẽ tạo rule không bao giờ khớp, âm thầm.
- **`srcip_is_private`** (C4) — cờ này mô tả thuộc tính địa chỉ, **không phải kết luận an ninh**. Cho phép nó làm điều kiện đóng là mời gọi rule "bỏ qua mọi alert từ IP nội bộ", thứ nuốt trọn lateral movement. Muốn lọc dải nội bộ thì viết `cidr` tường minh, để rule nói rõ nó đang bỏ qua dải nào.
- **`regex`** như một toán tử — ReDoS trên một chuỗi do kẻ tấn công kiểm soát, ngay trong vùng advisory lock. Nếu bắt buộc phải có, đặt timeout riêng và ghi vào danh sách rủi ro.

---

## Thuật toán

### Bước 1 — Chặn cứng trước khi xét rule

```python
if alert.severity == "critical":                 return None   # lớp 3
if alert.agent_name in NEVER_AUTOCLOSE_AGENTS:   return None   # lớp 3b · M5
```

**Vì sao cần lớp 3b (M5):** lớp 3 dựa hoàn toàn vào `rule.level` của Wazuh. Nhưng mức nghiêm trọng thật thường đến từ **tài sản**, không từ rule — một alert `medium` trên domain controller nguy hiểm hơn một alert `high` trên máy in. Auto-close chạy trước enrichment ngoài nên không có độ trọng yếu tài sản để dùng.

```python
NEVER_AUTOCLOSE_AGENTS = []   # ví dụ ["dc-01", "dc-02", "db-prod-01"]
```

Danh sách ngắn, tĩnh, analyst tự duy trì. Rỗng thì hành vi y hệt trước. Nếu về sau muốn dựa vào `assets.criticality` thay danh sách cứng, M1 đã mở đường — ngữ cảnh nội bộ đã có sẵn ở bước này.

**Đặt trước, không đặt sau.** Kiểm tra sau khi khớp rule vẫn cho kết quả đúng, nhưng đặt trước làm cho luật này không thể bị vô hiệu bởi bất kỳ rule nào, dưới bất kỳ dạng nào — và đọc code là thấy ngay.

> Mẫu thật của Phase 1 rơi đúng vào đây: brute-force **thành công** từ `127.0.0.1`, `rule.level = 12` → `severity = critical`. Kẻ tấn công đã ở trên chính máy đó. Dù có rule "bỏ qua mọi alert từ 127.0.0.0/8" thì alert này **vẫn không bị đóng**.

### Bước 2 — Khớp rule

```sql
SELECT rule_id, name, match, reason
FROM autoclose_rules
WHERE enabled = true
ORDER BY created_at ASC, rule_id ASC;   -- thứ tự TẤT ĐỊNH
```

Duyệt theo thứ tự trên, **rule đầu tiên khớp thì thắng và dừng**. Mỗi rule khớp khi **tất cả** điều kiện trong `match` cùng đúng (AND).

**`ORDER BY created_at ASC, rule_id ASC` là bắt buộc.** Không có `ORDER BY` thì Postgres trả theo thứ tự tùy ý, và hai alert giống hệt nhau có thể bị đóng bởi hai rule khác nhau — `close_reason` khác nhau, audit khác nhau, báo cáo không giải thích được. `rule_id` là khóa phụ để phá hòa khi hai rule cùng `created_at`.

### Bước 3 — Áp dụng

```sql
-- ① Alert: đóng, ghi lý do. sealed_at để NULL — cụm vẫn hút bản sao (M4)
INSERT INTO alerts (alert_id, ..., status, close_reason, closed_at, sealed_at, autoclose_rule_id)
VALUES ($id, ..., 'auto_closed', $reason, now(), NULL, $matched_rule_id);

-- ② Vết — BẮT BUỘC có rule_id, đây là nền của lớp bảo vệ thứ hai
INSERT INTO audit_events (event_type, subject_id, actor_role, payload)
VALUES ('alert.auto_closed', $id, 'system',
        jsonb_build_object('rule_id', $matched_rule_id,
                           'rule_name', $name,
                           'reason', $reason,
                           'sampled_for_control', $is_sample));
```

Rồi **`COMMIT` và dừng**. Không `INSERT jobs`, không gọi n8n, không gọi model — **trừ** mẫu đối chứng.

### Tách hai trục — M3

Máy trạng thái khai `AUTO_CLOSED: ()` (terminal). Nhưng M1 ghi ngữ cảnh nội bộ, và mẫu đối chứng ghi `risk_score` + `triage_status` + một dòng `llm_runs` lên alert đã `auto_closed`. Mâu thuẫn chỉ là bề ngoài — do chữ "terminal" đang bị đọc rộng hơn ý định.

| Trục | Cột | Ở alert auto-closed |
|---|---|---|
| **Quy trình người** | `status` | `auto_closed` — **terminal, không chuyển tiếp nữa** ✅ |
| Pipeline ① | `triage_status` | `pending`, hoặc `ready` nếu là mẫu |
| Ngữ cảnh | `risk_score`, cột enrichment | Được ghi |
| Vết | `llm_runs`, `audit_events` | Append-only, không phải trạng thái |

**"Terminal" nghĩa là `status` không chuyển tiếp nữa, không có nghĩa là dòng dữ liệu bị đóng băng.** Ràng buộc *"chỉ `domain/` được đổi trạng thái"* vẫn nguyên vẹn — không ai đổi `status`.

**Cần làm:** ghi định nghĩa này vào mục máy trạng thái (II‑06).

### Bước 4 — Không rule nào khớp

Alert đi tiếp: `INSERT alerts` với `status='received'` + `INSERT jobs` + `COMMIT` → `201`. Worker nhặt job và bắt đầu enrichment (`soar/`).

---

## Mẫu đối chứng — 5% vẫn chạy qua ①

Rule auto-close có thể sai mà không ai biết, vì alert bị đóng thì không ai nhìn. Giải pháp: một tỉ lệ nhỏ alert bị auto-close **vẫn chạy qua ①** làm mẫu đối chứng.

```python
AUTOCLOSE_SAMPLE_RATE = 0.05

def is_control_sample(alert_id: str) -> bool:
    # TẤT ĐỊNH — không dùng random()
    return int(hashlib.sha256(alert_id.encode()).hexdigest()[:8], 16) % 100 < 5
```

**Vì sao tất định chứ không phải `random()`:** chạy lại cùng một alert phải cho cùng kết quả. Nếu dùng ngẫu nhiên, không thể tái lập một ca để gỡ lỗi, và không thể chứng minh mẫu không bị chọn thiên lệch.

### Mẫu phải đi đường bình thường — M2

Mẫu đối chứng tồn tại để trả lời: *"nếu ta **không** auto-close alert này thì ① sẽ nói gì?"*

Nếu mẫu chạy ① mà **không có enrichment ngoài** trong khi alert thường **có**, ① phán trên ít thông tin hơn → thiếu tín hiệu đáng báo động (IoC khớp, tài sản trọng yếu) → nghiêng về "đóng" → **đồng ý với auto-close nhiều hơn thực tế**.

> ⚠️ **Đây là thiên lệch theo hướng nguy hiểm:** nó làm tỉ lệ đóng nhầm **thấp hơn sự thật**. Một cơ chế tự kiểm tra báo cáo sai theo hướng "mọi thứ ổn" còn tệ hơn không có cơ chế nào.

> **Chốt M2:** mẫu đối chứng đi **đúng con đường bình thường** — enrichment đầy đủ (cả ngoài), rồi ①. Chỉ khác một điều: kết quả **không vào hàng đợi Tier 1**.

Đó mới đúng nghĩa "đối chứng": cùng đầu vào, cùng xử lý, chỉ khác điểm đến.

**Alert được chọn làm mẫu:**
- Vẫn `status = 'auto_closed'` — **không** vào hàng đợi Tier 1, analyst không thấy
- **Có** sinh job đi qua `soar/` (enrichment đầy đủ) rồi pipeline ①
- Kết quả ghi vào `llm_runs` + `triage_status` + `risk_score`, **không đổi `status`** (M3)
- Cờ `sampled_for_control = true` trong audit

**Hai trần chặn chi phí:**

```python
AUTOCLOSE_SAMPLE_RATE             = 0.05
AUTOCLOSE_SAMPLE_MAX_PER_RULE_DAY = 20     # trần theo rule, theo ngày
```

Trần thứ hai quan trọng hơn tỉ lệ: một rule đóng 100.000 alert/ngày thì 5% là 5.000 lần gọi model cho thuần nhiễu. Trần 20 vẫn đủ để ước lượng tỉ lệ sai của rule đó.

**Cơ chế đếm (N3):** bộ đếm trong bộ nhớ tiến trình, khóa `(rule_id, ngày UTC)`, reset lúc nửa đêm.

```python
_sample_count: dict[tuple[str, date], int]
```

**Không** đếm bằng `COUNT(*)` trên `audit_events` — đó là thêm một truy vấn nữa vào vùng advisory lock, đúng thứ P4 đang tìm cách rút ngắn.

**Đánh đổi phải nói rõ:** bộ đếm trong tiến trình nên nó **reset khi restart**, và **không chia sẻ giữa nhiều tiến trình**. Với `n` worker, trần thực tế là `n × 20`. Đây là trần chống cháy ngân sách, không phải hạn mức kế toán — sai số vài lần vẫn đạt mục đích. Nếu về sau cần chính xác, chuyển sang một bảng đếm riêng với `INSERT … ON CONFLICT DO UPDATE`, **đặt ngoài transaction webhook**.

**Đơn vị lấy mẫu là cụm, không phải alert.** Sau M4 (dưới đây), 5.000 alert nhiễu gộp thành 1 cụm → lấy mẫu một lần, không phải 250 lần.

**Đọc kết quả:** ① nói "đáng điều tra" trên một alert đã bị auto-close là **tín hiệu rule đang đóng nhầm**. Đây vừa là cơ chế tự kiểm tra, vừa là số liệu cho báo cáo:

```sql
-- Tỉ lệ rule đóng nhầm, ước lượng từ mẫu
SELECT a.autoclose_rule_id,
       count(*) FILTER (WHERE r.result->>'suggested_action' <> 'false_positive') AS nghi_ngo,
       count(*)                                                                  AS tong_mau
FROM alerts a
JOIN llm_runs r ON r.subject_id = a.alert_id AND r.pipeline = 'triage'
WHERE a.status = 'auto_closed'
GROUP BY a.autoclose_rule_id;
```

> **Nhất quán với C4:** mẫu đối chứng có enrichment đầy đủ nên `skipped` chỉ xuất hiện khi IP thực sự nội bộ. Với alert auto-close **thường** (không phải mẫu), mọi lookup ngoài đều là `skipped` — nếu có lý do nào đó phải dựng prompt cho chúng, phải ghi rõ *"chưa tra cứu bên ngoài"*, không ghi *"không tìm thấy"*.

---

## Ba lớp bảo vệ

Một rule quá rộng làm câm cả một loại tấn công. Rule "bỏ qua mọi alert từ `10.0.0.0/8`" nghe hợp lý cho máy quét nội bộ, nhưng nó cũng nuốt luôn mọi dấu hiệu lateral movement.

| Lớp | Cơ chế | Chặn được gì |
|---|---|---|
| **1** | Mỗi lần khớp ghi `rule_id` vào audit | Truy được rule nào đóng bao nhiêu — điều kiện cần cho lớp 2 |
| **2** | Cảnh báo khi một rule vượt **30%** tổng alert | Rule quá rộng, phát hiện bằng số chứ không bằng linh cảm |
| **3** | **Cấm auto-close alert `severity=critical`** bất kể rule nói gì | Ca nghiêm trọng lọt qua rule sai |

Lớp 4 bổ sung từ thiết kế này: **mẫu đối chứng 5%** — bắt được rule đóng nhầm ở mức nhẹ hơn `critical`, thứ mà cả ba lớp trên đều không thấy.

```sql
-- Lớp 2 · chạy định kỳ, cảnh báo khi vượt ngưỡng
-- CỘNG occurrence_count, KHÔNG đếm dòng — sau M4 một cụm nhiễu chỉ là 1 dòng
WITH tong AS (
  SELECT count(*)::numeric AS n FROM alerts
  WHERE received_at >= now() - interval '7 days'
)
SELECT autoclose_rule_id,
       sum(occurrence_count)                            AS so_alert_dong,
       round(100.0 * sum(occurrence_count) / tong.n, 1) AS ti_le
FROM alerts, tong
WHERE status = 'auto_closed'
  AND received_at >= now() - interval '7 days'
GROUP BY autoclose_rule_id, tong.n
HAVING sum(occurrence_count) > 0.30 * tong.n;
```

> ⚠️ **Đây là chỗ M4 dễ làm hỏng lớp bảo vệ 2 nếu quên sửa.** Đếm dòng sau M4 thì một rule đóng 5.000 alert chỉ hiện thành **1** — rule rộng nhất trở nên vô hình đúng lúc cần thấy nhất.

---

## Tương tác với Phase 2 — điểm cần quyết

Ban đầu bản đặc tả này khuyến nghị **giữ nguyên** (cụm auto-closed không hút bản sao), lập luận rằng auto-close rẻ. Lập luận đó sai ở một điểm: nó bỏ qua tương tác với mẫu đối chứng.

```
Máy quét sinh 5.000 alert nhiễu
  → mỗi alert là một cụm riêng (gốc auto-closed có closed_at)
  → 5% × 5.000 = 250 mẫu đối chứng
  → 250 lần enrichment ngoài + 250 lần gọi model   ← cho thuần nhiễu
```

Nguyên nhân thật: **đơn vị lấy mẫu sai.** Quyết định auto-close là quyết định **trên cụm**, nên mẫu cũng phải trên cụm.

> **Chốt M4:** Phase 2 đổi vị từ thành `closed_at IS NULL OR sealed_at IS NULL` (truy vấn **và** index). Cụm `auto_closed` **hút bản sao** cho tới khi bị niêm hoặc chạm trần 30 phút.

**Điều này nhất quán hơn với lập luận gốc, không kém.** Luật "chỉ gộp vào alert đang mở" ra đời vì *"kẻ tấn công quay lại sau khi ta đóng ca là thông tin analyst cần biết"* — lập luận đó nói về **quyết định của con người**. Không ai muốn biết máy quét lỗ hổng vừa chạy lại.

| | Trước | Sau |
|---|---|---|
| 5.000 alert nhiễu | 5.000 dòng | **1 dòng**, `occurrence_count = 5000` |
| Lần khớp rule | 5.000 | **1** |
| Mẫu đối chứng | ~250 | **0 hoặc 1** |
| Ba trần cụm | Không áp dụng | Áp dụng bình thường |

**Kéo theo cho phép đo:** phân tách theo rule phải **cộng `occurrence_count`**, không đếm dòng — xem mục dưới.

---

## Sweeper khi tắt rule — B4

Tắt một rule **không** tự động có hiệu lực lên các cụm rule đó đã mở. Không có sweeper thì kịch bản sau xảy ra:

```
10:00  Rule R đóng nhầm hàng loạt, analyst phát hiện
10:01  Analyst tắt rule R
10:02  Alert mới tới, khóa cụm trùng cụm R đã đóng lúc 09:30
       → cụm vẫn còn hút → gộp vào, KHÔNG vào hàng đợi
```

Alert tiếp tục bị nuốt tới khi cụm chạm trần. Hai lớp xử lý:

**Lớp 1 · trần ngắn (mặc định).** `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES = 30` ở Phase 2 giới hạn độ trễ tối đa xuống 30 phút cho ca không ai bấm gì.

**Lớp 2 · sweeper (tức thì).** Khi analyst tắt rule, chạy ngay:

```sql
UPDATE alerts
SET sealed_at = now()
WHERE autoclose_rule_id = $1
  AND sealed_at IS NULL;
```

Cụm bị niêm trượt khỏi vị từ *"cụm còn hút"* của Phase 2 → alert tiếp theo mở cụm mới và **đi vào hàng đợi bình thường**.

**Vì sao dùng `sealed_at` chứ không đổi `status`:** đổi `status` sẽ làm hỏng âm thầm bốn truy vấn đo lường đang lọc `status = 'auto_closed'`. `sealed_at` giữ `status` nguyên vẹn — đúng nguyên tắc M3: `status` là vị trí trong quy trình, không phải cờ điều khiển.

Sweeper chạy **ngoài** transaction webhook, đồng bộ với thao tác tắt rule của analyst.

---

## Cache rule

Truy vấn `autoclose_rules` mỗi alert, **bên trong advisory lock**, là điều không được làm — nó kéo dài vùng tuần tự hóa vì một bảng gần như không đổi.

```
Cache toàn bộ rule đang bật trong bộ nhớ tiến trình
TTL = 60 giây  ·  nạp lại nền, không chặn request
```

**Đánh đổi phải nói rõ:** analyst thêm rule xong phải chờ tối đa 60 giây mới có hiệu lực. Với thao tác "tắt gấp một rule đang đóng nhầm", 60 giây là dài. Hai cách xử lý: hạ TTL xuống 10 giây, hoặc thêm một endpoint nội bộ để xóa cache thủ công. Với quy mô đồ án, TTL 60 giây và ghi rõ giới hạn là đủ.

---

## Ảnh hưởng tới phép đo

Phép đo "giảm false positive" (mục II‑08) dùng alert auto-close làm tử số. Sau khi chuyển lớp, ba điều chỉnh:

1. **`risk_score` so được một phần.** Sau M1, alert auto-close có ngữ cảnh nội bộ nên `risk_score` tính được trên phần đó; chỉ thiếu đóng góp từ IoC ngoài. Báo cáo phải nói rõ hai nhóm không cùng bộ tín hiệu.
2. **Phân tách theo `autoclose_rule_id`**, cộng `occurrence_count` chứ không đếm dòng.
3. **Kèm tỉ lệ đóng nhầm ước lượng từ mẫu** — con số làm cho phép đo đáng tin. Một hệ thống đóng 60% alert mà không biết tỉ lệ sai thì con số 60% vô nghĩa.
4. **Nhiễu giờ phân bố sang hai cột.** Sau M4, 5.000 alert máy quét hiện thành 1 dòng `auto_closed` + 4.999 dòng `duplicate`. Tổng "không tới tay analyst" không đổi, nhưng nếu chỉ nhìn cột `auto_closed` sẽ tưởng auto-close gần như không làm gì.

```sql
-- Khối lượng không tới tay analyst, theo tuần
SELECT date_trunc('week', received_at) AS tuan,
       count(*) FILTER (WHERE status = 'auto_closed')          AS cum_tu_dong_dong,
       sum(occurrence_count) FILTER
           (WHERE status = 'auto_closed')                      AS alert_tu_dong_dong,
       count(*) FILTER (WHERE duplicate_of IS NOT NULL)        AS gop_trung,
       count(*) FILTER (WHERE duplicate_of IS NULL
                          AND status <> 'auto_closed')         AS toi_hang_doi
FROM alerts
WHERE NOT is_synthetic
GROUP BY 1 ORDER BY 1;
```

Hai cột đầu tách bạch **số cụm** và **số alert** — sau M4 chúng khác nhau rất xa, và báo cáo cần cả hai: số cụm là khối lượng công việc tiết kiệm được, số alert là khối lượng dữ liệu lọc được.

---

## Xử lý lỗi

| Tình huống | Hành động |
|---|---|
| Cache rule rỗng / nạp thất bại | **Không đóng alert nào.** Fail-open: alert đi tiếp vào hàng đợi. Đóng nhầm nguy hiểm hơn xử lý thừa |
| `match` có trường ngoài danh sách trắng | Bỏ qua **cả rule đó**, ghi log mức cảnh báo. Không bỏ qua riêng điều kiện lỗi — rule mất một điều kiện là rule rộng hơn ý định |
| `match` sai cú pháp jsonb | Như trên, và rule nên bị `enabled=false` tự động sau N lần lỗi |
| Nhiều rule cùng khớp | Rule đầu tiên theo `ORDER BY` thắng; ghi log debug các rule còn lại (không ghi audit, tránh nhiễu) |
| Alert `critical` khớp rule | **Không đóng.** Ghi audit `alert.autoclose_blocked_critical` kèm `rule_id` — đây là tín hiệu rule cần xem lại |

> **Luật fail-open là có chủ đích.** Mọi lỗi ở phase này đều nghiêng về **không đóng**. Alert thừa vào hàng đợi thì analyst mất thời gian; alert bị đóng nhầm thì không ai biết.

**Fail-open ở đây rẻ hơn vẻ ngoài — nhờ thứ tự Phase 2 → Phase 3.** Lo ngại thường gặp là *"cache rule hỏng giữa cơn bão 50.000 alert nhiễu thì hàng đợi vỡ"*. Điều đó **không xảy ra**: dedup chạy **trước** auto-close, nên 50.000 alert nhiễu gộp thành **1 cụm** và sinh **đúng 1 job**. Cái vào hàng đợi là một dòng có `occurrence_count` lớn, không phải 50.000 dòng.

Nói cách khác: dedup là lưới an toàn cho auto-close. Nếu hai phase đảo thứ tự, fail-open sẽ là một lựa chọn đắt và có lẽ không dám chọn.

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng bằng |
|---|---|---|
| A1 | Alert `severity=critical` **không bao giờ** bị auto-close | Test với rule khớp mọi thứ |
| A2 | Mọi lần đóng đều ghi `rule_id` vào audit | Đối chiếu `count(auto_closed)` với `count(audit)` |
| A3 | Cùng một alert + cùng bộ rule → cùng rule thắng (tất định) | Chạy 100 lần, so kết quả |
| A4 | Alert auto-close **không** sinh job (trừ mẫu đối chứng) | Test 100 alert nhiễu → đúng ~5 job |
| A5 | Mẫu đối chứng chọn tất định theo `alert_id` | Chạy lại cùng alert → cùng kết quả |
| A6 | Alert auto-close vẫn nằm trong bảng, không bị xóa | Test đếm dòng |
| A7 | Rule bị tắt không bao giờ được áp | Test |
| A8 | Lỗi bất kỳ → không đóng (fail-open) | Test với cache rỗng, jsonb hỏng |
| A9 | Không rule nào khớp được trên trường enrichment | Test danh sách trắng |
| A10 | Làm giàu nội bộ chạy **sau** quyết định khớp rule | Review code — giữ tính tất định của A3 |
| A11 | Alert auto-close không gọi n8n (trừ mẫu) | Test đếm lời gọi ngoài |
| A12 | Ghi ngữ cảnh / `triage_status` không đổi `status` | Test |

---

## Test bắt buộc

```
# Khớp cơ bản
test_rule_khop_thi_auto_closed_va_ghi_rule_id_vao_audit
test_rule_bi_tat_thi_khong_ap_dung
test_khong_rule_nao_khop_thi_alert_di_tiep_va_sinh_job
test_match_nhieu_dieu_kien_la_AND_khong_phai_OR
test_toan_tu_cidr_khop_dung_dai

# Lớp bảo vệ 3 và 3b — quan trọng nhất
test_alert_critical_khop_rule_van_khong_bi_dong          # A1
test_alert_critical_bi_chan_ghi_audit_autoclose_blocked
test_mau_that_127001_brute_force_thanh_cong_khong_bi_dong
test_agent_trong_never_autoclose_khong_bi_dong           # M5 · lớp 3b
test_danh_sach_never_autoclose_rong_thi_hanh_vi_nhu_cu

# Tất định
test_nhieu_rule_cung_khop_ghi_rule_dau_tien              # A3
test_chay_100_lan_cung_ket_qua
test_hai_rule_cung_created_at_pha_hoa_bang_rule_id

# Mẫu đối chứng — M2
test_ti_le_mau_xap_xi_5_phan_tram
test_mau_chon_tat_dinh_theo_alert_id                     # A5
test_alert_mau_van_auto_closed_khong_vao_hang_doi
test_alert_mau_co_sinh_job_pipeline_1
test_alert_mau_co_enrichment_ngoai_day_du                # M2 · chống thiên lệch
test_alert_khong_phai_mau_khong_sinh_job                 # A4
test_tran_20_mau_moi_rule_moi_ngay
test_lay_mau_mot_lan_tren_mot_cum_khong_phai_moi_alert   # M4

# Enrichment nội bộ — M1
test_alert_auto_close_van_co_ngu_canh_noi_bo
test_alert_auto_close_khong_goi_n8n
test_rule_van_khong_duoc_khop_tren_truong_enrichment     # A9 · thứ tự vẫn đúng

# Tách trục — M3
test_ghi_triage_status_len_alert_auto_closed_khong_doi_status
test_ghi_risk_score_len_alert_auto_closed_khong_doi_status

# Gộp cụm — M4
test_5000_alert_nhieu_ra_1_dong_occurrence_5000
test_ban_sao_gop_duoc_vao_goc_auto_closed
test_ban_sao_khong_gop_duoc_vao_goc_closed_fp
test_lop_bao_ve_2_cong_occurrence_count_khong_dem_dong

# Sweeper — B4
test_tat_rule_thi_cum_bi_niem_ngay
test_cum_bi_niem_khong_hut_ban_sao_nua
test_alert_sau_khi_niem_di_vao_hang_doi_binh_thuong
test_cum_auto_closed_tu_het_han_sau_30_phut
test_truy_van_do_luong_van_dem_du_cum_da_niem   # status vẫn là auto_closed

# Danh sách trắng
test_rule_dung_truong_enrichment_bi_bo_qua               # A9
test_rule_dung_srcip_is_private_bi_bo_qua
test_rule_dung_truong_la_bi_bo_qua_ca_rule_khong_bo_rieng_dieu_kien

# Fail-open
test_cache_rong_thi_khong_dong_alert_nao                 # A8
test_jsonb_hong_thi_bo_qua_rule_khong_crash
test_loi_bat_ky_deu_nghieng_ve_khong_dong

# Không mất dữ liệu
test_alert_auto_close_van_nam_trong_bang                 # A6
test_alert_auto_close_giu_du_raw_payload

# Cache
test_rule_moi_co_hieu_luc_sau_ttl
test_truy_van_rule_khong_chay_trong_advisory_lock
```

---

## Quyết định cần chốt

| # | Vấn đề | Khuyến nghị |
|---|---|---|
| **AC‑C1** | Auto-close trước hay sau ① | **Trước** — đó là toàn bộ lý do nó tồn tại. Kèm mẫu đối chứng 5% |
| **AC‑C2** | Tỉ lệ mẫu đối chứng | **5%**, tất định theo `alert_id`. Đo lại sau vài tuần |
| **AC‑C3** | Gộp bản sao vào gốc auto-closed | **Có** (M4, sửa lại) — vị từ `closed_at IS NULL OR status = 'auto_closed'` |
| **AC‑C4** | TTL cache rule | **60 giây**, ghi rõ giới hạn "tắt rule gấp phải chờ" |
| **AC‑C5** | Cho phép toán tử `regex` | **Không**, trừ khi có timeout riêng |
| **AC‑C6** | Ngưỡng cảnh báo rule quá rộng | **30%** trên cửa sổ 7 ngày |
| **AC‑C7** | Sửa câu "đầy đủ enrichment" ở VI‑08 | Đổi thành **"ngữ cảnh nội bộ đầy đủ"** (M1), không bỏ hẳn |
| **AC‑C8** | Mẫu đối chứng có enrichment ngoài không | **Có** (M2) — nếu không thì thiên lệch về hướng nguy hiểm |
| **AC‑C9** | Bảo vệ tài sản trọng yếu | `NEVER_AUTOCLOSE_AGENTS` (M5) — lớp 3b |
| **B3** | Dời M1 ra sau `COMMIT` | **Không** — đo cho thấy vùng khóa không phải nút thắt |
| **B4** | Tắt rule có hiệu lực khi nào | **Tức thì** qua sweeper + trần 30 phút làm hàng rào |

### Việc còn lại

1. **Thêm cột `autoclose_rule_id`** vào `alerts` (nullable, FK tới `autoclose_rules`) — hiện `rule_id` chỉ nằm trong audit, nhưng phép đo phân tách theo rule sẽ phải join audit mỗi lần. Một cột rẻ hơn nhiều.
2. **Sửa VI‑08** câu "với đầy đủ enrichment" → "với ngữ cảnh nội bộ đầy đủ".
5. **Sửa II‑06** — định nghĩa "terminal" là terminal về `status`, không phải đóng băng cả dòng (M3).
6. **Rà mọi truy vấn đếm alert auto-close** — sau M4 phải cộng `occurrence_count`, không đếm dòng.
3. **Giao diện quản lý rule** — thêm/tắt/xem tỉ lệ. Không có nó thì lớp bảo vệ 2 chỉ là một câu SQL không ai chạy.
4. **Bộ rule khởi tạo** — cần ít nhất vài rule thật (máy quét nội bộ, cửa sổ bảo trì, health-check) để phép đo có ý nghĩa ngay từ tuần đầu.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `domain/alert.py` | Kiểu `Alert` từ Phase 1 | `ingest/` → `domain/` ✅ |
| `domain/transitions.py` | `received` → `auto_closed` kèm kiểm tra hợp lệ | `ingest/` → `domain/` ✅ |
| `infra/db.py` | Đọc `autoclose_rules`, transaction | `ingest/` → `infra/` ✅ |
| `infra/config.py` | `AUTOCLOSE_SAMPLE_RATE`, `AUTOCLOSE_SAMPLE_MAX_PER_RULE_DAY`, `NEVER_AUTOCLOSE_AGENTS`, `RULE_CACHE_TTL`, ngưỡng 30% | `ingest/` → `infra/` ✅ |
| `audit/` | `alert.auto_closed`, `alert.autoclose_blocked_critical` | `ingest/` → `audit/` ✅ |
| `enrichment/` | Làm giàu nội bộ (M1) — 3 SELECT tất định | `ingest/` → `enrichment/` ✅ |

Phase này **không** import `soar/`, `tier1/`, `tier2/`, `llm/`, `kb/` — chính là lý do nó được chuyển từ `soar/` sang `ingest/`.

`enrichment/` là **hạ tầng**, không phải tầng nghiệp vụ, nên import xuống nó hợp lệ. Đây là điểm khác so với bản trước, và là điều làm M1 khả thi mà không phá luật tầng.

---

*Đặc tả Phase 3 · Tự động đóng nhiễu · AI Support SOC · đã áp M1–M5 · 9 điểm chốt (AC‑C1…AC‑C9)*
