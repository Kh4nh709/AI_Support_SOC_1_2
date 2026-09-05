# Phase 7 — Điều tra Tier 2 và kết luận

`tier2/investigate.py` · `tier2/conclude.py` · `llm/` · `kb/` · `security/` · `domain/`

> **Chặng cuối trong phạm vi đồ án.** Đồng bộ, do thao tác của analyst kích hoạt.
> **Vào:** `Case` ở `investigating` · **Ra:** một trong ba kết luận, áp cho toàn case.

---

## Mục tiêu

Cho analyst Tier 2 một trợ lý đọc **toàn bộ** case — thứ mà con người phải mất nhiều phút mới đọc hết — rồi để người quyết.

Khác biệt cốt lõi so với ①:

| | ① Auto-triage (Phase 5) | ② Trợ lý điều tra |
|---|---|---|
| Đơn vị | Một alert (+ tóm tắt tương quan) | **Một case** (nhiều cụm alert) |
| Chạy khi | Tự động, nền, song song | **Chỉ khi analyst bấm**, đồng bộ |
| Chạy mấy lần | Một lần | **Nhiều lần** trong một case |
| Vai trò | **Hỗ trợ lọc** | **Hỗ trợ điều tra** |
| Tra cứu thêm | Không — tất định ở Phase 4 (P5‑6) | **Được gọi tool đọc** (P7‑8) |
| Người đọc | Analyst Tier 1, xem lướt | Analyst Tier 2, đọc kỹ |

---

## P7‑1 · "Đọc toàn bộ case" là một cái bẫy

Tài liệu gốc mô tả ② *"đọc toàn bộ case + mọi alert đã gom"*. Với trần `MAX_ALERTS_PER_CASE = 200` từ Phase 6, và mỗi alert có `raw_log` cùng ngữ cảnh enrichment:

```
200 alert × ~250 token/alert (đã gồm raw_log rút gọn)  ≈  50.000 token
+ mọi ghi chú analyst, playbook, lịch sử hội thoại ②
→ vượt ngân sách, và phần lớn là lặp lại vì các alert trong một cụm gần giống hệt nhau
```

Đây **cùng một vấn đề** với P4‑2, ở quy mô lớn hơn: dữ liệu thô đưa thẳng vào prompt.

| | Cách | Vấn đề |
|---|---|---|
| (a) | Cắt còn N alert đầu | Mất phần đuôi — thường là phần diễn biến mới nhất, thứ đáng đọc nhất |
| (b) | Tóm tắt gộp toàn bộ như P4‑2 | Tier 2 **cần** chi tiết; gộp hết là bỏ mất bằng chứng |
| **(c)** | **Ba tầng: tóm tắt + đại diện đầy đủ + dòng thời gian rút gọn** | Phức tạp hơn khi dựng prompt |

> **Chốt (c).** Prompt ② gồm ba tầng thay vì một danh sách:

| Tầng | Nội dung | Trần |
|---|---|---|
| **1 · Tóm tắt** | Gộp theo `rule_id` × `category`: số cụm, tổng alert, khoảng thời gian, số IP, số tài khoản | 20 dòng |
| **2 · Đại diện đầy đủ** | Alert có `occurrence_count` cao nhất và alert mới nhất của mỗi `rule_id`, kèm `raw_log` và ngữ cảnh | 10 alert |
| **3 · Dòng thời gian** | Một dòng một sự kiện: `thời điểm · rule · host · user` | 100 dòng |

```python
CASE_PROMPT_BUDGET_TOKENS = 30_000    # gấp 2,5 lần ① vì đơn vị là case
```

**Vì sao ba tầng chứ không phải một:** Tier 2 hỏi ba câu khác nhau — *"chuyện gì đang xảy ra"* (tầng 1), *"cho tôi xem bằng chứng"* (tầng 2), *"theo thứ tự nào"* (tầng 3). Một danh sách thô trả lời cả ba một cách tệ và tốn gấp nhiều lần.

**Cắt theo thứ tự ưu tiên ngược:** tầng 3 → tầng 2 → tầng 1. Tầng 1 **không bao giờ** bị cắt. Mỗi lần cắt ghi `citation_warnings`.

---

## P7‑2 · Case vẫn hút alert khi đang điều tra

D‑C5 đã chốt: `escalated_tier2` không set `sealed_at`, nên cụm vẫn gộp bản sao. Hai hệ quả cần xử lý ở phase này:

**Hệ quả 1 — `occurrence_count` nhảy số trong lúc analyst làm việc.** Giao diện phải hiển thị nhãn *"đợt tấn công đang tiếp diễn — bộ đếm đang tăng"*, kèm mốc `last_seen_at`. Không hiển thị thì analyst sẽ nghi ngờ dữ liệu.

**Hệ quả 2 — hai lần chạy ② trên cùng một case cho hai kết quả khác nhau.** Đây là **đúng**, không phải lỗi: dữ liệu đã đổi thật. Nhưng phải truy được:

> Mỗi lần chạy ② ghi một dòng `llm_runs` riêng, kèm ảnh chụp số liệu tại thời điểm chạy: `alert_count`, `total_occurrences`, `last_seen_at`. Không ghi đè dòng cũ.

**Alert mới có được thêm vào `case_alerts` không?** Bản sao của cụm đã trong case thì **tự động thuộc case** qua `duplicate_of`. Cụm **mới** (khóa cụm khác) thì **không** — nó vào hàng đợi Tier 1 bình thường. Phase này không tự mở rộng case.

> **Chốt:** case chỉ mở rộng khi **có người bấm**. Tự động gom là đường dẫn tới một case nuốt cả hệ thống, và không ai chịu trách nhiệm về ranh giới của nó.

---

## P7‑8 · Vòng lặp tool — ② được tra cứu thêm, ① thì không

Bản đặc tả trước áp `V1` (*"hai lần chạy phải cho cùng ngữ cảnh"*) cho **cả hai** pipeline. Đó là mở rộng một ràng buộc **quá phạm vi lý do sinh ra nó**.

`V1` tồn tại để phục vụ đúng một thứ: **phép đo ③** của báo cáo — *độ khớp giữa đề xuất ① và quyết định người* (`KT` §B7). Phép đo đó `JOIN llm_runs ↔ audit_events` theo `subject_id`, mà `subject_id` của nó là **`alert_id`**. Nó đo pipeline ①. Nó **không** đo ②.

Và ② vốn **đã** không tất định — P7‑2 đã tự nhận điều đó:

> *"hai lần chạy ② trên cùng một case cho hai kết quả khác nhau. Đây là **đúng**, không phải lỗi: dữ liệu đã đổi thật."*

Cho ② gọi tool vì vậy **không phá thêm bất kỳ phép đo nào**.

| | ① Auto-triage | ② Trợ lý điều tra |
|---|---|---|
| Vai trò | **Hỗ trợ lọc** — *"cái này có đáng mở ra xem không?"* | **Hỗ trợ điều tra** — *"chuyện gì đã xảy ra, bằng chứng ở đâu?"* |
| Tra cứu | Tất định, xong hết ở Phase 4 | **Được gọi tool đọc**, tối đa `TOOL_MAX_ROUNDS` vòng |
| Ràng buộc `V1` | **Áp** — điều kiện của phép đo ③ | **Không áp** — không phép đo nào đo ② |
| Người đọc | Analyst Tier 1, xem lướt | Analyst Tier 2, đọc kỹ |

> **Chốt:** ② chạy theo vòng lặp tool. ① giữ nguyên P5‑6 — **không** tool.

**Vì sao ② cần tool, nói bằng chính điểm yếu của P7‑1.** Prompt ba tầng chỉ mang **10 alert đại diện** trong tối đa 200. Phương án (a) bị loại vì *"mất phần đuôi — thường là phần diễn biến mới nhất, thứ đáng đọc nhất"*; phương án (c) được chọn nhưng **vẫn cắt**, chỉ là cắt khéo hơn. Tool đóng đúng khoảng trống đó: model đọc tóm tắt trước, rồi **tự kéo về đúng alert nó cần**, thay vì hệ thống phải đoán trước 10 alert nào là đủ.

---

### Danh mục tool — tám tool, tất cả **chỉ đọc**

| Tool | Đọc gì | Package | Vì sao ② cần |
|---|---|---|---|
| `get_alert_detail(alert_id)` | Một alert đầy đủ, kèm `raw_log` | `domain/` | Kéo về alert nằm ngoài 10 đại diện |
| `search_case_timeline(rule_id?, host?, user?, from?, to?)` | Dòng thời gian đã lọc | `domain/` | Tầng 3 bị cắt còn 100 dòng |
| `get_correlation_summary(alert_id)` | Tóm tắt cụm tương quan | `domain/correlation.py` | Cụm liên quan chưa vào case |
| `get_playbook(category)` | Một playbook | `kb/` | Playbook của category **khác** category chính của case |
| `lookup_ioc(value)` | Uy tín IoC nội bộ | `enrichment/` | Giá trị mới lộ ra giữa chừng điều tra |
| `lookup_asset(hostname)` | Mức trọng yếu tài sản | `enrichment/` | Host xuất hiện trong `raw_log` |
| `lookup_identity(username)` | Danh tính, `is_privileged` | `enrichment/` | Tài khoản lộ ra giữa chừng |
| `get_audit_history(subject_id)` | Lịch sử `audit_events` | `audit/` | *"Alert này Tier 1 đã quyết gì?"* |

**Không tool nào ghi.** Không `INSERT`, không `UPDATE`, không đổi `status`. `G2` và `I3` nguyên vẹn — vòng lặp tool là **một chuỗi `SELECT`**, không hơn.

**Không tool nào gọi ra ngoài.** Cả tám đọc DB nội bộ. n8n / VirusTotal / MISP **không** nằm trong danh mục — xem *Việc còn lại*.

---

### Allowlist tham số — hàng rào quan trọng nhất

> Model **không bao giờ** được cung cấp tham số tự do. Mọi tham số phải là **giá trị đã có sẵn trong case**.

Trước khi vòng lặp bắt đầu, dựng năm tập giá trị hợp lệ trong **một** transaction đọc:

```python
ALLOWED = {
  "alert_id":  {alert_id  FROM case_alerts WHERE case_id=$1}
             | {alert_id  FROM alerts WHERE duplicate_of IN (…)},   # bản sao cũng hợp lệ
  "hostname":  {DISTINCT agent_name FROM alerts WHERE alert_id IN (…)},
  "username":  {DISTINCT alert_user FROM alerts WHERE alert_id IN (…) AND alert_user IS NOT NULL},
  "ioc_value": {DISTINCT srcip, dstip FROM alerts WHERE alert_id IN (…)} - {''},
  "category":  CATEGORY_MAP.keys(),      # tập đóng, từ bảng ánh xạ
}
```

Tham số ngoài tập → **từ chối trước khi chạy**, không chạm DB. Trả về khối từ chối có cấu trúc, **tính là một vòng**, ghi `agent_trace[n].status = 'rejected_arg'` và một dòng `citation_warnings`.

**Vì sao đây là hàng rào chứ không phải sự cẩn thận thừa.** `raw_log` do kẻ tấn công kiểm soát một phần. Không có allowlist, một dòng log dựng có chủ đích lái được model gọi `lookup_ioc("<giá trị kẻ tấn công chọn>")` — biến hệ thống thành công cụ tra cứu hộ, và nếu về sau có tool nào gọi ra ngoài thì thành đường rò dữ liệu. Có allowlist, model **chỉ đọc lại được thứ hệ thống đã biết về chính case này**. Bề mặt đó bằng đúng bề mặt của prompt ba tầng — tool không mở rộng nó, chỉ đổi **thứ tự** truy cập.

`alert_user IS NOT NULL` khớp chốt ⑨c: `alert_user` chỉ nhận `NULL`, cấm `''`.

---

### Ba ngân sách, ba cách dừng

```python
TOOL_MAX_ROUNDS             = 6        # CHƯA KIỂM CHỨNG
TOOL_WALL_CLOCK_BUDGET_S    = 60       # CHƯA KIỂM CHỨNG — người đang chờ
TOOL_RESULT_MAX_TOKENS      = 2_000    # trần MỘT kết quả tool
CASE_SESSION_BUDGET_TOKENS  = 60_000   # trần TÍCH LŨY cả vòng lặp
```

`CASE_PROMPT_BUDGET_TOKENS = 30_000` **giữ nguyên** — nó là trần cho **lượt dựng đầu**. `CASE_SESSION_BUDGET_TOKENS` là thứ khác: trần cho **toàn phiên**, gồm mọi kết quả tool cộng dồn. Lẫn hai cái là cách chắc chắn để một case 200 alert với 6 vòng tool thổi bay mọi dự toán.

| Hết ngân sách nào | `stopped_by` | Làm gì |
|---|---|---|
| Model tự trả lời xong | `model_finished` | Đường bình thường |
| Hết `TOOL_MAX_ROUNDS` | `max_rounds` | **Ép trả kết luận** với dữ liệu đã có |
| Hết `TOOL_WALL_CLOCK_BUDGET_S` | `wall_clock` | **Ép trả kết luận** ngay |
| Hết `CASE_SESSION_BUDGET_TOKENS` | `token_budget` | **Ép trả kết luận** ngay |

Cả ba đường ép đều ghi `citation_warnings` — sáu tuần sau còn biết model đã **không** kịp nhìn thấy gì. Và cả ba đều **trả về kết luận**, không trả lỗi: người đang chờ, một bản phân tích thiếu vẫn hơn một màn hình trắng.

`TOOL_WALL_CLOCK_BUDGET_S = 60` phải **nhỏ hơn** timeout của giao diện. P7‑6 chốt ② đồng bộ, không retry nền — vòng lặp không được phép biến điều đó thành treo vô hạn.

---

### `agent_trace` — cột đã có, nay mới có việc

`llm_runs.agent_trace jsonb` tồn tại trong schema nhưng toàn bộ 7 đặc tả chỉ nhắc **đúng một lần** (`P5`, danh sách cột `INSERT`) và **chưa có gì để ghi vào**. `schema-notes` §1.2 đánh dấu ⚠️ vì lý do đó. P7‑8 cho nó nội dung thật:

```json
{
  "rounds": [
    {"n": 1, "tool": "get_alert_detail", "args": {"alert_id": "…"},
     "status": "ok", "result_tokens": 312, "latency_ms": 45,
     "injection_findings": []},
    {"n": 2, "tool": "lookup_ioc", "args": {"value": "203.0.113.9"},
     "status": "rejected_arg", "reason": "ngoài allowlist ioc_value",
     "result_tokens": 0, "latency_ms": 0}
  ],
  "stopped_by":   "model_finished | max_rounds | wall_clock | token_budget",
  "rounds_used":  2,
  "tokens_used":  41200
}
```

`status` là tập đóng: `ok · rejected_arg · error · timeout`.

**Ghi cả vòng bị từ chối, không chỉ vòng thành công.** Một chuỗi `rejected_arg` liên tiếp là dấu hiệu model đang bị lái — đó chính là thứ cần nhìn thấy khi rà lại một case đáng ngờ.

---

### Kết quả tool là dữ liệu **không tin cậy**

Bảng nguồn không tin cậy ở mục *Chạy ②* được bổ sung một dòng:

| Nguồn không tin cậy | Ai kiểm soát |
|---|---|
| **Kết quả tool** | Chứa `raw_log`, tên host, tên tài khoản — **một phần do kẻ tấn công** |

Mọi kết quả tool đi qua `security/` trước khi vào vòng sau, cùng lớp bọc như mọi thứ khác:

```
<untrusted_data source="tool:get_alert_detail" round="2" alert_id="…">
  … nội dung đã thoát …
</untrusted_data>
```

Và **tầng 3 phòng thủ áp cho cả kết quả tool**: injection mức cao phát hiện trong kết quả tool → cấm `false_positive`, **ép `need_more_data`**, đúng như injection trong prompt gốc.

> Đây là chỗ P7‑4 (*injection tích lũy qua các vòng*) trở nên nghiêm trọng hơn hẳn. Trước P7‑8, "các vòng" nghĩa là nhiều lần analyst bấm chạy ②, cách nhau vài phút, mỗi lần có người nhìn. Sau P7‑8, "các vòng" còn nghĩa là **6 vòng tool trong một lần bấm, không ai nhìn giữa chừng**. Nội dung độc kéo về ở vòng 2 nằm trong ngữ cảnh của vòng 3–6. Lớp bọc phải áp **mọi vòng**, không chỉ lượt đầu.

**Dấu hiệu "đã cắt" của kết quả tool cũng nằm TRONG lớp bọc** — cùng lý do đã nêu ở `P5`: đặt ngoài thì một `raw_log` dựng có chủ đích tự chèn chuỗi `…[đã cắt]` giả để đánh lừa model về độ dài thật.

---

### `G7` vẫn nguyên vẹn

Vòng lặp tool **không** làm bất kỳ trạng thái nào phụ thuộc model:

- ② không đổi `status` (I3) — tool cũng không.
- Model chết, tool lỗi, hết ngân sách giữa chừng → analyst vẫn kết luận được bằng tay (I7).
- Tool lỗi **không** làm hỏng cả phiên: ghi `status='error'` vào vòng đó, model đi tiếp với những gì có.

---

## Chạy ②

Lượt dựng đầu đọc bốn nguồn; sau đó model đi vào **vòng lặp tool** của P7‑8, cũng chỉ đọc.

```sql
-- Đọc, không ghi
SELECT * FROM cases WHERE case_id = $1;
SELECT a.* FROM alerts a JOIN case_alerts ca USING (alert_id) WHERE ca.case_id = $1;
SELECT * FROM audit_events WHERE subject_id IN (…) ORDER BY created_at;
SELECT * FROM llm_runs WHERE subject_id = $1 AND pipeline = 'investigate' ORDER BY created_at;
```

Dựng prompt ba tầng, **bọc mọi dữ liệu không tin cậy qua `security/`** — ở phase này bề mặt tấn công rộng hơn ①:

| Nguồn không tin cậy | Ai kiểm soát |
|---|---|
| `raw_log` | Một phần do kẻ tấn công |
| Tên host, tên tài khoản | Một phần do kẻ tấn công |
| Kết quả n8n / IoC | Bên thứ ba |
| **Ghi chú của analyst** | Người dùng hợp pháp — **vẫn bọc** |
| **Kết quả ② lần trước** | Chính model — **vẫn bọc** |
| **Kết quả tool** (P7‑8) | `raw_log`, tên host, tên tài khoản — **một phần do kẻ tấn công** |

> Hai dòng cuối dễ bị bỏ sót. Ghi chú analyst có thể chứa nguyên văn một đoạn log dán vào. Và kết quả ② lần trước, nếu lần đó đã bị injection, sẽ mang chỉ thị của kẻ tấn công vào lần chạy sau — **injection tích lũy qua các vòng**. Cả hai đều phải nằm trong khối bọc.

Ba tầng phòng thủ injection giống Phase 5, với một khác biệt: ở đây `suggested_conclusion = 'false_positive'` bị cấm khi phát hiện injection mức cao.

### Đầu ra

```json
{
  "summary":              "…",
  "attack_narrative":     "…",
  "suggested_conclusion": "false_positive | policy_violation | confirmed_incident | need_more_data",
  "confidence":           "low | medium | high",
  "evidence":             [{"alert_id": "…", "why": "…"}],
  "next_steps":           ["…"],
  "playbook_used":        "…|null"
}
```

`need_more_data` là giá trị thứ tư **không** có ở ① — vì Tier 2 có thể chờ thêm dữ liệu, còn Tier 1 phải quyết ngay.

Mọi `alert_id` trong `evidence` được **đối chiếu với `case_alerts`**; id không thuộc case → ghi vào `citation_warnings` và bỏ khỏi giao diện. Model bịa ra id là chuyện có thật, và một bằng chứng bịa nguy hiểm hơn không có bằng chứng.

```sql
INSERT INTO llm_runs (pipeline, subject_type, subject_id, system_prompt, user_message,
                      result, injection_findings, citation_warnings,
                      input_tokens, output_tokens, latency_ms)
VALUES ('investigate', 'case', $case_id, …);

UPDATE cases SET last_analyzed_at = now() WHERE case_id = $1;

INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload)
VALUES ('case.analyzed', $case_id, $user_id, 'llm', …);
```

---

## Kết luận

```sql
BEGIN;
SET LOCAL statement_timeout = '5s';

-- ① Khóa lạc quan như P6-1, đơn vị là case
SELECT status, (SELECT count(*) FROM case_alerts WHERE case_id=$1) AS n
FROM cases WHERE case_id = $1 FOR UPDATE;
--    status đã rời 'investigating' → ROLLBACK, 409

-- ② Case
UPDATE cases
SET status = $conclusion,          -- concluded_fp | concluded_policy_violation | confirmed_incident
    conclusion_reason = $reason, concluded_by = $user_id, concluded_at = now()
WHERE case_id = $1;

-- ③ Mọi alert trong case, kể cả bản sao của chúng
UPDATE alerts
SET status = $alert_status, closed_at = now(), sealed_at = now(), close_reason = $reason
WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = $1)
   OR duplicate_of IN (SELECT alert_id FROM case_alerts WHERE case_id = $1);

-- ④ Một dòng audit cho cả case, kèm đề xuất ②
INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload)
VALUES ('tier2.concluded', $1, $user_id, 'analyst',
        jsonb_build_object('conclusion', $conclusion, 'reason', $reason,
                           'alert_count', $n,
                           'llm_suggestion', $llm_suggestion,
                           'llm_confidence', $llm_confidence));
COMMIT;
```

**Bốn chi tiết:**

1. **`OR duplicate_of IN (…)` là bắt buộc.** `case_alerts` chỉ chứa dòng gốc của mỗi cụm. Thiếu vế này, hàng nghìn bản sao ở lại trạng thái cũ trong khi case đã kết luận.
2. **`sealed_at = now()`** — case đã kết luận thì cụm ngừng hút. Đây là lúc `sealed_at` được đặt cho cụm đã escalate (Phase 6 cố ý không đặt).
3. **`statement_timeout` 5 giây**, dài hơn Phase 6, vì `UPDATE` chạm nhiều dòng hơn.
4. **Một dòng audit cho cả case**, `subject_id = case_id`.

### Ba kết luận, và cái thứ ba là điểm dừng

| Kết luận | `alerts.status` | Ý nghĩa |
|---|---|---|
| `concluded_fp` | `closed_fp` | Không phải sự cố |
| `concluded_policy_violation` | `closed_benign` | Có vi phạm nội quy, không phải tấn công |
| `confirmed_incident` | `closed_confirmed` | **Là sự cố thật** |

> **`confirmed_incident` là điểm dừng phạm vi đồ án.** Case đổi trạng thái và dừng — không có bước ứng cứu, cách ly, hay khắc phục. Tier 3 đã được thiết kế trong kiến trúc nhưng **chưa hiện thực**.
>
> Điều này phải được nói rõ trong báo cáo: hệ thống **phát hiện và phân loại**, không **ứng cứu**. Một hội đồng đọc "confirmed_incident" mà tưởng có hành động tự động theo sau là hiểu sai phạm vi.

---

## Xử lý lỗi

| Tình huống | Mã | Hành động |
|---|---|---|
| Case đã được người khác kết luận | `409` | Trả ai, kết luận gì, lúc nào |
| Model timeout khi chạy ② | — | Trả lỗi cho analyst, **không** retry nền (đồng bộ, người đang chờ) |
| Model trả JSON sai | — | Thử lại 1 lần; vẫn sai → báo lỗi, analyst tự làm |
| `evidence` chứa `alert_id` ngoài case | — | Bỏ khỏi giao diện, ghi `citation_warnings` |
| Injection mức cao | — | Cấm `false_positive`, ép `need_more_data` |
| Vượt `CASE_PROMPT_BUDGET_TOKENS` | — | Cắt tầng 3 → tầng 2, ghi `citation_warnings`, vẫn gửi |
| Tham số tool ngoài allowlist | — | Từ chối **trước khi chạy**, tính một vòng, ghi `agent_trace.status='rejected_arg'` |
| Một tool lỗi hoặc timeout | — | Ghi `status='error'\|'timeout'` vào vòng đó, model **đi tiếp** với dữ liệu đã có |
| Hết `TOOL_MAX_ROUNDS` / `TOOL_WALL_CLOCK_BUDGET_S` / `CASE_SESSION_BUDGET_TOKENS` | — | **Ép trả kết luận**, ghi `stopped_by` + `citation_warnings` — không trả lỗi |
| Injection mức cao trong **kết quả tool** | — | Như injection prompt gốc: cấm `false_positive`, ép `need_more_data` |
| Analyst không có vai trò Tier 2 | `403` | Ghi `authz.denied` |
| `statement_timeout` khi kết luận case lớn | `503` | Rollback; case không kết luận một nửa |

> **② hỏng không chặn kết luận.** Analyst vẫn kết luận được bằng tay — đây là ràng buộc G7 áp ở chặng cuối.

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng |
|---|---|---|
| I1 | Kết luận áp cho **toàn case + mọi bản sao** trong một transaction | Test kill giữa chừng |
| I2 | Kết luận set `closed_at` **và** `sealed_at` cho mọi alert | Test cụm ngừng hút sau kết luận |
| I3 | ② **không** đổi `status` của case hay alert | Test |
| I4 | Mỗi lần chạy ② ghi một dòng `llm_runs` mới, không ghi đè | Test chạy 3 lần |
| I5 | Ghi chú analyst và kết quả ② lần trước **đều** qua `security/` | Test injection tích lũy |
| I6 | `evidence` được đối chiếu với `case_alerts` | Test model bịa id |
| I7 | ② hỏng không chặn analyst kết luận | Test tắt LLM |
| I8 | Case chỉ mở rộng khi có người bấm | Review |
| I9 | Mọi tool **chỉ đọc** — không `INSERT`/`UPDATE`, không đổi `status` | Test quét AST + review |
| I10 | Mọi tham số tool nằm trong allowlist dựng từ chính case | Test tham số bịa |
| I11 | Kết quả tool **mọi vòng** đều qua `security/` | Test injection ở vòng 2 |
| I12 | Hết ngân sách vòng lặp vẫn **trả kết luận**, không trả lỗi | Test ép cả ba đường dừng |

---

## Test bắt buộc

```
# Prompt ba tầng — P7-1
test_case_200_alert_prompt_van_duoi_30000_token
test_cat_theo_thu_tu_tang3_tang2
test_tang1_khong_bao_gio_bi_cat
test_dai_dien_gom_ca_cum_lon_nhat_va_alert_moi_nhat

# Case đang tiếp diễn — P7-2
test_case_dang_dieu_tra_van_hut_ban_sao
test_chay_hai_lan_ghi_hai_dong_llm_runs           # I4
test_llm_runs_ghi_kem_anh_chup_so_lieu
test_cum_moi_khong_tu_dong_vao_case               # I8

# Injection
test_ghi_chu_analyst_duoc_boc                     # I5
test_ket_qua_lan_truoc_duoc_boc                   # injection tích lũy
test_injection_cao_ep_need_more_data
test_evidence_id_ngoai_case_bi_loai               # I6

# Kết luận
test_ket_luan_dong_ca_ban_sao_khong_chi_dong_goc  # I1
test_ket_luan_set_sealed_at                       # I2
test_cum_ngung_hut_sau_ket_luan
test_kill_giua_ket_luan_khong_co_case_mot_nua
test_hai_analyst_ket_luan_nguoi_sau_nhan_409
test_confirmed_incident_dung_lai_khong_co_buoc_tiep

# Vòng lặp tool — P7-8
test_tool_chi_doc_khong_ghi                       # I9
test_tham_so_ngoai_allowlist_bi_tu_choi           # I10
test_alert_id_ngoai_case_khong_goi_duoc_tool
test_ket_qua_tool_duoc_boc_untrusted_data         # I11
test_injection_vong_2_ep_need_more_data           # I11
test_dau_hieu_da_cat_cua_tool_nam_trong_lop_boc
test_het_max_rounds_van_tra_ket_luan              # I12
test_het_wall_clock_van_tra_ket_luan              # I12
test_het_session_token_van_tra_ket_luan           # I12
test_agent_trace_ghi_du_moi_vong_ke_ca_bi_tu_choi
test_mot_tool_loi_khong_hong_ca_phien
test_vong_lap_tool_khong_bao_gio_doi_status       # I3

# Không phụ thuộc model
test_tat_llm_van_ket_luan_duoc                    # I7
test_2_khong_bao_gio_doi_status                   # I3
```

---

## Quyết định đã chốt

| # | Vấn đề | Chốt | Căn cứ |
|---|---|---|---|
| **P7‑1** | "Đọc toàn bộ case" | **Prompt ba tầng** có trần 30.000 token | 200 alert thô ≈ 50.000 token, phần lớn lặp |
| **P7‑2** | Case tiếp tục hút alert | Giữ (D‑C5); mỗi lần ② ghi kèm ảnh chụp số liệu | Đợt tấn công còn diễn ra là thông tin cần |
| **P7‑3** | Case tự mở rộng sang cụm mới | **Không** — chỉ khi có người bấm | Tự động gom tạo case không ai chịu trách nhiệm |
| **P7‑4** | Ghi chú analyst có phải bọc không | **Có** — cùng với kết quả ② lần trước | Injection tích lũy qua các vòng |
| **P7‑5** | `evidence` model trả về | Đối chiếu `case_alerts`, loại id lạ | Bằng chứng bịa nguy hiểm hơn không có |
| **P7‑6** | ② timeout | Báo lỗi ngay, **không** retry nền | Đồng bộ — người đang chờ |
| **P7‑7** | Sau `confirmed_incident` | **Dừng** — ngoài phạm vi đồ án | Tier 3 thiết kế rồi, chưa hiện thực |
| **P7‑8** | ② có được gọi tool không | **Có** — 8 tool chỉ đọc, allowlist tham số, 3 ngân sách | `V1` chỉ ràng buộc ①; ② vốn đã không tất định (P7‑2) |

### Việc còn lại

1. **`CASE_PROMPT_BUDGET_TOKENS = 30.000` chưa kiểm chứng** — đo phân bố kích thước case thật.
2. **Trạng thái `closed_confirmed`** cần thêm vào máy trạng thái của `alerts` ở mục II‑06 — hiện chưa có.
3. **Giao diện phải hiện nhãn "đang tiếp diễn"** khi `last_seen_at` mới hơn `last_analyzed_at`.
4. **Ba hằng số của P7‑8 chưa kiểm chứng** — `TOOL_MAX_ROUNDS`, `TOOL_WALL_CLOCK_BUDGET_S`, `CASE_SESSION_BUDGET_TOKENS`. Đo phân bố số vòng thật rồi chỉnh.
5. **Tool gọi ra ngoài (n8n / VirusTotal / MISP) — CHƯA CHỐT, cố ý để trống.** Danh mục P7‑8 chỉ có tool nội bộ. Mở tool ra ngoài kéo theo ba thứ chưa có lời giải: bề mặt SSRF khi tham số do model chọn · `N8N_TIMEOUT_S = 10` × số vòng phá `TOOL_WALL_CLOCK_BUDGET_S` · hạn ngạch API ngoài mà phép đo ③ của `KT` §B7 đang tính là tiết kiệm được. Cần người chủ trì đồ án quyết.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `llm/` | Gọi model, dựng prompt | `tier2/` → `llm/` ✅ |
| `security/` | Bọc mọi dữ liệu không tin cậy | `tier2/` → `security/` ✅ |
| `kb/` | Playbook theo `category` của case; tool `get_playbook` | `tier2/` → `kb/` ✅ |
| `domain/` | Chuyển trạng thái case + alert; tool `get_alert_detail` · `search_case_timeline` · `get_correlation_summary` | `tier2/` → `domain/` ✅ |
| `infra/` | DB, auth, config | `tier2/` → `infra/` ✅ |
| `audit/` | `case.analyzed`, `tier2.concluded`; tool `get_audit_history` | `tier2/` → `audit/` ✅ |
| `enrichment/` | Tool `lookup_ioc` · `lookup_asset` · `lookup_identity` (P7‑8) | `tier2/` → `enrichment/` ✅ |

Phase này **không** import `ingest/`, `soar/`, `tier1/`.

---

*Đặc tả Phase 7 · Điều tra Tier 2 và kết luận · 8 điểm chốt (P7‑1…P7‑8) · điểm dừng phạm vi đồ án*
