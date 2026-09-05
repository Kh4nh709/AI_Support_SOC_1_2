# Kiến trúc tổng quát và chi tiết

**AI Support SOC** · bản hợp nhất sau C1–C5 · Đề xuất 1 · M1–M5 · B1–B6

> Tài liệu này thay thế mô tả kiến trúc trong `Kiến_trúc.html` Phần II ở những chỗ mâu thuẫn.

**Bộ đặc tả thi hành — bảy phase:**

| Phase | Tệp | Package chủ trì | Tính chất |
|---|---|---|---|
| 1 · Tiếp nhận + chuẩn hóa | `phase-tiep-nhan-chuan-hoa.md` | `ingest/` | Đồng bộ, hàm thuần |
| 2 · Chống trùng lặp | `phase-2-chong-trung-lap.md` | `ingest/` | Đồng bộ, trong khóa |
| 3 · Tự động đóng nhiễu | `phase-3-auto-close.md` | `ingest/` | Đồng bộ, trong khóa |
| 4 · Làm giàu + tương quan | `phase-4-enrichment.md` | `soar/` `enrichment/` | Nền, worker |
| 5 · ① Auto-triage | `phase-5-auto-triage.md` | `tier1/` `llm/` | Nền, **ngoài trục chính** |
| 6 · Hàng đợi + quyết định T1 | `phase-6-tier1.md` | `tier1/` | Đồng bộ, con người |
| 7 · Điều tra + kết luận T2 | `phase-7-tier2.md` | `tier2/` `llm/` | Đồng bộ, con người |

---

# PHẦN A — KIẾN TRÚC TỔNG QUÁT

## A1 · Bài toán và phạm vi

Một SOC nhỏ nhận vài nghìn alert mỗi ngày từ Wazuh. Phần lớn là nhiễu lặp lại; phần còn lại cần người đọc. Hệ thống này chen vào giữa SIEM và analyst để làm ba việc:

1. **Lọc** — bỏ bản sao và nhiễu đã biết trước khi tốn công gì
2. **Làm giàu** — bổ sung ngữ cảnh tài sản, danh tính, IoC
3. **Gợi ý** — LLM đề xuất, người quyết, hệ thống ghi cả hai để so

**Điểm dừng phạm vi:** Tier 3 (ứng cứu, khắc phục) đã thiết kế nhưng **chưa hiện thực**. Luồng kết thúc khi Tier 2 kết luận.

**Nguyên tắc xuyên suốt:** *LLM đề xuất, người quyết.* Không trạng thái nào phụ thuộc việc gọi model thành công. Model chết thì hệ thống suy biến về một SIEM có dedup — vẫn dùng được.

## A2 · Thành phần hệ thống

```
┌────────────┐   webhook    ┌──────────────────────────────┐
│   Wazuh    │─────────────▶│      Ứng dụng AI Support     │
│  Manager   │   (HTTP)     │   ingest · soar · tier1/2    │
└────────────┘              └───────┬──────────┬───────────┘
                                    │          │
                       gọi ra ▼     │          │  ▼ gọi ra
                  ┌──────────────┐  │          │  ┌──────────────┐
                  │     n8n      │◀─┘          └─▶│   LLM API    │
                  │ CMDB·AD·VT·  │                │  (2 điểm)    │
                  │    MISP      │                └──────────────┘
                  └──────────────┘
                                    │
                            ┌───────▼────────┐
                            │   PostgreSQL   │
                            │  dữ liệu + hàng│
                            │   đợi job      │
                            └────────────────┘
```

**Bốn quyết định hình dạng:**

| Quyết định | Vì sao |
|---|---|
| Wazuh đẩy **thẳng** vào ứng dụng, không qua n8n | n8n là dịch vụ **được gọi**, không đứng chắn trước app — nó hỏng thì enrichment thiếu, chứ không mất alert |
| Hàng đợi job nằm **trong PostgreSQL** (`SELECT … FOR UPDATE SKIP LOCKED`) | Không cần Redis. Đủ cho quy mô đồ án; hàng đợi và dữ liệu cùng một transaction |
| Dedup và auto-close chạy **trong webhook**, trước enrichment | Chống ngập hàng đợi và tiết kiệm hạn ngạch API — xem A4 |
| Correlation **không lưu**, tính lúc hiển thị | Lưu thì phải cập nhật; cập nhật thì có lúc quên |

## A3 · Bốn tầng nghiệp vụ và bảy hạ tầng

```
   TẦNG NGHIỆP VỤ  (dữ liệu chảy qua theo thứ tự, KHÔNG import lẫn nhau)
   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │ ingest/ │──▶│  soar/  │──▶│ tier1/  │──▶│ tier2/  │
   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
        │             │             │             │
        └─────────────┴──────┬──────┴─────────────┘
                             ▼  chỉ được import XUỐNG
   ┌──────────────────────────────────────────────────────┐
   │  domain/   infra/   audit/   security/               │
   │  llm/      kb/      enrichment/                      │
   └──────────────────────────────────────────────────────┘
```

| Package | Vai trò một câu |
|---|---|
| `ingest/` | Cửa vào: nhận · chuẩn hóa · phân loại · dedup · auto-close |
| `soar/` | Làm giàu ngữ cảnh qua n8n, chấm `risk_score`, đẩy vào hàng đợi |
| `tier1/` | Hàng đợi phân loại, LLM ①, quyết định của analyst Tier 1 |
| `tier2/` | Gom case, LLM ②, kết luận điều tra |
| `domain/` | Model + máy trạng thái + truy vấn correlation. **Nơi duy nhất đổi trạng thái** |
| `infra/` | DB, hàng đợi job, worker, auth, config. Đáy cây phụ thuộc |
| `audit/` | Ghi vết append-only: `audit_events`, `llm_runs` |
| `security/` | Bọc dữ liệu không tin cậy trước khi vào prompt |
| `llm/` | Gọi model. **Một điểm dựng prompt duy nhất** cho cả hai pipeline |
| `kb/` | Tra playbook tất định theo `category`. RAG chỉ là dự phòng. Cấp tool `get_playbook` cho ② |
| `enrichment/` | Tra asset/identity/IoC tất định trên DB nội bộ. Không gọi model, không gọi API ngoài. Cấp ba tool đọc cho ② (P7‑8) |

## A4 · Luật phụ thuộc — xương sống

> **Tầng nghiệp vụ không bao giờ import lẫn nhau.** Bàn giao đi qua **hàng đợi job**, không qua lời gọi hàm.

Tier 1 muốn chuyển cho Tier 2 thì gọi `domain.escalate()` → đổi trạng thái → đẩy job → worker Tier 2 tự nhặt. Luật này **được cưỡng chế bằng test quét AST**, không phải chỉ ghi trong tài liệu.

**Hai hệ quả cụ thể của luật này:**

- `autoclose` phải chuyển từ `soar/` sang `ingest/`. Muốn tiết kiệm hạn ngạch API thì phải chạy trước enrichment; chạy trước enrichment nghĩa là chạy trong webhook; để ở `soar/` thì `ingest/` phải import `soar/` — vi phạm luật.
- `correlation` phải chuyển từ `soar/` sang `domain/`, vì có ba nơi dùng (Tier 1 khi mở alert, Tier 2 khi gom case, pipeline ① khi dựng prompt). Để ở tầng nào thì hai nơi kia đều import chéo.

## A5 · Bốn điểm kết thúc và ba nhánh dừng sớm

```
Wazuh ─▶ ingest/ ─┬─▶ ① TRÙNG LẶP        (duplicate)      ← dừng sớm 1
                  ├─▶ ② NHIỄU ĐÃ BIẾT    (auto_closed)    ← dừng sớm 2
                  └─▶ soar/ ─▶ tier1/ ─┬─▶ ③ TIER 1 ĐÓNG  ← dừng sớm 3
                                       └─▶ tier2/ ─▶ ④ KẾT LUẬN
```

| # | Điểm kết thúc | Ở đâu | Tốn gì |
|---|---|---|---|
| ① | `duplicate` | `ingest/` đồng bộ | 1 `SELECT` + 2 `INSERT`/`UPDATE` |
| ② | `auto_closed` | `ingest/` đồng bộ | + khớp rule + 3 SELECT enrichment nội bộ |
| ③ | `closed_fp` / `closed_benign` | `tier1/`, người quyết | + enrichment ngoài + 1 lần gọi ① |
| ④ | `concluded_fp` · `concluded_policy_violation` · `confirmed_incident` | `tier2/`, người quyết | + 1 lần gọi ② |

**Ba nhánh dừng sớm là ba cơ chế giảm tải**, và chúng xếp theo thứ tự rẻ dần từ trên xuống — cái rẻ nhất chặn nhiều nhất.

Vì cả ba đều nằm ở `received`/`ingest/`, trạng thái `enriching` **chỉ còn một lối ra**: đã tốn công làm giàu thì alert phải tới tay analyst.

## A6 · Hai điểm chạm LLM

| | ① Auto-triage | ② Trợ lý điều tra |
|---|---|---|
| Chạy khi | Worker, **song song** với hàng đợi | Đồng bộ, chỉ khi analyst bấm |
| Package | `tier1/` + `llm/` | `tier2/` + `llm/` |
| Đầu vào | 1 alert + ngữ cảnh + playbook | Toàn bộ case + mọi alert đã gom |
| Vai trò | **Hỗ trợ lọc** — *đáng mở ra xem không?* | **Hỗ trợ điều tra** — *chuyện gì đã xảy ra?* |
| Tra cứu thêm | **Không** — tất định ở Phase 4 (P5‑6) | **Được gọi tool đọc**, 8 tool nội bộ (P7‑8) |
| Ai quyết | Analyst Tier 1 | Analyst Tier 2 |
| Hỏng thì sao | Cờ `unavailable`, alert vẫn vào hàng đợi | Analyst tự làm, không chặn |

**Nằm ngoài trục chính.** ① chạy song song với việc alert vào hàng đợi — hỏng cũng không chặn ai.

**Luật cứng về dữ liệu không tin cậy:** mọi nội dung không do người dùng hợp pháp gõ (`raw_log`, kết quả tool, ghi chú analyst) đều phải qua `security/` trước khi vào prompt. Không ngoại lệ — kể cả **kết quả tool ở mọi vòng** của ② (P7‑8).

---

# PHẦN B — KIẾN TRÚC CHI TIẾT

## B1 · Trách nhiệm từng package

### `ingest/` — cửa vào

| | |
|---|---|
| **Vào** | Envelope JSON từ Wazuh (có hoặc không có `_source`) |
| **Ra** | `201` + một dòng `alerts`, có thể kèm một dòng `jobs` |
| **Dùng** | `domain/` (kiểu + chuyển trạng thái) · `infra/` (DB, auth, config) · `audit/` · `enrichment/` (làm giàu nội bộ cho alert auto-close) |
| **Không dùng** | `soar/` `tier1/` `tier2/` `llm/` `kb/` |

Ba khối: **Phase 1** (parse, phân loại, băm — hàm thuần) → **Phase 2** (dedup) → **Phase 3** (auto-close).

### `soar/` — làm giàu

| | |
|---|---|
| **Vào** | Job `enrich` từ hàng đợi |
| **Ra** | `UPDATE alerts` (ngữ cảnh + `risk_score`), `status = queued_tier1` |
| **Dùng** | `enrichment/` (nội bộ) · n8n qua HTTP (ngoài) · `domain/` · `audit/` |

Kết quả mỗi lookup ghi **ba trạng thái**: `found` · `not_found` · `skipped`. `skipped` **không** phải tín hiệu an ninh và **không** được trừ điểm `risk_score`.

### `tier1/` — phân loại

| | |
|---|---|
| **Vào** | Alert ở `queued_tier1`; thao tác của analyst |
| **Ra** | `closed_fp` / `closed_benign`, hoặc `escalated_tier2` + một `Case` |
| **Dùng** | `domain/` · `llm/` · `kb/` · `security/` · `audit/` |

### `tier2/` — điều tra

| | |
|---|---|
| **Vào** | Case ở `investigating`; thao tác của analyst |
| **Ra** | Một trong ba kết luận, áp cho toàn case trong một transaction |
| **Dùng** | `domain/` · `llm/` · `kb/` · `security/` · `audit/` |

## B2 · Mô hình dữ liệu

```
                    ┌──────────────┐
                    │    alerts    │◀────┐ duplicate_of (tự tham chiếu)
                    └──┬────┬───┬──┘─────┘
          case_id  ┌───┘    │   └────┐ autoclose_rule_id
                   ▼        │        ▼
            ┌──────────┐    │  ┌──────────────────┐
            │  cases   │    │  │ autoclose_rules  │
            └────┬─────┘    │  └──────────────────┘
                 │          │
          ┌──────▼──────┐   │   ⇄ nối theo GIÁ TRỊ, không FK cứng
          │ case_alerts │   ├──▶ assets · identities · iocs
          └─────────────┘   │
                            └──▶ audit_events · llm_runs   (append-only)
                                 jobs · rejected_alerts
```

### Thay đổi so với bản gốc

| Bảng/cột | Thay đổi | Chốt |
|---|---|---|
| `alerts.fingerprint` | **Đổi tên** → `event_bucket_hash` | B6 |
| `alerts.sealed_at` | **Thêm** `timestamptz NULL` | B4 |
| `alerts.id_synthesized` | **Bỏ** — cờ không bao giờ `True` | B5 |
| `alerts.srcip` / `dstip` | `TEXT NOT NULL DEFAULT ''` (trước: nullable) | B1 |
| `alerts.src_port` / `dst_port` | `INT NOT NULL DEFAULT 0` (trước: nullable) | C2 |
| `alerts.categories` | Mảng, sắp theo độ ưu tiên | C5 |
| `alerts.srcip_is_private` / `dstip_is_private` | **Thêm** `bool NULL` | C4 |
| `alerts.raw_log_truncated` | Ngưỡng 1000 KB | C3 |
| `autoclose_rules` | Bảng mới | VI‑08 |

### Ba quyết định lưu trữ

1. **Enrichment không có bảng riêng** — nằm trong `llm_runs.user_message` (chính prompt đã gửi), để dựng lại đúng thứ model từng thấy.
2. **Feedback loop không có bảng riêng** — đề xuất LLM và quyết định người dùng chung `subject_id`, khớp bằng `JOIN`.
3. **Correlation không lưu** — tính lại mỗi lần; chỉ "đóng băng" thành `case_alerts` khi có người xác nhận đáng điều tra.

### Ba định nghĩa phải nhớ

| Khái niệm | Vị từ | Sai lầm thường gặp |
|---|---|---|
| **Một cụm** | `duplicate_of IS NULL` | `COUNT(DISTINCT event_bucket_hash)` — cao gấp nhiều lần thực tế |
| **Đã kết thúc vòng đời** | `closed_at IS NOT NULL` | — |
| **Cụm còn hút bản sao** | `closed_at IS NULL OR sealed_at IS NULL` | Dùng chung vị từ với "đã đóng" |

## B3 · Máy trạng thái — hai trục tách bạch

**Trục 1 · `status` — vị trí trong quy trình người**

```
received ──┬──▶ duplicate        ← kết thúc vòng đời, nhưng KHÔNG terminal — xem (*)
           ├──▶ auto_closed                                  (terminal)
           └──▶ enriching ──▶ queued_tier1 ──▶ tier1_active ──┬──▶ closed_fp        (terminal)
                                   ╎                          ├──▶ closed_benign    (terminal)
                                   ╎                          └──▶ escalated_tier2
                                   ╎  fan-out escalate ③a:                │
                                   └──▶ escalated_tier2                   │
                                        cụm tương quan cũng rời           │
                                        hàng đợi ngay lúc escalate        │
                                                     ┌───────────────────┘
                                                     ▼  (Tier 2 kết luận, fan-out)
                                     closed_fp | closed_benign | closed_confirmed   (terminal)

  (*) `duplicate` đạt G3 (có `closed_at`) nhưng `status` vẫn bị fan-out ghi đè — ba cạnh ra:
      Tier 1 đóng cụm → `closed_fp | closed_benign` · Tier 2 kết luận → `closed_*`.
      Escalate là ngoại lệ: KHÔNG đổi `status` của bản sao, chỉ gắn `case_id` (phase-6 ③b).
      "Kết thúc vòng đời" (G3) và "terminal" (status hết chuyển tiếp) là HAI khái niệm khác nhau.

   Case:  investigating ──▶ concluded_fp | concluded_policy_violation | confirmed_incident
```

| Kết luận case | `alerts.status` tương ứng |
|---|---|
| `concluded_fp` | `closed_fp` |
| `concluded_policy_violation` | `closed_benign` |
| `confirmed_incident` | `closed_confirmed` ← **trạng thái mới, chưa có trong II‑06 bản gốc** |

**`queued_tier1` do `soar/` đặt ở cuối Phase 4, KHÔNG phải do pipeline ① đặt.** Mục 05 bản gốc để ① đặt trạng thái này, khiến model hỏng có thể làm alert trễ tới ~8 phút — vi phạm G7. Xem P5‑1.

**Trục 2 · xử lý nền** — `triage_status`, `risk_score`, `llm_runs`, cột enrichment.

> **"Terminal" nghĩa là `status` không chuyển tiếp nữa, KHÔNG có nghĩa là dòng bị đóng băng.** Alert `auto_closed` vẫn nhận ngữ cảnh nội bộ (M1) và, nếu là mẫu đối chứng, nhận cả kết quả ①. Không ai đổi `status` nên ràng buộc *"chỉ `domain/` được đổi trạng thái"* vẫn nguyên vẹn.

## B4 · Ranh giới cụm — bốn hằng số, bốn câu hỏi

| Hằng số | Giá trị | Trả lời câu hỏi |
|---|---|---|
| `DEDUP_IDLE_GAP_MINUTES` | 15 | Đợt tấn công đã dừng chưa? |
| `MAX_CLUSTER_AGE_HOURS` | 4 | Cụm thường sống quá lâu chưa? |
| `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES` | 30 | Cụm **nhiễu** sống quá lâu chưa? |
| `MAX_CLUSTER_SIZE` | 1000 | Cụm to quá chưa? |

Cả bốn thay cho ba vai trò mà bucket 5 phút từng gánh ngầm. Khóa cụm là **4 cột định danh** (`rule_id`, `srcip`, `dstip`, `agent_name`), so bằng `=` thuần.

## B4b · Chấm điểm rủi ro

```python
risk_score = min(100, RISK_BASE[severity] + min(CONTEXT_CAP, context))
```

`context` cộng từ bốn nguồn: mức trọng yếu tài sản · danh tính đặc quyền · uy tín IoC · số lần lặp của cụm.

**Ngữ nghĩa:** *severity quyết định, ngữ cảnh điều chỉnh — tối đa một bậc.*

| Tính chất | Vì sao |
|---|---|
| Chỉ cộng, không trừ | `skipped` và `not_found` cùng đóng góp `0` — thiếu dữ liệu không kéo điểm xuống |
| Sàn là `RISK_BASE[severity]` | Enrichment hỏng hoàn toàn thì điểm vẫn bằng đánh giá của SIEM |
| Tất định | Hàm thuần, test không cần DB. Điều kiện để phép đo độ khớp có nghĩa (V1) |
| `CONTEXT_CAP` giới hạn nghịch đảo | Ngữ cảnh nâng được tối đa **một bậc** severity, không phải hai |
| Hiển thị theo **dải**, không phải số trần | 0–24 Thấp · 25–49 Vừa · 50–74 Cao · 75–100 Rất cao |

**Không có ngưỡng nào đặt trên `risk_score`** trong toàn hệ thống — nó chỉ dùng để `ORDER BY` hàng đợi Tier 1 và để đưa vào prompt ①. Không tự đóng, không tự escalate.

Cột `risk_score_components jsonb` lưu từng khoản cộng, phục vụ giải thích trong giao diện và hiệu chỉnh trọng số về sau.

## B5 · Bảng hằng số cấu hình đầy đủ

```python
# ── Thời gian & hiển thị ──────────────────────────────
DISPLAY_TZ                          = "Asia/Ho_Chi_Minh"

# ── Kích thước: ba vai trò, ba nơi cắt ────────────────
MAX_PAYLOAD_BYTES                   = 2_097_152   # 2 MB    · chặn 413   → infra/
RAW_LOG_MAX_BYTES                   = 1_024_000   # 1000 KB · lưu trữ    → ingest/
PROMPT_LOG_MAX_BYTES                = 4_096       # 4 KB    · vào prompt → llm/
assert MAX_PAYLOAD_BYTES > RAW_LOG_MAX_BYTES

# ── Ranh giới cụm ─────────────────────────────────────
DEDUP_IDLE_GAP_MINUTES              = 15
MAX_CLUSTER_AGE_HOURS               = 4
MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES  = 30
MAX_CLUSTER_SIZE                    = 1000

# ── Triage lại ────────────────────────────────────────
RETRIAGE_FACTOR                     = 10
RETRIAGE_ABS_DELTA                  = 200

# ── Transaction ───────────────────────────────────────
STATEMENT_TIMEOUT                   = "3s"
IDLE_IN_TRANSACTION_TIMEOUT         = "10s"
TXN_BUDGET_MS                       = 5000

# ── Chấm điểm rủi ro (Phase 4) ────────────────────────
RISK_BASE   = {"critical": 70, "high": 50, "medium": 28, "low": 10}
CONTEXT_CAP = 25          # trần TỔNG cho mọi khoản thưởng ngữ cảnh

# ── Auto-close (Phase 3) ──────────────────────────────
AUTOCLOSE_SAMPLE_RATE               = 0.05
AUTOCLOSE_SAMPLE_MAX_PER_RULE_DAY   = 20
AUTOCLOSE_RULE_WIDTH_ALERT_PCT      = 30
RULE_CACHE_TTL_SECONDS              = 60
NEVER_AUTOCLOSE_AGENTS              = []
NAT_AGENTS                          = []

# ── Hàng đợi job (Phase 4) ────────────────────────────
JOB_MAX_ATTEMPTS                    = 3
JOB_BACKOFF                         = [10, 60, 300]   # giây
JOB_LOCK_TIMEOUT_S                  = 300             # worker chết → nhặt lại

# ── n8n (Phase 4) ─────────────────────────────────────
N8N_TIMEOUT_S                       = 10
N8N_RETRY                           = 0               # một tầng retry duy nhất, ở job
N8N_CIRCUIT_FAIL_THRESHOLD          = 5
N8N_CIRCUIT_OPEN_SECONDS            = 60
CLOCK_SKEW_WARN_SECONDS             = 300

# ── Ngân sách prompt (Phase 5, 7) ─────────────────────
PROMPT_TOTAL_BUDGET_TOKENS          = 12_000          # ① một alert
CASE_PROMPT_BUDGET_TOKENS           = 30_000          # ② một case · LƯỢT DỰNG ĐẦU

# ── Vòng lặp tool của ② (Phase 7, P7‑8) ───────────────
TOOL_MAX_ROUNDS                     = 6               # CHƯA KIỂM CHỨNG
TOOL_WALL_CLOCK_BUDGET_S            = 60              # CHƯA KIỂM CHỨNG · người đang chờ
TOOL_RESULT_MAX_TOKENS              = 2_000           # trần MỘT kết quả tool
CASE_SESSION_BUDGET_TOKENS          = 60_000          # trần TÍCH LŨY cả vòng lặp
assert CASE_SESSION_BUDGET_TOKENS > CASE_PROMPT_BUDGET_TOKENS

# ── Tier 1 / Tier 2 (Phase 6, 7) ──────────────────────
REVIEW_DELTA_TOLERANCE              = 20              # khóa lạc quan
MAX_ALERTS_PER_CASE                 = 200
SLA_ACK_MINUTES                     = None            # CHƯA CHỐT — theo quy trình SOC
# ── Xác thực & tích hợp ngoài (chốt 28/08) ────────────
JWT_TTL_HOURS                       = 8               # một ca trực · KHÔNG refresh token
JWT_SECRET                          = env             # BÍ MẬT — khai ở đây để §B5 còn đủ
N8N_BASE                            = env             # P4-4 · POST {N8N_BASE}/webhook/enrich
```

> **Bảy hằng số chưa được kiểm chứng bằng dữ liệu**, đánh dấu để chỉnh sau vài tuần chạy:
> `REVIEW_DELTA_TOLERANCE` · `PROMPT_TOTAL_BUDGET_TOKENS` · `CASE_PROMPT_BUDGET_TOKENS` · trọng số `risk_score`
> · `TOOL_MAX_ROUNDS` · `TOOL_WALL_CLOCK_BUDGET_S` · `CASE_SESSION_BUDGET_TOKENS`.
> `SLA_ACK_MINUTES` thì **chưa có giá trị nào** — cần thống nhất với quy trình của đơn vị.

## B6 · Ràng buộc bất biến toàn hệ thống

| # | Ràng buộc | Cưỡng chế bằng |
|---|---|---|
| G1 | Tầng nghiệp vụ không import lẫn nhau | Test quét AST |
| G2 | Chỉ `domain/` đổi `status`, mỗi **quyết định** đều ghi audit | `GRANT` mức cột + test quét AST |
| G3 | Mọi trạng thái kết thúc phải set `closed_at` | `CHECK` hoặc trigger |
| G4 | `srcip`/`dstip` không bao giờ `NULL` | `NOT NULL` |
| G5 | Mốc thời gian điều khiển do **DB** sinh, không phải SIEM hay Python | Review: cấm truyền tham số thời gian vào `UPDATE last_seen_at` |
| G6 | Mọi dữ liệu không tin cậy qua `security/` trước khi vào prompt | Một điểm dựng prompt duy nhất ở `llm/` |
| G7 | Không trạng thái nào phụ thuộc việc gọi model thành công | Test: tắt LLM, chạy hết luồng |
| G8 | Alert `severity=critical` không bao giờ bị auto-close | Test với rule khớp mọi thứ |
| G9 | `raw_payload` giữ nguyên vẹn, không cắt xén | Test so byte |
| G10 | Cấm `SELECT *` trên `alerts` trong truy vấn danh sách | Review |

## B7 · Ba phép đo của báo cáo

```sql
-- ① Khối lượng không tới tay analyst, theo tuần
SELECT date_trunc('week', received_at) AS tuan,
       count(*) FILTER (WHERE status='auto_closed')                  AS cum_tu_dong_dong,
       sum(occurrence_count) FILTER (WHERE status='auto_closed')     AS alert_tu_dong_dong,
       count(*) FILTER (WHERE duplicate_of IS NOT NULL)              AS gop_trung,
       count(*) FILTER (WHERE duplicate_of IS NULL
                          AND status <> 'auto_closed')               AS toi_hang_doi
FROM alerts WHERE NOT is_synthetic GROUP BY 1 ORDER BY 1;

-- ② Thời gian triage: mốc acknowledged_at → closed_at
--    LỌC `acknowledged_at IS NOT NULL`. Alert bị fan-out escalate (phase-6 ③a) kéo khỏi
--    hàng đợi mà chưa ai acknowledge sẽ có mốc đầu NULL — đưa vào sẽ làm hỏng trung vị.
-- ③ Độ khớp đề xuất ① với quyết định người: JOIN llm_runs ↔ audit_events theo subject_id
--    So trên `category` CHÍNH, không so trên tập `categories`
--    `subject_id` của llm_runs là alert_id, nên `tier1.escalated` PHẢI giữ subject_id =
--    alert_id. Đó là lý do escalate ghi HAI dòng audit chứ không đổi hẳn sang case_id.
```

### Ba công thức của báo cáo — mẫu số và tử số, viết ra để không ai tự suy

Cả ba tính **từ `alerts`, không `JOIN jobs`**. Đây là hệ quả trực tiếp của thứ tự
`dedup → auto-close → enrichment`: alert bị chặn ở webhook **không sinh job nào**, nên `jobs`
không biết gì về phần tiết kiệm được. Đếm bằng `jobs` sẽ ra 0.

```sql
-- ① Luận điểm chính "giảm false positive", theo tuần
--   MẪU SỐ  = count(*)                                        WHERE NOT is_synthetic
--   TỬ SỐ   = count(*) FILTER (WHERE status = 'auto_closed')
--           + count(*) FILTER (WHERE duplicate_of IS NOT NULL)
--   Hiệu chỉnh × (1 − tỉ lệ đóng nhầm)
--   tỉ lệ đóng nhầm = (mẫu đối chứng có result->>'suggested_action' IN ('escalate','needs_review'))
--                   / (mẫu đối chứng đã chạy ①)

-- ② "Số lời gọi model tiết kiệm được"
--   MẪU SỐ  = count(*)                          WHERE NOT is_synthetic  -- 1 alert = 1 job triage nếu không chặn
--   TỬ SỐ   = count(*) FILTER (WHERE duplicate_of IS NOT NULL)
--           + count(*) FILTER (WHERE status = 'auto_closed' AND triage_status = 'pending')
--   `triage_status='pending'` loại mẫu đối chứng (đã 'ready') và ca model hỏng (đã 'unavailable')

-- ③ "Hạn ngạch API ngoài tiết kiệm được" — chỉ đúng nhờ thứ tự dedup → auto-close → enrichment
--   TỬ SỐ   = count(*) FILTER (WHERE duplicate_of IS NOT NULL)
--           + count(*) FILTER (WHERE status = 'auto_closed' AND lookup_status IS NULL)
```

> **Vì sao cả ba tử số đơn điệu theo thời gian.** `auto_closed` **không có cạnh ra** trong bảng
> chuyển tiếp (`AUTO_CLOSED: ()` giữ nguyên rỗng — quyết định A). Nếu có một cạnh
> `auto_closed → escalated_tier2`, một cụm đã tính vào tử số sẽ rời khỏi đó **sau khi báo cáo đã
> in**, và cùng một tuần cho hai con số khác nhau ở hai lần chạy. Đó là lý do cạnh đó bị từ chối,
> không phải vì nó khó hiện thực.
>
> Analyst vẫn có đường sửa sai khi rule đóng nhầm: **tắt rule** (`phase-3` sweeper) cộng **mẫu
> đối chứng 5%** — cả hai nằm ngoài tử số nên không làm nó nhảy ngược.

**Ba điều chỉnh sau khi chuyển lớp auto-close:**

1. Alert auto-close có **ngữ cảnh nội bộ** nhưng không có IoC ngoài → hai nhóm không cùng bộ tín hiệu, phải nói rõ trong báo cáo.
2. Phân tách theo `autoclose_rule_id` phải **cộng `occurrence_count`**, không đếm dòng — sau M4 một cụm nhiễu chỉ là 1 dòng.
3. Kèm **tỉ lệ đóng nhầm ước lượng từ mẫu đối chứng 5%**. Một hệ thống đóng 60% alert mà không biết tỉ lệ sai thì con số 60% vô nghĩa.

---

# PHẦN C — SỔ QUYẾT ĐỊNH

| Mã | Vấn đề | Chốt |
|---|---|---|
| **C1** | Hai công thức băm mâu thuẫn | Theo Phần VI: bỏ `alert_user`, bucket 5 phút dạng số nguyên |
| **C2** | Cổng thiếu: `None` hay `0` | `0`, cột `INT NOT NULL DEFAULT 0` |
| **C3** | Ngưỡng cắt `raw_log` | 1000 KB lưu trữ; 4 KB cho prompt; 2 MB cho `413` |
| **C4** | IP nội bộ | Cờ `*_is_private` qua `ipaddress`; lookup 3 trạng thái |
| **C5** | `T1078` có trong bảng ánh xạ | Có, nhưng `T1110` ưu tiên cao hơn → bảng độ ưu tiên tường minh |
| **Đề xuất 1** | Khóa cụm | 4 cột trực tiếp, không dùng cột băm |
| **D‑C2** | Cửa sổ neo vào đâu | `last_seen_at`, cửa sổ trượt |
| **D‑C3** | Trần cụm | `MAX_AGE` + `MAX_SIZE` + trần riêng cho auto-closed |
| **D‑C4** | Định nghĩa cụm | `duplicate_of IS NULL` |
| **D‑C5** | Gốc đang ở Tier 2 | Vẫn gộp; giao diện phải hiện bộ đếm đang đổi |
| **D‑C6** | Vị từ "cụm còn hút" | `closed_at IS NULL OR sealed_at IS NULL` |
| **D‑C7** | Deploy | Restart thẳng, không rolling |
| **M1** | Enrichment cho alert auto-close | Có **nội bộ**, không có **ngoài** |
| **M2** | Mẫu đối chứng | Đi đường bình thường, enrichment đầy đủ |
| **M3** | `AUTO_CLOSED` terminal | Terminal về `status`, không đóng băng dòng |
| **M4** | Cụm auto-closed hút bản sao | Có |
| **M5** | Tài sản trọng yếu | `NEVER_AUTOCLOSE_AGENTS`, lớp 3b |
| **AC‑C1** | Auto-close trước hay sau ① | Trước, kèm mẫu đối chứng |
| **AC‑C5** | Toán tử `regex` trong rule | Không |
| **AC‑C6** | Ngưỡng rule quá rộng | 30% trên 7 ngày |
| **B1** | So sánh IP trong khóa cụm | `=` thuần trên `NOT NULL DEFAULT ''` — đo: 154 → 4 buffer |
| **B2** | Nguồn của `last_seen_at` | `now()` của DB, bỏ `GREATEST` |
| **B3** | Dời M1 ra sau `COMMIT` | Không — đo cho thấy không phải nút thắt |
| **B4** | Tắt rule có hiệu lực khi nào | Tức thì qua sweeper `sealed_at` + trần 30 phút |
| **B5** | `id_synthesized` | Bỏ; định nghĩa `is_synthetic` |
| **B6** | Tên cột băm | `event_bucket_hash` |
| **P4‑2** | Tương quan vào prompt | **Tóm tắt gộp** 20 dòng + 5 alert đại diện — đo: giảm 213 lần token |
| **P4‑3** | Công thức `risk_score` | Severity trội + `CONTEXT_CAP = 25`, hiển thị theo dải |
| **P5‑1** | Ai đặt `queued_tier1` | **`soar/`** ở cuối Phase 4 — ① không chạm `status` |
| **P6‑1** | Cụm phình giữa lúc xem và bấm | Khóa lạc quan, dung sai 20 |
| **P6‑3** | `sealed_at` khi đóng Tier 1 | Có khi đóng, **không** khi escalate |
| **P7‑1** | "Đọc toàn bộ case" | Prompt ba tầng, trần 30.000 token |
| **P7‑7** | Sau `confirmed_incident` | **Dừng** — Tier 3 ngoài phạm vi |
| **P7‑8** | ② có được gọi tool không | **Có** — 8 tool chỉ đọc, allowlist tham số, 3 ngân sách. `V1` chỉ ràng buộc ① |

## Giới hạn đã biết

| Giới hạn | Ảnh hưởng | Đường xử lý |
|---|---|---|
| Index chứa `sealed_at IS NULL` tăng đơn điệu | Kích thước index, thời gian `VACUUM` | Partition `alerts` theo tháng ở quy mô sản xuất |
| Cache rule TTL 60 giây | Tắt rule chậm tối đa 60 giây (sweeper bù phần cụm) | Hạ TTL hoặc thêm endpoint xóa cache |
| Bộ đếm mẫu trong tiến trình | Với `n` worker, trần thực tế là `n × 20` | Bảng đếm riêng, đặt ngoài transaction |
| Không rolling deploy | Cần dừng hẳn khi đổi khóa advisory | Hậu quả nếu bỏ qua: 2 cụm thay vì 1, không mất dữ liệu |
| Tier 3 chưa hiện thực | `confirmed_incident` là điểm dừng | Ngoài phạm vi đồ án |

---

*Kiến trúc tổng quát và chi tiết · AI Support SOC · hợp nhất C1–C5 · Đề xuất 1 · M1–M5 · B1–B6*
