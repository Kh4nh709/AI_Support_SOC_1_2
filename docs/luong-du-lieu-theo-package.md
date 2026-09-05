# Luồng dữ liệu theo package

**AI Support SOC** · đọc theo *thành phần nào xử lý*, không theo bước giao diện

> Bản này **thay thế** `luong-du-lieu-theo-package.html` — tệp đó dựng trước khi có Đề xuất 1, M1–M5 và B1–B6 nên đã sai ở khóa cụm, thứ tự enrichment và vị từ dedup.

---

## Sơ đồ toàn cảnh

```
                        Wazuh Manager
                              │ webhook (không qua n8n)
                              ▼
╔═════════════════════════════════════════════════════════════════════╗
║  ĐỒNG BỘ — một transaction webhook, trả 201 rồi mới có worker      ║
╠═════════════════════════════════════════════════════════════════════╣
║                                                                     ║
║  ingest/ · Phase 1 — hàm THUẦN, ngoài advisory lock                ║
║  parse → chuẩn hóa → phân loại (5 tầng) → event_bucket_hash        ║
║                              │                                      ║
║  ── BEGIN · statement_timeout=3s · TXN_BUDGET_MS=5000 ──            ║
║  ── pg_advisory_xact_lock(hashtext(cluster_key)) ──                ║
║                              ▼                                      ║
║  ingest/ · Phase 2 — dedup                                          ║
║  tra cụm còn hút theo 4 cột ─────────▶ ① duplicate ──▶ COMMIT      ║
║                              │                                      ║
║                              ▼ không trùng                          ║
║  ingest/ · Phase 3 — auto-close                                     ║
║  chặn critical + NEVER_AUTOCLOSE ──▶ khớp rule                     ║
║        │                                    │                       ║
║        │ không khớp          khớp ──▶ enrichment/ (nội bộ)         ║
║        │                                    └──▶ ② auto_closed     ║
║        ▼                                         └─ mẫu 5%? ─┐      ║
║  INSERT alerts + INSERT jobs ──▶ COMMIT ──▶ 201              │      ║
╚══════════════════════════════════════════════════════════════│══════╝
                              │                                │
   ═══ worker nhặt job từ đây ═══                              │
                              ▼                                ▼
                    soar/ + enrichment/  ◀────────────────────┘
                    n8n (CMDB·AD·VT·MISP) + 3 SELECT nội bộ
                              │  → risk_score
                              ▼
                    domain/ · status = queued_tier1
                              ├────────── song song ──────────┐
                              │                               ▼
                              │                    tier1/ + llm/ + kb/
                              │                    ① Auto-triage
                              │                    (ngoài trục chính)
                              ▼
                    tier1/ · analyst mở alert · acknowledged_at
                              ▼
                    domain/ · correlation ±2h (chỉ đọc)
                              ▼
                    tier1/ → domain/ · quyết định
                              ├──────────▶ ③ closed_fp / closed_benign
                              ▼ escalate
                    tier2/ + llm/ · ② Trợ lý điều tra
                              ▼
                    tier2/ → domain/ · kết luận
                              ▼
                    ④ concluded_fp · concluded_policy_violation
                       · confirmed_incident  ← điểm dừng phạm vi
```

---

## Chặng 1 · `ingest/` Phase 1 — tiếp nhận và chuẩn hóa

**Tính chất:** đồng bộ · **hàm thuần** · không I/O · nằm **ngoài** advisory lock

| Bước | Đọc | Ghi |
|---|---|---|
| Ánh xạ trường | payload | — |
| Ép kiểu an toàn | — | port thiếu → `0`, IP thiếu → `''` |
| Chuẩn hóa thời gian | — | `alert_time` UTC, `event_time` |
| Quy đổi severity | `rule.level` | `severity` |
| Phân giải category | mitre · groups · decoder · port | `category` + `categories` sắp theo ưu tiên |
| Tính `event_bucket_hash` | — | băm sự việc trong ô 5 phút |
| Cờ suy ra | — | `*_is_private`, `raw_log_truncated` |

**Chưa chạm DB.** Mọi việc nặng làm xong trước khi vào khóa — đây là lý do vùng tuần tự hóa ở chặng sau chỉ còn một `SELECT` và vài câu ghi.

**Lỗi:** thiếu trường bắt buộc → `400` + một dòng `rejected_alerts`. Sai API key → `401`, **không ghi gì cả**.

## Chặng 2 · `ingest/` Phase 2 — dedup

**Tính chất:** đồng bộ · trong transaction · **trong advisory lock**

```sql
pg_advisory_xact_lock(hashtext(rule_id||'|'||srcip||'|'||dstip||'|'||agent_name))
```

Khóa tính trên **khóa cụm**, không phải trên cột băm — đây là lỗi dễ sót nhất khi đọc bản cũ.

| Tra cụm còn hút | Giá trị |
|---|---|
| Khóa | `rule_id` = · `srcip` = · `dstip` = · `agent_name` = |
| Còn hút | `closed_at IS NULL OR sealed_at IS NULL` |
| Không phải bản sao | `status <> 'duplicate'` |
| Chưa dừng | `last_seen_at >= now() - 15 phút` |
| Chưa quá già | `first_seen_at >=` 4 giờ (thường) hoặc 30 phút (auto-closed) |
| Chưa quá to | `occurrence_count < 1000` |

**Trùng →** `INSERT` bản sao (`status='duplicate'`, `closed_at` **và** `sealed_at` đều đặt) · `UPDATE` gốc (`occurrence_count+1`, `last_seen_at = now()`) · ghi `alert.duplicate_merged` · **COMMIT, không sinh job**.

**Không trùng →** đi tiếp chặng 3 trong cùng transaction.

## Chặng 3 · `ingest/` Phase 3 — auto-close

**Tính chất:** đồng bộ · trong transaction · trong advisory lock

```
1. severity == critical                → KHÔNG xét rule       (lớp 3)
2. agent ∈ NEVER_AUTOCLOSE_AGENTS      → KHÔNG xét rule       (lớp 3b)
3. khớp autoclose_rules ORDER BY created_at, rule_id → rule đầu tiên thắng
4. khớp → enrichment/ nội bộ → INSERT status='auto_closed', sealed_at=NULL
5. mẫu 5% (tất định theo alert_id, trần 20/rule/ngày) → vẫn sinh job
6. không khớp → INSERT alerts + INSERT jobs → COMMIT → 201
```

**`sealed_at = NULL` là chi tiết quan trọng:** cụm auto-closed **vẫn hút bản sao**, nên một máy quét sinh 5.000 alert ra **1 dòng** với `occurrence_count = 5000`, không phải 5.000 dòng.

**Fail-open:** mọi lỗi ở chặng này đều nghiêng về **không đóng**. An toàn vì dedup đứng trước — cache rule hỏng giữa cơn bão 50.000 alert nhiễu vẫn chỉ sinh 1 job.

## Chặng 4 · `soar/` + `enrichment/` — làm giàu

**Tính chất:** nền · worker · ngoài transaction webhook

| Nguồn | Package | Chi phí | Alert auto-close có không |
|---|---|---|---|
| CMDB · AD · VirusTotal · MISP | `soar/` → n8n | Hạn ngạch API | ❌ (trừ mẫu đối chứng) |
| `assets` · `identities` · `iocs` | `enrichment/` | 3 SELECT nội bộ | ✅ |

Ghi `UPDATE alerts` (ngữ cảnh + `risk_score`). Lỗi thì bỏ qua, ghi audit, đi tiếp — thiếu ngữ cảnh không chặn triage.

**Ba trạng thái lookup:** `found` · `not_found` · `skipped`. `skipped` **không** phải tín hiệu an ninh, **không** trừ điểm `risk_score`.

## Chặng 5 · `domain/` — vào hàng đợi, và nhánh song song

`status = queued_tier1`. **Không chờ model.**

Ngay tại đây tách một nhánh song song: **① Auto-triage** (`tier1/` + `llm/`, qua `security/`, tra playbook qua `kb/`, và **tóm tắt tương quan** từ `domain/correlation.py`). Ghi `INSERT llm_runs` + `UPDATE triage_status`. Lỗi 3 lần retry → cờ `unavailable`, alert vẫn vào hàng đợi bình thường, chỉ thiếu gợi ý.

## Chặng 6 · `tier1/` — hàng đợi gặp con người

| Bước | Package | Ghi |
|---|---|---|
| Analyst mở alert | `tier1/` | `status='tier1_active'`, `acknowledged_at` — mốc SLA |
| Correlation ±2h | `domain/` | **Chỉ đọc**, không ghi |
| Quyết định | `tier1/` → `domain/` | Cho **cả cụm**, fan-out |

Cụm analyst thấy có thể lớn hơn cụm mà ① từng thấy — đây là **trung thực, không phải lỗi**. Cờ `needs_retriage` bật khi cụm phình `×10` hoặc `+200` so với lúc triage.

**Đóng →** `closed_fp` / `closed_benign`, ghi `audit_events(tier1.decided)` kèm **cả** đề xuất LLM **lẫn** quyết định người → luồng dừng.

**Escalate →** `domain.escalate()`: mở `Case`, gom cụm **và các cụm tương quan** vào `case_alerts`, rồi **hai câu ghi tách bạch** — alert **gốc** của mọi thành viên case đổi `status='escalated_tier2'` + nhận `case_id`; **bản sao** chỉ nhận `case_id`, **giữ nguyên** `status='duplicate'` (bản sao luôn có `sealed_at`, đổi status sẽ vi phạm H3). Xem phase-6 ③a/③b.

## Chặng 7 · `tier2/` — điều tra và kết thúc

**② Trợ lý điều tra** — đồng bộ, chỉ chạy khi analyst bấm. Đọc toàn bộ case + mọi alert đã gom. `raw_log` cắt xuống 4 KB khi vào prompt (dấu hiệu "đã cắt" nằm **trong** lớp bọc `security/`).

**Kết luận** — người quyết, ba nhánh, một transaction cho toàn case.

---

## Ma trận package × chặng

| Chặng | ingest | soar | tier1 | tier2 | domain | infra | audit | security | llm | kb | enrichment |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 1 · Chuẩn hóa | ● | | | | ○ | ○ | | | | | |
| 2 · Dedup | ● | | | | ○ | ○ | ○ | | | | |
| 3 · Auto-close | ● | | | | ○ | ○ | ○ | | | | ○ |
| 4 · Enrichment | | ● | | | ○ | ○ | ○ | | | | ○ |
| 5 · Hàng đợi | | ● | | | ○ | ○ | | | | | |
| 5b · ① Triage | | | ● | | ◆ | ○ | ○ | ○ | ○ | ○ | |
| 6 · Tier 1 | | | ● | | ○ | ○ | ○ | | | | |
| 7 · ② + kết luận | | | | ● | ○ | ○ | ○ | ○ | ○ | ○ | |

● chủ trì · ○ được gọi tới · ◆ `domain/correlation.py` — tóm tắt gộp, không phải danh sách thô

## Ma trận đọc/ghi bảng

| Bảng | ingest | soar | tier1 | tier2 |
|---|:-:|:-:|:-:|:-:|
| `alerts` | R/W | R/W | R/W | R/W |
| `jobs` | W | R/W | R/W | R |
| `audit_events` | W | W | W | W |
| `llm_runs` | — | — | W | W |
| `autoclose_rules` | R | — | — | — |
| `rejected_alerts` | W | — | — | — |
| `assets` `identities` `iocs` | R | R | R | R |
| `cases` `case_alerts` | — | — | W | R/W |

**Không package nào `DELETE`.** `audit_events` và `llm_runs` là append-only.

## Điểm chạm hệ thống ngoài

| Điểm | Ai gọi | Chặng | Hỏng thì sao |
|---|---|---|---|
| Wazuh → webhook | Wazuh gọi vào | 1 | Alert không tới; `rejected_alerts` giữ ca payload hỏng |
| n8n → CMDB/AD/VT/MISP | `soar/` | 4 | Bỏ qua, ghi audit, đi tiếp — `skipped` ≠ `not_found` |
| LLM API ① | `tier1/` | 5b | Cờ `unavailable`, hàng đợi không bị chặn |
| LLM API ② | `tier2/` | 7 | Analyst tự làm |

**Không điểm nào trong bốn cái trên có thể chặn một alert đi hết luồng.** Đây là ràng buộc G7, và nó thể hiện xuyên suốt chứ không chỉ ở một chỗ.

---

## Bốn điểm kết thúc — bảng tổng kết

| # | Trạng thái | Chặng | Sinh job? | Gọi model? | Gọi API ngoài? |
|---|---|---|:-:|:-:|:-:|
| ① | `duplicate` | 2 | ✗ | ✗ | ✗ |
| ② | `auto_closed` | 3 | ✗ (trừ mẫu 5%) | ✗ (trừ mẫu) | ✗ (trừ mẫu) |
| ③ | `closed_fp` · `closed_benign` | 6 | ✓ | ✓ ① | ✓ |
| ④ | `concluded_*` · `confirmed_incident` | 7 | ✓ | ✓ ① ② | ✓ |

---

## Bốn điểm khác biệt so với bản HTML cũ

| Bản cũ | Bản này | Vì sao |
|---|---|---|
| Dedup theo `fingerprint` (có bucket 5 phút) | Dedup theo **4 cột định danh** | Bucket làm đợt tấn công dài vỡ thành nhiều cụm |
| Auto-close "không tốn lời gọi model nào" | Vẫn có **enrichment nội bộ**, và mẫu 5% đi đường đầy đủ | Enrichment nội bộ miễn phí; mẫu thiếu ngữ cảnh gây thiên lệch nguy hiểm |
| Gốc đã đóng thì bản sao mở cụm mới | Cụm **`auto_closed` vẫn hút** | Không ai cần biết máy quét chạy lại lần thứ 5.000 |
| Ghi chú "cần chốt thứ tự auto-close" | **Đã chốt**: dedup → auto-close → enrichment, tất cả trong webhook | Mục II‑05 của `Kiến_trúc.html` cần sửa theo |

---

*Luồng dữ liệu theo package · AI Support SOC · thay cho bản HTML dựng trước Đề xuất 1*
