# schema-notes.md — Schema PostgreSQL cho AI Support SOC

> Tài liệu đi kèm `schema.sql` và `migrations/001…005`.
> Mọi con số trong tệp này là **kết quả chạy thật** trên PostgreSQL 16.15 với
> 500.000 dòng, không phải ước lượng. Lệnh tái lập ghi ở mục 7.

---

## 0 · Tóm tắt một trang

| | |
|---|---|
| Bảng | 11 nghiệp vụ + `schema_migrations` |
| Cột `alerts` | **51** (nhiệm vụ ước 45 — xem §1.1) |
| `CHECK` constraint | 27 |
| Index | 27 toàn schema · 10 trên `alerts` |
| Migration | 5 tệp, có thứ tự, ghi vết vào `schema_migrations` |
| Kiểm chứng | 34/34 ca vi phạm bị chặn · 7/7 ca đối chứng dương được cho qua |
| Mâu thuẫn phải xử lý | 3 (M‑A, M‑B, M‑C) — §2 |
| Cần bổ sung | 9 mục — §6 |

Ba yêu cầu EXPLAIN của nhiệm vụ, kết quả thật:

| Yêu cầu | Kết quả |
|---|---|
| 4 cột khóa cụm vào `Index Cond`, không cột nào xuống `Filter` | ✅ cả 4 · `Buffers: shared hit=4` · 0,049 ms |
| Không có node `Sort` trong truy vấn dedup | ✅ không có |
| `BitmapOr` trên ba index correlation | ✅ đủ ba nhánh |

---

## 1 · Bảng truy vết cột

Dựng bằng `trace_columns.py` — quét **cả 8 tệp đặc tả cộng `luong-du-lieu-theo-package.html`**, khớp từng tên cột như một định danh (chặn khớp nhầm trong `alerts.rule_id` khi tìm `rule_id`). Không đọc bằng trí nhớ.

### 1.1 · Ba chỗ kết quả quét lệch so với mô tả nhiệm vụ

Nhiệm vụ nêu ba con số. Cả ba đều lệch, và ghi lại chỗ lệch quan trọng hơn là im lặng làm cho khớp:

| | Nhiệm vụ nêu | Quét thật ra | Ý nghĩa |
|---|---|---|---|
| Số cột `alerts` | 45 | **51** | Gõ tay theo con số 45 sẽ thiếu 6 cột |
| Cột chỉ ở 1 tệp | 6 (có nêu tên) | **33** toàn schema · **14** riêng `alerts` | Rủi ro sót rộng gấp 5 lần ước tính |
| `last_analyzed_at` thuộc bảng nào | ngụ ý `alerts` | thuộc **`cases`** (phase‑7:125) | Đặt nhầm bảng thì `UPDATE cases SET last_analyzed_at` ở P7:283 không chạy |

Sáu cột nhiệm vụ nêu tên (`agent_ip`, `resolved_by`, `mapping_version`, `event_time`, `risk_score_components`, `last_analyzed_at`) đều nằm trong tập 33 cột đó. Nhưng còn 27 cột nữa cùng mức rủi ro, đáng chú ý nhất:

- **`asset_context`, `identity_context`, `ioc_context`, `lookup_status`** — mỗi cột xuất hiện **đúng một lần trong toàn bộ hồ sơ** (phase‑4:297‑298, trong câu `UPDATE` của Phase 4). Bốn cột enrichment. Sót chúng thì Phase 4 không có chỗ ghi kết quả làm giàu.
- **`acknowledged_by`** — đúng một lần (phase‑6:90). Không có nó thì P6‑2 (*"ghi người đầu tiên mở alert"*) không thi hành được.
- **`agent_trace`** trong `llm_runs` — đúng một lần (phase‑5:132). **✅ Đã có nội dung thật từ P7‑8** (26/08): vòng lặp tool của ② ghi `rounds[]` · `stopped_by` · `rounds_used` · `tokens_used` vào cột này. Trước P7‑8 đây là cột thừa còn sót của vòng lặp agent bản tiền nhiệm — không có gì ghi vào.

### 1.2 · Ba cột không truy được ở dạng SQL

| Cột | Tồn tại ở dạng | Vị trí |
|---|---|---|
| `assets.criticality` | thuộc tính Python `asset.criticality` | phase‑4:161, phase‑3:134 |
| `identities.is_privileged` | thuộc tính Python `identity.is_privileged` | phase‑4:162 |
| `iocs.reputation` | thuộc tính Python `ioc.reputation` | phase‑4:163 |

Cả ba **có nguồn** nhưng chưa bao giờ được viết dưới dạng DDL. Tập giá trị thì có: `{crown_jewel, high, normal, low}`, `{true,false}`, `{malicious, suspicious, clean}` — lấy từ chính công thức `risk_score`. Đã đặt `CHECK` theo các tập đó; xem §6 mục 5 về phần còn thiếu (kiểu, cột phụ, khóa chính của `iocs`).

### 1.3 · Bảng truy vết đầy đủ

Ký hiệu: **Nguồn định nghĩa** = tệp:dòng nơi cột xuất hiện lần đầu. ⚠️ = cột chỉ được nhắc tới ở **đúng một tệp**, tức là không có tệp thứ hai để đối chiếu.

### `alerts` — 51 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `alert_id` | phase-1:51 | 7 | P1, P2, P3, P4, P5, P6, P7 |
| `rule_id` | kien-truc:280 | 6 | KT, P1, P2, P3, P4, P7 |
| `rule_level` | phase-1:66 | 2 | P1, P3 |
| `severity` | kien-truc:285 | 5 | KT, P1, P3, P4, P6 |
| `description` | phase-1:53 | 1 ⚠️ | P1 |
| `category` | kien-truc:93 | 8 | KT, P1, P3, P4, P5, P6, P7, HTML |
| `categories` | kien-truc:412 | 3 | KT, P1, P5 |
| `resolved_by` | phase-1:158 | 1 ⚠️ | P1 |
| `mapping_version` | phase-1:191 | 1 ⚠️ | P1 |
| `srcip` | kien-truc:280 | 5 | KT, P1, P2, P3, P4 |
| `dstip` | kien-truc:212 | 5 | KT, P1, P2, P3, P4 |
| `src_port` | phase-1:62 | 2 | P1, P3 |
| `dst_port` | kien-truc:213 | 3 | KT, P1, P3 |
| `alert_user` | kien-truc:464 | 6 | KT, P1, P2, P3, P4, P6 |
| `agent_id` | phase-1:64 | 2 | P1, P3 |
| `agent_name` | kien-truc:280 | 5 | KT, P1, P2, P3, P4 |
| `agent_ip` | phase-1:64 | 1 ⚠️ | P1 |
| `decoder` | phase-1:69 | 2 | P1, P3 |
| `mitre_ids` | phase-1:67 | 1 ⚠️ | P1 |
| `rule_groups` | phase-1:68 | 1 ⚠️ | P1 |
| `alert_time` | phase-1:55 | 3 | P1, P2, P4 |
| `event_time` | phase-1:70 | 1 ⚠️ | P1 |
| `raw_log` | kien-truc:141 | 4 | KT, P1, P5, P7 |
| `srcip_is_private` | phase-1:276 | 2 | P1, P3 |
| `dstip_is_private` | kien-truc:215 | 2 | KT, P1 |
| `raw_log_truncated` | phase-1:311 | 1 ⚠️ | P1 |
| `source` | phase-1:434 | 2 | P1, P5 |
| `is_synthetic` | kien-truc:406 | 3 | KT, P1, P3 |
| `status` | kien-truc:165 | 9 | KT, P1, P2, P3, P4, P5, P6, P7, HTML |
| `event_bucket_hash` | kien-truc:209 | 3 | KT, P1, P2 |
| `duplicate_of` | kien-truc:190 | 7 | KT, P1, P2, P3, P4, P6, P7 |
| `occurrence_count` | kien-truc:402 | 8 | KT, P1, P2, P3, P4, P6, P7, HTML |
| `risk_score` | kien-truc:85 | 6 | KT, P1, P3, P4, P6, HTML |
| `risk_score_components` | kien-truc:302 | 1 ⚠️ | KT |
| `triage_status` | kien-truc:267 | 6 | KT, P1, P3, P4, P5, P6 |
| `triaged_count` | phase-1:440 | 3 | P1, P2, P6 |
| `case_id` | kien-truc:192 | 4 | KT, P1, P6, P7 |
| `acknowledged_at` | kien-truc:408 | 4 | KT, P1, P6, HTML |
| `acknowledged_by` | phase-6:90 | 1 ⚠️ | P6 |
| `closed_at` | kien-truc:230 | 6 | KT, P1, P2, P3, P6, P7 |
| `sealed_at` | kien-truc:231 | 5 | KT, P2, P3, P6, P7 |
| `close_reason` | phase-1:441 | 4 | P1, P3, P6, P7 |
| `autoclose_rule_id` | kien-truc:192 | 2 | KT, P3 |
| `asset_context` | phase-4:306 | 1 ⚠️ | P4 |
| `identity_context` | phase-4:306 | 1 ⚠️ | P4 |
| `ioc_context` | phase-4:306 | 1 ⚠️ | P4 |
| `lookup_status` | phase-4:307 | 1 ⚠️ | P4 |
| `raw_payload` | kien-truc:393 | 3 | KT, P1, P2 |
| `received_at` | kien-truc:400 | 4 | KT, P1, P3, P4 |
| `first_seen_at` | phase-1:448 | 3 | P1, P2, P6 |
| `last_seen_at` | kien-truc:389 | 4 | KT, P1, P2, P7 |

### `cases` — 10 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `case_id` | kien-truc:192 | 4 | KT, P1, P6, P7 |
| `title` | phase-6:169 | 2 | P6, HTML |
| `status` | kien-truc:165 | 9 | KT, P1, P2, P3, P4, P5, P6, P7, HTML |
| `severity` | kien-truc:285 | 5 | KT, P1, P3, P4, P6 |
| `created_by` | phase-3:89 | 2 | P3, P6 |
| `created_at` | phase-3:90 | 4 | P3, P5, P6, P7 |
| `conclusion_reason` | phase-7:305 | 1 ⚠️ | P7 |
| `concluded_by` | phase-7:305 | 1 ⚠️ | P7 |
| `concluded_at` | phase-7:305 | 1 ⚠️ | P7 |
| `last_analyzed_at` | phase-7:283 | 1 ⚠️ | P7 |

### `case_alerts` — 4 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `case_id` | kien-truc:192 | 4 | KT, P1, P6, P7 |
| `alert_id` | phase-1:51 | 7 | P1, P2, P3, P4, P5, P6, P7 |
| `added_by` | phase-6:173 | 1 ⚠️ | P6 |
| `added_at` | phase-6:173 | 1 ⚠️ | P6 |

### `jobs` — 8 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `job_id` | phase-4:42 | 1 ⚠️ | P4 |
| `job_type` | phase-4:42 | 1 ⚠️ | P4 |
| `subject_id` | kien-truc:222 | 7 | KT, P2, P3, P4, P5, P6, P7 |
| `status` | kien-truc:165 | 9 | KT, P1, P2, P3, P4, P5, P6, P7, HTML |
| `scheduled_at` | phase-4:44 | 1 ⚠️ | P4 |
| `locked_at` | phase-4:49 | 1 ⚠️ | P4 |
| `attempts` | phase-4:49 | 1 ⚠️ | P4 |
| `last_error` | phase-4:57 | 1 ⚠️ | P4 |

### `audit_events` — 6 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `event_type` | phase-2:245 | 6 | P2, P3, P4, P5, P6, P7 |
| `subject_id` | kien-truc:222 | 7 | KT, P2, P3, P4, P5, P6, P7 |
| `actor_id` | phase-6:105 | 2 | P6, P7 |
| `actor_role` | phase-2:245 | 6 | P2, P3, P4, P5, P6, P7 |
| `payload` | phase-1:11 | 7 | P1, P2, P3, P4, P5, P6, P7 |
| `created_at` | phase-3:90 | 4 | P3, P5, P6, P7 |

### `llm_runs` — 14 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `run_id` | phase-5:131 | 1 ⚠️ | P5 |
| `pipeline` | kien-truc:92 | 7 | KT, P1, P3, P5, P6, P7, HTML |
| `subject_type` | phase-5:131 | 2 | P5, P7 |
| `subject_id` | kien-truc:222 | 7 | KT, P2, P3, P4, P5, P6, P7 |
| `system_prompt` | phase-5:132 | 2 | P5, P7 |
| `user_message` | phase-5:132 | 2 | P5, P7 |
| `agent_trace` | phase-5:132 | 1 → 2 ✅ | P5, **P7‑8** |
| `result` | phase-5:132 | 2 | P5, P7 |
| `injection_findings` | phase-5:133 | 2 | P5, P7 |
| `citation_warnings` | phase-5:133 | 2 | P5, P7 |
| `input_tokens` | phase-5:134 | 2 | P5, P7 |
| `output_tokens` | phase-5:134 | 2 | P5, P7 |
| `latency_ms` | phase-5:134 | 2 | P5, P7 |
| `created_at` | phase-3:90 | 4 | P3, P5, P6, P7 |

### `assets` — 2 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `hostname` | phase-1:345 | 2 | P1, P4 |
| `criticality` | **không truy được dạng SQL** | 0 | — |

### `identities` — 2 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `username` | phase-4:85 | 1 ⚠️ | P4 |
| `is_privileged` | **không truy được dạng SQL** | 0 | — |

### `iocs` — 3 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `value` | phase-1:91 | 3 | P1, P3, P4 |
| `reputation` | **không truy được dạng SQL** | 0 | — |
| `expires_at` | phase-4:86 | 1 ⚠️ | P4 |

### `autoclose_rules` — 7 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `rule_id` | kien-truc:280 | 6 | KT, P1, P2, P3, P4, P7 |
| `name` | phase-1:350 | 3 | P1, P3, HTML |
| `enabled` | phase-3:86 | 1 ⚠️ | P3 |
| `match` | phase-3:87 | 1 ⚠️ | P3 |
| `reason` | phase-3:88 | 3 | P3, P6, P7 |
| `created_by` | phase-3:89 | 2 | P3, P6 |
| `created_at` | phase-3:90 | 4 | P3, P5, P6, P7 |

### `rejected_alerts` — 3 cột

| Cột | Nguồn định nghĩa | Số tệp | Mọi tệp nhắc tới |
|---|---|---|---|
| `payload` | phase-1:11 | 7 | P1, P2, P3, P4, P5, P6, P7 |
| `reason` | phase-3:88 | 3 | P3, P6, P7 |
| `source_ip` | phase-1:459 | 1 ⚠️ | P1 |

---

## 2 · Ba mâu thuẫn giữa các đặc tả

Cả ba đều ảnh hưởng trực tiếp tới `CHECK` constraint, nên không thể để ngỏ: viết DDL là buộc phải chọn một bên.

---

### M‑A · `concluded_*` có phải là giá trị của `alerts.status` không?

**① Vấn đề.** Hai nhóm tệp nói khác nhau:

| Nguồn | Nói gì |
|---|---|
| kien-truc:259‑263 | Bảng ánh xạ: `concluded_fp → closed_fp`, `concluded_policy_violation → closed_benign`, `confirmed_incident → closed_confirmed`. `concluded_*` là trạng thái của **case** |
| phase-7:304, 315‑161 | `UPDATE cases SET status = $conclusion` rồi `UPDATE alerts SET status = $alert_status` — hai cột khác nhau, đúng bảng ánh xạ |
| phase-2:339 | *"Gốc đã `closed_fp` / `closed_benign` / `concluded_*` (người quyết)"* — dùng `concluded_*` cho **alert** |
| phase-2:447 | `test_goc_concluded_fp_thi_khong_gop` — tên test giả định `alerts.status = 'concluded_fp'` |
| phase-2:503 | Liệt kê trạng thái terminal của alert gồm cả `concluded_*` |

Phase 2 dùng `concluded_*` cho alert ở **3 chỗ**; kiến trúc và Phase 7 dùng `closed_*` ở **2 chỗ có SQL**.

**② Kiểm chứng bằng số.** Câu hỏi thật không phải "bên nào viết đúng chữ" mà **"chọn bên nào thì hành vi nghiệp vụ hỏng"**. Hành vi cần giữ là P2:339: *alert đã bị người kết luận thì bản sao mới phải mở cụm mới, không gộp vào*. Chạy trên 500.000 dòng:

```
      status      | so_dong | con_hut_ban_sao
------------------+---------+-----------------
 auto_closed      |   17278 |           13764
 closed_benign    |    4280 |               0
 closed_confirmed |    2145 |               0
 closed_fp        |    8294 |               0
 escalated_tier2  |    2690 |            2690
```

`con_hut_ban_sao` đếm theo đúng vị từ D‑C6 `closed_at IS NULL OR sealed_at IS NULL`. Kết quả: **0/14.719** alert do người đóng còn hút bản sao — vì ràng buộc H2 ép chúng phải có `sealed_at`. Ý định của P2:339 giữ nguyên **mà không cần** `concluded_*` xuất hiện trong `alerts.status`.

Đối chứng ngược cũng đúng: 13.764/17.278 cụm `auto_closed` và **2.690/2.690** cụm `escalated_tier2` vẫn hút — đúng M4 và D‑C5.

**③ Ba phương án.**

| | Cách | Hệ quả |
|---|---|---|
| (a) | `CHECK` nhận **cả** `closed_*` lẫn `concluded_*` cho alert | Hai chính tả cho một trạng thái. Truy vấn đo lường lọc `status='closed_fp'` sẽ **âm thầm bỏ sót** alert ghi `concluded_fp`. Sai kiểu im lặng, đúng loại nguy hiểm nhất |
| (b) | Chỉ nhận `concluded_*`, bỏ `closed_confirmed` | Mâu thuẫn thẳng với SQL của P7:315‑319 và với phase-7:451 (*"trạng thái `closed_confirmed` cần thêm vào máy trạng thái của `alerts`"*) |
| **(c)** | **Chỉ nhận `closed_*` cho alert; `concluded_*` chỉ thuộc `cases.status`** | Phase 2 phải sửa 3 chỗ chữ nghĩa |

**④ Chọn (c).** Căn cứ: chỗ duy nhất trong toàn hồ sơ có **câu SQL thật ghi trạng thái kết luận xuống `alerts`** là P7:315‑319, và nó ghi `closed_*`. Ba chỗ của Phase 2 đều là văn xuôi và tên test, không phải SQL.

**⑤ Phản biện chính lựa chọn này.**

Điểm yếu thật của (c): nó **làm mất thông tin**. Sau khi Tier 2 kết luận, nhìn một dòng `alerts` lẻ ra `closed_fp` thì không phân biệt được nó bị Tier 1 đóng hay bị Tier 2 kết luận — hai việc rất khác nhau về chi phí và độ tin cậy, mà báo cáo có thể cần tách. Phương án (a) giữ được phân biệt đó.

Phản biện lại: thông tin ấy **không mất**, chỉ nằm chỗ khác. `alerts.case_id` khác `NULL` là dấu hiệu tất định của "đi qua Tier 2", và `case_alerts` giữ đủ quan hệ. Truy vấn phân biệt được viết là `WHERE case_id IS NOT NULL`. Đổi lại, (a) sẽ tạo ra một lớp lỗi mà không truy vấn nào phát hiện được.

Điểm yếu thứ hai, phải nói thẳng: **`closed_confirmed` chưa từng được chốt chính thức.** phase-7:451 xếp nó vào *"việc còn lại"*, kien-truc:263 đánh dấu *"trạng thái mới, chưa có trong II‑06 bản gốc"*. Tôi đưa nó vào `CHECK` dựa trên hai nguồn đồng thuận, nhưng nó **chưa qua một vòng phản biện có đo đạc nào**. Ghi vào §6 mục 3.

**Hệ quả phải sửa ở tài liệu:** phase-2:339, 444, 500 đổi `concluded_*` → `closed_fp | closed_benign | closed_confirmed`. Tên test `test_goc_concluded_fp_thi_khong_gop` không chạy được như đang viết.

---

### M‑B · `triage_status` khi ① xong là `'ready'` hay `'done'`?

**① Vấn đề.** phase-5:137 viết `UPDATE alerts SET triage_status = 'ready'`. phase-3:178 viết *"`pending`, hoặc `done` nếu là mẫu"*.

**② Kiểm chứng bằng số.** Đếm bối cảnh xuất hiện của mỗi chữ trong toàn hồ sơ:

| Giá trị | Số lần | Xuất hiện trong |
|---|---|---|
| `'ready'` | 2 | phase-5:25 và phase-5:137 — **cả hai đều là câu SQL `UPDATE`** |
| `'done'` | 1 | phase-3:178 — một ô trong bảng văn xuôi |
| `'pending'` | 2 | phase-1:440 (giá trị khởi tạo), phase-3:178 |
| `'unavailable'` | 3 | phase-5:152, phase-5:157, phase-6:44 |

Phase 5 là phase **duy nhất ghi cột này** (P5:6 *"Ra: một dòng `llm_runs` + `triage_status`"*). Phase 3 chỉ mô tả cột sẽ trông thế nào.

**③ Ba phương án.** (a) nhận cả bốn giá trị · (b) chốt `'done'`, sửa Phase 5 · (c) chốt `'ready'`, sửa Phase 3.

**④ Chọn (c):** `{pending, ready, unavailable}`. Người viết cột thắng người mô tả cột.

**⑤ Phản biện.** Lập luận "ai viết cột thì người đó thắng" nghe gọn nhưng không phải luật. Nếu ngược lại — Phase 3 mới là bên đúng và Phase 5 gõ nhầm — thì tôi vừa đóng băng một lỗi vào `CHECK`. Cái bảo vệ ở đây không phải lập luận mà là **hậu quả khi sai**: `CHECK` sẽ ném lỗi ngay lần `UPDATE` đầu tiên, ồn ào và ở đúng dòng code sai. So với phương án (a) — nhận cả hai chữ — thì (a) mới nguy hiểm: hai chữ cùng nghĩa nằm song song trong dữ liệu, và bất kỳ truy vấn nào lọc một chữ sẽ bỏ sót nửa còn lại **mà không báo gì**. Chọn cái sai-thì-nổ thay vì cái sai-thì-im.

Đã kiểm chứng: ca `triage_status='done'` bị chặn bởi `ck_alerts_triage_status` (§4).

---

### M‑C · `llm_runs.pipeline` là số nguyên hay chuỗi, và có cột `suggested_action` không?

**① Vấn đề.** phase-3:249‑255 viết truy vấn mẫu đối chứng dùng `r.pipeline = 1` và cột `r.suggested_action`. phase-5:171‑178 viết **cùng truy vấn đó** nhưng dùng `r.pipeline = 'triage'` và `r.result->>'suggested_action'`.

**② Kiểm chứng bằng số — chạy cả hai trên DB thật.** Nạp 400 dòng `llm_runs` thật rồi chạy:

```
--- phiên bản phase-5:171-178 ---
          autoclose_rule_id           | nghi_ngo | tong_mau
--------------------------------------+----------+----------
 00000009-0000-4000-8000-ad7dfb3a0d85 |       19 |       46
 00000005-0000-4000-8000-6b296dd02815 |       26 |       42
 ...

--- phiên bản phase-3:249-255 ---
ERROR:  operator does not exist: text = integer
LINE 5: ...N llm_runs r ON r.subject_id = a.alert_id AND r.pipeline = 1
```

Thêm bằng chứng độc lập: danh sách cột của `INSERT INTO llm_runs` ở phase-5:131‑135 **không có** `suggested_action`; nó nằm trong JSON `result` (phase-5:118‑125). Và hai nơi khác cũng đọc bằng `result->>`: phase-6:35 và phase-7:241.

**③ Ba phương án.** (a) `pipeline smallint` + cột `suggested_action` riêng · (b) `pipeline text`, đọc qua `result->>` · (c) `pipeline text` **và** thêm cột `suggested_action` sinh tự động từ `result`.

**④ Chọn (b).** Ba tệp (P5, P6, P7) dùng chuỗi; một tệp (P3) dùng số, và tệp đó chính là tệp mà P5:175 viết lại câu truy vấn cho đúng.

**⑤ Phản biện.** (c) hấp dẫn hơn vẻ ngoài: một cột `GENERATED ALWAYS AS (result->>'suggested_action') STORED` sẽ làm phép đo độ khớp — số đo thứ ba của báo cáo (kien-truc:411) — vừa nhanh hơn vừa đánh chỉ mục được, và câu SQL của Phase 3 sẽ chạy nguyên văn không phải sửa.

Lý do vẫn không chọn (c): nó tạo **hai đường đọc cùng một sự thật**. Phase 5 chốt (P5‑5) rằng `suggested_action` là tập đóng ba giá trị và *"model trả giá trị lạ → coi như hỏng"*. Với cột sinh tự động, một `result` hỏng sẽ đẻ ra một cột hỏng đi kèm, và người viết truy vấn phải nhớ cột nào mới là bản đáng tin. Ràng buộc `ck_llm_runs_suggested_action` (§3) đạt được cùng mục tiêu cưỡng chế mà không nhân đôi sự thật. Nếu sau này phép đo độ khớp chậm thật thì thêm expression index `((result->>'suggested_action'))` — rẻ hơn và không thêm cột.

**Hệ quả phải sửa ở tài liệu:** phase-3:249‑255 thay bằng phiên bản của phase-5:171‑178.

---

## 3 · Ràng buộc cưỡng chế được

Nguyên tắc: ràng buộc nào **viết được thành `CHECK` row-local thì viết**, không để thành quy ước trong tài liệu. Ràng buộc nào cần nhìn nhiều dòng thì nói rõ là không cưỡng chế được ở tầng này.

### 3.1 · Ba ràng buộc nhiệm vụ yêu cầu

| Mã | Ràng buộc | Cưỡng chế bằng | Đã thử vi phạm |
|---|---|---|---|
| **G3** | Mọi trạng thái kết thúc phải set `closed_at` | `ck_alerts_g3_terminal_phai_co_closed_at` | 5/5 trạng thái terminal bị chặn |
| **G4** | `srcip`/`dstip` không bao giờ `NULL` | `NOT NULL DEFAULT ''` | 2/2 bị chặn |
| **C2** | `src_port`/`dst_port` `INT NOT NULL DEFAULT 0` | `NOT NULL DEFAULT 0` | 2/2 bị chặn |

G3 viết dạng suy diễn, không phải liệt kê ngược — để trạng thái không-terminal vẫn tự do:

```sql
CHECK (status NOT IN ('duplicate','auto_closed','closed_fp',
                      'closed_benign','closed_confirmed')
       OR closed_at IS NOT NULL)
```

### 3.2 · Chín ràng buộc thêm — đều là bất biến đã có trong đặc tả

Đặc tả đã tuyên bố chúng là bất biến nhưng để phần kiểm chứng cho test. `CHECK` rẻ hơn test và không quên chạy:

| Constraint | Bất biến | Nguồn |
|---|---|---|
| `ck_alerts_h2_dong_boi_nguoi_phai_seal` | H2 · đóng bởi **người** thì set cả `sealed_at` | phase-6:353 |
| `ck_alerts_h3_escalate_khong_seal` | H3 · `escalated_tier2` **không** set `sealed_at` | phase-6:354 |
| `ck_alerts_ban_sao_phai_seal_va_tro_goc` | Bản sao đặt cả `closed_at` lẫn `sealed_at`, và phải có `duplicate_of` | phase-2:227,255 |
| `ck_alerts_last_seen_khong_lui` | D6 · `last_seen_at` không lùi về quá khứ | phase-2:401 |
| `ck_alerts_occurrence_toi_thieu_1` | D3 · bộ đếm cụm bắt đầu từ 1 | phase-2:398 |
| `ck_alerts_risk_score_0_100` | E2 · `risk_score = min(100, …)`, chỉ cộng | phase-4:175 |
| `ck_alerts_hash_sha256_hex` | C1/B6 · sha256 hex 64 ký tự | phase-1:212 |
| `ck_alerts_raw_log_tran_1000kb` | C3 · `RAW_LOG_MAX_BYTES = 1_024_000` | phase-1:308 |
| `ck_llm_runs_suggested_action` | P5‑5 · tập đóng ba giá trị | phase-5:118 |

**H2 và M4 phải phân biệt cho đúng, đây là chỗ dễ sai nhất của cả schema.** `auto_closed` **cố ý** không nằm trong danh sách H2: theo M4 (phase-3:308) cụm nhiễu **vẫn hút bản sao** cho tới khi sweeper niêm hoặc chạm trần 30 phút. Nếu vô ý ép `auto_closed` phải có `sealed_at` thì M4 bị vô hiệu hoá ngay ở tầng DB, và 5.000 alert máy quét lại thành 5.000 dòng. Đã kiểm chứng bằng ca đối chứng dương (§4B).

### 3.3 · Ba bất biến KHÔNG cưỡng chế được bằng `CHECK`

Nói rõ để không ai tưởng chúng đã được bảo vệ:

| Mã | Ràng buộc | Vì sao không | Phải cưỡng chế ở đâu |
|---|---|---|---|
| **D2** | Bản sao không bao giờ làm gốc | Cần đọc dòng **khác** (`duplicate_of` trỏ tới dòng có `status <> 'duplicate'`) | Trigger, hoặc test + vị từ `status <> 'duplicate'` ở P2:124 |
| **D3** | `occurrence_count` của gốc = số bản sao trỏ về + 1 | Ràng buộc gộp trên nhiều dòng | Test đối chiếu (phase-2:398) |
| **P6‑4** | `MAX_ALERTS_PER_CASE = 200` | Ràng buộc trên **số dòng** mỗi `case_id` | Tầng ứng dụng (phase-6:300) |

D2 có thể làm bằng trigger, nhưng trigger chạy trong vùng advisory lock của mọi webhook — đúng thứ P4 (phase-2:191‑203) đang tìm cách rút ngắn. Không thêm.

---

## 4 · Kết quả thử vi phạm ràng buộc

Chạy bằng `test_constraints.py`. Mỗi ca gói trong `BEGIN … ROLLBACK` nên không bẩn dữ liệu.

**A · 34/34 ca vi phạm đều bị chặn**, và bị chặn bởi **đúng constraint dự kiến** (không phải bị chặn nhầm vì lý do khác — xem cảnh báo dưới).

| Nhóm | Số ca | Kết quả |
|---|---|---|
| G4 · `srcip`/`dstip` = NULL | 2 | chặn bởi `NOT NULL` |
| C2 · `src_port`/`dst_port` = NULL | 2 | chặn bởi `NOT NULL` |
| G3 · 5 trạng thái terminal thiếu `closed_at` | 5 | `ck_alerts_g3_terminal_phai_co_closed_at` |
| H2 · đóng bởi người mà không `sealed_at` | 3 | `ck_alerts_h2_dong_boi_nguoi_phai_seal` |
| H3 · `escalated_tier2` mà có `sealed_at` | 1 | `ck_alerts_h3_escalate_khong_seal` |
| Bản sao thiếu `sealed_at` / thiếu `duplicate_of` | 2 | `ck_alerts_ban_sao_phai_seal_va_tro_goc` |
| M‑A `concluded_fp` · M‑B `done` · severity lạ | 3 | `ck_alerts_status` / `_triage_status` / `_severity` |
| `risk_score` = 101 và −1 | 2 | `ck_alerts_risk_score_0_100` |
| hash không phải sha256 · `occurrence_count`=0 · `last_seen_at` lùi · tự tham chiếu · `raw_log` > 1000 KB | 5 | 5 constraint tương ứng |
| `cases`, `llm_runs`, `audit_events`, `jobs`, `assets`, `iocs` | 9 | 9 constraint tương ứng |

**B · 7/7 ca đối chứng dương được cho qua** — đây là nửa quan trọng không kém, nó chứng minh không có constraint nào chặn nhầm hành vi hợp lệ:

| Ca | Vì sao phải cho qua |
|---|---|
| `auto_closed` có `closed_at`, `sealed_at` NULL | **M4** — cụm nhiễu còn hút bản sao |
| `escalated_tier2` không seal | **D‑C5** — cụm đang điều tra còn hút |
| `srcip=''` và `dstip=''` | **B1** — rule FIM/rootcheck không có IP |
| `srcip_is_private = NULL` | **C4** — ba trạng thái, NULL nghĩa là không khẳng định |
| `triage_status='unavailable'`, `status` không đổi | **T1/G7** — model hỏng không đổi trạng thái |
| `suggested_action='needs_review'` | **P5‑4** — giá trị hợp lệ sau khi bị ép do injection |
| `llm_runs` có `result = NULL` | **T6** — ghi vết cả ca model hỏng |

> **Bộ test này tự bẫy mình hai lần, và cả hai lần đều do nhóm B phát hiện.**
> Lần một: `raw_payload="'{{}}'::jsonb"` trong một chuỗi thường (không phải f-string) nên `{{}}` giữ nguyên hai lớp ngoặc → JSON hỏng.
> Lần hai: SQL đi qua `psql -c "…"`, dấu `"` trong JSON đóng sớm tham số shell.
> Cả hai lần, nhóm A vẫn báo **34/34 "bị chặn"** — vì mọi ca đều lỗi, chỉ là lỗi cú pháp JSON chứ không phải lỗi ràng buộc. Nếu chỉ có ca vi phạm mà không có ca đối chứng dương, tôi đã kết luận sai và không có cách nào biết. Đã sửa: SQL đưa qua **stdin**, và thông điệp lỗi được in ra để đối chiếu tên constraint.

---

## 5 · Index — lý do và kết quả EXPLAIN

Mười index trên `alerts`. Mỗi cái truy được về một câu SQL cụ thể trong đặc tả; không có index "phòng xa".

| # | Index | Kích thước | Phục vụ |
|---|---|---|---|
| ① | `ix_alerts_dedup` | 2.704 kB | phase-2:116‑132 · dedup trong advisory lock |
| ②③④ | `ix_alerts_corr_agent/user/srcip` | 22 + 19 + 21 MB | phase-4:250‑266 · `summarize_for_prompt()` |
| ⑤ | `ix_alerts_duplicate_of` | 3.816 kB | phase-2:299 · phase-6:151 · phase-7:311 |
| ⑥ | `ix_alerts_queue_tier1` | 520 kB | phase-6:29‑40 · hàng đợi Tier 1 |
| ⑦ | `ix_alerts_sweeper` | 112 kB | phase-3:341‑345 · sweeper tắt rule |
| ⑧ | `ix_alerts_received_at` | 13 MB | phase-3:279 · kien-truc:400 |
| ⑨ | `ix_alerts_autoclose_7ngay` | 400 kB | phase-3:281‑288 · lớp bảo vệ 2 |

Tổng index trên `alerts`: **115 MB** trên bảng 1.317 MB (500.000 dòng có `raw_payload` kích thước thật).

### ① Index dedup — chỉ tiêu chính của nhiệm vụ

Vị từ partial chép **nguyên văn cú pháp** từ phase-2:137, đúng theo D7 (*"vị từ truy vấn khớp cú pháp với vị từ partial index"*):

```sql
CREATE INDEX ix_alerts_dedup
  ON alerts (rule_id, srcip, agent_name, dstip, last_seen_at DESC)
  WHERE (closed_at IS NULL OR sealed_at IS NULL) AND status <> 'duplicate';
```

**Kết quả `EXPLAIN (ANALYZE, BUFFERS)` — truy vấn phase-2:116‑132 nguyên văn, tham số hoá, sau 5 lần `EXECUTE` để plan chuyển sang generic:**

```
Limit  (actual time=0.032..0.032 rows=1 loops=1)
  Buffers: shared hit=6
  ->  LockRows  (actual time=0.031..0.032 rows=1 loops=1)
        Buffers: shared hit=6
        ->  Index Scan using ix_alerts_dedup on alerts  (actual time=0.022..0.022 rows=1)
              Index Cond: ((rule_id = $1) AND (srcip = $2) AND (agent_name = $4)
                           AND (dstip = $3) AND (last_seen_at >= (now() - ...)))
              Buffers: shared hit=4
Planning Time: 0.129 ms
Execution Time: 0.049 ms
```

| Chỉ tiêu nhiệm vụ | Kết quả |
|---|---|
| Cả **bốn** cột khóa cụm vào `Index Cond` | ✅ `rule_id`, `srcip`, `agent_name`, `dstip` — đủ bốn |
| **Không** cột khóa cụm nào rơi xuống `Filter` | ✅ không cột nào |
| **Không** có node `Sort` | ✅ không có |
| Buffers thật | **4** trên Index Scan · 6 tính cả `LockRows` |
| Thời gian thật | **0,049 ms** |

Con số 4 buffer **trùng đúng** giá trị B1 đo được (phase-1:107). Ca `srcip = ''` (rule FIM) cho cùng plan, 0,069 ms.

**Đối chứng B1 — chạy lại vị từ bản cũ trên chính bộ dữ liệu này:**

| Vị từ | `srcip`/`dstip` vào đâu | Node `Sort` | Buffers | Thời gian |
|---|---|---|---|---|
| `srcip = $2` (sau B1) | `Index Cond` | **không** | 4 | 0,049 ms |
| `srcip IS NOT DISTINCT FROM $2` | **`Filter`** | **có** | 4 (+3 cho Sort) | 0,071 ms |

> **Chỗ tôi không tái lập được, và phải nói rõ.** B1 đo tỉ lệ **154 → 4** buffer. Bộ dữ liệu của tôi cho **7 → 6**. Hình dạng plan tái lập chính xác (rơi xuống `Filter`, xuất hiện `Sort`), nhưng **độ lớn thì không**. Nguyên nhân: `IS NOT DISTINCT FROM` làm scan phải quét mọi dòng khớp tiền tố `(rule_id, agent_name)`; dữ liệu tôi sinh phân bố `rule_id × agent_name` gần đều nên tiền tố đó chỉ có vài dòng, còn dữ liệu B1 đo hẳn có tiền tố dày hơn nhiều. **Kết luận của B1 vẫn đứng vững — nhưng đứng nhờ hình dạng plan, không nhờ con số 154 mà tôi tái lập được.** Không mượn con số của họ.

#### Vì sao vị từ partial vẫn hiện trong `Filter` — không phải D7 hỏng

`EXPLAIN` in ra:

```
Filter: (((closed_at IS NULL) OR (sealed_at IS NULL)) AND (status <> 'duplicate')
         AND (occurrence_count < $8) AND (first_seen_at >= ...))
```

Nhìn qua tưởng vị từ partial không khớp. Đã kiểm chứng bằng cách chạy **cùng truy vấn, bỏ `FOR UPDATE`**:

```
Filter: (occurrence_count < 1000)
```

Hai clause của vị từ partial biến mất. Nguyên nhân: Postgres chỉ loại bỏ clause dư thừa nhờ index predicate khi bảng **không có rowmark**; `FOR UPDATE` tạo rowmark nên bước đó bị bỏ qua. Index **vẫn được chọn** (điều kiện là chứng minh được hàm ý — và nó chứng minh được), chỉ là clause được kiểm lại trên chính tuple đã nạp. Chi phí bằng không.

**Đáng ghi vào tài liệu triển khai**: `FOR UPDATE` là bắt buộc theo phase-2:132, nên `EXPLAIN` của truy vấn dedup **sẽ luôn** hiện vị từ partial ở `Filter`. Người kiểm tra D7 mà không biết điều này sẽ báo động nhầm.

### ②③④ Ba index correlation — `BitmapOr`

Truy vấn phase-4:250‑266, chạy trên agent bận **3.012 alert trong cửa sổ 4 giờ** (dựng đúng theo phase-4:231):

```
Bitmap Heap Scan on alerts (actual time=0.536..3.955 rows=287)
  Heap Blocks: exact=470
  ->  BitmapOr (actual time=0.463..0.464)
        ->  Bitmap Index Scan on ix_alerts_corr_agent  (rows=2987)  Buffers: shared hit=19
        ->  Bitmap Index Scan on ix_alerts_corr_user   (rows=1)     Buffers: shared read=3
        ->  Bitmap Index Scan on ix_alerts_corr_srcip  (rows=902)   Buffers: shared hit=4 read=9
Execution Time: 4.500 ms
```

✅ **`BitmapOr` trên đủ ba index** — xác nhận phase-4:279 (*"`OR` nhiều cột không phải vấn đề, miễn là mỗi cột có index riêng"*).

**Đối chứng danh sách thô** (như tài liệu gốc, không `LIMIT`): 287 dòng, 1,927 ms, 502 buffer.

| | Số dòng vào prompt | Thời gian |
|---|---|---|
| Danh sách thô | 287 | 1,93 ms |
| Tóm tắt gộp (P4‑2) | **20** (`LIMIT 20`) | 4,50 ms |

Chiều của kết quả khớp P4‑2: bản tóm tắt **chậm hơn** (họ đo 3,47 vs 0,68 ms; tôi đo 4,50 vs 1,93 ms) nhưng cắt mạnh số dòng vào prompt.

> **Một phát hiện đi ngược trực giác, cần ghi lại.** Phép gộp `GROUP BY rule_id, category, status` trên dữ liệu của tôi nén **287 dòng thành 286 nhóm** — tức là gần như **không nén gì**. P4‑2 đo được 1.792 → 6.
>
> Nguyên nhân: generator của tôi gán `rule_id` và `category` ngẫu nhiên đều, nên thiếu đúng cái độ lệch của đời thật — *"một agent bận thì bắn đi bắn lại vài rule giống nhau"*. Dữ liệu của tôi là ca xấu nhất cho phép gộp.
>
> **Hệ quả cho thiết kế:** thứ giữ prompt trong ngân sách là **`LIMIT 20`**, không phải phép gộp. Phép gộp chỉ nén tốt khi dữ liệu thật có độ lệch; `LIMIT` thì chặn được cả ca xấu nhất. Con số "giảm 213 lần" của P4‑2 là **phụ thuộc dữ liệu** và không nên trích trong báo cáo như một hằng số. Trần thì không phụ thuộc dữ liệu — và đó mới là thứ đáng nói.

### ⑤ `ix_alerts_duplicate_of`

`Index Cond: (duplicate_of = $0)`, 0,788 ms. Partial `WHERE duplicate_of IS NOT NULL` loại 52.661 dòng gốc khỏi index — chúng không bao giờ là kết quả của ba truy vấn dùng index này.

### ⑥ `ix_alerts_queue_tier1`

```
Bitmap Index Scan on ix_alerts_queue_tier1 (rows=11186)  Buffers: shared read=64
Bitmap Heap Scan  Heap Blocks: exact=5086
Sort Method: top-N heapsort  Memory: 36kB
Execution Time: 41.769 ms
```

Index được dùng. **Node `Sort` vẫn còn, và đây là điều không tránh được**: khóa sắp xếp đầu tiên là `needs_retriage` — một biểu thức tính lúc truy vấn theo phase-6:46 (*"tính lúc truy vấn, không lưu cột"*). Biểu thức đó không đánh chỉ mục được nếu không lưu thành cột, mà lưu thành cột thì phá đúng quyết định của P6.

41,8 ms cho 11.186 alert trong hàng đợi, trong đó phần lớn là 5.086 heap block. Chấp nhận được cho một trang danh sách; nếu hàng đợi phình lên nhiều lần thì đây là chỗ cần nhìn lại trước tiên.

### ⑦ `ix_alerts_sweeper`

```
Bitmap Index Scan on ix_alerts_sweeper  Index Cond: (autoclose_rule_id = $0)  rows=1154
UPDATE ... Execution Time: 135.645 ms
```

Niêm 1.154 cụm của một rule trong 136 ms, trong đó phần index tìm kiếm chỉ 0,15 ms — phần còn lại là ghi. Đây là đường "tắt rule có hiệu lực tức thì" của B4; không có index thì thao tác này quét toàn bảng đúng lúc analyst đang vội.

### ⑧⑨ Lớp bảo vệ 2 — index thứ chín tìm ra bằng đo đạc

Truy vấn phase-3:277‑288 với **chỉ** `ix_alerts_received_at`:

```
Bitmap Heap Scan on alerts  Filter: (status = 'auto_closed')
  Rows Removed by Filter: 120406      Heap Blocks: exact=20704
  Buffers: shared hit=5317 read=15778 written=3259
(phần này) 117,5 ms
```

Đọc 124.295 dòng để lấy 3.889 — thừa 32 lần. Thêm `ix_alerts_autoclose_7ngay`:

| | Thời gian | Buffers | Dòng bị loại ở Filter |
|---|---|---|---|
| Chỉ ⑧ | 117,5 ms | 21.095 | 120.406 |
| Thêm ⑨ | **11,4 ms** | **2.905** | **0** |

Nhanh gấp **10,3 lần**, đổi lấy **400 kB**. Vì phát hiện này đến sau khi `004` đã áp, nó đi thành `005_index_lop_bao_ve_2.sql` chứ không sửa ngược vào `004`.

Index ⑧ vẫn giữ: nó phục vụ **nửa mẫu số** của cùng truy vấn (`count(*)` trên toàn bộ cửa sổ 7 ngày, chạy bằng `Index Only Scan`) và báo cáo theo tuần ở kien-truc:400.

### Index cố ý KHÔNG tạo

`event_bucket_hash`. phase-2:505 ghi rõ *"bỏ index cũ theo cột băm — không còn truy vấn nào dùng"*, và D8 (phase-2:405) **cấm** mọi truy vấn đếm cụm bằng cột này. Tạo index sẽ mời gọi đúng thứ D8 cấm.

---

## 6 · Quyết định thiết kế phải tự đưa ra

Bốn quyết định không phải mâu thuẫn giữa các tệp mà là **khoảng trống** — đặc tả không nói, nhưng viết DDL thì buộc phải chọn. Ghi lại để người sau biết chúng là lựa chọn của tôi, không phải của đặc tả.

**Q1 · `alerts.alert_id` là `text`, không phải `uuid`.** Nguồn là `_source.id` của Wazuh, dạng `"1786903016.121311"` (phase-1:376). Nó là `PRIMARY KEY` và là **cơ chế chống gửi lặp duy nhất** (phase-1:78), nên không được đổi dạng.

**Q2 · `subject_id` của `audit_events`, `llm_runs`, `jobs` là `text`, không phải `uuid`.** Bắt buộc, vì cột này **đa hình**: phase-5:135 ghi `alert_id` (text), phase-7:327 ghi `case_id` (uuid), và phase-7:325 dùng `case_id` làm `subject_id` của `tier2.concluded`. Một cột `uuid` sẽ không nhận được `alert_id`. Đây cũng là điều kiện để phép đo độ khớp `JOIN llm_runs r ON r.subject_id = a.alert_id` (phase-6:35) chạy được mà không cần ép kiểu.

**Q3 · `audit_events` và `llm_runs` KHÔNG có khóa ngoại tới `alerts`/`cases`.** Hai lý do: (a) `subject_id` đa hình nên không có một bảng đích duy nhất; (b) hai bảng này là **append-only ghi vết** (kien-truc:90) — vết phải sống sót kể cả khi đối tượng bị dọn. FK sẽ biến "dọn dữ liệu cũ" thành "mất vết".

**Q4 · `schema.sql` được SINH RA từ `migrations/`, không gõ tay.** Hai tệp gõ tay sẽ lệch nhau sau vài đợt sửa và không ai phát hiện cho tới lúc dựng lại DB từ đầu. Đã kiểm chứng: `pg_dump --schema-only` của DB dựng bằng 5 migration và DB dựng bằng `schema.sql` **giống hệt nhau** (255 dòng DDL, diff rỗng).

---

## 7 · Cần bổ sung — ✅ **cả chín mục đã chốt**

Chín mục dưới đây **không có trong đặc tả**. Chỗ nào tôi phải chọn thì ghi rõ đã chọn gì và vì sao; chỗ nào không đủ căn cứ thì **cố ý để trống** thay vì bịa.

> **Vòng chốt hợp đồng (25/08) đã đóng cả chín.** Mục này giữ nguyên phần *nêu vấn đề* — đó là thứ cần kiểm lại được — và thêm một dòng **→ CHỐT** ở cuối mỗi mục. Bảng tổng cùng lý lẽ đầy đủ ở **§10**.
>
> | Mục | Chốt | Cưỡng chế |
> |---|---|---|
> | ① `jobs.status` | thêm `succeeded`; dòng job xong **giữ lại** | `ck_jobs_status` · 006 |
> | ② khoá chính `audit_events` | giữ `audit_id bigint IDENTITY`, **không** thêm unique trên nội dung | xác nhận, không đổi |
> | ③ `closed_confirmed` | **giữ** trong `ck_alerts_status` | xác nhận, không đổi |
> | ④ tên cột `rejected_alerts` | **giữ nguyên** | xác nhận, không đổi |
> | ⑤ `iocs` chỉ 2–3 cột · `value` là PK | thêm `source`; PK → `(value, source)`; chấm điểm *"xấu nhất trong các dòng còn hạn"* | 006 |
> | ⑥ `resolved_by` chỉ biết 2/6 | 6 giá trị: `mitre · mitre_parent · rule_groups · decoder · dst_port · none` | `ck_alerts_resolved_by` · 006 |
> | ⑦ `autoclose_rules.rule_id` trùng tên | **đổi tên** → `autoclose_rule_id` | 006 |
> | ⑧ không có bảng `users` | tạo `users` + FK cho **5 cột trạng thái sống**; `audit_events.actor_id` **cố ý không** FK | 007 |
> | ⑨a `llm_runs.run_id` · ⑨b `agent_ip` | giữ nguyên (`uuid` app cấp · `text` không CHECK) | xác nhận, không đổi |
> | ⑨c `alert_user` `NULL` vs `''` | chỉ `NULL`, **cấm `''`**; `phase-4` đã sửa | `ck_alerts_alert_user_khong_rong` · 006 |

**① `jobs.status` thiếu giá trị cho job chạy XONG.** Đặc tả nêu `'pending'` (phase-4:44), `'running'` (phase-4:49), `'failed'` (phase-4:68) — **không nêu** giá trị cho job thành công. Đây là khoảng trống có thật, không phải tôi đọc sót: phase-4:65‑70 liệt kê bốn tình huống và không tình huống nào là "xong".
→ **Cố ý KHÔNG đặt `CHECK` trên cột này.** Bịa một giá trị (`'done'`? `'completed'`? `'succeeded'`?) rồi cưỡng chế nó bằng `CHECK` là biến phỏng đoán của tôi thành luật của DB. Cần chốt, rồi thêm `CHECK` trong một migration sau.

**② `audit_events` không có khóa chính trong đặc tả.** Không tệp nào nêu. → Đã đặt `audit_id bigint GENERATED BY DEFAULT AS IDENTITY`. Cần xác nhận: có cần id ổn định giữa các lần khôi phục không, và có cần chống ghi trùng không.

**③ `closed_confirmed` chưa qua vòng chốt chính thức.** phase-7:451 xếp nó vào *"việc còn lại"*; kien-truc:263 đánh dấu *"trạng thái mới, chưa có trong II‑06 bản gốc"*. Tôi đưa vào `ck_alerts_status` dựa trên hai nguồn đồng thuận, nhưng nó **chưa được phản biện có đo đạc** như các chốt khác. Là chỗ dễ bị lật nhất trong schema này.

**④ Tên cột của `rejected_alerts` không có trong đặc tả.** phase-1:459 chỉ mô tả bằng văn xuôi: *"payload gốc + lý do + `source_ip` + thời điểm"*. → Đã đặt `raw_payload`, `reason`, `source_ip`, `received_at` cho khớp cách đặt tên của `alerts`. Cần xác nhận, và cần chốt thêm chính sách lưu giữ (bảng này phình theo số payload hỏng, không có ai dọn).

**⑤ `assets`, `identities`, `iocs` chỉ biết được 2–3 cột mỗi bảng.** Phase 4 dùng `SELECT *` (phase-4:84‑86) nên không lộ danh sách cột; chỉ suy ra được `hostname`/`criticality`, `username`/`is_privileged`, `value`/`reputation`/`expires_at` từ công thức `risk_score`. → Đã tạo tối thiểu. Ba câu hỏi treo:
 - `iocs` có cần cột `ioc_type` không? Hiện `value` là `PRIMARY KEY`, nên **một giá trị chỉ nằm được trong một dòng** — không biểu diễn được ca "cùng một IP bị hai nguồn bêu tên với hai mức uy tín".
 - Ba bảng này ai ghi vào, và bao lâu một lần? Không tệp nào nói.
 - `criticality` của một host đổi theo thời gian thì có cần lịch sử không? Nếu có, `risk_score` cũ không dựng lại được.

**⑥ Tập giá trị `resolved_by` chỉ biết 2/6.** phase-1:158 nói *"ghi lại tầng đã quyết"*, 5 tầng ở phase-1:160‑166 chỉ có tên mô tả tiếng Việt. Đặc tả nêu đúng hai giá trị thật: `'mitre'` (phase-1:421) và `'none'` (phase-1:202).
→ **Cố ý KHÔNG đặt `CHECK`.** Tự đặt tên cho 4 tầng còn lại (`mitre_parent`? `groups`? `decoder`? `port`?) rồi cưỡng chế là đóng băng phỏng đoán của tôi vào DB.

**⑦ `autoclose_rules.rule_id` trùng tên với `alerts.rule_id` nhưng khác hẳn nghĩa.** Cái trước là `uuid` của rule auto-close (phase-3:84); cái sau là id rule Wazuh dạng text (`"40112"`). Cùng lúc, `alerts.autoclose_rule_id` lại trỏ tới `autoclose_rules.rule_id`. Một câu `JOIN … USING (rule_id)` viết vô ý sẽ hoặc lỗi kiểu hoặc — tệ hơn — nối sai. → Đã giữ nguyên tên theo phase-3:84 vì đó là DDL đã viết sẵn trong đặc tả, nhưng **nên đổi thành `autoclose_rule_id`** trong một migration đổi tên.

**⑧ Không có bảng `users`.** Năm cột `uuid` trỏ tới người: `alerts.acknowledged_by`, `cases.created_by`, `cases.concluded_by`, `case_alerts.added_by`, `autoclose_rules.created_by`, `audit_events.actor_id`. Không cột nào có FK vì không có bảng đích. Hệ quả: DB không chặn được `created_by` trỏ tới một uuid không tồn tại, và báo cáo không hiển thị được tên người quyết.

**⑨ Ba mục nhỏ hơn.** (a) `llm_runs.run_id` không nêu kiểu — đã chọn `uuid`, do app cấp (phase-5:131 liệt kê nó trong danh sách cột `INSERT`). (b) `alerts.agent_ip` để `text` chứ không `inet`, vì R2 cấm đường phân loại `raise` và một IP hỏng không được làm mất alert; đánh đổi là DB không kiểm được tính hợp lệ. (c) `alert_user` mặc định là `NULL` theo phase-1:63, nhưng phase-4:99 lại viết `alert_user = ''` khi mô tả ca `skipped` — hai chỗ không khớp, ảnh hưởng tới `SELECT DISTINCT alert_user … WHERE alert_user IS NOT NULL` ở phase-2:299.

---

## 8 · Dữ liệu thử và cách tái lập

### 8.1 · Bộ dữ liệu

500.000 dòng sinh bằng `gen_data.py` (seed cố định `20260823`, tái lập được).

| Trạng thái | Số dòng (cụm) | Tổng alert (`sum(occurrence_count)`) |
|---|---:|---:|
| `duplicate` | 447.339 | 447.339 |
| `auto_closed` | 17.278 | 176.738 |
| `queued_tier1` | 11.186 | 106.096 |
| `closed_fp` | 8.294 | 72.925 |
| `closed_benign` | 4.280 | 38.628 |
| `escalated_tier2` | 2.690 | 26.725 |
| `enriching` | 2.618 | 21.076 |
| `closed_confirmed` | 2.145 | 22.446 |
| `tier1_active` | 2.099 | 17.660 |
| `received` | 2.071 | 17.706 |

Bám theo đặc tả ở bốn điểm: kích thước cụm có **đuôi nặng** (72% cụm chỉ 1 dòng, một số cụm tới 1.000) theo phase-3:314; chặn ở `MAX_CLUSTER_SIZE = 1000`; 12% alert có `srcip = ''` (rule FIM/rootcheck, phase-2:345); và có **đúng một agent bận 3.012 alert trong 4 giờ** theo phase-4:231. `raw_payload` giữ hình dạng envelope Wazuh thật (~600 byte/dòng) nên bảng có TOAST như thật — 1.317 MB.

Alert `severity = 'critical'` **không bao giờ** được gán `auto_closed` trong generator, theo G8/A1.

### 8.2 · Ba chỗ bộ dữ liệu này KHÔNG đại diện

Nói trước để không ai trích số sai:

1. **Phép gộp correlation gần như không nén** (287 → 286) vì `rule_id`/`category` gán ngẫu nhiên đều. Xem §5②③④.
2. **Tỉ lệ buffer của đối chứng B1 không tái lập được** (7→6 thay vì 154→4) vì tiền tố `(rule_id, agent_name)` quá thưa. Xem §5①.
3. **Không có dòng `raw_log` nào chạm ngưỡng 1000 KB**, nên nhánh cắt C3 chưa được kiểm bằng dữ liệu thật — chỉ được kiểm bằng một ca vi phạm `CHECK` đơn lẻ.

### 8.3 · Lệnh tái lập

> **Ba tệp mà mục này viện dẫn trước đây KHÔNG tồn tại trong repo** — `build_schema.py`,
> `load.sql`, và thư mục `migrations/`. Nghĩa là lệnh tái lập ở đây không chạy được như đang
> viết. Vòng chốt hợp đồng đã tạo hai tệp đầu và sửa đường dẫn migration cho đúng thực tế
> (chúng nằm phẳng trong `docs/Schema/`, không trong `migrations/`).

```bash
# 0 · sinh lại schema.sql từ migrations (schema.sql KHÔNG được sửa tay)
python3 build_schema.py            # ghi schema.sql
python3 build_schema.py --check    # exit 1 nếu ai đó đã sửa thẳng schema.sql — đặt được vào CI

# 1 · dựng schema (một trong hai cách, cho kết quả giống hệt nhau)
psql -d soc -v ON_ERROR_STOP=1 -f schema.sql
# hoặc
for f in 0*.sql; do psql -d soc -v ON_ERROR_STOP=1 -f "$f"; done

# 2 · sinh + nạp 500k dòng
SOC_DATA_OUT=/tmp/socdata python3 gen_data.py
psql -d soc -v ON_ERROR_STOP=1 -v dir=/tmp/socdata -f load.sql
#   load.sql nạp users TRƯỚC (FK của migration 007), rồi VALIDATE
#   fk_alerts_acknowledged_by — lệnh đó chạy được là bằng chứng gen_data.py
#   dùng tập analyst CỐ ĐỊNH chứ không phải uuid ngẫu nhiên mỗi dòng.

# 3 · ba phép đo EXPLAIN
psql -d soc -f explain_dedup.sql       # ① dedup   · 4 cột vào Index Cond, không Sort
psql -d soc -f explain_corr.sql        # ②③④ BitmapOr ba index
psql -d soc -f explain_rest.sql        # ⑤⑥⑦⑧ index còn lại

# 4 · thử vi phạm ràng buộc (34 ca âm + 7 ca dương)
python3 test_constraints.py            # exit 0 nghĩa là cả 41 ca đều đúng kỳ vọng

# 5 · quét lại bảng truy vết cột từ đặc tả
python3 trace_columns.py
```

Môi trường đã dùng: **PostgreSQL 16.15 (Ubuntu 16.15‑0ubuntu0.24.04.1)** — cùng phiên bản với mọi phép đo trong bộ đặc tả.

---

## 9 · Bốn chỗ đặc tả cần sửa — ✅ **đã sửa**

Rút ra từ §2. Đây là thay đổi **tài liệu**, không phải thay đổi schema.

> **Đã thi hành cùng đợt với R1–R4 của `transitions.md`.** Bốn mục này được ghi nhận từ D3
> nhưng chưa ai áp; đợt sửa của D4 áp luôn để `docs/` chỉ còn một sự thật.
> Số dòng dưới đây là bản `docs/` **hiện hành** (sau đợt sửa).

| # | Tệp | Sửa gì | Trạng thái |
|---|---|---|---|
| 1 | phase-2:218, 223, 339, 447, 503 | `concluded_*` → `closed_confirmed` khi nói về `alerts.status` (chốt M‑A). Gồm cả tên test `test_goc_concluded_fp_thi_khong_gop` vốn không chạy được như đang viết — nay là `test_goc_closed_confirmed_thi_khong_gop`. Rà lại thấy **năm** chỗ chứ không phải ba: §9 bản trước bỏ sót `:218` và `:223` | ✅ |
| 2 | phase-3:178 | `triage_status` là `'ready'`, không phải `'done'` (chốt M‑B) | ✅ |
| 3 | phase-3:249‑255 | Đồng bộ với phase-5:171‑177: `pipeline = 'triage'` và `result->>'suggested_action'` (chốt M‑C) | ✅ |
| 4 | phase-2:404 | Ghi chú D7: `EXPLAIN` truy vấn dedup **luôn** hiện vị từ partial ở `Filter` do `FOR UPDATE` tạo rowmark — không phải dấu hiệu index không khớp | ✅ |

> **Hai chốt của §2 nay được DB cưỡng chế và có test hồi quy.** `verify_transitions.py` giữ ca
> `Ma` (`alerts.status='concluded_fp'` phải bị `ck_alerts_status` chặn) và ca `Mb`
> (`triage_status='done'` phải bị `ck_alerts_triage_status` chặn). Ai lật mục 1 hoặc mục 2 sẽ
> nhận `FAIL`, không phải trông vào việc có người rà lại bằng mắt.

**Đợt sửa của D4 thêm sáu chỗ nữa vào `docs/`** — xem `output/transitions.md` §13 cho danh sách
đầy đủ. Tóm tắt: `phase-6:183‑194` (escalate tách hai câu), `phase-6:257‑267` (vị từ
`correlated_cluster_ids()` được viết ra), `kien-truc:238` + `:389` + `:372` + `:395`,
`phase-2:406` (bất biến **D11**), `luong-du-lieu:157`.

Ngoài ra, bản `DESIGN-DOSSIER.html` (ảnh chụp 20/08, cũ hơn bộ `.md` ngày 23/08) từng nêu một mâu thuẫn về **thứ tự auto-close so với enrichment**. Bộ đặc tả Phase 1–7 đã chốt xong (auto-close ở `ingest/`, **trước** enrichment — phase-3:23‑34), nên mâu thuẫn đó không còn treo.

> **Dossier đã được xoá khỏi `docs/` (25/08).** Nó lệch quá nhiều so với bộ `.md` để giữ lại mà không gây hiểu nhầm: `cases.status='open'` (nay là `investigating`), sơ đồ máy trạng thái cũ, và một phiên bản khác nữa của phép đo `gop_trung_lap`. **Nguồn sự thật duy nhất là bộ `.md` trong `docs/` cộng `output/transitions.*`.** Nếu về sau cần dựng lại một hồ sơ thiết kế dạng trình bày, hãy sinh mới từ bộ `.md` hiện hành chứ đừng khôi phục bản cũ.

---

## 10 · Vòng chốt hợp đồng — 15 quyết định trước khi viết `domain/transitions.py`

Rút ra từ §2 và §7 của tệp này cộng §11 của `output/transitions.md`. **Không mục nào là đoán:**
mỗi dòng ghi lý do và đánh đổi đã chấp nhận. Hai migration mới — `006_chot_hop_dong.sql` và
`007_users.sql` — là toàn bộ hệ quả DDL; `001`–`005` **không bị sửa**.

| Mã | Quyết định | Lý do | Đánh đổi đã chấp nhận |
|---|---|---|---|
| **A** | Cạnh `auto_closed → escalated_tier2` **không tồn tại** | Cạnh này rút cụm khỏi tử số phép đo **sau khi báo cáo đã in** — cùng một tuần cho hai con số khác nhau ở hai lần chạy. Đường sửa sai đã có: tắt rule + mẫu đối chứng 5 % | Analyst không đưa được cụm `auto_closed` vào case. Đường *"đính kèm bằng chứng"* hoãn |
| **B** | Escalate alert đã có `case_id` → **409**, không bao giờ gộp case | Gộp case = gộp hai kết luận + hai vết audit = tính năng Tier 2 ngoài phạm vi | Hai analyst đua nhau escalate cùng cụm thì người sau phải làm lại thao tác |
| **C** | A1 = `alert.received`, A4 = `alert.enrich_started`, **có tên nhưng không phát** | A1 nổ trên 100 % alert, A4 trên gần hết phần còn lại — phát ra là biến `audit_events` thành bảng nhật ký chứ không phải bảng **quyết định**. Có tên để phase sau không tự bịa | Timeline một alert thiếu hai mốc; bù bằng `received_at` và `alert.enriched` vốn đã có |
| **D** | Escalate ghi **hai dòng**: `tier1.escalated` (alert_id) + `case.opened` (case_id) | Đổi hẳn sang `case_id` làm hỏng phép đo độ khớp ① ↔ người: nó nối `llm_runs.subject_id = alert_id` | +1 dòng audit mỗi lần escalate — 2.690/500.000 ở bộ thử |
| **T** | Thứ tự `dedup → auto-close → enrichment`, tất cả trong webhook | Lý do *"tiết kiệm hạn ngạch API"* chỉ đứng vững ở thứ tự này. Repo **đã chốt sẵn** ở `kien-truc:104` + `luong-du-lieu:228` | Alert `auto_closed` không có IoC ngoài → hai nhóm không cùng bộ tín hiệu, phải nói rõ trong báo cáo |
| **N1** | Một tên duy nhất `job.exhausted`, xoá `enrich.exhausted` | `phase-4` dùng **cả hai tên** cho cùng một sự kiện. Có 2 `job_type` nên tên phải chung; `job_type` nằm trong payload | `phase-4:334` và `:412` phải sửa — đã sửa |
| **N2** | ③a thêm `AND case_id IS NULL`, so `rowcount` với số dòng `case_alerts`; lệch → `ROLLBACK` 409 | `WHERE alert_id IN (case_alerts)` **không nhắc tới `status`** nên không được bảo vệ bởi bộ lọc của `correlated_cluster_ids()`. Dưới `READ COMMITTED`, hai escalate chồng nhau cướp `case_id` của nhau — im lặng | Escalate có thêm một phép so số dòng |
| **S1** | `jobs.status ∈ {pending, running, succeeded, failed}`; dòng job xong **giữ lại** | `succeeded` là phản nghĩa của `failed` mà đặc tả đã cố định. Xoá dòng xong là mất dữ liệu đo độ trễ job và số lần retry | `jobs` phình; chính sách dọn hoãn |
| **S5** | `iocs` thêm `source`, PK → `(value, source)`; chấm điểm *"xấu nhất trong các dòng còn hạn"* | Đổi PK sau khi có dữ liệu là migration. `phase-4:86` vốn đã là `value IN (…)` nên trả tập dòng — tầng ứng dụng không phải đổi. Luật *"xấu nhất"* giữ `risk_score` tất định | Chưa có `ioc_type` — hoãn |
| **S6** | `resolved_by` 6 giá trị + `CHECK` | Ngữ nghĩa 5 tầng đã đặc tả đầy đủ (`phase-1:160‑166`); thứ duy nhất còn trống là **chính tả**, mà chính tả thì `phase-1` buộc phải chốt. Sai chính tả không có `CHECK` = tỉ lệ `unknown` sai âm thầm | Nếu sau này tách thêm tầng thứ 6 thì phải sửa `CHECK` |
| **S7** | `autoclose_rules.rule_id` → `autoclose_rule_id` | `JOIN … USING (rule_id)` viết vô ý nối `alerts.rule_id` (text Wazuh) với uuid rule auto-close — hoặc lỗi kiểu, hoặc nối sai **im lặng**. Đổi bây giờ khi chưa dòng code nào tham chiếu là **một lệnh** | Lệch một chữ so với DDL nguyên văn `phase-3:84` |
| **S8** | Bảng `users` tối thiểu + FK cho 5 cột trạng thái sống; `audit_events.actor_id` **không** FK | Thêm FK sau khi đã có dòng mồ côi là migration có thể thất bại. Loại trừ `audit_events`: vết phải sống sót khi người dùng bị dọn | Không phân quyền theo nhóm. **GIẢ ĐỊNH:** < 50 analyst, vai trò phẳng |
| **S9c** | `alert_user` chỉ `NULL`, cấm `''`; `phase-4:99` sửa theo | `phase-2:299` lọc `IS NOT NULL`; nếu `''` lọt vào, `SELECT DISTINCT alert_user` trả `''` như một *"tài khoản bị nhắm"* — sai kiểu im lặng | Phải sửa một câu ở `phase-4` và kiểm `gen_data.py` — đã làm |
| **S2·S3·S4·S9a·S9b** | Xác nhận, **không đổi** | Xem §7 | — |

### 10.1 · Ba chỗ vỡ tìm được khi thi hành S8, và cách xử lý

S8 ghi *"bảng nhỏ, chưa có dữ liệu thử → validate ngay"*. Rà lại thì **không đúng hẳn**:

1. **`cases` CÓ dữ liệu thử.** `gen_data.py` sinh `cases.tsv` (4.856 dòng) và
   `autoclose_rules.tsv`. Chúng validate được **chỉ vì** cả hai dùng đúng một uuid. Phải seed
   user đó trước — `load.sql` nay nạp `users` ở bước ①.
2. **`acknowledged_by` là uuid ngẫu nhiên MỖI DÒNG** — tới hàng chục nghìn "người" không tồn
   tại trong 500.000 dòng, nên `VALIDATE CONSTRAINT` không bao giờ chạy được. `gen_data.py` nay
   bốc từ **tập `ANALYSTS` cố định 20 người** và sinh `users.tsv`.
3. **Hai bộ test dùng uuid tự bịa** (`00000000-0000-…`, `44444444-…`, `66666666-…`) → FK mới
   chặn. Cả hai nay seed user fixture **lấy từ chính tập `ANALYSTS`**, để bộ test và bộ dữ liệu
   thử nói về cùng những con người.

Đã chạy thật sau khi sửa: nạp 500.229 dòng vào schema đủ 7 migration, **5/5 FK `convalidated`**,
`VALIDATE fk_alerts_acknowledged_by` chạy được, `alert_user = ''`: **0 dòng**.

---

*schema-notes.md · AI Support SOC · 51 cột `alerts` · 7 migration · 15 quyết định của vòng chốt hợp đồng ·
34/34 ca vi phạm bị chặn · PostgreSQL 16.15 · 500.229 dòng*
