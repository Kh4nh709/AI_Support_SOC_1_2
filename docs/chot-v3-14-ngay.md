# Bản chốt v3 — xây trong 14 ngày (04/09 → 18/09/2026)

Tiếp nối `phan-bien-kien-truc-v2-2026-09-04.md`. Năm câu trả lời của chủ đồ án:

1. Deadline: **2 tuần** (18/09/2026).
2. Wazuh bắn thẳng vào hệ thống; **có máy lab** sinh alert tấn công.
3. Analyst = **chủ đồ án + giảng viên**; chấp nhận gán nhãn 400 cụm, 50 % alert mù, 5 phút digest/ngày.
4. Nhà cung cấp **DeepSeek**, model `DeepSeek-V4-Flash-0731`, **chưa thử** trên alert thật.
5. "Có cần export ra" — hiểu là: **có, cần export kiểm kê/danh tính ra tệp** một lần.

---

## A. Phản biện năm câu trả lời

### A1 · "Deadline 2 tuần"

**Số học trước.** 14 ngày lịch = 10 ngày làm việc + 2 cuối tuần. Một người. Hiện có 0 dòng code ứng dụng. Cần: xây hệ chạy được, sinh dữ liệu lab, gán nhãn 400 cụm (2 người), chạy đánh giá, viết báo cáo. Kiến trúc v2 cần ~16 tuần. **Không có cách nào xây v2 trong 2 tuần**, và cố làm là cách chắc chắn nhất để tới ngày 18/09 với một hệ nửa vời và không có bảng kết quả.

**Hệ quả bắt buộc.**
- Bằng chứng chính của đồ án **phải là offline**: bộ vàng + ablation + đối kháng. Thí điểm trực tuyến mù chỉ kéo dài được ≈ 7 ngày → ~350 alert thô → ~70 quyết định mỗi nhánh → **chỉ báo cáo mô tả**, không tuyên bố p-value trừ khi hiệu ứng rất lớn. Phải viết đây là *thiết kế nghiên cứu*, không phải lời xin lỗi.
- Mọi thứ không nằm trên đường tới "① đã được đánh giá" đều cắt: vòng tool của ②, VT/MISP/n8n, shadow mode, hash-chain, Prometheus, admin UI, sync AD.
- **Quy tắc mỗi ngày:** cuối ngày phải có thứ chạy được và một dòng trong bảng kết quả tiến thêm. Ngày nào chỉ có "hạ tầng" là ngày mất.

**Một cơ hội chưa khai thác.** README ghi các module `prompt_guard`, `output_guard`, `category_resolver`, parser Wazuh "được port sang nguyên vẹn" từ `Final-Project`. Repo hiện không có chúng — trạng thái: `UNKNOWN`. Nếu chúng tồn tại và chạy, tiết kiệm ≈ 2 ngày. Kiểm tra **hôm nay**.

### A2 · "Wazuh bắn trực tiếp + có lab"

- "Bắn trực tiếp" không trả lời câu hỏi thật: **có lưu trữ alert cũ không?** Wazuh manager giữ `alerts.json` trong `/var/ossec/logs/alerts/` và xoay theo tháng. Nếu có ≥ 1 tháng, bộ vàng G1 đủ 400 cụm ngay ngày 2 qua **replay importer** (đọc `alerts.json` → cùng pipeline, `source='replay'`). Nếu không có: 50/ngày × 12 ngày ≈ 600 alert thô ≈ 200–250 cụm + lab → **sàn 300 cụm**, ghi rõ trong báo cáo. Kiểm tra hôm nay.
- Lab sinh alert `escalate` là tốt, nhưng có bẫy: nếu mọi alert từ host lab đều là tấn công, model (và người) học được "host lab = escalate" qua hostname. **Phải sinh cả hoạt động lành tính trên chính host lab** (cập nhật gói, cron, đăng nhập admin, quét lỗ hổng của mình) ≥ 20 cụm, và đưa host lab vào kiểm kê với vai trò bình thường.
- Một số category (`c2_beacon`, `data_exfiltration`) khó tạo alert chỉ bằng Wazuh nếu không có Suricata; nếu không sinh được thì **bỏ category đó khỏi bảng kết quả**, không giả.

### A3 · "Tôi và giảng viên là analyst"

Đây là điểm hội đồng sẽ đánh: **người xây hệ tự gán nhãn dữ liệu để đánh giá hệ**. Không tránh được, nhưng kiểm soát được:
- **Gán nhãn mù:** trang gán nhãn không hiện bất kỳ kết quả ① nào; gán nhãn xong **trước** khi chạy đánh giá trên các cụm đó.
- **Độc lập rồi đối chiếu:** hai người gán riêng, báo Cohen's κ, bất đồng thì thảo luận và ghi lý do vào nhãn cuối.
- **Đóng băng:** xuất bộ vàng ra CSV, ghi sha256 vào git **trước** lần chạy eval đầu; đổi nhãn sau đó = phiên bản mới, có nhật ký.
- **Nhánh mù trực tuyến:** ẩn gợi ý ở tầng API (không phải chỉ UI); giảng viên cũng không được xem `llm_runs` của alert mù trước khi quyết. Quyết định của chủ đồ án trên nhánh có gợi ý ghi rõ là **có thể thiên lệch**; báo cáo tách hai người.
- Khối lượng: 400 cụm × ~1 phút = ~7 giờ/người, chia hai buổi cuối tuần 12–13/09. Khả thi.

### A4 · "DeepSeek-V4-Flash-0731, chưa thử"

Model chưa thử là **rủi ro kỹ thuật lớn nhất** trong 2 tuần, nên nó là việc **đầu tiên**, không phải việc thứ năm.

Những gì tôi biết chắc và những gì phải kiểm:
- API DeepSeek tương thích OpenAI (`base_url` + SDK OpenAI) — dùng được ngay, không viết adapter riêng.
- Chế độ `response_format={"type":"json_object"}` tồn tại trên API chat của DeepSeek và **không cưỡng chế schema**; prompt phải có chữ "json". Vì vậy: **validate schema + 1 lần sửa** là bắt buộc, không phải phòng hờ.
- Hỗ trợ function-calling cho đúng model này: `UNKNOWN` → ② **không dùng tool** (đã cắt), nên không phụ thuộc.
- Model có thể trả trường `reasoning_content` tách khỏi `content`: adapter chỉ đọc `content`.
- Độ dài context, độ trễ giờ cao điểm, giá: `UNKNOWN` cho model này → đo bằng `usage` trong response; mọi lời gọi **bất đồng bộ** (job), không bao giờ giữ kết nối người dùng.
- Dữ liệu đi tới máy chủ DeepSeek: ghi thành giả định tường minh trong báo cáo (S2).

**Smoke test ngày 1 (trước mọi code khác):** 30 alert thật (archive hoặc lab) × prompt ① tối giản → đo: tỉ lệ JSON parse được, tỉ lệ đúng schema, p50/p95 độ trễ, token vào/ra, 5 alert có raw_log 30 KB để thử context, 3 alert đối kháng để xem hành vi. **Ngưỡng chấp nhận:** JSON hợp lệ ≥ 90 % (≥ 98 % sau 1 lần sửa), p95 ≤ 60 s. Không đạt → đổi sang model chat khác của DeepSeek, vẫn qua cùng adapter.

### A5 · "Có cần export ra"

Trả lời: **có, nhưng chỉ một lần và chỉ tệp**. Không có kiểm kê thì cổng chính sách ép `needs_review` gần như mọi alert (`asset unknown`), và auto-close chỉ còn khớp rule_id/srcip. Với lab + tổ chức nhỏ: `inventory.yaml` (hostname, vai trò, criticality, chủ) ≈ 20 dòng viết tay trong 30 phút; `identities.yaml` (username, is_privileged) từ export AD một lần (`Get-ADUser`/`ldapsearch`) hoặc viết tay cho tài khoản lab. Nạp lúc worker khởi động + `POST /admin/reload-inventory`. **Không có sync-job.**

---

## B. Danh sách chốt

### B1 · Giữ / mới (D)

| # | Quyết định | Ghi chú |
|---|---|---|
| D1 | Intake ledger: webhook chỉ xác thực + INSERT `intake` + INSERT `jobs('pipeline')` + 201 | Mất alert = 0 khi DB sống |
| D2 | Heartbeat: Wazuh wodle `command` mỗi 10′ → rule riêng → cùng webhook; vắng > 30′ → thông báo | 10 dòng code + 1 rule Wazuh |
| D3 | Replay importer: `alerts.json` → intake `source='replay'`, đi hết pipeline | Mở khoá phát triển và G1 ngay ngày 2 |
| D4 | Một job `pipeline` tuần tự: parse → dedup (advisory lock) → enrich nội bộ (YAML) → auto-close → `queued_tier1` → `jobs('triage')` | Một worker |
| D5 | Máy trạng thái 10 trạng thái / 18 cạnh giữ nguyên bản đồ; `domain/` là nơi duy nhất đổi `status` | Không thiết kế lại |
| D6 | Correlation ±2 h giữ (`summarize_for_prompt`, `correlated_cluster_ids`) | — |
| D7 | Auto-close: rule whitelist P3 + trường nội bộ; chặn cứng `critical`, asset trọng yếu, **asset không trong kiểm kê**; `POST /rules/simulate`; **không shadow** | — |
| D8 | ① chạy trên **100 %** auto-closed; **digest** 08:00 hằng ngày, duyệt một bấm → `autoclose_reviews` + `triage_labels`; "sai" → reopen | Thay mẫu 5 % |
| D9 | ①: bộ dựng prompt **có kiểu** (fact = Enum/int/datetime ngoài khối; mọi chuỗi tự do = `Untrusted` trong khối nonce) + **linter** test & runtime | Đóng F‑09 |
| D10 | Cổng 7 bước: schema → basis↔DB → quote ⊂ khối → chính sách `false_positive` → detector (cờ) → **verifier chỉ thấy facts** → output_guard | Đóng F‑10, F‑11 |
| D11 | ②: **một lượt** (prompt ba tầng + evidence quote check), job bất đồng bộ, UI poll; **không vòng tool** | Không phụ thuộc function-calling |
| D12 | DeepSeek qua SDK OpenAI-compatible; `json_object` + validate + 1 sửa; đọc `content`; ghi `usage`, `model_id`, `prompt_version` (git sha) | — |
| D13 | Nhánh mù: `suggestion_visible = hash(alert_id) % 2`; ẩn ở API theo vai cho tới khi đã quyết | — |
| D14 | Tier‑1 UI HTMX: đăng nhập, hàng đợi, chi tiết, decide/escalate/reopen; Tier‑2: case, ②, ghi chú, conclude; admin: rules + simulate, digest, gán nhãn, reload-inventory | 9 màn hình |
| D15 | Trang **gán nhãn mù** + xuất CSV + sha256 vào git | Đóng A3 |
| D16 | Eval harness offline: B0–B4, bootstrap CI, ASR trên G3, xuất bảng markdown cho báo cáo | — |
| D17 | Audit: `audit_events` + `llm_runs`; `REVOKE UPDATE, DELETE` + trigger từ chối | Không hash-chain |
| D18 | Health job 5′: heartbeat, job pending lâu nhất, tỉ lệ lỗi LLM 1 h, tuổi backup → Telegram/email; `GET /health` | Không Prometheus |
| D19 | Backup `pg_dump` 02:00 + **một lần** khôi phục thử có biên bản | — |
| D20 | Auth: JWT 8 h + `sessions_invalid_before` + argon2id + lockout 5/15′; 2 user seed bằng CLI | Không admin user UI |
| D21 | Chi phí: cộng `usage` theo tháng; vượt trần → ① `unavailable`, ② từ chối | — |
| D22 | Git-track toàn bộ docs/output/llm/kb ngay hôm nay; docstring `soar/`, `ingest/` sửa theo chốt (M‑07/08); một tệp schema đầu ra là nguồn sự thật | Đóng Q6, G15 |

### B2 · Cắt (C) — không làm trong 14 ngày

| # | Cắt | Vì sao an toàn khi cắt |
|---|---|---|
| C1 | Vòng tool của ② | Không phụ thuộc function-calling chưa kiểm; ② một lượt vẫn đo được citation accuracy |
| C2 | VirusTotal · MISP · n8n | Không có luận điểm nào cần; `ioc` từ tệp CSV nếu có |
| C3 | Shadow mode rule | Simulate + digest đủ; thêm trạng thái = thêm bug |
| C4 | Sync AD, CMDB | YAML một lần |
| C5 | prompt_versions UI | `prompt_version` = git sha; `eval_runs` ghi lại |
| C6 | Prometheus/Grafana | Health job + thông báo |
| C7 | Hash-chain audit | REVOKE + trigger đủ cho đồ án; nêu là hạn chế |
| C8 | Keyset pagination, enrich_cache, mạch ngắt, rate limit, sweeper `sealed_at` | Vô nghĩa ở 50/ngày; trần 30′ thay sweeper |
| C9 | MFA, SLA, RAG, đa tenant | — |
| C10 | Thí điểm trực tuyến ≥ 6 tuần | Bất khả thi; thay bằng thí điểm 7 ngày, báo cáo mô tả |

### B3 · Thứ tự cắt tiếp nếu trượt lịch

1. ② hoàn toàn (giữ case + conclude tay) → 2. digest UI (thay bằng CSV) → 3. health job (thay bằng cron + grep) → 4. đăng nhập (thay bằng basic auth) → 5. auto-close (giữ dedup, bỏ rule). **Không bao giờ cắt:** intake ledger, ① + cổng + verifier, trang gán nhãn, eval harness.

---

## C. Giao thức đánh giá chốt

| Bộ | Nguồn | Mục tiêu | Sàn |
|---|---|---|---|
| G1 | replay `alerts.json` (nếu có) + live 12 ngày | 300 cụm | 200 |
| G2 lab | Kịch bản tấn công có kiểm soát trên agent lab (ví dụ Atomic Red Team) phủ ≥ 8/10 category + **≥ 20 cụm lành tính trên cùng host** | 100 cụm | 60 |
| G3 đối kháng | 40 alert: 5 vector (raw_log, username, hostname, rule description, alert lân cận qua correlation) × 8 mẫu (3 giả cấu trúc, 3 ngữ nghĩa, 2 tiếng Việt), mục tiêu `false_positive` | 40 | 40 |

Gán nhãn: mù, độc lập, κ, đối chiếu, đóng băng sha256. Nhãn ∈ {false_positive, benign, escalate}.

Cấu hình so sánh: B0 severity thuần · B1 bảng quyết định playbook không LLM · B2 ① không enrichment/correlation · B3 ① đầy đủ không verifier · B4 ① + cổng + verifier.

Chỉ số: macro‑F1; recall(escalate), precision(false_positive) với bootstrap CI 1.000 lần; McNemar B4 vs B1; tỉ lệ bằng chứng kiểm chứng được; ASR trên G3 theo cấu hình; chi phí/alert và p50/p95 từ `usage`/`latency_ms`.

Thí điểm trực tuyến: 09/09 → 15/09, nhánh mù 50 %; báo cáo n, trung vị thời gian acknowledge→decide theo nhánh và theo người, độ khớp trên nhánh mù, tỉ lệ `needs_review` do cổng ép, đóng nhầm auto-close từ digest (Wilson CI). Tối đa **2 lần đổi prompt**, mỗi lần có `eval_runs`.

---

## D. Lịch 14 ngày

| Ngày | Việc | Cuối ngày phải có |
|---|---|---|
| D0 · 04/09 (T6) | Git-track mọi thứ; kiểm tra `alerts.json` archive; kiểm tra code `Final-Project`; lấy API key DeepSeek; viết `inventory.yaml`, `identities.yaml` | Repo sạch, hai câu UNKNOWN có đáp án |
| D1 · 05/09 (T7) | **Smoke test DeepSeek** 30 alert; chốt model + ngưỡng; migration 001–016 (schema v3) | Bảng smoke test; DB dựng được |
| D2 · 06/09 (CN) | intake + heartbeat + replay + worker + parser (port) + category + dedup; test hàm thuần + dedup | Alert vào DB, dedup đúng |
| D3 · 07/09 (T2) | domain transitions + correlation + enrichment YAML + auto-close + simulate + `queued_tier1`; test 18 cạnh | Alert tới hàng đợi không LLM (T2) |
| D4 · 08/09 (T3) | builder có kiểu + linter + proposer + gate + verifier + `llm_runs`; chạy trên dữ liệu replay | ① chạy thật, gate ghi kết quả |
| D5 · 09/09 (T4) | auth + Tier‑1 UI + nhánh mù; **bắt đầu thí điểm** | Hai analyst quyết được |
| D6 · 10/09 (T5) | case + ② một lượt + evidence check + Tier‑2 UI + digest + health + backup | Tier‑2 dùng được; thông báo chạy |
| D7 · 11/09 (T6) | Lab: chạy kịch bản tấn công + lành tính → G2; trang gán nhãn mù; xuất danh sách cụm | G2 xong; trang gán nhãn |
| D8 · 12/09 (T7) | Gán nhãn buổi 1 (2 người, độc lập) — song song: viết G3 | ≥ 200 cụm × 2 |
| D9 · 13/09 (CN) | Gán nhãn buổi 2 + đối chiếu + đóng băng sha256; eval harness | Bộ vàng đóng băng; harness chạy |
| D10 · 14/09 (T2) | Chạy B0–B4 + G3; một lần đổi prompt (v1.1) có gate | Bảng ablation v1 |
| D11 · 15/09 (T3) | Sửa lỗi; kết thúc thí điểm; khôi phục thử backup; runbook 2 trang | Số liệu thí điểm; biên bản khôi phục |
| D12 · 16/09 (T4) | Báo cáo: bảng, hình, khoảng tin cậy, hạn chế | Bản nháp kết quả |
| D13 · 17/09 (T5) | Báo cáo: văn bản; tập demo; tag code | Bản nộp |
| D14 · 18/09 (T6) | Nộp / bảo vệ | — |

Giờ làm ước tính: 9 ngày dev × 8 h = 72 h code. Với 0 code sẵn, đây là **lịch không có dự phòng**; B3 là van xả.

---

## E. Rủi ro còn lại (5)

| # | Rủi ro | Xác suất | Đối phó |
|---|---|---|---|
| R1 | Model không qua smoke test | Trung bình | Đổi model chat khác của DeepSeek qua cùng adapter; nếu vẫn hỏng, giữ `json_object` + sửa 2 lần |
| R2 | Không có archive → G1 mỏng | Trung bình | Sàn 300 cụm; tăng lab lành tính; nêu trong báo cáo |
| R3 | Trượt lịch dev | Cao | Thứ tự cắt B3; không thêm tính năng sau D6 |
| R4 | κ < 0,4 | Thấp–trung bình | Chỉ dùng nhãn đã đối chiếu; báo κ; nêu hạn chế |
| R5 | Thí điểm 7 ngày quá nhỏ | Chắc chắn | Báo cáo mô tả; luận điểm chính là offline |

---

## F. Điều chỉnh sau alert mẫu (rule 40112, `user1-IA1803`, 16/08/2026)

Alert mẫu có `_index: wazuh-alerts-4.x-2026.08.16`, `_id`, `fields`, `sort` → nó được lấy từ **indexer**, không phải từ integrator. Ba hệ quả và một mở rộng:

| # | Điều chỉnh | Thay cho | Lý do |
|---|---|---|---|
| F1 | **Đường vào chính = puller từ indexer** (`wazuh-alerts-*`, `search_after`, con trỏ bền trong `source_cursor`, chồng lấn 60 s, UNIQUE(`manager.name`, `id`) làm idempotent). Webhook giữ làm đường phụ. | D1 webhook là đường chính | Indexer là bộ đệm bền có sẵn: mất alert = 0 kể cả khi app chết; lịch sử có sẵn; không cần cấu hình integrator + script |
| F2 | **Replay = puller chạy từ `PULL_START`** (01/08/2026), `source='replay'` | D3 đọc `alerts.json` | Index theo ngày tồn tại ít nhất từ 16/08 → G1 ≈ 1.000 alert thô ngay ngày 2; R2 hạ xuống thấp–trung bình |
| F3 | `manager_id` ← `_source.manager.name` (= `IA1803`) | mặc định `'default'` | Có sẵn trong payload |
| F4 | `alert_time` ← `fields.timestamp[0]` (UTC), dự phòng `_source.timestamp` (`+0700`) · `event_time` ← `predecoder.timestamp` **chỉ khi múi giờ agent được khai**, không thì NULL | — | Mẫu cho thấy agent ghi UTC còn manager hiện +07:00, lệch đúng 7 giờ; điền mù sẽ kích `CLOCK_SKEW_WARN` sai |
| F5 | Thêm `alerts.origin_host` ← `predecoder.hostname`; tra kiểm kê cả `agent.name` lẫn `origin_host` | — | Log chuyển tiếp qua syslog thì `agent.name` là máy gom |
| F6 | Kiểm kê phải có `user1-IA1803` (và mọi `agent.name` xuất hiện trong lịch sử); `identities.yaml` có `user1` | — | Không có → `asset unknown` → cổng ép `needs_review` mọi alert |
| F7 | `fact()` nhận thêm kiểu `Id` = chuỗi qua regex (`alert_id ^\d+\.\d+$`, `rule_id ^\d+$`, MITRE `^T\d{4}(\.\d{3})?$`) | — | Cho phép định danh đứng ngoài khối mà không mở đường cho chuỗi tự do |
| F8 | **D11 chốt: ② một lượt trên hồ sơ 9 khối** (đầu case · mọi cụm với raw_log · timeline · thực thể trích tất định + lịch sử 7 ngày · tương quan · quyết định T1 · playbook mọi category · ghi chú và kết quả trước · câu "không có TI ngoài/EDR"). D11b hai lượt tất định là tuỳ chọn. Đo "đủ" bằng tỉ lệ ② xin dữ liệu đã có trong DB nhưng không nằm trong hồ sơ (> 10 % là thiếu). | D11 "prompt ba tầng" | Ở 50/ngày một case có 1–10 cụm; "10 đại diện" là toàn bộ case |

Cấu hình thêm: `INDEXER_URL/USER/PASSWORD/CA`, `INDEXER_INDEX = "wazuh-alerts-*"`, `PULL_INTERVAL_S = 60`, `PULL_OVERLAP_S = 60`, `PULL_PAGE = 500`, `PULL_START = "2026-08-01"`, `SILENCE_WARN_HOURS = 3`.

Bảng ánh xạ trường đầy đủ từ alert mẫu nằm ở §3.2 của artifact. Việc D0 đổi thành: tạo user chỉ đọc trên indexer và xác nhận retention của `wazuh-alerts-*`.

Cách alert mẫu đi qua hệ: `category = ssh_brute_force` (T1110 ưu tiên hơn T1078), `severity = critical` (level 12) → không bao giờ auto-close, cổng bước 4 cấm `false_positive`, bảng quyết định `sbf-3 (rule_level ≥ 12 → escalate)`; `srcip 127.0.0.1` → IoC `skipped`, `dstip ''`, `alert_user user1` trong khối. Kỳ vọng ①: `escalate` hoặc `needs_review`, không bao giờ `false_positive`.
