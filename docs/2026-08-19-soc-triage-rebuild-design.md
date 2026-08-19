# Thiết kế: Xây lại hệ thống quanh luồng triage SOC

> **Ngôn ngữ:** phần diễn giải viết tiếng Việt để người duyệt đọc kỹ được; mọi định danh code, tên bảng, tên file, khối lệnh giữ tiếng Anh theo quy ước sẵn có của repo.

**Ngày:** 2026-08-19
**Trạng thái:** chờ duyệt
**Thay thế:** hướng đi hiện tại của `Improve_rag/` (tối ưu retrieval) — xem mục 1

---

## 1. Bối cảnh và lý do xây lại

Đề bài của đồ án là **LLM hỗ trợ SOC Analyst phân tích và xử lý alert**. Trên thực tế, codebase đã dần trở thành một **đồ án tối ưu RAG**: 2.070 dòng cho hạ tầng retrieval (BM25 + vector + RRF + cross-encoder rerank + contextual header + corpus 7.166 chunk + hiệu chỉnh ngưỡng), 28/52 file test phục vụ nó, và một lộ trình cải tiến 6 giai đoạn.

Giai đoạn cải tiến gần nhất (GĐ1) được ghi nhận là **kết quả âm** — xem `Improve_rag/reports/`. Đây là một kết quả nghiên cứu hợp lệ và sẽ được trích dẫn trong báo cáo, không phải thứ để giấu đi.

Chẩn đoán kỹ thuật dẫn tới quyết định xây lại: **playbook không cần tìm bằng ngữ nghĩa.** Trong luồng triage, playbook cần lấy được xác định bởi `alert.category`, mà `category_resolver` đã phân giải tất định qua 5 tầng (MITRE ID → parent technique → rule groups → decoder → destination port), và `data_access.load_playbook_by_category()` đã tra được bằng khớp category. Toàn bộ hạ tầng embedding đang giải một bài toán mà bước trước nó đã giải xong bằng cách chính xác hơn và rẻ hơn.

Bản rà soát kiến trúc kèm theo (`docs/audit-report.html`) liệt kê 20 phát hiện; spec này xử lý các phát hiện Critical và High liên quan tới luồng nghiệp vụ.

---

## 2. Trọng tâm và phạm vi

### Trọng tâm

Luồng xử lý alert từ Wazuh tới quyết định của analyst, với LLM đóng vai trò trợ lý đề xuất. RAG tụt xuống vai trò chi tiết kỹ thuật phục vụ một bước, không phải luận điểm.

### Trong phạm vi

| Tầng | Nội dung |
|---|---|
| Ingestion | Webhook Wazuh · parse · chuẩn hóa · phân loại category · **fingerprint + dedup** |
| SOAR | Enrichment tất định (asset · identity · IoC) · **correlation đưa vào suy luận** · risk scoring · rule auto-close |
| Tier 1 | Hàng đợi · **pipeline LLM ① auto-triage** · quyết định FP/Benign/Escalate · **feedback loop** |
| Tier 2 | Case gom nhiều alert · **pipeline LLM ② trợ lý điều tra** · map ATT&CK · xác định phạm vi · kết luận 3 nhánh |
| Xuyên suốt | Định danh nhẹ + vai trò · **audit trail đầy đủ** · job queue + worker |

### Ngoài phạm vi — có thiết kế, không hiện thực

**Tier 3 (Incident Response)** và **Post-Incident (RCA, lessons learned)**.

Lý do, ghi rõ để đưa vào báo cáo:

1. Tier 1 và Tier 2 chứa **toàn bộ luận điểm đo được** của đồ án: giảm thời gian triage, giảm false positive, tăng chất lượng quyết định. Không luận điểm nào cần Tier 3 để chứng minh.
2. Do ràng buộc an toàn của chính đồ án (AI chỉ khuyến nghị, không thực thi), Tier 3 rút gọn thành: tạo bản ghi incident, sinh phiếu hành động, người bấm đã-làm. Đó là CRUD, không mang nội dung AI.
3. Pipeline soạn RCA cần audit trail của nhiều sự cố đã khép để có đầu ra thực chất. Một hệ thống demo với vài sự cố tự tạo sẽ cho ra văn bản đẹp mà rỗng.

Máy trạng thái ở mục 4 **đã tách sẵn** thực thể Incident, nên phần này có thể nối tiếp sau mà không phải thiết kế lại.

### Quyết định phạm vi đã chốt

| Hạng mục | Quyết định |
|---|---|
| Định danh | **Nhẹ**: bảng `users` + `role` + API key qua header. Không login/JWT/RBAC/màn quản lý user |
| Điểm chạm LLM | **2**: auto-triage (Tier 1), trợ lý điều tra (Tier 2) |
| Xử lý nền | Job table trong Postgres + worker. Không thêm Redis/Celery |
| Cấu trúc module | Phân theo tầng SOC |
| Cơ chế xây lại | Nhánh `rebuild/soc-triage` tạo từ `main`, dọn tại chỗ |
| Dữ liệu ra bên thứ ba | **Chấp nhận**, ghi rõ giới hạn — xem mục 6.3 |

---

## 3. Kiến trúc

### 3.1 Bố cục module

Cấu trúc theo tầng mục nát khi mọi thứ dùng chung bị đổ vào một `shared/`. Biện pháp: **cấm tồn tại `shared/`**; mỗi mối quan tâm xuyên suốt được đặt tên theo bản chất và thành package hạng nhất.

```
app/
  # ---------- CÁC TẦNG ----------
  ingest/         webhook · wazuh parser · category resolver · fingerprint + dedup
  soar/           chuỗi stage enrichment · correlation · risk scoring · rule auto-close
  tier1/          hàng đợi · auto-triage ① · quyết định FP/Benign/Escalate
  tier2/          case · trợ lý điều tra ② · ATT&CK · phạm vi · kết luận

  # ---------- HẠ TẦNG ----------
  domain/         Alert · Case · Incident: model + hằng số trạng thái + phép chuyển hợp lệ
  platform/       db · jobs · worker · auth (API key + role) · config
  audit/          ghi vết mọi quyết định của người và mọi lần gọi LLM
  security/       prompt_guard · output_guard          ← giữ nguyên, đã tốt
  llm/            providers · run_agentic · dựng prompt · bọc dữ liệu untrusted
  kb/             tra playbook tất định + RAG tối giản
  enrichment/     asset · identity · IoC
```

### 3.2 Hai luật import — cưỡng chế bằng test

1. **Chỉ import xuống.** Tầng được import hạ tầng. Hạ tầng **không bao giờ** import tầng. Vi phạm luật này là lúc `platform/` bắt đầu biến thành `shared/`.
2. **Tầng không import tầng.** Tier 1 escalate lên Tier 2 không bằng cách gọi hàm của `tier2/`, mà bằng `domain.escalate(alert, actor)` — đổi trạng thái, tạo `cases` row, đẩy một job. Worker nhặt job và chạy pipeline Tier 2.

Hai luật này được kiểm chứng bằng một test quét AST toàn bộ `app/`, fail khi có import vi phạm. Luật kiến trúc cưỡng chế bằng test, không bằng lời dặn trong tài liệu — cùng tinh thần với `output_guard` hiện có.

Hệ quả: mỗi tầng test được độc lập, không cần dựng cả chuỗi; và bàn giao giữa các tầng đi qua hàng đợi đúng như SOC thật vận hành.

### 3.3 Thành phần giữ nguyên

`security/prompt_guard` (bọc nonce + vô hiệu hóa delimiter giả) · `security/output_guard` (cưỡng chế "chỉ khuyến nghị") · `llm_service.run_agentic` (vòng ReAct + xử lý suy giảm nhiều lớp) · `category_resolver` (chuyển vào `ingest/`, logic không đổi) · `wazuh_ingest` (chuyển vào `ingest/`).

---

## 4. Mô hình dữ liệu và máy trạng thái

### 4.1 Ba thực thể, ba vòng đời tách biệt

Một case gom được **nhiều alert** — đây là chỗ `correlation_service` có việc thật, thay vì làm panel trang trí như hiện nay.

```
ALERT                                  CASE (Tier 2)
─────                                  ───────────
received
   │ worker: fingerprint
   ├──► duplicate (gộp, tăng đếm) ──┐
   ▼                                │
enriching                           │
   │ soar: asset·identity·IoC       │
   │       ·correlation·risk score  │
   ├──► auto_closed ────────────────┤   (whitelist / known FP / maintenance window)
   ▼                                │
queued_tier1                        │
   │ (auto-triage ① đã sẵn sàng)    │
   ▼                                │
tier1_active ◄── analyst nhận       │   ⏱ acknowledged_at
   │                                │
   ├──► closed_fp ──────────────────┤
   ├──► closed_benign ──────────────┤
   │                                │
   └──► escalated_tier2 ────────────┼──► open
                                    │      │ trợ lý điều tra ②
                                    │      ▼
                                    │   investigating
                                    │      │
                                    │      ├──► concluded_fp
                                    │      ├──► concluded_policy_violation
                                    │      └──► confirmed_incident   ← điểm dừng phạm vi
                                    │           (tạo Incident: NGOÀI PHẠM VI)
```

Chuyển trạng thái **chỉ** xảy ra qua `domain/`. Mỗi phép chuyển kiểm tra tính hợp lệ và ghi `audit_events`. Phép chuyển không hợp lệ raise lỗi, không âm thầm bỏ qua.

### 4.2 Bảng

**Vòng đời**

- `alerts` — mở rộng bảng hiện có, thêm: `status`, `fingerprint`, `duplicate_of`, `occurrence_count`, `risk_score`, `case_id`, `received_at`, `acknowledged_at`, `closed_at`, `close_reason`, `triage_status` ∈ {pending, ready, unavailable}
- `cases` — `status`, `assigned_to`, `conclusion`, `attack_chain` (JSONB), `scope`, `opened_at`, `concluded_at`
- `case_alerts` — nối nhiều-nhiều giữa case và alert

**Audit — append-only, không sửa không xóa**

- `audit_events` — `actor_id` (hoặc `system` / `llm`), `actor_role`, `event_type`, `subject_type`, `subject_id`, `payload` JSONB, `created_at`
- `llm_runs` — `pipeline` ∈ {triage, investigate}, `system_prompt`, `user_message`, `agent_trace` JSONB, `result` JSONB, `injection_findings` JSONB, `citation_warnings` JSONB, `input_tokens`, `output_tokens`, `latency_ms`, `created_at`

Hai bảng này khiến **feedback loop không cần bảng riêng**: "LLM đề xuất gì" nằm ở `llm_runs`, "người quyết gì" nằm ở `audit_events`, chung khóa `subject_id`. Độ khớp giữa hai cái lấy ra bằng một câu JOIN và là chỉ số chính của báo cáo.

**Hạ tầng**

- `jobs` — `job_type`, `subject_type`, `subject_id`, `status`, `attempts`, `last_error`, `scheduled_at`, `locked_at`. Worker dùng `SELECT ... FOR UPDATE SKIP LOCKED`
- `users` — `username`, `full_name`, `role` ∈ {tier1, tier2, admin}, `api_key_hash`, `is_active`

**Enrichment**

- `assets` — `hostname` PK, `criticality`, `owner`, `environment`, `os`. Join theo `alert.agent`
- `identities` — `username` PK, `department`, `is_privileged`, `risk_score`. Join theo `alert.user`
- `iocs` — giữ nguyên bảng hiện có

**Thiết kế sẵn, không tạo trong phạm vi này:** `incidents`, `action_tickets`. Ghi lại ở đây để phần nối tiếp không phải thiết kế lại. Ràng buộc bắt buộc khi làm: `action_tickets` **không có cột nào cho phép hệ thống tự đánh dấu đã thực thi** — chỉ người mới chuyển được sang `done`. Ràng buộc "AI chỉ khuyến nghị" được cưỡng chế ở tầng schema, không chỉ ở tầng code.

### 4.3 SLA không cần bảng

Ngưỡng SLA là hằng số trong `domain/`; thời điểm nằm sẵn trên bản ghi (`received_at`, `acknowledged_at`, `closed_at`). Trạng thái SLA tính khi truy vấn.

Ưu điểm thực tế: không có timer nền nào để lệch, và container restart không làm sai số liệu — khác hẳn việc nuôi một cột `sla_breached` phải cập nhật liên tục.

---

## 5. Hai pipeline LLM

Nguyên tắc xuyên suốt: **LLM đề xuất, người quyết, hệ thống ghi cả hai lại để so.**

### 5.1 Pipeline ① Auto-triage — chạy nền, trước Tier 1

| | |
|---|---|
| Chạy khi | Worker, sau khi SOAR enrichment xong. Analyst mở alert là đã có sẵn kết quả |
| Đầu vào | Alert đã chuẩn hóa · asset (criticality, owner) · identity (privileged?) · IoC reputation · **chuỗi alert liên quan từ correlation** · playbook khớp category |
| Đầu ra | Cấu trúc 8.1–8.5 hiện có, nhưng trường `tp_fp_verdict` **được thay thế** bằng `suggested_classification` ∈ {false_positive, benign, suspicious} — khớp đúng ba lựa chọn của Tier 1, không phải ba giá trị khác. Giữ `confidence` và `missing_information` |

Phần lớn `prompts.py` và tool `submit_analysis` tái sử dụng được. Hai thay đổi: bổ sung khối correlation và asset/identity vào prompt; thay `tp_fp_verdict` bằng `suggested_classification`. Lý do thay chứ không thêm: hai trường song song cùng nói về một kết luận sẽ lệch nhau, và analyst không biết tin cái nào.

### 5.2 Pipeline ② Trợ lý điều tra — Tier 2 bấm, chạy đồng bộ

| | |
|---|---|
| Đầu vào | Toàn bộ case: mọi alert đã gom · kết quả triage ① · quyết định escalate của Tier 1 kèm lý do · bằng chứng analyst nhập thêm |
| Đầu ra | `attack_chain` theo thứ tự thời gian · `scope` ∈ {single_host, lateral_movement, exfiltration_suspected} · `mitre_coverage` · `hypotheses[]` mỗi giả thuyết kèm **bằng chứng ủng hộ và bằng chứng phản bác** · `open_questions[]` · `suggested_conclusion` |

`open_questions` là giá trị lớn nhất ở tầng này: LLM giỏi liệt kê "bạn chưa kiểm tra X" hơn là kết luận thay người, và điều đó khớp đúng vai trò hỗ trợ.

---

## 6. Dữ liệu không tin cậy

### 6.1 Bọc mọi kênh — sửa G‑02

Hiện tại chỉ `description` và `raw_log` được bọc, trong khi system prompt **nói với model rằng** IoC notes và threat intel excerpts cũng đã được bọc. Chunk RAG (`prompts.py:165`) và kết quả tool (`llm_service.py:153`) đi thẳng vào prompt không bọc.

Thiết kế mới: một hàm duy nhất trong `llm/` dựng prompt cho cả hai pipeline, và **mọi** nội dung không do người dùng hợp pháp gõ vào đều qua `wrap_untrusted()`:

`raw_log` · `description` · **chunk RAG** · **kết quả tool** · mô tả IoC · trích đoạn threat intel · **ghi chú analyst nhập ở Tier 2**

Không có ngoại lệ. Kèm một test liệt kê mọi nguồn nội dung đi vào prompt và khẳng định từng nguồn đã qua wrapper.

**Thời điểm:** thay đổi này thuộc **SP3**, không phải SP0 — SP0 chỉ di chuyển code, không đổi hành vi (xem tiêu chí 8.4 mục 4).

### 6.2 Đưa phát hiện ra ánh sáng — sửa G‑06

`findings` từ `wrap_untrusted()` hiện bị vứt bỏ (chỉ lấy `.wrapped`). Thiết kế mới:

- Ghi vào `llm_runs.injection_findings`
- Hiện thành cảnh báo trên UI cạnh kết quả, song song với `citation_warnings` vốn đã có cơ chế hiển thị
- **Nếu `risk_level == "high"`, Pipeline ① bị chặn không được đề xuất `false_positive`** — một alert chứa nỗ lực injection tự nó là phát hiện an ninh, không thể là false positive

Ngoài ra `check_narrative_for_leakage()` (hiện chỉ chạy trong harness offline) được gọi trong đường chạy thật và kết quả ghi vào `llm_runs`.

### 6.3 Giới hạn về quyền riêng tư dữ liệu — G‑03, chấp nhận có ý thức

**Quyết định: gửi nguyên văn, không che.** Ghi rõ ở đây để bê thẳng vào báo cáo.

Hệ thống gọi model qua endpoint bên thứ ba (`ANTROPHIC_URL`, hiện trỏ `api.deepseek.com`). Các trường rời khỏi hạ tầng trong mỗi lần gọi:

| Trường | Nội dung |
|---|---|
| `srcip`, `dstip` | Địa chỉ IP, bao gồm IP nội bộ |
| `user` | Tên tài khoản liên quan tới alert |
| `agent` | Tên host/máy chủ |
| `description`, `raw_log` | Nội dung log gốc, có thể chứa đường dẫn, tên tiến trình, dữ liệu người dùng |
| Ngữ cảnh enrichment | `assets.owner`, `identities.department` |

**Chấp nhận được trong phạm vi này** vì dữ liệu là môi trường lab tự dựng, không phải telemetry của tổ chức thật. **Không được dùng nguyên trạng với dữ liệu SOC thật** — khi đó cần lớp pseudonymize thay định danh bằng token ổn định trước khi gọi model và khôi phục khi hiển thị, hoặc chuyển sang model tự host.

---

## 7. Xử lý lỗi

Luật cứng: **không phép chuyển trạng thái nào phụ thuộc vào việc gọi LLM thành công.**

| Tình huống | Hành xử |
|---|---|
| Pipeline ① lỗi | Job retry 3 lần có backoff. Vẫn thất bại → alert **vẫn** chuyển sang `queued_tier1`, gắn `triage_status = unavailable`. Analyst làm việc bình thường, chỉ không có gợi ý |
| Pipeline ② lỗi | Báo lỗi tại chỗ. Không chặn Tier 2 kết luận case bằng tay |
| Nhà cung cấp model chết hoàn toàn | Hệ thống suy biến thành một SIEM có workflow tử tế. Vẫn dùng được |
| Enrichment lỗi (asset/identity/IoC) | Stage đó bỏ qua, ghi lý do vào audit, chuỗi tiếp tục. Thiếu ngữ cảnh không được chặn triage |
| Tool lỗi trong vòng agent | Giữ nguyên hành vi hiện có: chuỗi lỗi feed lại model, không abort |

Thông báo lỗi trả ra client không được chứa tên class hay message của exception gốc (sửa G‑15).

---

## 8. SP0 — Dọn dẹp và tái cấu trúc

**Không thêm tính năng nào.** Một loạt commit thuần xóa và di chuyển thì dễ review, dễ revert, và không lẫn với hành vi mới.

Nhánh `rebuild/soc-triage` tạo từ **`main`**, không phải từ `improve-rag/gd1-retrieval`: nhánh đó chỉ là `main` + 13 commit toàn bộ về RAG/ingest/chat, tức đúng thứ sắp xóa. Tạo từ `main` loại chúng tự động thay vì phải `git rm` thủ công. Công sức GĐ1 vẫn nguyên vẹn trên nhánh cũ và trong bundle sao lưu.

### 8.1 Xóa hẳn

```
app/services/ti_feeds/                    app/models/ti_feed.py
scripts/fetch_threat_intel.py             scripts/expire_iocs.py
app/routers/chat.py                       app/routers/compare.py
app/providers/ollama_provider.py          app/services/query_expansion.py
app/models/interaction.py
scripts/retrieval_probe.py                scripts/calibrate_rerank_threshold.py
scripts/generate_contextual_headers.py    scripts/extract_mitre_overlay.py
scripts/fetch_kb_sources.py
+ các file test tương ứng
+ các file kế hoạch trong Improve_rag/  (GIỮ Improve_rag/reports/)
```

`Improve_rag/reports/` được giữ: đó là bằng chứng cho đoạn "đã thử nâng cấp retrieval, đo được, không cải thiện" trong báo cáo.

### 8.2 Thu nhỏ

| Mục | Từ | Còn |
|---|---|---|
| `rag_service.py` | 598 dòng, BM25 + RRF + rerank + diversity + MITRE join + parent expansion + query rewrite | ~120 dòng, vector-only, MiniLM 384 chiều |
| `ingest.py` | Corpus 7.166 chunk (MITRE 697 kỹ thuật, Sigma, TI generated) | Chỉ playbook + ghi chú MITRE cần thiết |
| `requirements.txt` | — | Bỏ `rank-bm25`, `ollama`, `pyyaml` |
| `config.py` | — | Bỏ toàn bộ `TI_*`, `RERANK_*`, `RAG_RERANK_THRESHOLD`, `OLLAMA_*` |
| Evaluation | 4 suite (retrieval, answers, alerts, injection) | **2 suite**: triage và injection |

Giữ 2 suite thay vì 1 vì mục 6 siết phòng thủ injection lên cả hai pipeline — cần số đo cho nó.

### 8.3 Di chuyển

Theo bố cục mục 3.1. **Không sửa logic, chỉ đổi chỗ.** Mỗi lần di chuyển là một commit riêng để đối chiếu dễ.

### 8.4 Tiêu chí hoàn thành — không đạt đủ thì không sang SP1

1. Toàn bộ test còn lại xanh
2. Test kiến trúc (quét AST) xác nhận hai luật import ở mục 3.2 không bị vi phạm
3. `docker compose up` khởi động **dưới 60 giây** — hiện `start_period` là 900 giây vì phải nạp corpus và tải bge-m3 2,2 GB
4. `POST /wazuh-webhook` và `POST /analyze-alert` hành xử **y hệt trước khi dọn**

---

## 9. Lộ trình

| SP | Nội dung | Đóng phát hiện |
|---|---|---|
| **SP0** | Dọn dẹp + tái cấu trúc | G‑18, G‑19, G‑20 |
| **SP1** | Nền tảng: định danh nhẹ · vòng đời + máy trạng thái · job/worker · **audit trail** · dedup | G‑01, G‑04, G‑08, G‑16 |
| **SP2** | SOAR: `assets` + `identities` · chuỗi stage enrichment · **nối correlation vào suy luận** · risk scoring · auto-close | G‑07, G‑11, G‑12 |
| **SP3** | Tier 1: pipeline ① · hàng đợi + SLA · quyết định · **feedback loop** | G‑05, G‑10, và **G‑02, G‑06** |
| **SP4** | Tier 2: case · pipeline ② · ATT&CK · phạm vi · kết luận | — |

Mỗi sub-project có spec riêng, plan riêng, và **chạy được khi xong**. Không viết trước spec của SP1 lúc này — viết khi tới lượt, với hiểu biết thu được từ SP0.

---

## 10. Chiến lược test

TDD cho mọi code mới. Ba loại:

- **Unit** — mỗi stage enrichment, mỗi phép chuyển trạng thái, mỗi hàm dựng prompt
- **Kiến trúc** — hai luật import ở mục 3.2, cưỡng chế bằng test quét AST
- **Tích hợp** — webhook → worker → hàng đợi → quyết định Tier 1, với **biên LLM luôn được stub**

Không test nào gọi model thật. Theo ràng buộc môi trường đã biết của dự án (host không cài được fastapi/chromadb), test chạy trong container:

```
docker compose exec backend python -m pytest tests/ -v
```

---

## 11. Đo lường cho báo cáo

Ba luận điểm, ba phép đo, tất cả rút từ `audit_events` JOIN `llm_runs` — chỉ khả thi nhờ audit trail ở SP1:

| Luận điểm | Phép đo | Nguồn dữ liệu |
|---|---|---|
| Giảm thời gian triage | Thời gian từ `received_at` → `closed_at`, so giữa alert có và không có gợi ý ①. Nhóm đối chứng **chủ động tắt ① cho một tỉ lệ alert ngẫu nhiên**; không dùng `triage_status = unavailable` làm đối chứng chính vì lỗi pipeline có thể tương quan với loại alert bất thường, gây lệch mẫu | `alerts` |
| Giảm false positive tới tay analyst | Tỉ lệ alert bị `auto_closed` đúng, và tỉ lệ Tier 1 đóng `closed_fp` trước/sau khi bật auto-close | `alerts`, `audit_events` |
| Tăng chất lượng quyết định | Độ khớp giữa `suggested_classification` của ① và quyết định thật của Tier 1; xu hướng theo thời gian khi feedback tích lũy | `llm_runs` JOIN `audit_events` |

Suite injection đo riêng: tỉ lệ phát hiện offline, tỉ lệ pipeline hoàn thành, và tỉ lệ rò rỉ tuân thủ chỉ thị nhúng — nay áp cho cả hai pipeline thay vì một.

---

## 12. Rủi ro đã biết

| Rủi ro | Giảm thiểu |
|---|---|
| SP0 làm hỏng hành vi hiện có khi di chuyển file | Tiêu chí hoàn thành 8.4 mục 4; mỗi lần di chuyển một commit riêng |
| Cấu trúc theo tầng khiến hạ tầng dùng chung phình to | Cấm `shared/`; hai luật import cưỡng chế bằng test |
| Correlation đưa vào prompt làm prompt dài, tốn token | Giới hạn số alert liên quan đưa vào; đo token trước/sau |
| Nhóm đối chứng cho phép đo thời gian triage quá nhỏ | Có thể chủ động tắt ① cho một tỉ lệ alert để tạo nhóm đối chứng |
| Phạm vi lại phình trong lúc làm | Mỗi SP có tiêu chí hoàn thành; không bắt đầu SP kế khi SP trước chưa đạt |
