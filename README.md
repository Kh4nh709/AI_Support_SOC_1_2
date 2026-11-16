# AI Support SOC — Tier 1 & 2

Hệ thống ứng dụng LLM **hỗ trợ** SOC Analyst phân loại và điều tra alert an ninh. Alert đọc từ **Wazuh**; LLM đóng vai trò trợ lý đề xuất, **con người luôn là người ra quyết định cuối**.

> **Trạng thái:** khởi tạo. Chưa có code ứng dụng — mới có khung package và tài liệu thiết kế.

---

## Trọng tâm

Luồng xử lý một alert từ lúc Wazuh phát sinh tới lúc analyst ra quyết định:

```
Wazuh → ingest → dedup → enrichment tất định → correlation → risk score
      → auto-close? → hàng đợi → [LLM ① auto-triage] → Tier 1 quyết định
      → escalate → case → [LLM ② trợ lý điều tra] → Tier 2 kết luận
```

Ba luận điểm đo được: **giảm thời gian triage**, **giảm false positive tới tay analyst**, **tăng chất lượng quyết định**.

## Phạm vi

**Trong phạm vi** — Tier 1 và Tier 2, cùng toàn bộ tầng tự động phía trước chúng.

**Ngoài phạm vi, có chủ đích** — Tier 3 (Incident Response) và Post-Incident. Đã thiết kế máy trạng thái để nối tiếp được, nhưng không hiện thực. Lý do đầy đủ ở mục 2 của tài liệu thiết kế; tóm tắt: Tier 1–2 chứa toàn bộ luận điểm đo được, còn Tier 3 — do ràng buộc "AI không tự thực thi" — rút gọn thành CRUD không mang nội dung AI.

## Kiến trúc

Chia theo tầng SOC. Hai luật giữ cho nó không mục nát, **cưỡng chế bằng test quét AST**, không bằng lời dặn:

1. **Chỉ import xuống** — tầng import được hạ tầng; hạ tầng không bao giờ import tầng.
2. **Tầng không import tầng** — Tier 1 escalate lên Tier 2 bằng cách đổi trạng thái và đẩy job, không gọi hàm của `tier2/`. Đúng như SOC thật bàn giao qua hàng đợi.

```
backend/app/
  ingest/      soar/      tier1/     tier2/        ← các tầng
  domain/  infra/  audit/  security/  llm/  kb/  enrichment/   ← hạ tầng
```

Không có package nào tên `shared/` — mỗi mối quan tâm xuyên suốt được gọi đúng tên của nó. Mỗi `__init__.py` ghi rõ trách nhiệm và luật import của package đó.

## Nguyên tắc bất di bất dịch

- **LLM đề xuất, người quyết.** Hệ thống ghi lại cả hai để so sánh — đó chính là nguồn dữ liệu cho phần đánh giá.
- **Không phép chuyển trạng thái nào phụ thuộc vào LLM chạy thành công.** Model chết thì hệ thống suy biến thành một SIEM có workflow tử tế, vẫn dùng được.
- **Mọi dữ liệu không tin cậy đều được bọc** trước khi vào prompt: `raw_log`, `description`, chunk RAG, kết quả tool, mô tả IoC, trích đoạn threat intel, ghi chú analyst. Không ngoại lệ.
- **Audit là append-only.** Không sửa, không xóa.

## Tài liệu

| File | Nội dung |
|---|---|
| `docs/kien-truc-v3-14-ngay.html` | Kiến trúc v3: quyết định, tổng quan, thành phần, tầng AI, dữ liệu/API/config, đánh giá, sequence, lịch trình, rủi ro |
| `docs/chot-v3-14-ngay.md` | Quyết định chốt v3 D1–D20, danh sách cắt giảm C1–C10 và thứ tự cắt |

## Quan hệ với dự án tiền nhiệm

Kế thừa từ `Final-Project`, xây lại quanh trọng tâm đúng. Bản cũ đã dần trở thành một đồ án **tối ưu RAG** thay vì một đồ án **hỗ trợ SOC**; giai đoạn cải tiến retrieval gần nhất cho kết quả âm có đo đạc.

Kết quả âm đó là dữ liệu nghiên cứu hợp lệ và sẽ được trích dẫn trong báo cáo, không phải thứ để giấu. Các module đã kiểm chứng của bản cũ — `prompt_guard`, `output_guard`, vòng lặp agent, `category_resolver`, parser Wazuh — được port sang nguyên vẹn.

## Quy ước

- **Tiếng Việt** cho tài liệu và diễn giải; **tiếng Anh** cho toàn bộ code, tên định danh, comment và docstring.
- TDD cho mọi code mới. Biên LLM luôn được stub trong test — không test nào gọi model thật.

## Phản hồi SOAR

Hệ thống gồm SIEM (Graylog) → SOAR (n8n) → AI Support SOC (repo này). SOAR **hành động trước**: khi có alert, n8n tự chặn IP trên pfSense, sinkhole domain, cô lập máy, khoá tài khoản AD, tắt `xp_cmdshell` hoặc kill tiến trình, rồi mở một **phiếu review** cho analyst trực. Trước đây phiếu là tin nhắn Telegram có hai nút; nay phiếu và các nút nằm trên web, trang **Phản hồi SOAR** (`/soar`, cả ba vai trò):

1. n8n **đẩy** phiếu (và các thông báo `notice`) tới `POST /webhook/soar-notices` của backend.
2. Analyst bấm nút trên trang: **giữ** (`keep`), **gỡ** (`undo`) hoặc **báo nhầm** (`fp`). Ai được bấm nút nào do cấu hình quyết định (`SOAR_ROLES_*`).
3. Backend **gọi ngược** n8n (`N8N_APPROVAL_URL`, header `X-SOAR-Secret`) và n8n thực hiện. Kết quả (`ok`, `failed`, `unavailable`, `conflict`) hiện ngay trên dòng của phiếu; mỗi lần bấm có một dòng audit `soar.review_decided`, mỗi lần n8n đẩy có một dòng `soar.review_received`.

Đặc tả đầy đủ: `docs/superpowers/specs/2026-11-16-soar-review-web-design.md`.

### Cổng n8n phải gọi

n8n phải gửi tới **cổng của chính `app`**, không phải cổng của UI: trial là `:8001` (live là `:8000`), tức `http://<máy chạy app>:8001/webhook/soar-notices`. **Không** dùng `:8081` (trial) hay `:8080` (live): nginx của UI chỉ chuyển tiếp `/api/`, nên `/webhook/...` ở đó là 404.

### Cấu hình (`.env`, ghi vào `docs/runbook.md` mục *Environment keys*)

| Khóa | Ý nghĩa | Mặc định |
|---|---|---|
| `SOAR_NOTICE_API_KEY` | khóa n8n gửi trong header `X-API-Key`; **bí mật**, chỉ nằm trong `.env`. Để trống → route trả `503` | trống |
| `SOAR_NOTICE_IP_ALLOWLIST` | danh sách JSON các IP/CIDR được gửi, ví dụ `["79.79.79.14"]`; để trống → từ chối tất cả (`403`) | trống |
| `N8N_APPROVAL_URL` | nơi backend gọi n8n khi có người bấm nút | `http://79.79.79.14:5678/webhook/soar-approval` |
| `N8N_APPROVAL_SECRET` | giá trị header `X-SOAR-Secret` của lần gọi đó; **bí mật**. Trống (hoặc URL trống) → nút bấm trả `503 soar approval not configured`, chưa khoá phiếu nào | trống |
| `N8N_APPROVAL_TIMEOUT_SECONDS` | chờ n8n tối đa bao lâu; từ `1` đến `100` (khoá quá hai phút được nhả ở lần bấm kế tiếp, nên một lần gọi đang chạy không được dài hơn) | `45` |
| `SOAR_ROLES_KEEP` · `SOAR_ROLES_UNDO` · `SOAR_ROLES_FP` | vai trò được bấm từng nút (danh sách cách nhau bằng dấu phẩy của `tier1`, `tier2`, `admin`; vai trò lạ làm app không khởi động) | `tier1,tier2,admin` · `tier2,admin` · `tier1,tier2,admin` |
| `SOAR_AD_HOSTS` | danh sách JSON tên máy (không phân biệt hoa thường) mà việc cô lập được cảnh báo mạnh trên trang: domain controller của lab | `["AD-server"]` |

Đổi `.env` thì tạo lại container: `docker compose up -d --force-recreate app`.

### Gọi thử `POST /webhook/soar-notices`

Kiểm tra theo thứ tự: khoá rỗng `503` → thiếu/sai `X-API-Key` `401` (so sánh thời gian hằng, trước khi đọc thân) → IP ngoài danh sách `403` → thân quá `MAX_PAYLOAD_BYTES` `413` → thân sai `400 {"detail": {"errors": [{"field", "reason"}]}}` (liệt kê **mọi** lỗi). Thành công: `201 {"id", "created": true}` cho phiếu mới, `200` cho phiếu đã có (`{"created": false}`, hoặc thêm `"ignored": true, "reason": "stale"|"terminal"` khi thân cũ hơn bản đã áp, hoặc đòi mở lại một phiếu đã đóng). Thay `<KHÓA>` bằng giá trị của `SOAR_NOTICE_API_KEY` và `localhost:8001` bằng địa chỉ của app.

Phiếu review `block_ip` (hai nút: giữ chặn, gỡ chặn):

```bash
curl -sS -X POST http://localhost:8001/webhook/soar-notices \
  -H 'Content-Type: application/json' -H 'X-API-Key: <KHÓA>' \
  -d '{
  "schema_version": "1.0", "event": "created", "kind": "review", "id": "K7QM2XHP",
  "sent_at": "2026-11-13T21:40:05.123+07:00", "status": "open", "severity": "info",
  "title": "ĐÃ TỰ XỬ LÝ", "simulated": false,
  "case": { "id": "~4096", "number": 65 },
  "action": { "type": "block_ip", "text": "Chặn IP 79.79.78.202 trên pfSense", "target": "79.79.78.202", "via": "pfsense", "agent": null },
  "host": "pfSense.home.arpa", "agent_id": "003", "src_ip": "79.79.78.202",
  "scenario": { "id": "SC03", "name": "Quét cổng từ bên ngoài" }, "score": 50,
  "note": "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
  "created_at": "2026-11-13T21:40:03.000+07:00", "auto_expire_at": "2026-11-13T22:40:03.000+07:00",
  "buttons": [ { "decision": "keep", "label": "✅ Giữ chặn" }, { "decision": "undo", "label": "↩️ Gỡ chặn IP" } ]
}'
```

Phiếu review `kill_process` (giữ hoặc báo nhầm; một tiến trình đã kill không có nút gỡ):

```bash
curl -sS -X POST http://localhost:8001/webhook/soar-notices \
  -H 'Content-Type: application/json' -H 'X-API-Key: <KHÓA>' \
  -d '{
  "schema_version": "1.0", "event": "created", "kind": "review", "id": "M4HT8WZC",
  "sent_at": "2026-11-13T21:52:10.000+07:00", "status": "open", "severity": "warning",
  "title": "ĐÃ KILL TIẾN TRÌNH",
  "case": { "id": "~8192", "number": 71 },
  "action": { "type": "kill_process", "text": "Kết thúc mimikatz.exe trên WIN-DC01", "target": "mimikatz.exe", "via": "wazuh", "agent": "WIN-DC01" },
  "host": "WIN-DC01", "agent_id": "005", "scenario": { "id": "MW03", "name": "Mã độc trên endpoint" }, "score": 82,
  "buttons": [ { "decision": "keep", "label": "✅ Giữ (đã kill)" }, { "decision": "fp", "label": "🚫 Báo nhầm" } ]
}'
```

Thông báo `notice` (một dòng thông tin, không có nút; `status` luôn là `info`, id là `N` + 12 ký tự chữ, số, `_` hoặc `-`):

```bash
curl -sS -X POST http://localhost:8001/webhook/soar-notices \
  -H 'Content-Type: application/json' -H 'X-API-Key: <KHÓA>' \
  -d '{
  "schema_version": "1.0", "event": "created", "kind": "notice", "id": "Nab12cd34ef56",
  "sent_at": "2026-11-13T22:00:00.000+07:00", "status": "info", "severity": "warning",
  "title": "SOAR TẠM DỪNG", "note": "pfSense không phản hồi, các hành động chặn IP được hoãn", "buttons": []
}'
```

Gửi lại cùng `id` với `event` `updated` hoặc `reminder` để cập nhật (n8n là nguồn sự thật: mọi trường của thân mới thay trường đã lưu). `id` phải ổn định qua các lần gửi lại; `sent_at` cũ hơn bản đã áp bị bỏ qua; phiếu đã `undone`, `false_positive` hoặc `expired` không bị mở lại bởi thân `open`.

### Thử trang khi chưa có phía n8n: n8n giả lập

`scripts/mock_n8n_approval.py` (chỉ dùng thư viện chuẩn) đứng thay `soar-approval` của n8n: nó chỉ trả lời, không làm gì cả. Chế độ chọn bằng `--mode`:

| `--mode` | n8n giả lập trả lời |
|---|---|
| `ok` (mặc định) | `200 {"ok": true, "status": "kept"\|"undone"\|"false_positive", ...}`: thành công |
| `fail` | `200 {"ok": false, ...}`: thao tác thất bại, phiếu giữ nguyên trạng thái |
| `conflict` | `409 {"ok": false, "status": "undone", ...}`: phiếu đã được xử lý ở nơi khác |
| `slow` | chờ `--slow-seconds` (mặc định 60 giây) rồi trả lời như `ok`: thử hạn chờ |

```bash
python3 scripts/mock_n8n_approval.py --mode ok --secret thu-nghiem --port 5678
```

Rồi trong `.env`: `N8N_APPROVAL_URL=http://127.0.0.1:5678/webhook/soar-approval` và `N8N_APPROVAL_SECRET=thu-nghiem` (app chạy trong container thì dùng địa chỉ máy chủ mà container thấy được, và chạy n8n giả lập với `--host 0.0.0.0`), tạo lại container `app`, đẩy một phiếu bằng các lệnh `curl` ở trên và bấm nút trên `/soar`. Dùng khoá thử nghiệm, không dùng khoá thật; dừng n8n giả lập bằng Ctrl+C.

## Đổi nhà cung cấp LLM (provider)

Biên LLM là một endpoint **tương thích OpenAI** (`backend/app/llm/adapter.py`). Đổi provider hoàn toàn qua `.env`, **không sửa code**:

| Khóa `.env` | Ý nghĩa |
|---|---|
| `LLM_BASE_URL` | URL gốc của API (DeepSeek, OpenAI, hoặc một gateway nội bộ tương thích OpenAI) |
| `LLM_API_KEY` | khóa API của provider — chỉ nằm trong `.env`, không commit, không in ra |
| `LLM_MODEL_PROPOSER` | tên model cho ① đề xuất (proposer) |
| `LLM_MODEL_VERIFIER` | tên model cho ① kiểm chứng (verifier) |
| `LLM_TIMEOUT_S` · `LLM_RETRY` · `LLM_THINKING` | hạn thời gian mỗi lần gọi, số lần thử lại khi lỗi mạng/5xx, chế độ "thinking" |

Yêu cầu provider: nhận `response_format={"type":"json_object"}` (prompt hệ thống phải chứa chuỗi `JSON` — adapter tự kiểm trước khi gọi). Sau khi đổi: `docker compose up -d --force-recreate worker app` (thêm `rag-worker` nếu đang dùng `docker-compose.rag.yml`, và đổi cả `RAG_MODEL` nếu khóa này không để trống).

Khi provider **hết số dư / hết hạn mức (HTTP 402)**, ① đặt `triage_status='unavailable'`, ghi một dòng `llm_runs` với `stopped_by='unavailable'` kèm thông điệp của provider, và health check `triage_unavailable` **báo động** (không báo "ổn"). Job không "failed" treo lơ lửng. Cũng lỗi 402 đó, với ② là `stopped_by='permanent'`; với RAG, lookup được lưu `failed` (run `permanent`) và bản nháp tri thức rỗng kèm cảnh báo `llm_permanent` — sau khi nạp lại số dư, bấm **Soạn lại** ở `/admin/knowledge`. Alert mới được xử lý sau khi nạp lại số dư/đổi provider; alert cũ đang `unavailable` không tự chạy lại — xem `docs/runbook.md` mục *Common failures · Model API down*.
