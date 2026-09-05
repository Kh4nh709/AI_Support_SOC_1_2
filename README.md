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
