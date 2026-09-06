# Hướng dẫn vận hành chi tiết — điều phối 4 agent trong 14 ngày

Bản tiếng Việt, chi tiết hơn `README.md`. Mọi đường dẫn tính từ gốc repo `AI_Support_SOC_1_2`.

---

## 0. Chuẩn bị một lần (20 phút)

1. Mở công cụ agent của bạn (Claude Code hoặc tương đương) với **thư mục làm việc = gốc repo** `AI_Support_SOC_1_2`. Mọi prompt giả định điều này; nếu agent đứng ở `D:\Đồ án\project` thì đường dẫn trong prompt sai hết.
2. Dùng **mỗi vai một phiên chat riêng**, đặt tên phiên theo vai: `director`, `planner-P0`, `coder-P0-T01`, `reviewer`. Không trộn vai trong một phiên: ngữ cảnh của coder làm director quyết sai.
3. Đọc một lần `docs/plan/00-context-pack.md` (20 phút). Bạn là người duy nhất đọc toàn bộ; agent chỉ đọc phần được chỉ.
4. Commit thư mục `docs/plan/` ngay: `git add docs/plan && git commit -m "plan: coordination files"`. Từ đây mọi thay đổi của agent trong `docs/plan/` đều có lịch sử.
5. Ba việc chỉ bạn làm được, cần xong **trước khi chạy Planner P0** (hoặc song song, nhưng P0 sẽ đứng ở "Owner actions" cho tới khi xong):
   - Tạo user chỉ đọc trên OpenSearch (`https://127.0.0.1:9400`; **không phải** `wazuh-indexer` — service đó `inactive`/`disabled`); copy `root-ca.pem` (máy này: `/etc/logstash/opensearch-certs/root-ca.pem`, đọc được không cần sudo) vào `conf/root-ca.pem`. <!-- superseded-ok: DEC-001 names the service only to say it is inactive -->
   - Lấy API key DeepSeek.
   - Mở `Final-Project`, kiểm tra parser Wazuh / `category_resolver` / `prompt_guard` còn chạy được không (chạy thử một hàm với alert mẫu). Ghi kết quả một dòng vào `docs/plan/INBOX.md` dạng `QUESTION` để Director ghi thành `DEC-002`.
6. **Cấp LOGIN cho `app_rw` — việc superuser làm một lần; trên máy này đã xong 05/09, kiểm lại 06/09 (DEC-023 mục 2, DEC-024).** Role `app_rw` không cần tồn tại sẵn: migration 017 tự tạo role dạng NOLOGIN nếu thiếu và không bao giờ dừng vì thiếu role (DEC-024(a) thay DEC-023 mục 3; `user1` là superuser). Việc duy nhất còn lại của bước này là cấp LOGIN + mật khẩu để ứng dụng kết nối ở P2. Kiểm 06/09: `pg_authid` → `app_rw|rolcanlogin=t|có mật khẩu`; `psql "$DATABASE_URL" -Atc "select session_user, current_user"` → `app_rw|app_rw`. Cụm khác — role có sẵn: `sudo -u postgres psql -c "ALTER ROLE app_rw LOGIN PASSWORD '<openssl rand -base64 24>'"`; cụm mới: `CREATE ROLE app_rw LOGIN PASSWORD '…' ROLE user1` (mệnh đề `ROLE user1` giữ quyền `SET ROLE app_rw` cho test). Ghi vào `.env`: `DATABASE_URL=postgresql://app_rw:<mật khẩu>@127.0.0.1:5432/soc_dev` (TCP vì `pg_hba` chỉ cho socket peer với tài khoản hệ điều hành cùng tên), **không bao giờ commit**. P1 không cần bước này: test dùng `SET ROLE app_rw` từ `user1`, và cổng ra P1 không còn mang phụ chú nào về cụm (DEC-024(a)).

Lưu ý lịch: hôm nay đã là 05/09, tức D0 và D1 của plan gộp làm một ngày. Chạy P0 buổi sáng, P1 buổi chiều; P1-T01 (smoke test) có thể chạy ngay khi có API key, song song với P0.

---

## 1. Vòng đời một giai đoạn — từng bước, kèm câu cần gõ

### Bước A · Chạy Planner (đầu mỗi giai đoạn, ~15–30 phút agent)

1. Phiên mới, tên `planner-P<n>`.
2. Gõ đúng một câu:
   > Read `docs/plan/prompts/P<n>.md` and act as that Planner. Do everything it says, then give me the summary it asks for.
   Nếu công cụ của bạn không đọc file tốt, dán nguyên nội dung `P<n>.md` vào thay cho câu trên.
3. Kết quả phải có: `docs/plan/tasks/P<n>/P<n>-tasks.md`, một `P<n>-Tnn.prompt.md` cho mỗi task, các dòng mới trong `STATE.md`, và (nếu có) mục trong `INBOX.md`.
4. **Kiểm tra 5 phút** trước khi dùng (checklist §5). Nếu sai: nói với Planner trong cùng phiên, ví dụ:
   > Tasks T03 and T05 both modify `backend/app/infra/db.py`. Re-assign files so no two tasks share a file, then rewrite the affected prompt files.
5. Commit: `git add docs/plan && git commit -m "plan: P<n> tasks"`.

### Bước B · Dispatch Coder (mỗi task một phiên)

1. Xem `STATE.md`: chọn task `todo` mà mọi task ở cột "Depends on" đã `done`. Tối đa 3 task cùng lúc, file không trùng nhau.
2. Phiên mới, tên `coder-P<n>-Tnn`, **thư mục làm việc = worktree `../AI_Support_SOC_1_2-P<n>-Tnn` mà Director đã tạo (bước 3)**. Gõ:
   > Read `docs/plan/tasks/P<n>/P<n>-Tnn.prompt.md` and act as that Coder. Work only on this task. Finish with the report file it asks for.
3. **Worktree do Director tạo lúc phát (DEC-010, ghi thành lời tại DEC-031):** trong buổi sáng Director chạy `git worktree add ../AI_Support_SOC_1_2-P<n>-Tnn -b task/P<n>-Tnn main`, nên khi bạn mở phiên đã có thư mục `../AI_Support_SOC_1_2-P<n>-Tnn` trên nhánh `task/P<n>-Tnn` — mở phiên **trong thư mục đó**; card quy tắc 1 bảo Coder tự tạo nếu chưa có. Coder viết test, code, chạy `make test`, ghi `…report.md`, đặt `STATE.md` thành `review` **và commit tất cả trên nhánh task** (DEC-028). Sau khi merge, Director gỡ worktree bằng `git worktree remove` **không** `--force`: lệnh từ chối là dấu hiệu còn việc chưa commit (DEC-028).
4. Nếu coder hỏi bạn câu gì: **không trả lời bằng ngữ cảnh mới trong chat**. Trả lời một trong ba cách: (a) chỉ tới mục trong context pack, (b) bảo nó ghi `DECISION_REQUEST`/`BLOCKER` vào `INBOX.md` rồi dừng, (c) nếu là quyết định thật, đưa cho Director (§1 bước D).
5. Coder kết thúc mà chưa xong (blocked): để nguyên phiên, không đóng; Director sẽ xử lý INBOX rồi bạn quay lại phiên đó gõ:
   > INBOX item resolved as DEC-0xx. Continue the task accordingly.

### Bước C · Reviewer (sau mỗi coder báo xong)

1. Phiên `reviewer` (một phiên dùng lại được, nhưng gõ `/clear` hoặc mở mới nếu công cụ giữ ngữ cảnh dài).
2. Gõ:
   > Read `docs/plan/prompts/reviewer.md` and act as the Reviewer. Task: P<n>-Tnn.
3. Kết quả: `docs/plan/tasks/P<n>/P<n>-Tnn.review.md` với `APPROVE` hoặc `CHANGES`; `STATE.md` đổi thành `approved` hoặc `changes`.
4. Nếu `CHANGES`: quay lại **đúng phiên coder cũ** (nó còn ngữ cảnh), gõ:
   > Read `docs/plan/tasks/P<n>/P<n>-Tnn.review.md`. Fix every blocking finding, re-run all acceptance commands, update the report, set STATE.md back to `review`.
   Rồi chạy Reviewer lại. Lặp tới `APPROVE`. Quá 2 vòng → đưa Director quyết (cắt, chia nhỏ, hay đổi cách).

### Bước D · Director (sáng và tối, và khi INBOX có mục mới)

1. Phiên `director` dùng suốt 14 ngày (nếu ngữ cảnh quá dài, mở phiên mới: nó đọc lại STATE/INBOX/DECISIONS nên không mất gì).
2. Sáng:
   > Read `docs/plan/prompts/director.md` and do the morning run.
   Nó: đối chiếu STATE với git, xử lý INBOX, **merge** các task `approved` vào `main` và chạy `make test`, in "Owner actions today" và "Dispatch now".
3. Bạn làm "Owner actions", rồi dispatch theo danh sách (bước B).
4. Khi có mục INBOX giữa ngày:
   > INBOX has new items. Resolve or escalate them.
5. Tối:
   > Read `docs/plan/prompts/director.md` and do the evening run (daily gate).
   Nó kiểm exit gate của giai đoạn bằng lệnh thật, ghi "Daily gate log", áp cut nếu trễ (ghi `DEC-`), in kế hoạch ngày mai.
6. Khi Director escalate (ghi trong "Owner actions" kèm phương án đề nghị): bạn quyết bằng một câu trong phiên director:
   > Decision on DEC request about <x>: approve option B. Record it.

### Bước E · Sang giai đoạn kế

Chỉ khi Director ghi "exit gate met" cho giai đoạn hiện tại. Nếu chưa mà đã hết ngày kế hoạch: Director sẽ đề nghị cắt; bạn duyệt; phần bị cắt được ghi vào `DECISIONS.md` và sau này vào `docs/limitations.md`.

---

## 2. Một ngày mẫu (ví dụ D2, 06/09)

| Giờ | Việc | Vai |
|---|---|---|
| 08:00 | Director morning run → đọc "Owner actions today" | director |
| 08:15 | Làm Owner actions (ví dụ: thêm wodle heartbeat trên Wazuh) | bạn |
| 08:30 | Nếu giai đoạn mới: Planner P2 → kiểm tra 5 phút → commit | planner-P2 |
| 09:00 | Dispatch 3 coder: T01, T03, T04 (file không trùng) | 3 phiên coder |
| 10:30 | T01 báo `review` → Reviewer → `approved` | reviewer |
| 10:45 | Director "merge approved" (hoặc gõ: *Merge approved tasks now and dispatch the next ones*) → dispatch T02 | director |
| 12:00 | T03 `changes` → quay lại phiên coder T03 với review → Reviewer lại | coder-T03, reviewer |
| 14:00 | Coder T05 hỏi về schema → bảo nó ghi INBOX → Director xử lý → tiếp | coder-T05, director |
| 17:00 | 5 phút digest (từ D6 trở đi) | bạn |
| 17:30 | Director evening run → gate, cut, kế hoạch mai | director |
| 17:45 | `git log --oneline -20`, đọc STATE.md 2 phút, đóng máy | bạn |

Số phiên mở cùng lúc: director + reviewer + ≤ 3 coder = 5. Planner chỉ mở đầu giai đoạn.

---

## 3. Bảng câu gõ nhanh

| Tình huống | Gõ vào phiên nào | Câu |
|---|---|---|
| Bắt đầu giai đoạn | planner-P<n> | `Read docs/plan/prompts/P<n>.md and act as that Planner.` |
| Planner làm sai một điểm | cùng phiên planner | `Fix: <điểm sai>. Rewrite the affected task cards and prompt files. Do not change other tasks.` |
| Giao task | coder mới | `Read docs/plan/tasks/P<n>/P<n>-Tnn.prompt.md and act as that Coder.` |
| Coder xong, cần review | reviewer | `Read docs/plan/prompts/reviewer.md and act as the Reviewer. Task: P<n>-Tnn.` |
| Review ra CHANGES | phiên coder cũ | `Read docs/plan/tasks/P<n>/P<n>-Tnn.review.md. Fix every blocking finding, re-run acceptance, update the report.` |
| Sáng | director | `Read docs/plan/prompts/director.md and do the morning run.` |
| Tối | director | `Read docs/plan/prompts/director.md and do the evening run (daily gate).` |
| INBOX có mục | director | `INBOX has new items. Resolve or escalate them.` |
| Bạn quyết một escalation | director | `Decision on <mục>: <approve/refuse> option <X>. Record as DEC.` |
| Cần re-plan giữa chừng | director rồi planner | Director: `Order a re-plan of P<n> because <lý do>; list what to keep.` → Planner: `Re-plan P<n> per DEC-0xx: keep tasks <ids>, re-cut the rest.` |
| Trễ lịch | director | `We are one day behind. Propose cuts from this phase's cut candidates and the cross-phase order; do not extend.` |
| Coder muốn đổi schema | phiên coder | `Do not change contracts. Write a DECISION_REQUEST to docs/plan/INBOX.md and stop.` |
| Kết thúc ngày cuối giai đoạn | director | `Confirm the P<n> exit gate by running its commands; record the result.` |
| **Coder báo xong** | director | `<TASK_ID> reported. Do a result-intake run.` |
| **Reviewer trả APPROVE** | director | `<TASK_ID> approved. Merge and continue.` |
| **Reviewer trả CHANGES** | director | `<TASK_ID> review returned CHANGES. Triage it.` |
| **Coder báo blocked** | director | `<TASK_ID> is blocked. Resolve or escalate.` |
| **Planner chạy xong** | director | `Planner P<n> finished. Validate its output.` |

Năm dòng in đậm là **nhịp thứ ba** của Director (`prompts/director.md` → *Result-intake run*), chạy giữa ngày mỗi khi có agent trả kết quả. Bạn **không dán ngữ cảnh**, chỉ dán con trỏ: mã task + chuyện gì xảy ra. Director tự đọc file.

---

## 3b. Định tuyến: vấn đề nào đưa ai

| Vấn đề | Ai trả lời | Cách đưa |
|---|---|---|
| Coder không hiểu yêu cầu trong card | Không ai — chỉ đường | `See context pack §6.3.` Không giải thích lại bằng ngữ cảnh mới trong chat |
| Coder muốn sửa schema / `output_schemas.json` / config key / route API / job type | Director → Owner nếu đụng §6 | Gõ vào phiên coder: `Do not change contracts. Write a DECISION_REQUEST to docs/plan/INBOX.md and stop.` |
| Coder bí vì thiếu hạ tầng (DB, credential, mạng) | Director → thành Owner action | Coder tự ghi `BLOCKER` sau 30′; bạn gõ vào director: `<TASK_ID> is blocked. Resolve or escalate.` |
| **Lệnh acceptance trong card viết sai** | **Director**, không phải Coder | Card do Planner viết, Coder không có quyền sửa: `<TASK_ID> acceptance #<n> is malformed: <lý do>. Rule on it and correct the card.` |
| Coder vượt ước tính > 50 % | Director | `<TASK_ID> is 2h over estimate. Split or cut.` |
| Hai coder đụng cùng một file | Director (Reviewer phát hiện) | Director dừng coder sau, tái phân file, bảo Planner sửa card |
| Reviewer trả `CHANGES` | Đúng phiên coder cũ, sau khi Director phân loại | `Read docs/plan/tasks/<PHASE>/<TASK_ID>.review.md. Fix every blocking finding, re-run all acceptance commands, update the report, set STATE.md back to review.` |
| `CHANGES` quá 2 vòng | Director | `<TASK_ID> has failed review twice. Decide: split, cut, or change approach.` |
| `make test` đỏ sau merge | Director tự xử | Nó `git revert -m 1`, task về `changes`, dán lỗi vào file review |
| Trễ lịch, gate không nhích | Director đề xuất → **bạn duyệt** | `We are one day behind. Propose cuts from this phase's cut candidates and the cross-phase order; do not extend.` |
| Cắt một D-item (D1–D20) | **Bạn** | `Decision on cutting <x>: approve. Record as DEC.` |
| Đổi model, vượt trần chi phí | **Bạn** | — |
| Bất cứ gì đụng **tính hợp lệ đánh giá** (gán nhãn mù, đóng băng gold, nhánh mù, G3) | **Bạn, và chỉ bạn** | Director bị cấm nới các quy tắc này vì lý do lịch |
| Việc §11 (credential, wodle, lab, gán nhãn, inventory) | **Bạn** | Không giao agent trong mọi trường hợp |
| Agent quên, hỏi lại thứ đã có trong tài liệu | Chỉ đường; nếu tài liệu **thiếu thật** thì thêm vào context pack rồi bảo nó đọc lại | Không bao giờ vá bằng lời giải thích trong chat |

Gộp một câu: **kỹ thuật → Director · phạm vi, tiền, tính hợp lệ khoa học, việc tay chân → bạn · mọi câu hỏi đi qua file, không đi qua chat.**

---

## 4. Việc chỉ bạn làm được, theo ngày

| Ngày | Việc của bạn |
|---|---|
| 05/09 | Indexer user + `root-ca.pem` → `conf/`; API key DeepSeek → `.env`; kiểm tra `Final-Project`; viết `conf/inventory.yaml` (có `user1-IA1803`), `conf/identities.yaml` (có `user1`); đọc `docs/smoke-test-D1.md` và duyệt model |
| 06/09 | Mở 3 phiên Coder trong worktree đã tạo sẵn — P1-T05, P1-T06, **P1-T08** (đo lại smoke test ở chế độ không suy luận, hợp đồng trong DEC-032); P1-T04 xếp sau, giới hạn 3 (DEC-029); P1-T01 đã duyệt 11/11 và merge @ `1349edc` lúc ~03:00; chạy Planner P2 (`prompts/P2.md`, đã sửa theo DEC-014/017/019 — DEC-031); quyết định model sau khi P1-T08 báo cáo — hai bộ số liệu cạnh nhau (DEC-032). Wodle `command` + rule heartbeat trên Wazuh manager: làm khi card puller/heartbeat của P2 phát. **Backfill không còn là `--since 2026-08-01`** (DEC-017: indexer chỉ có từ 02/09): lịch sử 08/08–01/09 nạp từ kho lưu manager bằng root, `source='replay'`, theo lệnh trong card backfill của P2 (DEC-019) |
| 07–08/09 | Cùng giảng viên viết 10 bảng quyết định playbook (`kb/decision_tables/*.yaml`, mỗi bảng 3–6 dòng); rà 10 playbook, điền `reviewed_by/at` |
| 09/09 | Seed user; đăng nhập; **bắt đầu thí điểm**: quyết alert thật mỗi ngày; nhắc giảng viên luật nhánh mù (không xem `llm_runs` trước khi quyết) |
| 10/09 | Cấu hình Telegram bot (hoặc SMTP) vào `.env`; duyệt digest đầu tiên; bấm `/analyze` trên một case thật |
| 11/09 | Chạy kịch bản lab theo `docs/lab-scenarios.md`: tấn công **và** hoạt động lành tính trên cùng host; ghi giờ vào checklist |
| 12/09 | Gán nhãn buổi 1 (bạn và giảng viên, độc lập, không trao đổi) |
| 13/09 | Gán nhãn buổi 2; họp đối chiếu; commit `eval/gold_v1.sha256` |
| 14/09 | Duyệt chi phí chạy live B2–B4; chọn v1.0 hay v1.1 sau regression gate |
| 15/09 | Ký biên bản khôi phục backup; kết thúc thí điểm |
| 16–17/09 | Viết luận văn từ `docs/results/*.md`, `docs/limitations.md`; tập demo theo `docs/demo.md` |
| Mỗi ngày từ 10/09 | 5 phút digest lúc 17:00 |

---

## 5. Checklist 5 phút sau khi Planner chạy

- [ ] Mỗi task có **Acceptance** là lệnh chạy được (`pytest …`, `make …`, `python …`), không phải câu "hoạt động đúng".
- [ ] Mỗi lệnh Acceptance có **ca hỏng chứng minh được**, không chỉ ca chạy (DEC-025). Tự hỏi "làm gì thì nó đỏ?" — nếu không làm nó đỏ được thì lệnh đó không kiểm cái nó nói là kiểm. Bốn lỗi trong dự án này đều một hình dạng: lệnh xanh mà không chứng minh gì.
- [ ] Không có hai task cùng sửa một file — grep tên tệp trong các `P<n>-T*.prompt.md`, **không phải** trong `P<n>-tasks.md`: phạm vi tệp nằm ở prompt (DEC-007 mục 7), bản chỉ mục có thể thiếu.
- [ ] Tổng giờ `must` ≤ ngân sách ngày × 1,3; nếu vượt, Planner đã ghi rõ ở đầu file cắt gì.
- [ ] Không còn `{{` trong bất kỳ `*.prompt.md` nào: `grep -l "{{" docs/plan/tasks/P<n>/*.prompt.md` phải rỗng.
- [ ] Việc chỉ người làm không bị giao cho agent (so với context pack §11).
- [ ] Task nào chạm hợp đồng đóng băng thì có mục INBOX, không âm thầm sửa.
- [ ] `STATE.md` có dòng cho mọi task, trạng thái `todo`.

---

## 6. Quy tắc merge và nhánh

- Một task = một nhánh `task/P<n>-Tnn`, tạo từ `main`. Task phụ thuộc task khác: chờ task kia `done` (đã vào `main`) rồi mới bắt đầu; không tạo nhánh từ nhánh.
- Director merge bằng `git merge --no-ff task/<id>` theo thứ tự phụ thuộc, chạy `make test` sau mỗi merge. Đỏ → revert merge, task về `changes`.
- Bạn có thể tự merge nếu muốn nhanh: cùng lệnh, cùng điều kiện (đã `approved`, test xanh), rồi đổi STATE thành `done`.
- Không bao giờ commit thẳng lên `main` ngoài `docs/plan/` và các merge.

---

## 7. Khi có sự cố

| Sự cố | Làm gì |
|---|---|
| Smoke test không đạt ngưỡng | Director sẽ escalate kèm số; bạn chọn model chat khác của DeepSeek; sửa `LLM_MODEL_PROPOSER` trong `.env`; P2 vẫn chạy vì không cần LLM |
| Indexer không kết nối được | Owner action: CA/user/mạng. P2 vẫn chạy trên fixture; puller test dùng fixture |
| Coder chạy quá 2 giờ so với ước tính | Nói Director: `T<nn> is 2h over estimate. Split or cut.` |
| Hai coder đụng file | Reviewer sẽ báo; Director dừng coder sau, giao lại file; bạn merge theo thứ tự |
| Agent "quên" ngữ cảnh, hỏi lại điều đã có | Trả lời bằng đường dẫn mục trong context pack, không giải thích lại; nếu thiếu thật, **thêm vào context pack** rồi bảo agent đọc lại |
| Cần đổi schema thật (lỗi thiết kế) | Coder ghi INBOX → Director escalate với DDL chính xác → bạn duyệt → Director ghi DEC → coder được phép sửa migration mới (không sửa migration đã áp) |
| Trễ 1 ngày cuối P2/P3 | Director đề nghị cắt ② (P5) để giữ P6/P7; bạn duyệt. Không bao giờ cắt: intake/puller, ① + cổng + verifier, trang gán nhãn, eval harness |
| Ai đó đã xem kết quả ① trước khi gán nhãn một cụm | Bỏ nhãn đó của người đó; ghi DEC; không dùng lại |

---

## 8. Ba thói quen giữ cho hệ không loạn

1. **Mọi ngữ cảnh vào file, không vào chat.** Context pack là nơi duy nhất; INBOX là nơi duy nhất cho câu hỏi; DECISIONS là nơi duy nhất cho quyết định.
2. **Không tin báo cáo, tin lệnh.** Reviewer và Director đều chạy lệnh thật. Bạn cũng vậy: trước khi ngủ, `make test` trên `main` một lần.
3. **Mỗi ngày phải có thứ chạy được.** Nếu 17:30 mà gate không nhích, cắt — đừng thêm giờ.
