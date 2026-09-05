# STATE — AI Support SOC v3 build board

Updated by the Planner (adds tasks), Coders (status of their task), Reviewer (review verdict), Director (everything else). Keep rows one line. Status ∈ todo · in-progress · review (Coder reported) · approved (Reviewer APPROVE, awaiting merge) · changes (Reviewer CHANGES) · done (merged by Director) · blocked · cut. The authority for this list is `README.md` §Conventions; `prompts/reviewer.md` mandates `approved` on an APPROVE. Never drop `approved` — it is what makes the approved-but-unmerged queue visible.

## Phase gates

| Phase | Planned days | Status | Exit gate met on | Notes |
|---|---|---|---|---|
| P0 Preparation | D0 04/09 | **done** | **2026-09-05** | Cổng ra ĐẠT cả 5 mục (kiểm từng mục trên `main`). T01–T06 merged, 77 test xanh. T07 (không thuộc cổng ra) đang chờ duyệt và là thứ duy nhất chặn phát P1. |
| P1 Smoke test + schema | D1 05/09 | todo | — | — |
| P2 Intake + pipeline | D2–D3 06–07/09 | todo | — | — |
| P3 AI pipeline ① | D4 08/09 | todo | — | — |
| P4 UI + auth + blind | D5 09/09 | todo | — | — |
| P5 Tier-2 + digest + ops | D6 10/09 | todo | — | — |
| P6 Lab data + labeling | D7–D9 11–13/09 | todo | — | — |
| P7 Evaluation | D10 14/09 | todo | — | — |
| P8 Stabilise + report | D11–D13 15–17/09 | todo | — | — |

## Tasks

| Task | Title | Priority | Status | Branch | Depends on | Owner action needed? | Last update | Dispatch |
|---|---|---|---|---|---|---|---|---|
| P0-T01 | Repo hygiene and `.gitignore` | must | done | task/P0-T01 | — | no — duyệt vòng 2 ĐẠT (8/8), merge vào `main` @ `8ecddb5` | 2026-09-05 director |
| P0-T02 | Build scaffold: requirements, pyproject, Makefile, compose, `.env.example` | must | done | task/P0-T02 | — | no — đã rebase lên `main`, chạy lại 9/9 lệnh nghiệm thu ĐẠT, merge @ `7450778` | 2026-09-05 director |
| P0-T03 | Test harness: DB fixture, fake LLM, import-rule scan, canonical fixture | must | done | task/P0-T03 | P0-T01, P0-T02 | no — duyệt ĐẠT, rebase + chạy lại 9/9 (gồm DB thật và mục 9 kiểm bản vá `migrate.sh`), merge @ `eb3916d` | 2026-09-05 director | — |
| P0-T04 | `eval/indexer_probe.py` — offline-verifiable indexer probe | must | done | task/P0-T04 | P0-T02 | no — duyệt ĐẠT, rebase + chạy lại 8/8, merge @ `8b68466`. Quy tắc 6 nay chạy được vì T03 đã merge | 2026-09-05 director | — |
| P0-T05 | Inventory examples, format document, `inventory.validate()` | must | done | task/P0-T05 | P0-T02 | có — chủ đồ án viết `conf/inventory.yaml`, `conf/identities.yaml`, `conf/iocs.csv` từ 3 tệp `.example`. **Duyệt vòng 2 (độc lập) ĐẠT** — 10/10 nghiệm thu theo *prompt card*, đo lại trên worktree cô lập và trên cây đã merge; quy tắc nhập khẩu nay chạy thật (`test_import_rules.py` 12 passed, quét thẳng module → 0 vi phạm), `make test` 77 passed, `make lint` sạch. Không có phát hiện chặn; 9 ghi chú không chặn ở `docs/plan/tasks/P0/P0-T05.review.md` | 2026-09-05 reviewer | — |
| P0-T06 | Package skeletons per context pack §4 | should | done | task/P0-T06 | P0-T02 | no — duyệt ĐẠT (7/7), rebase + chạy lại, merge @ `2ad5dc2`. 53 module, tất cả chỉ có docstring | 2026-09-05 director | — |
| P0-T07 | `make test-db` không cần docker; `.gitignore` `*.sw?`; mặc định DSN trong `.env.example` | must | done | task/P0-T07 | P0-T02 | no — duyệt ĐẠT, rebase + chạy lại, merge @ `0bdbede`. **Toàn bộ P0 đã merge.** | 2026-09-05 director | — |

## Blockers (open)

| Task | Since | What is blocked | Who can unblock |
|---|---|---|---|
| P0 exit gate item 2 | 2026-09-05 | `eval/indexer_probe.py` cannot be run for real — `soc_ro` does not exist. P0-T04 ships and is accepted offline; the live run stays an Owner action. | Owner (INBOX 05/09 · P0/P2 · BLOCKER) |
| ~~P0-T03 / P1 / P2~~ | 2026-09-05 | **ĐÓNG 05/09 — DEC-008.** `CREATEDB` đã cấp và tự kiểm lại: `rolcreatedb = t`, createdb/CREATE/INSERT/SELECT/dropdb đều chạy. `TEST_DATABASE_URL=postgresql:///soc_test` (socket; dạng TCP trong báo cáo đòi mật khẩu, không dùng được). Đóng nó lộ ra lỗi thứ hai: `make migrate` thoát 3 trên DB sạch — xem DEC-008. | — |

## Owner actions (Director writes; Owner clears)

- [x] Tạo `soc_ro` — xong 05/09, tự kiểm lại: role `soc_reader`, `_count`=7.452, `POST _doc`=403. `INDEXER_URL` giữ `https://127.0.0.1:9400` (SAN chỉ có localhost/127.0.0.1/::1). Xem DEC-015.
- [x] API key DeepSeek → `.env` — xong 05/09, nghiệm thu §7.5 ĐẠT (`deepseek-v4-flash`, HTTP 200, JSON hợp lệ, có `usage`, 1,02 s). P1-T01 hết chặn.
- [x] Xác nhận retention — xong 05/09 bằng kho lưu của manager (root), KHÔNG cần `soc_ro`: 84,376 alert / 29 ngày (08/08–05/09), median 592, mean 3,013, đỉnh 47,917 ngày 16/08. R2 chết, xem DEC-014.
- [ ] **Planner P2 (lệnh, DEC-014):** thêm task đo **tỉ lệ nén dedup trên một ngày thật** — chạy TRƯỚC mọi phát biểu về ngân sách LLM. Chừng nào chưa có số, không tài liệu nào được nói `LLM_MONTHLY_USD_CAP=30` là đủ.
- [ ] **Planner P2 (lệnh, DEC-014):** dùng ngày **16/08** (47,917 alert, rule 40112) làm fixture kiểm dedup thay cho burst tổng hợp — nó đụng thật vào `MAX_CLUSTER_SIZE=1000` và `MAX_CLUSTER_AGE_HOURS=4`.
- [ ] **Chủ đồ án (sau khi có số dedup, DEC-014):** xem lại C8. Lý do cắt đã ghi ("vô nghĩa ở 50/ngày") nay vô hiệu. C8 vẫn cắt cho tới khi anh quyết — bỏ cắt là quyền của anh, không phải Director.
- [ ] **Planner P6 (DEC-014):** G1 nay backfill được từ kho lưu (36,459 alert ngoài ngày bão). Xem lại sàn 300 cụm và tỉ lệ lab lành tính — không cần độn nữa.
- [ ] `conf/inventory.yaml` (phải có `user1-IA1803`) + `conf/identities.yaml` (phải có `user1`) — sau khi Planner P0 sinh `.example`.
- [x] `.gitignore` chặn `.env`/`conf/` — xong 05/09 (repo có remote GitHub công khai).
- [x] Copy CA vào `conf/root-ca.pem`, TLS verify sạch — xong 05/09.
- [x] Kiểm tra `Final-Project` — xong, kết quả ở INBOX 05/09 QUESTION (sẽ thành DEC-002).
- [x] **Director:** ghi INBOX 05/09 QUESTION (`Final-Project`) thành `DEC-002` — xong 05/09, phương án A: bê bảng ánh xạ category + `detect_injection` sang, viết mới `ingest/wazuh_parser.py` và `security/wrap.py`. Đóng mục 5 của P0 exit gate.
- [x] **Director:** trả lời 2 DECISION_REQUEST của Planner P0 — xong 05/09: `DEC-003` (3 khoá database vào §6.3, 4 khoá Compose ở ngoài) và `DEC-004` (DB đổi theo §6.2: CHECK `high|medium|low|unknown`, thêm `owner`/`role` NULL). P0-T02 và P0-T05 đã cập nhật theo.
- [ ] **P1 Planner:** DEC-004 còn kéo theo 2 việc (việc thứ 3 — chọn migration — đã chốt 05/09: `013_assets_enrichment.sql`, bốn migration cũ dời thành `014`–`017`, cổng ra P1 nay là "migrations 013–017"): tính lại công thức risk_score `docs/phase-4-enrichment.md:170` (mất 2 bậc `crown_jewel`/`normal` — là sửa đặc tả v1, cần quyết định riêng), và sửa 2 playbook rẽ nhánh theo `crown_jewel` (`kb/playbooks/malware.md:36`, `kb/playbooks/ssh_brute_force.md:34`, làm khi duyệt playbook ở P3). Chi tiết ở `docs/plan/tasks/P0/P0-tasks.md` §Hand-off to P1.
- [x] **Owner/Director:** commit khối sửa kế hoạch — xong 05/09, `main` @ `202e9ca` (14 tệp, DEC-002…DEC-006 + 2 phiếu duyệt). Bản sao mới của repo nay tìm được đầy đủ vết phê duyệt; working tree sạch nên AC3 của P0-T01 đo được thật. Coder phải rebase `task/P0-T01`, `task/P0-T02` lên `main` trước khi làm lại.
- [x] **Director:** soát trước khi phát 4 card T03–T06 theo DEC-006 — xong 05/09. Chạy thật 37 lệnh nghiệm thu trên cây "main + P0-T02 đã merge"; 3 nghi vấn, 2 bị bác sau khi phản biện, 1 đúng. Đã sửa 9 chỗ (5 card gọi `pytest` trần trái DEC-005; T05 bắt viết bảng ánh xạ trái DEC-004; `P0-tasks.md` còn `013`–`016`; T03 `localhost:9400` trái DEC-001; …). Biên bản: `docs/plan/tasks/P0/P0-predispatch-audit.md`. Còn 7 điểm cần anh quyết, xem §Still open.
- [x] **Director:** DEC-009 — chủ đồ án bắt được `reviewer.md:7` còn trỏ vào bản chỉ mục sau DEC-007 mục 7. Đo ra 3 chỗ nữa: `coder-template.md` (bản sinh), cả 6 `P0-T0*.prompt.md` đã sinh (gồm 3 task vừa phát), và checklist `HUONG-DAN` §169 kiểm trùng tệp. Suýt hỏng thật: prompt của T03 có 9 mục nghiệm thu, chỉ mục chỉ nhắc 7 — thiếu đúng mục 9 kiểm bản vá `migrate.sh`. Đã sửa cả 4.
- [x] ~~**Planner — lệnh re-plan**~~ — Planner không bao giờ được chạy; chủ đồ án cho làm thẳng. Card chưa từng tồn tại. DEC-011 + DEC-013 đóng vai hợp đồng nghiệm thu cho lần này (DEC-018). Planner vẫn còn nợ card cho P1. Lệnh cũ:
- [ ] ~~(đã thay bằng dòng trên)~~ **Planner (DEC-011, DEC-015):** card vẫn chưa tồn tại; đây là thứ DUY NHẤT của P0 còn chặn việc lập kế hoạch P1. Toàn bộ phạm vi đã gom sẵn ở DEC-011 + DEC-013, bản vá đã tự kiểm — chỉ cần định dạng lại thành card, không phải nghĩ lại. Viết `docs/plan/tasks/P0/P0-T07.prompt.md` — sửa target `make test-db` (dùng `TEST_DATABASE_URL` nếu kết nối được, compose chỉ là phương án dự phòng; bỏ câu dẫn tới blocker đã đóng). Bản vá đã tự kiểm sẵn trong DEC-011, khỏi dựng lại. Nghiệm thu PHẢI chạy chính cái target. Không thuộc cổng ra P0 — nhưng phải xong TRƯỚC khi phát P1. **Mở rộng phạm vi (DEC-013):** thêm `*.sw?` vào `.gitignore`; `.env.example` lấy DSN không-docker làm mặc định cho máy này, và thêm `DATABASE_URL`/`DATABASE_URL_OWNER` trỏ `soc_dev`. Cả hai tệp là sản phẩm P0 nên không được sửa thẳng trên `main` (HUONG-DAN:183).
- [ ] **P8:** ghi `user1 is_privileged=false` thành hạn chế có tên trong `docs/limitations.md`, và chương đánh giá phải nói rõ sản lượng auto-close + so sánh B1 phụ thuộc vào cách đọc này (DEC-012). Không công bố = con số auto-close bị nghi ngờ.
- [ ] **Planner P6:** chỉ agent 001 sinh ra digest; đừng tính 400 cụm như thể cả hai agent đóng góp (DEC-012).
- [x] **Chủ đồ án:** thêm `TEST_DATABASE_URL=postgresql:///soc_test` vào `.env` — xong 05/09, test `-m db` chạy qua đường `.env`.
- [ ] **CHỦ ĐỒ ÁN QUYẾT — migration 017 CHẶN LẠI (DEC-020, rút DEC-016).** Hai câu hỏi hợp đồng:
  **(a)** §6.1 bắt `REVOKE UPDATE ... intake` nhưng G12 đòi ghi `processed_at`/`outcome` sau khi chèn — hợp đồng tự mâu thuẫn, hỏng ở MỌI phương án, không riêng D. Bản vá đã đo: `GRANT UPDATE (processed_at, outcome, error)` theo cột + trigger ghim các cột biên nhận. Đo được: INSERT ok, sửa biên nhận ok, sửa `raw_payload` bị từ chối, DELETE bị từ chối.
  **(b)** §6.1 ghi nguyên văn "The application connects as `app_rw`"; route D cho app nối bằng `user1` rồi `SET ROLE`. Đó là sửa chữ đóng băng — đúng tiêu chuẩn tôi đã áp cho route C mà lại không áp cho D.
  Route A (`ALTER ROLE user1 CREATEROLE`) vẫn là lệnh duy nhất bỏ được chú thích "trên cụm đã có app_rw" khỏi cổng ra P1.
- [x] **Nguồn G1 — CHỐT 05/09: "cả hai" (DEC-019).** Indexer là đường sống (`source='wazuh'`); lịch sử trước 02/09 lấy từ kho lưu manager, chủ đồ án đọc bằng root, nạp `source='replay'`. F2 đã sửa tại chỗ, số dòng không đổi nên 2 trích dẫn theo dòng vẫn đúng. R2 chết.
- [ ] **Planner P2 (DEC-019):** thêm đường nạp lịch sử — `sort_key` cho dòng replay = epoch-millis của timestamp (kho lưu không có `sort`); `raw_payload` giữ NGUYÊN dòng kho lưu (G9), không bọc giả `_source`; và khi sửa lỗi `alert_time` của `Final-Project` thì **giữ** nhánh dự phòng `_source.timestamp` — đó là đường replay, không phải lỗi.
- [ ] **Planner P4/P6 (DEC-019):** `alerts.source` KHÔNG được hiện trên trang gán nhãn — người gán thấy `replay` vs `wazuh` là suy ra được ngày bão, phá gán nhãn mù.
- [ ] ~~**Chủ đồ án (chặn migration 017, DEC-013):** chọn A/B/C.~~
- [ ] **Director:** DEC-005 chốt 2 lời gọi chiến thuật của Planner — migration nằm phẳng trong `docs/Schema/`, pytest luôn gọi `python3 -m pytest -c backend/pyproject.toml`. Mọi lệnh nghiệm thu trong task card dùng đúng dạng đó.
- [x] Mở đường cho test DB — xong 05/09, `ALTER ROLE user1 CREATEDB`. Đã tự kiểm lại đầu-cuối (DEC-008). DSN dùng được là `postgresql:///soc_test`, KHÔNG phải dạng TCP `user1@127.0.0.1:5432` (đòi mật khẩu). P1 exit gate hết chặn.
- [x] Chạy probe thật — xong 05/09, exit 0. **Cổng ra P0 mục 2: ĐẠT.** Đếm theo ngày: 02/09 **6.395** · 03/09 **371** · 04/09 **354** · 05/09 **332** · tổng **7.452**. Ngày index sớm nhất: **2026-09-02**. 5 fixture (rule 591, 5503, 5760, 92601, 521) đã ghi. Câu trả lời retention chính là tin xấu: indexer chỉ có 4 ngày, không phải 5 tuần → F2 sai, xem DEC-016.
- [x] Sau khi P0-T05 merge: viết `conf/inventory.yaml` (phải có `user1-IA1803`), `conf/identities.yaml` (phải có `user1`), `conf/iocs.csv` từ ba tệp `.example`; kiểm bằng `python3 -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print(validate() or 'OK')"`.
- [ ] Xác nhận `Bản đồ kiến trúc AI Support SOC.html` + `_files/` ở gốc repo được đưa vào `.gitignore` (P0-T01) — bản page-save cũ, bản hiện hành là `docs/kien-truc-v3-14-ngay.html`.

## Daily gate log

| Date | Phase | Gate advanced? | Cuts applied | Notes |
|---|---|---|---|---|
| 2026-09-05 | P0 | 5/6 | — | T01–T05 merged, 77 test xanh. DEC-007…DEC-010. Lỗi `make migrate` (008–012 không tự ghi) phát hiện nhờ `CREATEDB` và đã vá trong T03. Còn T06 + `soc_ro`. |
| 2026-09-05 | P0 | chưa | — | P0-T02 duyệt ĐẠT; P0-T01 trả về sửa báo cáo. DEC-002…DEC-006 đã commit lên `main` (`202e9ca`). Soát trước khi phát T03–T06 theo DEC-006: sửa 9 chỗ, còn 7 điểm chờ quyết. Cổng kế tiếp: merge `task/P0-T02` vào `main`. |
