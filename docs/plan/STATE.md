# STATE — AI Support SOC v3 build board

Updated by the Planner (adds tasks), Coders (status of their task), Reviewer (review verdict), Director (everything else). Keep rows one line. Status ∈ todo · in-progress · review · changes · done · blocked · cut.

## Phase gates

| Phase | Planned days | Status | Exit gate met on | Notes |
|---|---|---|---|---|
| P0 Preparation | D0 04/09 | todo | — | — |
| P1 Smoke test + schema | D1 05/09 | todo | — | — |
| P2 Intake + pipeline | D2–D3 06–07/09 | todo | — | — |
| P3 AI pipeline ① | D4 08/09 | todo | — | — |
| P4 UI + auth + blind | D5 09/09 | todo | — | — |
| P5 Tier-2 + digest + ops | D6 10/09 | todo | — | — |
| P6 Lab data + labeling | D7–D9 11–13/09 | todo | — | — |
| P7 Evaluation | D10 14/09 | todo | — | — |
| P8 Stabilise + report | D11–D13 15–17/09 | todo | — | — |

## Tasks

| Task | Title | Priority | Status | Branch | Depends on | Owner action needed? | Last update |
|---|---|---|---|---|---|---|---|
| P0-T01 | Repo hygiene and `.gitignore` | must | todo | task/P0-T01 | — | no | 2026-09-05 planner |
| P0-T02 | Build scaffold: requirements, pyproject, Makefile, compose, `.env.example` | must | todo | task/P0-T02 | — | yes — INBOX 05/09 P0-T02 DECISION_REQUEST (database keys) | 2026-09-05 planner |
| P0-T03 | Test harness: DB fixture, fake LLM, import-rule scan, canonical fixture | must | todo | task/P0-T03 | P0-T01, P0-T02 | yes — INBOX 05/09 P0/P1 BLOCKER (no DB for `make test-db`) | 2026-09-05 planner |
| P0-T04 | `eval/indexer_probe.py` — offline-verifiable indexer probe | must | todo | task/P0-T04 | P0-T02 | yes — live run needs `soc_ro` (INBOX 05/09 P0/P2 BLOCKER) | 2026-09-05 planner |
| P0-T05 | Inventory examples, format document, `inventory.validate()` | must | todo | task/P0-T05 | P0-T02 | yes — INBOX 05/09 P0-T05/P1 DECISION_REQUEST (assets contract) | 2026-09-05 planner |
| P0-T06 | Package skeletons per context pack §4 | should | todo | task/P0-T06 | P0-T02 | no | 2026-09-05 planner |

## Blockers (open)

| Task | Since | What is blocked | Who can unblock |
|---|---|---|---|
| P0 exit gate item 2 | 2026-09-05 | `eval/indexer_probe.py` cannot be run for real — `soc_ro` does not exist. P0-T04 ships and is accepted offline; the live run stays an Owner action. | Owner (INBOX 05/09 · P0/P2 · BLOCKER) |
| P0-T03 / P1 / P2 | 2026-09-05 | `make test-db` cannot be exercised by any agent: docker socket unreachable and the account has no `CREATEDB`. DB tests skip loudly; P1's "migrations apply on a clean DB" cannot be verified. | Owner (INBOX 05/09 · P0/P1 · BLOCKER, option A is one command) |

## Owner actions (Director writes; Owner clears)

- [ ] Tạo `soc_ro` trên OpenSearch — chặn P0 exit gate + P2 puller (06/09). Xem INBOX 2026-09-05 BLOCKER, chọn phương án A/B/C.
- [x] API key DeepSeek → `.env` — xong 05/09, nghiệm thu §7.5 ĐẠT (`deepseek-v4-flash`, HTTP 200, JSON hợp lệ, có `usage`, 1,02 s). P1-T01 hết chặn.
- [ ] Xác nhận retention `wazuh-alerts-*` (index sớm nhất + tổng docs) — quyết định sàn của G1. Chờ `soc_ro`.
- [ ] `conf/inventory.yaml` (phải có `user1-IA1803`) + `conf/identities.yaml` (phải có `user1`) — sau khi Planner P0 sinh `.example`.
- [x] `.gitignore` chặn `.env`/`conf/` — xong 05/09 (repo có remote GitHub công khai).
- [x] Copy CA vào `conf/root-ca.pem`, TLS verify sạch — xong 05/09.
- [x] Kiểm tra `Final-Project` — xong, kết quả ở INBOX 05/09 QUESTION (sẽ thành DEC-002).
- [ ] **Director:** ghi INBOX 05/09 QUESTION (`Final-Project`) thành `DEC-002` — đây là mục 5 của P0 exit gate, không phải task của coder.
- [ ] **Director:** trả lời 2 DECISION_REQUEST của Planner P0 (khoá cấu hình database; hợp đồng `assets`) — P0-T02 và P0-T05 chạy được trong lúc chờ, nhưng P1 cần câu trả lời trước khi viết migration 013–016.
- [ ] Mở đường cho test DB (INBOX 05/09 · P0/P1 · BLOCKER). Nhanh nhất: `sudo -u postgres psql -c 'ALTER ROLE user1 CREATEDB'`. Chặn P1 exit gate.
- [ ] Sau khi có `soc_ro`: chạy `python3 eval/indexer_probe.py --save-samples 5`, dán bảng đếm theo ngày + ngày index sớm nhất vào STATE.md, commit 5 fixture mẫu. Đóng P0 exit gate item 2 và trả lời luôn câu hỏi retention.
- [ ] Sau khi P0-T05 merge: viết `conf/inventory.yaml` (phải có `user1-IA1803`), `conf/identities.yaml` (phải có `user1`), `conf/iocs.csv` từ ba tệp `.example`; kiểm bằng `python3 -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print(validate() or 'OK')"`.
- [ ] Xác nhận `Bản đồ kiến trúc AI Support SOC.html` + `_files/` ở gốc repo được đưa vào `.gitignore` (P0-T01) — bản page-save cũ, bản hiện hành là `docs/kien-truc-v3-14-ngay.html`.

## Daily gate log

| Date | Phase | Gate advanced? | Cuts applied | Notes |
|---|---|---|---|---|
