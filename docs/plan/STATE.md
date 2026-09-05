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
| (Planner fills rows) | | | | | | | |

## Blockers (open)

| Task | Since | What is blocked | Who can unblock |
|---|---|---|---|

## Owner actions (Director writes; Owner clears)

- [ ] Tạo `soc_ro` trên OpenSearch — chặn P0 exit gate + P2 puller (06/09). Xem INBOX 2026-09-05 BLOCKER, chọn phương án A/B/C.
- [x] API key DeepSeek → `.env` — xong 05/09, nghiệm thu §7.5 ĐẠT (`deepseek-v4-flash`, HTTP 200, JSON hợp lệ, có `usage`, 1,02 s). P1-T01 hết chặn.
- [ ] Xác nhận retention `wazuh-alerts-*` (index sớm nhất + tổng docs) — quyết định sàn của G1. Chờ `soc_ro`.
- [ ] `conf/inventory.yaml` (phải có `user1-IA1803`) + `conf/identities.yaml` (phải có `user1`) — sau khi Planner P0 sinh `.example`.
- [x] `.gitignore` chặn `.env`/`conf/` — xong 05/09 (repo có remote GitHub công khai).
- [x] Copy CA vào `conf/root-ca.pem`, TLS verify sạch — xong 05/09.
- [x] Kiểm tra `Final-Project` — xong, kết quả ở INBOX 05/09 QUESTION (sẽ thành DEC-002).

## Daily gate log

| Date | Phase | Gate advanced? | Cuts applied | Notes |
|---|---|---|---|---|
