# Runbook chuyển AI Support SOC sang server khác — lấy gì, khôi phục thế nào, tiếp tục ra sao

Viết 20/09/2026 sau cutover Docker (DEC-105, `docs/db-docker.md`). Áp dụng cho **đợt 1**: dời app +
DB + worker + toàn bộ trạng thái làm việc (repo, session Claude Code); **Wazuh (manager, indexer,
dashboard, agent) ở lại IA1803** — server mới đọc indexer qua mạng. Đợt 2 (dời Wazuh) là việc khác,
cần DEC riêng.

Nguyên tắc: **không bao giờ có hai worker cùng sống** trên một `source_cursor` — tắt bên cũ trước khi
bật bên mới. Mọi bước có lệnh kiểm; chưa kiểm thì chưa tính là xong.

---

## 1 · Lấy gì mang đi

Ba thứ, không hơn:

| # | Thứ cần lấy | Ở đâu trên IA1803 | Chứa gì |
|---|---|---|---|
| 1 | **Repo** | GitHub `Kh4nh709/AI_Support_SOC_1_2` (55 nhánh) — hoặc `git/soc.bundle` trong bộ backup | code, docs, 10 bảng KB, `backups/latest.dump` (dữ liệu DB tại mốc commit) |
| 2 | **Bộ backup mới nhất** | `~/soc-backup/<ngày-giờ>/` (cả thư mục, ~220 MB) | xem bảng dưới |
| 3 | **Không có gì khác** — `.git-credentials`, `.claude/.credentials.json` cố ý không mang: đăng nhập lại | | |

Nội dung một bộ backup (`~/soc-backup/backup-full.sh` tạo, `MANIFEST.md` + `SHA256SUMS` bên trong):

```
db/        soc_dev.dump                 ← dữ liệu MỚI NHẤT (Docker DB), mới hơn backups/latest.dump trong git
           globals.sql                  ← role app_rw/soc (hash mật khẩu)
           soc_dev-native-fallback.dump ← cụm native cũ, chỉ để phòng
           counts-before.txt            ← số đối chiếu lúc dump
git/       soc.bundle, worktrees.txt, branches.txt, uncommitted.tgz (file chưa commit lúc backup)
claude/    dot-claude.tgz               ← ~/.claude: mọi session (Director, Coder, Reviewer, phiên này), memory, settings, plugins
secrets/   env                          ← .env (LLM key, indexer creds, JWT_SECRET, mật khẩu DB)
           root-ca.pem                  ← CA của indexer (0400)
           etc-hosts                    ← dòng alias wazuh.indexer
           conf/inventory.yaml, identities.yaml, iocs.csv   ← file estate git-ignored
wazuh/     single-node-config.tgz, agent-compose.tgz, wazuh_etc.tgz   ← chỉ cần cho đợt 2
host/      packages.txt, pip-freeze.txt, services.txt, versions.txt, soc-logs.tgz  ← để đối chiếu, không restore
```

Chốt bộ cuối cùng **ngay trước khi rời máy** (mục 3.1), không dùng bộ của đêm trước.

---

## 2 · Chuẩn bị server mới (làm trước, không ảnh hưởng máy cũ)

Cùng **user `user1`**, cùng **home `/home/user1`**, cùng **đường dẫn `/project/project/AI_Support_SOC_1_2`** —
session Claude Code khoá theo đường dẫn tuyệt đối và transcript chứa đường dẫn tuyệt đối; khác đi là
`/resume` không thấy gì.

```bash
# Ubuntu 24.04. Docker + compose v2, user1 dùng được socket
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git make curl jq python3.12 python3-pip postgresql-client-16
sudo usermod -aG docker user1 && newgrp docker && docker ps        # phải chạy không sudo
# Claude Code CLI (cách cài như trên IA1803), rồi `claude` → đăng nhập
# Tailscale (hoặc VPN) để tới IA1803 — indexer ở đó
sudo mkdir -p /project/project && sudo chown user1:user1 /project/project
```

Trên **IA1803**: mở port indexer cho IP server mới (Tailscale): `19200/tcp` (`ss -ltn | grep 19200` đang
nghe `0.0.0.0`, chỉ cần firewall nếu có).

---

## 3 · Cutover — thứ tự bắt buộc

### 3.1 · Trên IA1803: đóng băng và chốt backup cuối

```bash
cd /project/project/AI_Support_SOC_1_2
git status --porcelain                     # commit hoặc ghi nhớ những gì còn dở; các phiên Claude phải KẾT THÚC LƯỢT
docker compose stop worker app             # tắt worker TRƯỚC — từ đây không ai ghi vào DB
set -a; . ./.env; set +a
psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at from source_cursor; select count(*) from alerts; select count(*) from llm_runs"   # ghi lại 3 số
git push --all origin && git push --tags origin
~/soc-backup/backup-full.sh                # bộ cuối, ví dụ ~/soc-backup/2026-09-2X-HHMM
cd ~/soc-backup/2026-09-2X-HHMM && sha256sum -c SHA256SUMS | grep -vc ': OK$'   # → 0
```
`db/counts-before.txt` của bộ này phải khớp 3 số vừa ghi.

### 3.2 · Chuyển bộ backup

```bash
rsync -a ~/soc-backup/2026-09-2X-HHMM/ user1@<server-mới>:/home/user1/soc-backup/2026-09-2X-HHMM/
```
Trên server mới: `cd ~/soc-backup/2026-09-2X-HHMM && sha256sum -c SHA256SUMS | grep -vc ': OK$'` → `0`.

### 3.3 · Trên server mới: repo + file riêng

```bash
B=~/soc-backup/2026-09-2X-HHMM
git clone https://github.com/Kh4nh709/AI_Support_SOC_1_2.git /project/project/AI_Support_SOC_1_2
#   (không có mạng GitHub: git clone $B/git/soc.bundle /project/project/AI_Support_SOC_1_2 && cd đó && git checkout main)
cd /project/project/AI_Support_SOC_1_2
install -m 600 $B/secrets/env .env
install -m 400 $B/secrets/root-ca.pem conf/root-ca.pem
install -m 600 $B/secrets/conf/*.{yaml,csv} conf/
tar xzf $B/git/uncommitted.tgz             # file chưa commit lúc backup (nếu có)
```

Sửa `.env` cho server mới (4 chỗ):

```
DB_PORT=5432                 # không còn cụm native chiếm 5432 → dùng port chuẩn
DATABASE_URL=postgresql://app_rw:<APP_RW_PASSWORD>@127.0.0.1:5432/soc_dev
DATABASE_URL_OWNER=postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:5432/soc_dev
TEST_DATABASE_URL=postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:5432/soc_test
INDEXER_HOST_IP=<IP Tailscale của IA1803>   # container tới indexer qua IP này; trên IA1803 để trống
```
và `/etc/hosts` của server mới: `<IP Tailscale IA1803>  wazuh.indexer` (cho psql/curl/test chạy ngoài container).

Kiểm indexer trước khi bật gì: `set -a; . ./.env; set +a; curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/_cluster/health" | head -c 200` → JSON `"status"`.

### 3.4 · Dữ liệu: dùng dump MỚI NHẤT, không phải bản trong git

`backups/latest.dump` trong git là mốc commit cuối (cũ hơn). Thay bằng dump của bộ backup **trước lần
`make up` đầu tiên** — init chỉ restore một lần, lúc volume còn trống:

```bash
cp $B/db/soc_dev.dump backups/latest.dump
make db-up                                  # tạo app_rw, restore dump, cấp default privileges
docker compose logs db | grep 'init:'       # "restored — 17 migrations recorded"
make migrate                                # "0 applied, 17 already present"
set -a; . ./.env; set +a
psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at from source_cursor; select count(*) from alerts; select count(*) from llm_runs"
```
Ba số phải **bằng đúng** `db/counts-before.txt` của bộ backup (cùng snapshot).

Lỡ `make up` trước khi copy dump: `make db-restore FILE=$B/db/soc_dev.dump` (drop + restore lại, dừng app/worker trong lúc đó).

### 3.5 · Bật dịch vụ và chứng minh

```bash
docker compose build
make up                                     # db + app + worker
sleep 90
psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at, coalesce(last_error,'') from source_cursor"   # last_pull_at tiến, last_error rỗng
psql "$DATABASE_URL" -Atc "select last_seen_at, now()-last_seen_at from source_heartbeat"                 # < 10 phút
docker compose logs --tail=5 worker         # {"job_type":"pull","outcome":"succeeded"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"khanh","password":"x"}'   # 401 = auth + JWT + DB thông
make lint && make test && make test-db      # 0 · ~1042 · ~549 (số tăng theo card)
```
Pull đầu tiên sẽ có `duplicates` = số doc trong 60 s chồng lấp và `new` = số doc phát sinh trong lúc
chuyển — không mất, không trùng (cơ chế đã chứng minh ở DEC-099 và cutover 20/09).

### 3.6 · Máy cũ: không được bật lại worker

Trên IA1803: `docker compose down` (giữ volume làm đường lùi). Nếu vẫn cần Wazuh chạy ở đó thì chỉ
Wazuh chạy — `soc` compose phải xuống. Cụm Postgres native cũng để yên (không phải worker, không hại).

---

## 4 · Khôi phục Claude Code và tiếp tục các phiên

```bash
tar xzf $B/claude/dot-claude.tgz -C /home/user1        # ~/.claude nguyên trạng, trừ credentials
claude                                                  # đăng nhập lại (OAuth), thoát
```

Phiên nào mở ở đâu (session khoá theo thư mục lúc mở):

| Phiên | Thư mục để `cd` rồi `claude` → `/resume` | Ghi chú |
|---|---|---|
| Director, Reviewer, Planner, Owner Assist, KB Drafter | `/project/project/AI_Support_SOC_1_2` | 86+ session; `/resume` liệt kê theo ngày |
| **Phiên trợ giúp này** (backup/migration) | `/project/project` | `claude --resume b6b0bb2e-5508-49cb-b2e6-d06f4ae7ce9f` |
| Coder của task đang mở | worktree `../AI_Support_SOC_1_2-<task>` | tạo lại worktree trước (dưới) |

Tạo lại worktree cho task đang chạy (danh sách trong `$B/git/worktrees.txt`):
```bash
cd /project/project/AI_Support_SOC_1_2
git worktree add ../AI_Support_SOC_1_2-P3-T11 task/P3-T11      # lặp cho từng dòng trong worktrees.txt
git worktree list                                              # Director đọc danh sách này (DEC-045)
```

Phiên Coder khôi phục xong thì gõ tiếp như bình thường (`Continue.`); Coder đã chạy `make test-db`
bằng `postgresql:///soc_<task>_test` trên máy cũ — trên máy mới không có cụm native, nó phải dùng
`TEST_DATABASE_URL=postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:5432/soc_<task>_test` (đọc từ `.env`
của checkout chính). Director biết việc này (DEC-105 ghi chú).

Câu đầu tiên dán cho Director sau khi lên máy mới:
```
Host moved to <tên server> on <ngày>: repo at the same path, docker compose up from backup <ngày-giờ> (counts matched, cursor continued), Wazuh still on IA1803 reached via INDEXER_HOST_IP. Old host's compose is down. Re-read git worktree list; record a DEC.
```
Owner Assist: `The worker now runs on <server>; re-arm the watch on container ai_support_soc_1_2-worker-1 here.`

---

## 5 · Kiểm tra cuối — 8 dòng, thiếu một là chưa xong

1. `sha256sum -c SHA256SUMS` → 0 lỗi trên server mới.
2. `git status -sb` → `## main...origin/main`, `git worktree list` đủ task đang mở.
3. `make migrate` → `0 applied, 17 already present`.
4. 3 số `source_cursor` / `alerts` / `llm_runs` = `counts-before.txt`.
5. `last_pull_at` tiến, `last_error` rỗng, heartbeat < 10 phút.
6. `POST /api/auth/login` sai mật khẩu → 401.
7. `make lint` 0 · `make test` xanh · `make test-db` xanh.
8. `claude` trong `/project/project/AI_Support_SOC_1_2` → `/resume` thấy phiên Director; trên máy cũ `docker compose ps` → không còn worker.

---

## 6 · Đường lùi

Máy cũ còn nguyên volume `ai_support_soc_1_2_pgdata` + cụm native + bộ backup. Quay lại = trên máy
mới `docker compose down`, trên IA1803 `make up`, rồi `make db-restore FILE=<dump mới nhất từ máy mới>`
nếu đã có dữ liệu phát sinh bên đó. Vẫn quy tắc một worker.

---

## 7 · Đợt 2 — dời Wazuh (chưa làm; cần DEC)

`wazuh/single-node-config.tgz` + `wazuh_etc.tgz` (rules, `client.keys`) + volume `wazuh-indexer-data`
(lớn, đang ghi — phải dừng indexer để tar) → `/opt/wazuh/wazuh-docker/single-node/` trên máy mới → đổi
`WAZUH_MANAGER_SERVER` trong 4 agent (HR-computer, DC01, kali, user1-IA1803) và enroll lại →
`INDEXER_HOST_IP` bỏ trống (về `host-gateway`) → cursor: cùng index cũ thì giữ; index mới thì
`PULL_START` + reset cursor theo thủ tục riêng. Không làm trong tuần lab.
