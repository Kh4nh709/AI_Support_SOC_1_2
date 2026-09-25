# Dựng lại lab G2 trên ATTT-M1 — 25/09 tối (root) và 26–27/09 (chạy kịch bản)

Viết bởi Director, 25/09, theo DEC-111 và DEC-112. Mọi con số dưới đây đo lúc viết; khối nào
cũng có dòng **Kỳ vọng** để anh đối chiếu trước khi sang khối sau.

**Vì sao anh chạy, không phải agent:** agent bị chặn ghi vào container và chạy lệnh root trên máy
(auto-mode "Remote Shell Writes", 25/09). Mọi bước dưới đây đổi trạng thái manager, agent, gói
hệ thống hoặc CSDL, nên đều là của anh. Chạy từ checkout chính, theo đúng thứ tự.

```bash
cd /project/project/AI_Support_SOC_1_2
```

## Hiện trạng đo 25/09 (trước khối 1)

| Mục | Giá trị |
|---|---|
| Host | Ubuntu 26.04, `ATTT-M1`, `user1` có sudo |
| Manager | `single-node-wazuh.manager-1`, 4.14.7 rc1, cổng 1514/1515 mở trên host |
| Agent | 000 manager · 001 `Windows_Endpoint` Disconnected · 003 `pfSense.home.arpa` Disconnected |
| Agent Linux | **không có** |
| `local_rules.xml` trong manager | bản mẫu, md5 `11bdb298…` — bản đúng trong repo là `afd2ef60…` |
| authd | bật, `use_password=no` — enroll không cần mật khẩu |
| wazuh-agent, clamav, auditd trên host | **chưa cài** |
| `soc_dev` | 100.826 alert · 4 user · 6 asset · 17 migration |

## Khối 1 — nạp rule vào manager (không cần sudo, `user1` thuộc nhóm docker)

```bash
docker cp conf/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 md5sum /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1
```

**Kỳ vọng:** md5 `afd2ef60d7d3418cbdc27c493ad9eccf`. Manager lên lại sau khoảng một phút.

## Khối 2 — cài và enroll agent Linux trên chính ATTT-M1

Tên agent: **`attt-m1-lab`**. Tên này phải khớp đúng ở khối 5 và khi gắn cửa sổ.
Phiên bản agent **không được cao hơn** manager (4.14.7), nên xem danh sách trước khi cài.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
apt-cache madison wazuh-agent | head
```

Chọn phiên bản cao nhất **≤ 4.14.7** trong danh sách vừa in, thay vào `<VER>`:

```bash
sudo WAZUH_MANAGER='127.0.0.1' WAZUH_AGENT_NAME='attt-m1-lab' apt-get install -y wazuh-agent=<VER>
sudo apt-mark hold wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

**Kỳ vọng:** có dòng `Name: attt-m1-lab, ... Active`. `apt-mark hold` giữ agent khỏi bị nâng
vượt phiên bản manager.

## Khối 3 — ClamAV, auditd, và cho agent đọc log của chúng

```bash
sudo apt-get install -y clamav clamav-daemon auditd
sudo systemctl enable --now clamav-freshclam auditd
printf '%s\n' '-a always,exit -F arch=b64 -S execve -k exec' \
              '-a always,exit -F arch=b32 -S execve -k exec' \
  | sudo tee /etc/audit/rules.d/soc-exec.rules
sudo augenrules --load
sudo auditctl -l | grep -c execve
```

**Kỳ vọng:** dòng cuối in `2`. Đợi freshclam tải xong cơ sở dữ liệu rồi mới bật daemon:

```bash
sudo systemctl enable --now clamav-daemon
systemctl is-active clamav-daemon auditd clamav-freshclam
```

Thêm hai nguồn log cho agent. Wazuh chấp nhận nhiều khối `<ossec_config>` trong một tệp:

```bash
sudo tee -a /var/ossec/etc/ossec.conf >/dev/null <<'XML'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/clamav/clamav.log</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
XML
sudo systemctl restart wazuh-agent
sudo grep -E 'clamav.log|audit.log' /var/ossec/logs/ossec.log | tail -4
```

**Kỳ vọng:** ba dòng `active`, và log agent có dòng `Analyzing file` cho cả hai tệp.

## Khối 4 — kiểm heartbeat và rule từ indexer (chỉ đọc)

Host không tới được indexer theo tên (DEC-106), nên hỏi qua container worker:

```bash
docker compose exec -T worker python3 - <<'PY'
import os, httpx
u = os.environ["INDEXER_URL"].rstrip("/")
idx = os.environ.get("INDEXER_INDEX", "wazuh-alerts-*")
c = httpx.Client(verify=os.environ["INDEXER_CA"],
                 auth=(os.environ["INDEXER_USER"], os.environ["INDEXER_PASSWORD"]))
for r in ["100999", "100301", "100302", "100303"]:
    n = c.post(f"{u}/{idx}/_count", json={"query": {"term": {"rule.id": r}}}).json().get("count")
    print(r, n)
n = c.post(f"{u}/{idx}/_count",
           json={"query": {"term": {"agent.name": "attt-m1-lab"}}}).json().get("count")
print("attt-m1-lab", n)
PY
```

**Kỳ vọng:** mười phút sau khối 1, `100999` lớn hơn 0 vì wodle chạy mỗi 600 giây. Ba rule
`1003xx` vẫn bằng 0 cho tới khi có kịch bản. `attt-m1-lab` lớn hơn 0.

## Khối 5 — reset CSDL (xoá corpus cũ, giữ bản sao)

Đây là bước phá huỷ duy nhất. Bản sao nằm **ngoài repo**. Không dùng `make backup`, vì lệnh đó
ghi đè `backups/latest.dump`, tệp đang lộ trên remote công khai. Không dùng `make db-restore`,
vì lệnh đó nạp lại chính các alert cũ. `make` không đọc `.env`, nên migrate gọi thẳng script.

```bash
DSN="$(sed -n 's/^[[:space:]]*DATABASE_URL_OWNER[[:space:]]*=[[:space:]]*//p' .env | sed 's/[[:space:]][[:space:]]*#.*$//' | tail -1)"
mkdir -p /home/user1/soc-backups-keep
pg_dump --format=custom --file=/home/user1/soc-backups-keep/pre-reset-2026-09-25.dump "$DSN"
ls -l /home/user1/soc-backups-keep/pre-reset-2026-09-25.dump
git tag pre-lab-reset

docker compose stop app worker
psql "${DSN%/*}/postgres" -v ON_ERROR_STOP=1 \
  -c 'drop database if exists soc_dev with (force)' -c 'create database soc_dev'
MIGRATIONS_DIR=docs/Schema bash scripts/migrate.sh "$DSN"
```

**Kỳ vọng:** tệp dump khoảng 30 MB. `migrate` in `recorded 17 base migrations` rồi `0 applied, 17 already present`, vì `schema.sql` đã gồm cả 17 migration.

Chỉ nạp alert từ lúc lab bắt đầu. `PULL_START` chỉ nhận ngày, tính từ 00:00 UTC, tức 07:00
giờ Việt Nam ngày 26/09. Nếu để nguyên `2026-08-01`, CSDL mới sẽ kéo lại toàn bộ nền từ 22/09.

```bash
sed -i 's/^PULL_START=.*/PULL_START=2026-09-26/' .env
grep '^PULL_START' .env
```

Tạo lại bốn tài khoản. **Đặt mật khẩu mới**, không dùng lại mật khẩu cũ, vì hash cũ đã nằm trong
dump công khai. Gõ từng mật khẩu ở dấu nhắc:

```bash
PYTHONPATH=backend .venv/bin/python -m app.infra.auth seed-users --env-file .env \
  --user khanh tier1 "Nguyễn Chí Khanh" \
  --user nguyen tier2 "Mai Nam Nguyên" \
  --user khanh-admin admin "Nguyễn Chí Khanh" \
  --user nguyen-admin admin "Mai Nam Nguyên"
```

Thêm agent mới vào kiểm kê rồi nạp:

```bash
cat >> conf/inventory.yaml <<'YAML'

  - hostname: attt-m1-lab         # agent enrolled 25/09 on ATTT-M1 — the G2 lab workstation (DEC-111)
    criticality: medium           # medium so auto-close has somewhere to fire, as user1-IA1803 was
    owner: "Thesis author"
    role: "Linux lab workstation — G2 attack and benign scenarios"
YAML
PYTHONPATH=backend .venv/bin/python -c "from app.infra.db import connect; from app.enrichment.inventory import load; c = connect(); print(load(c)); c.commit()"

make run-worker
make run-app
psql "$DSN" -tAc "select (select count(*) from alerts),(select count(*) from users),(select count(*) from assets),(select count(*) from schema_migrations)"
```

**Kỳ vọng:** `0|4|7|17`. Alert bằng 0 cho tới 07:00 ngày 26/09.

## Báo lại cho Director

Dán nguyên phần in ra của **khối 2** (dòng `agent_control`), **khối 4**, và dòng cuối **khối 5**.
Director ghi gate row từ đó và mở ngày lab.

## 26–27/09 — chạy kịch bản

Kịch bản nằm ở `docs/lab-scenarios.md` §3, tám category. Chạy tất cả **trên ATTT-M1**. Chỗ nào
runbook ghi `user1-IA1803` thì hiểu là `attt-m1-lab`.

Mỗi kịch bản, ghi giờ UTC ngay trước và ngay sau, tới từng giây:

```bash
date -u +%FT%TZ    # trước khi chạy
# ... chạy kịch bản theo §3 ...
date -u +%FT%TZ    # sau khi alert cuối xuất hiện
```

Gửi Director bốn thứ cho mỗi kịch bản: `scenario_id` (tối đa 16 ký tự, ví dụ `S03`), category,
`attack` hay `benign`, và hai mốc giờ. Director chạy `eval/lab_tag.py` cho từng cửa sổ với agent
`attt-m1-lab`. Anh không gắn nhãn tay.

**Để có khoảng 100 cụm trong hai ngày:** xen kẽ các category, vì rule khác nhau không chung khoá
cụm. Đặt benign twin ngay sau mỗi kịch bản tấn công. Đổi `srcip` giữa các lần chạy cùng category,
vì cụm gom theo `rule_id|srcip|dstip|agent_name`.

## Việc code duy nhất trên đường găng

`eval/build_gold.py:1063` bắt buộc `--archive-file`. Không có kho lưu trữ G1 trên ATTT-M1, nên
`--g2` chạy một mình sẽ dừng. Card P6-T07 sửa chỗ này, và phải merge **trước tối 27/09**, lúc
dựng tập vàng.
