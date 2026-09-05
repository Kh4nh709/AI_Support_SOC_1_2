# Phase 1 — Tiếp nhận và chuẩn hóa

`ingest/wazuh_parser.py` · `ingest/category.py` · `domain/alert.py`

> **Trạng thái:** 5 điểm treo (C1–C5) đã chốt. Xem mục *Quyết định đã chốt* ở cuối.

---

## Mục tiêu

Nhận alert từ SIEM và biến envelope thô của nhà cung cấp thành **một đối tượng `Alert` nội bộ tất định**, đủ thông tin để mọi bước phía sau chạy được mà không cần đọc lại payload gốc.

Cụ thể, phase này phải đạt bốn mục tiêu con:

1. **Cách ly hình dạng nhà cung cấp.** Đây là nơi duy nhất trong toàn hệ thống biết cấu trúc JSON của Wazuh. Thêm nguồn EDR hay firewall sau này chỉ cần thêm một file parser, không đụng tới bất kỳ tầng nào khác.
2. **Phân giải `category`** — câu trả lời quyết định mọi thứ phía sau, vì category là khóa tra playbook ở `kb/`.
3. **Tính `event_bucket_hash`** — băm định danh sự việc trong ô 5 phút, dùng cho đối chiếu và audit.
4. **Không bao giờ làm mất alert.** Không hàm nào trong đường phân loại được `raise`; bí thì trả `unknown`. Payload hỏng thì ghi `rejected_alerts` chứ không im lặng biến mất.

---

## Ranh giới

| Làm | Không làm |
|---|---|
| Ánh xạ trường Wazuh → Alert | Ghi database (bước sau) |
| Ép kiểu an toàn, chuẩn hóa múi giờ | Tra bản sao (bước `◆ Dedup?`) |
| Quy đổi severity | Làm giàu ngữ cảnh (`soar/` gọi n8n) |
| Phân giải category qua 5 tầng | Tính correlation (`domain/`) |
| Tính `event_bucket_hash` | Gọi model (`llm/`) |
| Gắn cờ IP nội bộ, cắt `raw_log` quá khổ | Quyết định bỏ qua lookup (việc của `soar/`) |

**Tính chất kỹ thuật:** chạy đồng bộ trong request webhook, là **hàm thuần** — không I/O, không đọc đồng hồ hệ thống, không chạm DB. Thời gian chạy tính bằng micro giây. Hệ quả: test được toàn bộ phase này mà không cần dựng database.

Đây cũng là lý do phase này nằm **ngoài advisory lock**: phần bị tuần tự hóa ở bước dedup chỉ còn một câu `SELECT` và một, hai câu ghi.

---

## Mô tả chi tiết

Phase gồm bảy khối xử lý chạy tuần tự. Khối sau chỉ dùng kết quả của khối trước, không có vòng lặp ngược.

### Khối 1 — Ánh xạ trường

Nhận cả hai dạng payload: **có `_source`** (đẩy từ OpenSearch) và **không có `_source`** (đọc trực tiếp từ `alerts.json`). Parser dò sự tồn tại của khóa `_source` rồi mới bóc, chứ không giả định.

**Trường bắt buộc** — thiếu bất kỳ cái nào → `400` + một dòng `rejected_alerts`:

| Đích | Nguồn |
|---|---|
| `alert_id` | `_source.id` |
| `rule_id` | `_source.rule.id` |
| `description` | `_source.rule.description` |
| `agent_name` | `_source.agent.name` |
| `alert_time` | `_source.timestamp` |

**Trường tùy chọn** — thiếu thì để giá trị mặc định, tuyệt đối không lỗi:

| Đích | Nguồn | Mặc định khi thiếu |
|---|---|---|
| `srcip` / `dstip` | `_source.data.srcip` / `.dstip` | `''` (B1) |
| `src_port` / `dst_port` | `_source.data.srcport` / `.dstport` | `0` |
| `alert_user` | `_source.data.dstuser` ưu tiên, fallback `.srcuser` | `NULL` |
| `agent_id` / `agent_ip` | `_source.agent.id` / `.ip` | `NULL` |
| `raw_log` | `_source.full_log` | `''` |
| `rule_level` → `severity` | `_source.rule.level` | `low` |
| `mitre_ids[]` | `_source.rule.mitre.id[]` | `[]` |
| `rule_groups[]` | `_source.rule.groups[]` | `[]` |
| `decoder` | `_source.decoder.name`, fallback `.parent` | `NULL` |
| `event_time` | `_source.predecoder.timestamp` | `NULL` |

**Mọi trường không có trong bảng trên đều không bị vứt** — chúng nằm nguyên trong `raw_payload` (jsonb). Bao gồm: `manager`, `input.type`, `location`, `predecoder.program_name`, các mảng tuân thủ (`pci_dss`, `hipaa`, `tsc`, `nist_800_53`, `gdpr`, `gpg13`), `rule.frequency`, `rule.firedtimes`, `rule.mail`, `rule.mitre.technique[]`, `rule.mitre.tactic[]`, và cả `_id` / `_index` / `sort` của OpenSearch.

#### `alert_id` bắt buộc, không sinh thay — B5

Cờ `id_synthesized` **đã bị bỏ**. Lý do: `alert_id` nằm trong danh sách bắt buộc (thiếu → `400`), nên cờ không bao giờ có thể bằng `True` — nó là cờ chết.

Không hạ `alert_id` xuống trường tùy chọn, vì nó là `PRIMARY KEY` và là **cơ chế chống gửi lặp duy nhất**. Sinh ID thay cho alert không có ID nghĩa là mất tính idempotent: Wazuh gửi lại cùng một alert sẽ tạo hai dòng.

**`is_synthetic` thì ngược lại — có consumer nhưng thiếu định nghĩa**, nên phải bổ sung chứ không bỏ. Ba truy vấn đo lường đang dùng `WHERE NOT is_synthetic`.

> **Định nghĩa:** `is_synthetic = true` cho alert bơm vào từ script sinh dữ liệu thử nghiệm hoặc demo, để loại khỏi mọi số liệu báo cáo. Endpoint nạp dữ liệu thử đặt cờ này; **webhook Wazuh luôn đặt `false`**, không có đường nào để payload bên ngoài tự đặt `true`.

> **Vì sao `alert_id` lấy `_source.id` chứ không phải `_id`:** `_source.id` là id do Wazuh manager sinh; `_id` là id document của OpenSearch và **có thể đổi nếu alert được index lại**. Tính idempotent của webhook phụ thuộc vào khóa này, nên phải lấy cái ổn định. `_id` vẫn được giữ trong `raw_payload` để đối chiếu khi cần.

### Khối 2 — Ép kiểu an toàn

Wazuh gửi port dưới dạng **chuỗi**, và giá trị có thể là `"unknown"`, chuỗi rỗng, hoặc chuỗi có khoảng trắng thừa.

```python
def _safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default
```

**Chốt C2:** cổng thiếu hoặc không đọc được → **`0`**, áp dụng thống nhất cho cả `src_port` và `dst_port`. Kiểu cột là `INT NOT NULL DEFAULT 0`, không phải `int | None`.

**Chốt B1 — cùng nguyên tắc, áp cho IP.** `srcip` và `dstip` thiếu → **`''`**, không phải `NULL`. Cột là `TEXT NOT NULL DEFAULT ''`.

Đây là cùng một vấn đề với C2: `NULL` gánh hai ý nghĩa ("chưa biết" và "không có") và làm hỏng phép so sánh. Nhưng khác C2 ở chỗ hậu quả **đã đo được**, không phải suy đoán:

| Truy vấn dedup ở Phase 2 | Buffers | Sort? | Thời gian |
|---|---|---|---|
| `srcip IS NOT DISTINCT FROM $2` (khi `srcip` có giá trị) | 154 | Có | 0,820 ms |
| `srcip = $2` (sau B1) | **4** | Không | **0,030 ms** |

*(PostgreSQL 16.15, bảng 500.000 dòng, `EXPLAIN ANALYZE BUFFERS`)*

`IS NOT DISTINCT FROM` là vị từ **không dùng được index** — nó rơi xuống `Filter`. Với `''` thì dùng `=` thuần, cả bốn cột khóa cụm vào được `Index Cond`.

**Lý do quyết định cuối cùng không phải hiệu năng mà là khả năng cưỡng chế:** với `''`, DB tự chặn bằng `NOT NULL`; với `NULL` thì mọi truy vấn phải nhớ gọi `coalesce()`, và quên là lỗi **im lặng** — vẫn chạy đúng, chỉ mất index.

> **`event_bucket_hash` không đổi giá trị.** Quy ước ráp chuỗi ở Khối 6 vốn đã ghi *"trường `NULL` → chuỗi rỗng"*, nên chuỗi đầu vào giống hệt trước và sau B1. Giá trị `76fcfceb…` giữ nguyên.

Sự thật gốc vẫn nằm trong `raw_payload` nếu cần phân biệt "Wazuh không gửi trường này" với "Wazuh gửi chuỗi rỗng".

Quy tắc: **cổng không đọc được là chuyện thường, không phải lý do để mất alert.** Cách viết `int(data["srcport"]) if data.get("srcport") else 0` là sai vì `ValueError` nằm ngoài khối bắt lỗi validate → thành HTTP `500` thay vì `400`. Phải dùng `_safe_int`.

> **Đánh đổi đã chấp nhận:** `0` không phân biệt được "không có dữ liệu" với "cổng 0" (cổng 0 hầu như không xuất hiện trong lưu lượng thật, nên rủi ro thấp). Đổi lại, fingerprint và mọi truy vấn thống kê không phải xử lý `NULL`.

### Khối 3 — Chuẩn hóa thời gian

Hai mốc thời gian tách bạch, phục vụ hai mục đích khác nhau:

| Trường | Nguồn | Ý nghĩa | Dùng cho |
|---|---|---|---|
| `alert_time` | `_source.timestamp` | Giờ Wazuh **phát hiện** | SLA, correlation, `event_bucket_hash` |
| `event_time` | `_source.predecoder.timestamp` | Giờ trong **dòng log gốc** | Dựng timeline ở Tier 2 |

**Cạm bẫy `alert_time`:** Wazuh gửi offset **không có dấu hai chấm** (`+0700`). `datetime.fromisoformat` chỉ chấp nhận dạng này từ Python 3.11 trở lên. Phải chuẩn hóa `+0700` → `+07:00` **trước khi** parse. Nếu vẫn không parse được thì báo lỗi validate rõ ràng — **không** lặng lẽ thay bằng `now()`, vì đó là lệch giờ âm thầm và mọi phép đo SLA sai theo.

> `alert_time` là đầu vào của `event_bucket_hash`, và là mốc SLA. Parse sai giờ làm lệch mọi phép đo thời gian triage. Test parse timestamp ở mức bắt buộc tuyệt đối.
>
> *(Sau Đề xuất 1, `alert_time` **không còn** ảnh hưởng tới việc gộp cụm — khóa cụm là 4 cột định danh, cửa sổ dùng `last_seen_at` do DB sinh.)*

**Cạm bẫy `event_time`:** `predecoder.timestamp` dạng `"Aug 16 17:56:55"` — **không có năm, không có múi giờ**. Quy tắc suy ra:
- Năm: lấy năm của `alert_time`; nếu tháng/ngày của `event_time` lớn hơn `alert_time` quá 1 ngày thì trừ 1 năm (xử lý ca giao thừa 31/12 → 01/01).
- Múi giờ: coi là giờ local của agent, quy đổi bằng hằng số `DISPLAY_TZ` trong config.
- Parse thất bại → `event_time = NULL`, **không** chặn alert.

**Quy tắc chung:** DB luôn lưu `timestamptz` **UTC**; quy đổi múi giờ chỉ ở tầng hiển thị và ở các truy vấn gom nhóm theo ngày (`AT TIME ZONE 'Asia/Ho_Chi_Minh'`).

### Khối 4 — Quy đổi severity

```
rule.level >= 12  →  critical
rule.level >=  8  →  high
rule.level >=  5  →  medium
còn lại           →  low
```

Đây là severity **của SIEM**. Pipeline ① sẽ đánh giá lại độc lập ở bước sau — giữ cả hai để so, đó là một số liệu cho báo cáo.

### Khối 5 — Phân giải category (thang 5 tầng, có độ ưu tiên)

Hỏi lần lượt theo tầng; tầng nào có ít nhất một tín hiệu khớp thì dừng ở tầng đó. Ghi lại tầng đã quyết vào `resolved_by`.

| Tầng | Tín hiệu | Ví dụ | Độ tin cậy |
|---|---|---|---|
| 1 | MITRE technique | `T1110` → `ssh_brute_force` | Cao nhất |
| 2 | MITRE technique cha | `T1543.003` không có → thử `T1543` | Cao |
| 3 | `rule.groups` | `authentication_failed` → `ssh_brute_force` | Tốt nhất cho rule không có khối mitre |
| 4 | `decoder` | `sshd` → `ssh_brute_force`, `apache` → `web_attack` | Trung bình |
| 5 | Cổng đích | `22` → ssh, `3389` → rdp | Yếu nhất |

**Chốt C5 — trong một tầng, KHÔNG phải "khớp đầu tiên thắng".** Một alert có thể mang nhiều tín hiệu cùng khớp (mẫu thật có cả `T1078` lẫn `T1110`, **cả hai đều nằm trong bảng ánh xạ**). Thuật toán bắt buộc:

```
1. Thu THẤT CẢ tín hiệu khớp trong tầng hiện tại  → tập candidates
2. Sắp candidates theo BẢNG ĐỘ ƯU TIÊN (không theo thứ tự mảng SIEM gửi)
3. category   = candidates[0]
   categories = toàn bộ candidates đã sắp
```

**Bảng độ ưu tiên category** (cao → thấp), khai báo tường minh trong code:

```
ransomware > malware > c2_beacon > data_exfiltration
  > privilege_escalation > ssh_brute_force > web_attack
  > suspicious_login > recon > policy_violation > unknown
```

Áp lên mẫu thật: `T1110` → `ssh_brute_force`, `T1078` → `suspicious_login`. `ssh_brute_force` đứng trên `suspicious_login` → **`category = "ssh_brute_force"`**, `categories = ["ssh_brute_force", "suspicious_login"]`. Đúng kỳ vọng, và **không phụ thuộc thứ tự** `["T1078","T1110"]` hay `["T1110","T1078"]`.

**Ba ràng buộc bắt buộc:**

1. **Một hàm phân giải duy nhất** nhận đủ 4 tín hiệu `(mitre_ids, groups, decoder, dst_port)`, gọi từ cả đường ingest lẫn đường RAG. Bản cũ truyền `decoder=""` và `port=0` ở đường ingest nên tầng 4–5 không bao giờ chạy, dẫn tới hai đường cho hai kết quả khác nhau trên cùng một alert.
2. **Độ ưu tiên tường minh** như bảng trên, áp cho mọi tầng — không riêng tầng 1.
3. **Mọi category ánh xạ tới đều phải có playbook thật.** Bảng ánh xạ nằm trong code, kèm `mapping_version` để biết alert nào cần phân loại lại khi bảng đổi.

#### Vai trò của `category` và `categories` — không chia sẻ

| Trường | Vai trò | Được dùng cho | **Không** được dùng cho |
|---|---|---|---|
| `category` | Khóa chính | Tra playbook (`kb/`), đo lường (II‑08), hiển thị, thống kê | — |
| `categories` | Ngữ cảnh | Chèn vào prompt ① dạng *"tín hiệu phụ phát hiện được"* | Tra playbook, đo lường |

`kb/` và ba câu SQL đo lường vốn đã dùng `category` đơn, nên gán cho `categories` một vai trò **không chạm vào chúng** nghĩa là chúng không phải sửa gì. Phép đo độ khớp so trên `category` chính — một con số, một định nghĩa, không nhập nhằng trong báo cáo.

**Không phân giải được:** trả `category='unknown'`, `resolved_by='none'`, **vẫn cho alert chạy tiếp bình thường**. Prompt của pipeline ① sẽ chèn câu "không tìm được playbook khớp, chỉ suy luận từ dữ liệu alert". Tỉ lệ `unknown` được đếm như một chỉ số sức khỏe: tăng nghĩa là bảng ánh xạ đã lạc hậu so với rule set.

### Khối 6 — Tính `event_bucket_hash`

> **Đổi tên (B6):** cột này trước gọi là `fingerprint`. Tên cũ gợi ý nó là khóa cụm — nó **không phải**. Tên mới nói đúng bản chất: băm của một **sự việc** trong một **ô thời gian**. Công thức và giá trị không đổi.

**Chốt C1 — thống nhất theo công thức Phần VI. Phần III sửa lại cho khớp.**

```
bucket            = floor(epoch_seconds(alert_time_utc) / 300)      # ô 5 phút
event_bucket_hash = sha256("{rule_id}|{srcip}|{dstip}|{agent_name}|{bucket}")
```

**Qua ba thay đổi so với bản Phần III cũ:**

| | Cũ (Phần III) | **Chốt** |
|---|---|---|
| `alert_user` | có trong công thức | **bỏ** |
| Thời gian | không băm | **băm bucket 5 phút** |
| Biểu diễn bucket | — | **số nguyên** `floor(epoch/300)` |

**Vì sao bucket là số nguyên, không phải chuỗi ISO:** chuỗi ISO phụ thuộc cách format (`+00:00` hay `Z`, có hay không phần micro giây) — đổi thư viện là đổi giá trị băm. Số nguyên không có chỗ cho nhập nhằng. Trên cùng một alert, hai cách cho hai giá trị khác nhau:

```
[số nguyên] 40112|127.0.0.1||user1-IA1803|5956343
            → 76fcfceb90ed06f6be274be022445ff693254b73edbdb70180244328119b2a1a   ← CHỐT
[ISO]       40112|127.0.0.1||user1-IA1803|2026-08-16T17:55:00+00:00
            → f1406acb65c3b5e567200e816d47eb11050a899783780046e0cbd16920912276
```

**Quy ước ráp chuỗi:** trường `NULL` → chuỗi rỗng (`dstip` của mẫu này ra `||`); dấu phân cách là `|`; không trim, không lowercase; bucket tính trên `alert_time` **đã quy về UTC**.

#### ⚠️ Vai trò của `event_bucket_hash` — đọc kỹ trước khi dùng

> **Đây KHÔNG phải khóa cụm.** Nó là **băm định danh sự việc trong một ô 5 phút**, dùng cho đối chiếu và audit.

Nguyên bản C1 dự định dùng cột này làm khóa dedup. Cách đó gây bốn hậu quả (đợt tấn công dài vỡ thành nhiều cụm; hiệu ứng biên ở mốc 5 phút; cửa sổ trượt mất tác dụng; cụm gộp nhiều tài khoản). **Phase 2 đã chuyển khóa cụm sang 4 cột trực tiếp** (`rule_id`, `srcip`, `dstip`, `agent_name`), giải quyết cả bốn.

Hệ quả cho Phase 1: **không đổi một dòng logic nào.** Công thức và giá trị `76fcfceb…` giữ nguyên; chỉ **tên** và **vai trò** của cột đổi:

| | Dùng cho | **Không** dùng cho |
|---|---|---|
| `event_bucket_hash` | Đối chiếu, audit, phát hiện gửi lặp trong ô 5 phút | Khóa dedup, khóa advisory lock, **đếm số cụm** |

**Luật bắt buộc cho mọi truy vấn đo lường:**

```sql
-- ĐÚNG · cụm = dòng có duplicate_of IS NULL
SELECT count(*) FROM alerts
WHERE duplicate_of IS NULL AND status <> 'duplicate' AND NOT is_synthetic;

-- SAI · đếm theo ô 5 phút, cho số cao gấp nhiều lần thực tế
SELECT count(DISTINCT event_bucket_hash) FROM alerts;
```

Chi tiết khóa cụm, cửa sổ trượt và ba trần kích thước: xem **Phase 2 · Nhóm 1**.

### Khối 7 — Cờ suy ra (derived flags)

Ba cờ tính thuần túy từ dữ liệu đã có, không I/O — để tầng sau khỏi phải đoán.

**Chốt C4 — cờ IP nội bộ.** Dùng thư viện chuẩn `ipaddress`, không tự viết regex:

```python
def _is_private(ip: str) -> bool | None:
    if not ip:                            # B1: '' thay cho NULL — vẫn rơi vào đây
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None                       # không parse được → không khẳng định
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
```

Sinh ra `srcip_is_private` và `dstip_is_private`. Phạm vi bao phủ: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`), ULA IPv6 (`fc00::/7`).

Trên mẫu thật: `srcip_is_private = True` (127.0.0.1), `dstip_is_private = None` (không có `dstip`).

**Ba tầng sau dùng cờ này:**
- `soar/` bỏ qua lookup VirusTotal/MISP khi `is_private = True` — tiết kiệm hạn ngạch, tránh kết quả vô nghĩa.
- `llm/` chèn ghi chú "IP nguồn là địa chỉ nội bộ" vào ngữ cảnh prompt ①.
- `ingest/` (bước auto-close) **không** được dùng cờ này làm lý do đóng — xem cảnh báo dưới.

> ⚠️ **`is_private = True` không có nghĩa là an toàn.** Mẫu thật là brute-force **thành công** từ `127.0.0.1`: kẻ tấn công đã ở trên chính máy đó, hoặc đi qua SSH tunnel / port forward. Đây nghiêm trọng **hơn** brute-force từ ngoài. Rule auto-close tuyệt đối không được đóng ca này — may là đã có lớp bảo vệ sẵn: cấm auto-close alert `severity=critical` bất kể rule nói gì.

**Cờ này mô tả thuộc tính địa chỉ, KHÔNG phải kết luận an ninh.** Để tầng sau không đọc nhầm, `soar/` ghi kết quả mỗi lookup dưới **ba trạng thái**, không phải hai:

```
found      → đã tra, có kết quả
not_found  → đã tra, không có kết quả   ← tín hiệu an ninh
skipped    → KHÔNG tra (vì IP nội bộ)   ← KHÔNG phải tín hiệu an ninh
```

Hai luật cứng: `risk_score` **không được trừ điểm** cho `skipped`; prompt ① ghi *"chưa tra IoC vì địa chỉ nội bộ"*, không ghi *"không tìm thấy IoC"*.

**Ngoại lệ NAT / reverse proxy.** Sau NAT, `srcip` là IP nội bộ của load balancer trong khi kẻ tấn công ở ngoài Internet — cờ báo `True` nhưng bản chất là tấn công từ ngoài. Danh sách config chặn ca này:

```python
NAT_AGENTS = []   # ví dụ ["lb-01", "proxy-01"]
```

Agent nằm trong danh sách thì cờ private **không** được dùng làm lý do `skipped`. Danh sách rỗng thì hành vi y như hiện tại — Phase 1 không đổi gì.

**Chốt C3 — cắt `raw_log` quá khổ.**

```
RAW_LOG_MAX_BYTES = 1_024_000        # 1000 KB
```

Quy tắc: nếu `len(raw_log.encode('utf-8')) > RAW_LOG_MAX_BYTES` thì cắt `raw_log` đúng ngưỡng (cắt theo **byte**, lùi về ranh giới ký tự UTF-8 hợp lệ gần nhất để không tạo chuỗi hỏng) và bật `raw_log_truncated = True`. **`raw_payload` giữ nguyên vẹn, không cắt** — bản đầy đủ luôn truy được ở đó.

Trên mẫu thật: `raw_log` dài 101 byte → `raw_log_truncated = False`.

**Ba ngưỡng, ba vai trò, cắt ở ba nơi khác nhau:**

```python
MAX_PAYLOAD_BYTES    = 2_097_152   # 2 MB    · chặn ở bước 413      → infra/
RAW_LOG_MAX_BYTES    = 1_024_000   # 1000 KB · lưu trữ (C3)         → ingest/  ← khối này
PROMPT_LOG_MAX_BYTES = 4_096       # 4 KB    · đưa vào prompt       → llm/

assert MAX_PAYLOAD_BYTES > RAW_LOG_MAX_BYTES   # kiểm tra lúc khởi động
```

`assert` biến ràng buộc "ngưỡng `413` phải lớn hơn ngưỡng lưu trữ" thành thứ máy tự kiểm — nếu ngược lại thì nhánh cắt `raw_log` là code chết, và giờ ứng dụng sẽ không khởi động được thay vì âm thầm sai.

> **Việc cắt cho prompt xảy ra ở `llm/`, không phải ở đây.** Phase 1 luôn lưu bản đầy đủ tới 1000 KB; `llm/` tự cắt xuống 4 KB lúc dựng prompt. Một trường, hai vai trò, hai ngưỡng — không trộn lẫn. Dấu hiệu "đã cắt" phải nằm **trong** lớp bọc dữ liệu không tin cậy của `security/`, nếu không một `full_log` dựng có chủ đích có thể tự chèn chuỗi giả để đánh lừa model về độ dài thật.

**Dòng nặng ~2 MB (`raw_log` + `raw_payload`):** không cần đổi ngưỡng. Postgres đẩy hai cột này ra ngoài dòng (TOAST) và nén; chi phí chỉ phát sinh khi thực sự đọc chúng. Quy ước bắt buộc: **cấm `SELECT *` trên `alerts` trong mọi truy vấn danh sách** — liệt kê cột tường minh.

Với dòng log Wazuh thông thường (vài trăm byte), ngưỡng 1000 KB là **van an toàn chống ca bệnh lý**, không phải cơ chế cắt thường xuyên.

---

## Dữ liệu đầu vào

```json
{
  "_index": "wazuh-alerts-4.x-2026.08.16",
  "_id": "-pe4C6ABLQcppv5YO4pl",
  "_version": 1,
  "_score": null,
  "_source": {
    "predecoder": {
      "hostname": "user1-IA1803",
      "program_name": "sshd",
      "timestamp": "Aug 16 17:56:55"
    },
    "input": { "type": "log" },
    "agent": { "ip": "79.79.79.12", "name": "user1-IA1803", "id": "001" },
    "manager": { "name": "IA1803" },
    "data": { "srcip": "127.0.0.1", "dstuser": "user1", "srcport": "48104" },
    "rule": {
      "mail": true,
      "level": 12,
      "pci_dss": ["10.2.4", "10.2.5", "11.4"],
      "hipaa": ["164.312.b"],
      "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"],
      "description": "Multiple authentication failures followed by a success.",
      "groups": ["syslog", "attacks"],
      "nist_800_53": ["AU.14", "AC.7", "SI.4"],
      "frequency": 2,
      "gdpr": ["IV_35.7.d", "IV_32.2"],
      "firedtimes": 1,
      "mitre": {
        "technique": ["Valid Accounts", "Brute Force"],
        "id": ["T1078", "T1110"],
        "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation",
                   "Initial Access", "Credential Access"]
      },
      "id": "40112",
      "gpg13": ["7.1", "7.8"]
    },
    "location": "journald",
    "decoder": { "parent": "sshd", "name": "sshd" },
    "id": "1786903016.121311",
    "full_log": "Aug 16 17:56:55 user1-IA1803 sshd[136570]: Accepted password for user1 from 127.0.0.1 port 48104 ssh2",
    "timestamp": "2026-08-17T00:56:56.130+0700"
  },
  "fields": { "timestamp": ["2026-08-16T17:56:56.130Z"] },
  "sort": [1786903016130]
}
```

---

## Vết xử lý trên mẫu này

| Khối | Đầu vào | Kết quả | Ghi chú |
|---|---|---|---|
| 1 Ánh xạ | `_source.id` | `alert_id = "1786903016.121311"` | Không lấy `_id` |
| 2 Ép kiểu | `srcport = "48104"` | `src_port = 48104` | Chuỗi số sạch |
| 2 Ép kiểu | `dstport` không có | `dst_port = 0` | **C2** — mặc định `0`, không `NULL` |
| 2 Ép kiểu | `dstip` không có | `dstip = ''` | **B1** — mặc định `''`, không `NULL` |
| 3 Thời gian | `"2026-08-17T00:56:56.130+0700"` | `2026-08-16T17:56:56.130Z` | Offset không dấu `:` — chuẩn hóa trước khi parse |
| 3 Thời gian | `"Aug 16 17:56:55"` | `2026-08-16T17:56:55Z` | Suy năm từ `alert_time`; lệch 1s |
| 4 Severity | `rule.level = 12` | `critical` | `12 >= 12` |
| 5 Category | `mitre_ids = [T1078, T1110]` | `ssh_brute_force` | **C5** — cả hai khớp; T1110 ưu tiên cao hơn T1078 |
| 5 Category | — | `categories = [ssh_brute_force, suspicious_login]` | Sắp theo độ ưu tiên, không theo thứ tự mảng |
| 6 Băm | `alert_time` → bucket | `5956343` | `floor(1786... / 300)`, ô `17:55:00–17:59:59 UTC` |
| 6 Băm | `40112\|127.0.0.1\|\|user1-IA1803\|5956343` | `76fcfceb90ed06f6…` | **C1** — chuỗi không đổi sau B1 |
| 7 Cờ | `srcip = "127.0.0.1"` | `srcip_is_private = True` | **C4** — loopback |
| 7 Cờ | `dstip = ''` | `dstip_is_private = None` | Chuỗi rỗng → không khẳng định |
| 7 Cờ | `raw_log` dài 101 byte | `raw_log_truncated = False` | **C3** — xa ngưỡng 1000 KB |

**Tự kiểm chứng được ngay:** `alert_time` sau chuẩn hóa phải bằng đúng `fields.timestamp` trong payload (`2026-08-16T17:56:56.130Z`). Payload tự mang sẵn đáp án — dùng làm assertion trong test.

**Vì sao mẫu này là ca test quan trọng:** `full_log` ghi `"Accepted password"` — đăng nhập **thành công**. Nếu chỉ nhìn log thô hoặc nhìn `rule.groups` (`["syslog","attacks"]` — quá chung chung), rất dễ phân loại nhầm thành `suspicious_login`. Chỉ MITRE ID mới bắt đúng bản chất: **nhiều lần thất bại rồi thành công** — một đợt brute-force đã xuyên thủng. Và sau chốt C5, mẫu này còn là ca kiểm chứng bảng độ ưu tiên: `suspicious_login` (từ T1078) là câu trả lời **gần đúng nhưng sai**, `ssh_brute_force` (từ T1110) mới đúng.

---

## Dữ liệu đầu ra kỳ vọng

```python
Alert(
  # ---- ① từ SIEM ----
  alert_id="1786903016.121311", rule_id="40112", rule_level=12, severity="critical",
  description="Multiple authentication failures followed by a success.",
  category="ssh_brute_force",
  categories=["ssh_brute_force", "suspicious_login"],   # C5 · sắp theo độ ưu tiên
  resolved_by="mitre", mapping_version="v1",
  srcip="127.0.0.1", dstip="",                          # B1 · thiếu → '' , không NULL
  src_port=48104, dst_port=0,                           # C2 · thiếu → 0
  alert_user="user1",
  agent_id="001", agent_name="user1-IA1803", agent_ip="79.79.79.12",
  decoder="sshd",
  mitre_ids=["T1078", "T1110"], rule_groups=["syslog", "attacks"],
  alert_time="2026-08-16T17:56:56.130Z", event_time="2026-08-16T17:56:55Z",
  raw_log="Aug 16 17:56:55 user1-IA1803 sshd[136570]: Accepted password for user1 from 127.0.0.1 port 48104 ssh2",

  # ---- ② cờ suy ra (C3, C4) ----
  srcip_is_private=True, dstip_is_private=None,         # '' → None, không khẳng định
  raw_log_truncated=False,
  source="wazuh", is_synthetic=False,                   # B5 · bỏ id_synthesized

  # ---- ③ vòng đời (chưa gán ở phase này) ----
  status="received",          # set ở bước Ghi + xếp hàng
  event_bucket_hash="76fcfceb90ed06f6be274be022445ff693254b73edbdb70180244328119b2a1a",  # C1 · B6
  duplicate_of=None, occurrence_count=1,
  risk_score=None, triage_status="pending", triaged_count=0, case_id=None,
  acknowledged_at=None, closed_at=None, close_reason=None,

  # ---- ④ nguyên bản ----
  raw_payload=<toàn bộ JSON gốc, kể cả _id, _index, sort, các mảng tuân thủ>,
)
```

**Các trường mốc thời gian do DB sinh, không phải Python:** `received_at`, `first_seen_at`, `last_seen_at` đều lấy `DEFAULT now()` của Postgres. Container ứng dụng và container DB có thể lệch giờ; nếu một mốc lấy từ Python còn mốc kia từ DB thì hai giá trị trên cùng một dòng có thể mâu thuẫn.

---

## Xử lý lỗi

| Tình huống | Mã | Hành động |
|---|---|---|
| Sai / thiếu API key | `401` | **Không ghi gì cả**, kể cả `rejected_alerts` — nếu ghi thì kẻ tấn công làm phình DB mà không cần key |
| IP không nằm trong allowlist | `403` | Ghi log mức cảnh báo |
| Payload vượt kích thước | `413` | Chặn **trước** khi parse JSON; ngưỡng phải > `RAW_LOG_MAX_BYTES` |
| JSON hỏng / thiếu trường bắt buộc | `400` | Ghi một dòng `rejected_alerts` (payload gốc + lý do + `source_ip` + thời điểm) |
| Ép kiểu port thất bại | — | `_safe_int` trả `0`, **không** lỗi |
| Parse `event_time` thất bại | — | `event_time = NULL`, **không** lỗi |
| Parse IP thất bại | — | `*_is_private = None`, **không** lỗi |
| Không phân giải được category | — | `category='unknown'`, **không** lỗi |
| `raw_log` vượt 1000 KB | — | Cắt + bật cờ, `raw_payload` nguyên vẹn, **không** lỗi |

**Thông điệp lỗi không được chứa tên class hay message của exception gốc** (G‑15 trong bản rà soát). Trả tên trường bị thiếu, không trả stack trace.

**Vì sao cần `rejected_alerts`:** trả `400` nghĩa là alert biến mất, vì Wazuh integrator thường không retry. Nếu decoder đổi định dạng, ta mất dữ liệu mà không hề biết. Bảng này giữ bằng chứng để sửa parser.

---

## Ràng buộc bất biến

| # | Ràng buộc | Kiểm chứng bằng |
|---|---|---|
| R1 | Thuần ở đâu có thể — parse, phân loại, băm không I/O | Test chạy không cần DB |
| R2 | Toàn phần — không hàm nào trong đường phân loại được `raise` | Test fuzz payload thiếu trường |
| R3 | Cùng một payload luôn cho cùng một `Alert` (tất định) | Test chạy 2 lần, so bằng |
| R4 | Không phụ thuộc thứ tự mảng do SIEM gửi | Test đảo `groups`, đảo `mitre.id` |
| R5 | Mọi category ánh xạ tới đều có playbook thật | Test quét bảng ánh xạ ↔ thư mục playbook |
| R6 | `raw_payload` giữ nguyên vẹn, không cắt xén | Test so sánh byte-for-byte |
| R7 | Mốc thời gian do DB sinh, Python chỉ đọc | Review code, cấm `datetime.now()` trong `ingest/` |
| R8 | `event_bucket_hash` tính trên `alert_time` **UTC**, bucket là số nguyên | Test cùng thời điểm ở hai múi giờ → cùng giá trị |
| R9 | `srcip`/`dstip` không bao giờ là `NULL` (B1) | Ràng buộc `NOT NULL` của DB |

---

## Test bắt buộc

Toàn bộ nhóm này **không cần DB**:

```
# Parse & ánh xạ
test_nhan_ca_hai_dang_payload              # có _source và không có
test_alert_id_lay_source_id_khong_lay__id
test_thieu_agent_name_van_parse_duoc
test_thieu_rule_id_tra_400_neu_dung_ten_truong
test_raw_payload_giu_nguyen_ven            # kể cả _id, sort, mảng tuân thủ

# Thời gian
test_timestamp_offset_khong_dau_hai_cham   # "+0700" — dùng CHÍNH chuỗi mẫu thật
test_alert_time_khop_voi_fields_timestamp  # payload tự mang đáp án
test_event_time_suy_duoc_nam_tu_alert_time # "Aug 16 17:56:55" → 2026
test_event_time_giao_thua_tru_mot_nam      # alert 01/01, log 31/12
test_event_time_hong_thi_null_khong_raise

# Ép kiểu — C2, B1
test_srcport_khong_phai_so_tra_0           # "unknown", "", "  48104  "
test_dstport_thieu_tra_0_khong_phai_none
test_dstip_thieu_tra_chuoi_rong_khong_phai_none    # B1
test_srcip_thieu_tra_chuoi_rong_khong_phai_none    # B1
test_ip_rong_ra_is_private_none_khong_raise

# Category — C5
test_moi_tang_phan_loai                    # 5 test: mitre/parent/groups/decoder/port
test_dao_thu_tu_mang_khong_doi_ket_qua     # groups và mitre.id
test_mau_that_ra_ssh_brute_force           # KHÔNG phải suspicious_login
test_t1078_va_t1110_cung_khop_chon_t1110   # C5 · độ ưu tiên thắng thứ tự mảng
test_categories_sap_theo_do_uu_tien
test_khong_tin_hieu_nao_khop_ra_unknown    # không raise
test_moi_category_deu_co_playbook

# event_bucket_hash — C1, B6
test_hash_mau_that_bang_76fcfceb           # giá trị chốt, hardcode
test_hash_khong_chua_alert_user            # user1 vs user2 → CÙNG giá trị
test_cung_o_5_phut_thi_cung_hash           # 17:55:02 và 17:59:59
test_khac_o_5_phut_thi_khac_hash           # 17:54:58 và 17:55:02
test_cung_thoi_diem_khac_mui_gio_cung_hash # R8
test_bucket_la_so_nguyen_khong_phai_iso
test_hash_khong_doi_sau_B1                 # dstip='' cho cùng chuỗi như dstip=NULL

# Cờ suy ra — C3, C4
test_loopback_va_rfc1918_ra_private_true
test_ip_public_ra_private_false
test_ip_hong_ra_none_khong_raise
test_raw_log_duoi_nguong_khong_bi_cat
test_raw_log_vuot_1000kb_bi_cat_va_bat_co
test_raw_log_cat_khong_lam_hong_utf8       # cắt giữa ký tự nhiều byte
test_raw_payload_khong_bi_cat_du_raw_log_bi_cat

# Sau Đề xuất 1
test_khoi_dong_that_bai_neu_413_nho_hon_1000kb   # assert config
test_categories_khong_duoc_dung_tra_playbook     # chỉ category chính

# B5
test_khong_con_truong_id_synthesized
test_webhook_wazuh_luon_dat_is_synthetic_false
test_payload_ngoai_khong_the_tu_dat_is_synthetic_true
```

---

## Quyết định đã chốt

| # | Vấn đề | Quyết định | Ảnh hưởng |
|---|---|---|---|
| **C1** | Hai công thức fingerprint mâu thuẫn | **Theo Phần VI**: bỏ `alert_user`, thêm bucket 5 phút dạng số nguyên | Khối 6 · **vai trò đổi**: không còn là khóa cụm, xem Phase 2 |
| **C2** | `dst_port` thiếu: `None` hay `0` | **`0`**, áp cho cả `src_port`. Cột `INT NOT NULL DEFAULT 0` | Khối 2 · model đổi kiểu |
| **C3** | Ngưỡng `raw_log_truncated` | **1000 KB** cho lưu trữ, `raw_payload` nguyên vẹn | Khối 7 · thêm 2 ngưỡng cho 2 vai trò khác |
| **C4** | IP loopback / nội bộ | Thêm `srcip_is_private`, `dstip_is_private` qua `ipaddress` | Khối 7 · `soar/` dùng 3 trạng thái lookup |
| **C5** | `T1078` có trong bảng ánh xạ không | **Có**, nhưng `T1110` ưu tiên cao hơn → bảng độ ưu tiên tường minh | Khối 5 · "thu hết rồi sắp", không "khớp đầu tiên" |

### Cập nhật sau khi duyệt Đề xuất 1 (Phase 2)

Bốn hậu quả vận hành của C1 (cụm vỡ, hiệu ứng biên, cửa sổ mất tác dụng, gộp nhiều tài khoản) **đã được xử lý ở Phase 2** bằng cách chuyển khóa cụm sang 4 cột trực tiếp.

**Phase 1 khi đó không đổi dòng code nào** — công thức, giá trị `76fcfceb…`, và toàn bộ test giữ nguyên. Bốn thứ ở tầng tài liệu và cấu hình thay đổi:

| Thay đổi | Ở đâu |
|---|---|
| `fingerprint` → **`event_bucket_hash`**, vai trò là đối chiếu/audit, **không** phải khóa cụm | Khối 6 |
| Thêm `PROMPT_LOG_MAX_BYTES` (cắt ở `llm/`) và `MAX_PAYLOAD_BYTES` + `assert` | Khối 7 |
| Thêm luật 3 trạng thái lookup và `NAT_AGENTS` (áp ở `soar/`) | Khối 7 |
| Gán vai trò tách bạch cho `category` / `categories` | Khối 5 |

**Không cần migration dữ liệu cũ** — khóa cụm mới dùng 4 cột đã có sẵn giá trị.

### Việc còn lại

1. **Hoàn thiện bảng độ ưu tiên category** — bản trong Khối 5 là đề xuất; cần rà cho khớp đúng danh sách playbook thật.
2. **Xác nhận `T1078` ánh xạ tới `suspicious_login`** trong `category_map.py`, và `suspicious_login` có playbook thật (ràng buộc R5).
3. **Rà 3 câu SQL đo lường ở mục II‑08** — thay mọi chỗ dùng `fingerprint` sang `duplicate_of IS NULL`, và đổi tên cột còn lại sang `event_bucket_hash`.

---

## Phụ thuộc

| Package | Dùng để | Chiều |
|---|---|---|
| `domain/alert.py` | Kiểu `Alert`, `compute_event_bucket_hash()` | `ingest/` → `domain/` ✅ |
| `infra/auth.py` | Xác thực API key, allowlist IP, rate limit | `ingest/` → `infra/` ✅ |
| `infra/config.py` | `DISPLAY_TZ`, `RAW_LOG_MAX_BYTES`, `MAX_PAYLOAD_BYTES` | `ingest/` → `infra/` ✅ |
| `ipaddress` (stdlib) | Cờ IP nội bộ | — |
| `hashlib` (stdlib) | SHA‑256 cho `event_bucket_hash` | — |

Phase này **không** import `soar/`, `tier1/`, `tier2/`, `llm/`, `kb/`, `enrichment/` — luật tầng không import tầng, cưỡng chế bằng test quét AST.

**Hằng số Phase 1 tiêu thụ nhưng do tầng khác cắt:** `PROMPT_LOG_MAX_BYTES` (dùng ở `llm/`), `NAT_AGENTS` (dùng ở `soar/`). Khai báo chung trong `infra/config.py`, Phase 1 chỉ ghi dữ liệu để tầng đó dùng.

---

*Đặc tả phase Tiếp nhận + chuẩn hóa · AI Support SOC · C1–C5 đã chốt · cập nhật sau Đề xuất 1*
