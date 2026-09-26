# Hướng dẫn chạy lab G2 — bản thao tác

Bản này đi kèm `docs/lab-scenarios.md`, viết cho chủ đồ án chạy trực tiếp. Nó **không lặp lại lệnh tấn
công** — lệnh của mỗi kịch bản nằm nguyên trong `docs/lab-scenarios.md` §3, ở mục cùng tên (ví dụ
`### ssh_brute_force`). Bản này lo phần còn lại: chuẩn bị, canh giờ, kiểm tra, gắn nhãn, thứ tự chạy —
để anh theo từ trên xuống mà không phải lần trong file dài.

Người gắn nhãn hiện là phiên `Owner assist` (DEC-135/137). Anh chạy kịch bản; nó gắn nhãn. Anh **không**
chạy `lab_tag.py`.

---

## 0 · Chuẩn bị một lần mỗi phiên terminal

Từ checkout chính, mở một shell và giữ nó cho cả buổi:

```bash
cd /project/project/AI_Support_SOC_1_2
set -a; . ./.env; set +a          # nạp INDEXER_* và các biến khác; không in ra gì
echo "${INDEXER_URL:+env ok}"     # → env ok
```

Các lệnh kiểm ở dưới đọc biến từ shell này. Không có gì lộ mật khẩu ra màn hình.

---

## 1 · Vòng lặp cho MỖI cửa sổ — làm đúng 6 bước này

Lấy một hàng từ bảng lịch (`docs/lab-scenarios.md` §5): nó cho anh **id**, **category**, **kind**
(`attack`/`benign`), và cột **srcip**. Rồi:

**Bước 1 — Ghi giờ bắt đầu.** Chạy và chép lại cả hai dòng:
```bash
date -u +%FT%TZ ; date +%FT%T%z
```

**Bước 2 — Đặt biến nguồn rồi chạy kịch bản.** Với kịch bản dựa trên ssh (`ssh_brute_force`,
`suspicious_login`, `recon`), đặt `SRC` theo cột srcip của hàng đó; các kịch bản khác bỏ qua:
```bash
SRC=127.0.0.2      # đúng giá trị ở cột srcip của §5
```
Rồi mở `docs/lab-scenarios.md` §3, tới mục cùng tên category, và chạy **đúng khối trong đó**:
`#### Attack` nếu kind = `attack`, `#### Benign twin` nếu kind = `benign`. Chỉ chạy khối đó, không chạy
gì khác (đây là quy tắc mù: một cửa sổ = một kịch bản).

**Bước 3 — Chờ ≥ 3 phút.** Puller kéo mỗi 60 giây, cộng thêm biên. Đừng ghi End sớm hơn.

**Bước 4 — Ghi giờ kết thúc.** Chạy lại đúng hai lệnh `date` ở Bước 1, chép lại.

**Bước 5 — Kiểm nhanh (chỉ đọc).** Đặt `S`, `E` bằng hai mốc UTC (dạng `...Z`) vừa ghi, rồi xem những
rule nào đã bắn trong cửa sổ:
```bash
S="2026-09-27T00:05:00Z"; E="2026-09-27T00:06:30Z"   # thay bằng mốc thật của anh
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_search?size=0" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}},
       \"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.id\",\"size\":20}}}}"
```
Đối chiếu `by_rule` với cột "rule kỳ vọng" ở bảng §2 dưới. Nếu rule kỳ vọng **không** xuất hiện: kịch
bản chưa bắn — xem mục đó trong §3 (thường là do chờ chưa đủ, hoặc `auid`/ClamAV, xem §1 của
`docs/lab-scenarios.md`). Cứ ghi lại thực tế, kể cả khi bằng 0; buổi đối chiếu 28/09 quyết loại hay giữ.

**Bước 6 — Gửi người gắn nhãn.** Gửi phiên `Owner assist` một dòng:
```
<id>,<category>,<kind>,<S>,<E>
```
Ví dụ dạng: `SBF-A1,ssh_brute_force,attack,2026-09-27T00:05:00Z,2026-09-27T00:06:30Z`. Nó chờ pull qua
mốc End rồi gắn, và báo lại. Anh **không** tự chạy `lab_tag.py`.

**Trước khi mở cửa sổ kế:** phải đã ghi End của cửa sổ này (Bước 4). Một cửa sổ tại một thời điểm.

---

## 2 · Bản đồ 8 kịch bản — mở mục nào, chờ rule nào

Cột "Mục trong §3" là nơi có lệnh để chạy. Cột "Rule kỳ vọng" là thứ Bước 5 phải thấy.

| Tiền tố id | category | Mục trong `docs/lab-scenarios.md` §3 | Rule kỳ vọng (attack) | Nhãn kỳ vọng (attack) | Twin lành tính |
|---|---|---|---|---|---|
| `SBF` | ssh_brute_force | `### ssh_brute_force` | 5760 / 5710 / 5503 / 2501, cụm 5712 | escalate | một lần sai rồi đúng → 5715/5501 |
| `SL` | suspicious_login | `### suspicious_login` | 40112 (rơi vào category ssh_brute_force) | escalate | đăng nhập đúng ngay → 5715/5501 |
| `PE` | privilege_escalation | `### privilege_escalation` | 5401 | escalate | sudo thành công → 5402 |
| `RC` | recon | `### recon` | 5731 | escalate | (xem mục §3) |
| `MW` | malware | `### malware` | 52502 (ClamAV) | escalate | quét sạch → im lặng |
| `RW` | ransomware | `### ransomware` | 100301 (auditd) | escalate | thao tác lành → im lặng |
| `DX` | data_exfiltration | `### data_exfiltration` | 100302 (auditd) | escalate | thao tác lành → im lặng |
| `C2` | c2_beacon | `### c2_beacon` | 100303 (auditd) | escalate | thao tác lành → im lặng |

Nhãn kỳ vọng ở đây **chỉ để anh tự kiểm**, không hiện cho người gắn nhãn (trang gán nhãn mù).

Twin của `RW`, `DX`, `C2`, `MW` cố ý **không** bắn rule nào — mục đích của chúng là chứng minh rule đứng
im khi thao tác là lành tính. Bước 5 của twin đó kỳ vọng `by_rule` không có rule kỳ vọng.

---

## 3 · Thứ tự chạy và cách rút gọn nếu thiếu thời gian

**Thứ tự:** theo đúng bảng lịch §5 (ngày 1 rồi ngày 2). Lịch xen kẽ 8 phút một cửa sổ đã lo sẵn khoảng
cách ≥ 20 phút giữa hai cửa sổ cùng loại không dùng ssh — nên **đừng chạy dồn nhanh hơn 8 phút**, kẻo hai
cửa sổ cùng loại rơi vào một cụm.

**Ba cửa sổ audit đầu tiên chạy trước** (RW-A1, DX-A1, C2-A1) là bằng chứng rule 100301/100302/100303 còn
bắn dưới bộ lọc `auid`. Anh đã chạy xong cả ba, cả ba bắn đúng — phần rủi ro nhất đã qua.

**Nếu quỹ thời gian hẹp, ưu tiên theo thứ tự này** (mốc 100 cụm chỉ là mục tiêu, thiếu vẫn dựng được và
báo cáo ghi đúng số thật):
1. Hai khối lành tính `BB-D1`, `BB-D2` — nguồn nhãn `benign` chính; thiếu thì không có lớp `close` để đo.
2. Ít nhất 1 cửa sổ tấn công cho mỗi loại trong 8 loại (các `-A1`).
3. Rồi mới đến các lần lặp `-A2..A5` và các twin `-B*`.

Cuối ngày 27/09, người gắn nhãn gửi Director 1 danh sách id **không chạy** — báo cáo độ phủ G2 giải thích
được chỗ trống.

---

## 4 · Không làm

- Không mở cửa sổ mới khi chưa ghi End của cửa sổ đang chạy.
- Không tự chạy `eval/lab_tag.py` (việc của người gắn nhãn) và không sửa tay `eval/lab_windows.csv`.
- Không dựng lại giờ Start/End từ bảng alert — dùng đúng giây đã ghi lúc chạy.
- Không chạy quá một kịch bản trong một cửa sổ.
- Không in DSN hay mật khẩu ra màn hình chia sẻ.
