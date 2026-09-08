# Lịch trình 08/09 → 18/09 — ai làm gì, phiên nào chạy song song

Lập 08/09. Thay thế mọi ước lượng lịch cũ trong đầu; `01-plan.md` và `STATE.md` vẫn là nguồn
chính thức cho exit gate, file này chỉ sắp thứ tự và phân vai.

## 0. Ràng buộc không dời được

| Thứ | Ngày | Vì sao không dời |
|---|---|---|
| Lab sinh dữ liệu | **≤ 11/09** | Gán nhãn bắt đầu 12/09; phải có cái để gán |
| Gán nhãn | 12–13/09 (T7–CN) | Cần hai người, cuối tuần của giảng viên |
| Đóng băng gold_v1 | 14/09 | P7 cần bộ vàng đã khoá |
| Nộp | 18/09 | — |

Trần song song: **3 phiên coder**. Director, Reviewer, Planner không tính vào trần đó.

## 1. Việc CHỈ CHỦ ĐỒ ÁN làm được (§11)

### 1.1 Buổi ngồi Wazuh — hôm nay, **hai lệnh**. **Mở khoá nhiều nhất.**

`/var/ossec/etc/rules/` đang rỗng. Một file `local_rules.xml` giải quyết hai việc:

- `rule 100999` heartbeat → gỡ chặn **P2-T11** (chờ từ 06/09)
- 3 rule lab (T1486 ransomware · T1041 exfiltration · T1071 c2_beacon) → **G2 lên 8/10**, đạt sàn §C

Cộng `sudo apt install -y clamav clamav-daemon` → mở `malware`.

**Cách làm — sửa 08/09 sau khi đo quyền thật trên máy này.** Phần lớn không cần `sudo`:

| việc | cần root? | ai làm |
|---|---|---|
| ghi `/var/ossec/etc/rules/local_rules.xml` | **không** — thư mục `drwxrwx--- root:wazuh`, `user1` ở nhóm `wazuh` (gid 124) | agent |
| chạy `wazuh-logtest` | **không** — `rwxr-x--- root:wazuh`, đã chạy thật ra đủ rule debugging | agent |
| đọc/sửa `ossec.conf` (wodle heartbeat) | **không** — `rw-rw---- root:wazuh` | agent |
| `systemctl restart wazuh-manager` | **có** | **chủ đồ án** |
| `apt install -y clamav clamav-daemon` | **có** | **chủ đồ án** |

Nên phần của chủ đồ án là **hai lệnh cuối**, không phải một buổi ngồi. Agent soạn, tự nạp thử
bằng `wazuh-logtest`, chủ đồ án restart, rồi agent tự xác nhận alert nổ qua indexer.

Hai ràng buộc đã đo, không được bỏ: `ossec.conf:25` là `<log_alert_level>3</log_alert_level>` —
rule dưới level 3 không vào `alerts.json`, không tới indexer, G2 không thấy; và id `100101`,
`100112`, `100204`, `100205` có trong kho 30 ngày (nổ tới 17/08) nên **không được dùng lại**.

Hai prompt dán thẳng: `docs/plan/prompts/detection-author.md` (soạn rule + `lab-scenarios.md`) và
`docs/plan/prompts/owner-assist.md` (cầm nhịp bốn việc §1). Chạy song song được.

### 1.2 Chạy kịch bản lab — hôm nay hoặc mai, ≤ 11/09

Theo `docs/lab-scenarios.md` (assistant viết sau bước 1.1). Với **mỗi** kịch bản, ghi lại:

    <category> · bắt đầu HH:MM:SS · kết thúc HH:MM:SS · lệnh đã chạy

**Giờ chính xác là dữ liệu gắn thẻ.** Máy lab và máy sản xuất là một, nên `source='lab'` phải
gắn theo **cửa sổ thời gian**, không theo tên agent. Không ghi giờ = alert lab không tách được
khỏi alert thật = hỏng cả G1 lẫn G2.

Cộng **≥ 20 cụm lành tính** trên cùng host (cập nhật gói, cron, đăng nhập admin) — `§A2` bắt
buộc, để model không học "host lab = escalate".

### 1.3 Hai quyết định — 5 phút, bảng đã có

Đọc `docs/plan/A1-A5-decision-material-2026-09-07.md` §1, §2 rồi trả lời Director một câu.

### 1.4 Mỗi lần agent báo xong: Reviewer → Director. **Gộp lô.**

Đo được: report→merge **0,5 h khi gộp lô** so với **10 h khi không gộp**. Còn 12 vòng. Gộp lô là
hành động lịch trình rẻ nhất còn lại — chờ 2–3 task cùng báo rồi mới chạy Reviewer và Director
một lượt.

### 1.5 Gán nhãn 12–13/09 — hai người, độc lập, không trao đổi

## 2. Việc AGENT làm

| Vai | Mục tiêu | Số phiên |
|---|---|---|
| Coder | một card một phiên, worktree riêng | ≤ 3 cùng lúc |
| Reviewer | chạy lại acceptance, ra APPROVE/CHANGES | 1, dùng lại, `/clear` giữa các task |
| Director | intake, merge, cổng tối, quyết chiến thuật | 1, suốt 14 ngày |
| Planner | đầu mỗi phase | 1, mở khi cần |

## 3. Lịch theo ngày

### 08/09 (hôm nay)
- **Chủ đồ án**: commit 10 file · buổi ngồi Wazuh (1.1) · hai quyết định (1.3)
- **Coder ×3**: T02 rework · T04 rework · **T16** (bản sửa `attack`, không phụ thuộc gì)
- **Detection Author** (`prompts/detection-author.md`): soạn `conf/local_rules.xml` + `docs/wazuh-manager-changes.md`, rồi `docs/lab-scenarios.md`
- **Owner Assist** (`prompts/owner-assist.md`): cầm nhịp bốn việc §1 — buổi Wazuh, sổ giờ lab, hai quyết định A5/A6, hàng đợi gộp lô
- **Tối**: Director chạy cổng 08/09 — nơi ② được quyết

### 09/09
- **Chủ đồ án**: chạy lab (1.2) nếu chưa xong
- **Director**: gộp lô merge T02+T04+T16 trong **một** lượt intake → mở 6 card
- **Coder ×3**: T11 (chặn T13, T12) · T05 · T06
- **Planner P3** nếu cổng P2 nhích

### 10/09
- **Coder ×3**: T08 · T09 · T07
- **Director**: gộp lô merge → T10 mở
- **Chủ đồ án**: lab phải xong trong hôm nay nếu 09/09 chưa xong

### 11/09
- **Coder**: T10 → rồi T13, T15
- **Chủ đồ án**: **hạn chót tuyệt đối cho lab**
- **Planner P6** — sau khi A5/A6 đã quyết

### 12–13/09 — GÁN NHÃN. Không code.
### 14/09 — đối chiếu, κ, đóng băng `gold_v1` + sha256
### 15/09 — P7: B0–B4 + G3 + ablation thinking
### 16–17/09 — P8: báo cáo, runbook, restore drill, demo, tag
### 18/09 — nộp

## 4. Van xả

`§10` thứ tự cắt: ② → digest UI → health job → login → auto-close rules.
**Không bao giờ cắt:** intake/puller, ① + cổng + verifier, trang gán nhãn, eval harness.

Nếu tối 08/09 hoặc 09/09 cổng chưa nhích: cắt ② ở P5. Nó giải phóng ~8 h và giữ được P6/P7
đúng ngày. Đó là D-item, quyết định của chủ đồ án.
