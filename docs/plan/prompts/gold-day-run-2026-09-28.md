# Ngày tập vàng — tối 27/09 (chuyển tiếp) và 28/09 (ký bảng → gán nhãn → đối chiếu → đóng băng)

Viết bởi Director, 26/09 (DEC-137), theo DEC-111, 114, 115, 117, 120, 132, 135 và 136. Đây là bản chạy
duy nhất cho hai ngày này. Mỗi bước ghi **ai làm**, và bước nào cũng có dòng **Kỳ vọng** để đối chiếu
trước khi sang bước sau. Ký hiệu người làm:
- **O** — chủ đồ án;
- **A** — giảng viên, người gán nhãn thứ hai;
- **T** — phiên `ai-support-soc-1-2-d1`, người gắn nhãn cửa sổ lab duy nhất (DEC-135);
- **D** — Director.

**Ba quy tắc không nới vì lịch** (01-plan, cross-phase rules):
- gán nhãn mù;
- đóng băng trước khi đánh giá;
- trang gán nhãn không bao giờ hiện đầu ra của ①.

**Mù với chân lý:** trước và trong lúc gán nhãn, **O và A không mở** `eval/gold_candidates.csv`,
`eval/gold_coverage.md`, `eval/lab_windows.csv` hay bảng lịch §5 của `docs/lab-scenarios.md`. O là người
chạy kịch bản nên biết lịch; đó là giới hạn (xii), được nêu chứ không che. Nhãn của A là mốc sạch hơn.

---

## Phần A — chiều/tối 27/09, sau cửa sổ lab cuối cùng

**A1 · T — gắn nhãn cửa sổ cuối và báo D.** Gửi D: "cửa sổ cuối đã gắn", kèm danh sách id trong lịch §5
**không chạy** (nếu có). T kiểm cửa sổ cuối bằng lệnh đọc (DEC-136): trước khi gắn, `last_pull_at` phải đã
qua mốc End của nó.
- **Kỳ vọng:** mọi id đã chạy đều có đúng một dòng trong `eval/lab_windows.csv` của checkout chính (riêng
  RW-A1 hiện có hai dòng, xem A2).

**A2 · D — nhập tệp cửa sổ lên nhánh Director.**
- Chép `eval/lab_windows.csv` từ checkout chính.
- Chuẩn hoá RW-A1 theo DEC-135 mục 5: một dòng `RW-A1` mang dữ liệu lần chạy đầu (3 retag, 05:47:34Z), bỏ
  dòng 0-retag.
- So từng dòng còn lại với bản gốc, phải giống hệt từng byte.
- Commit.
- **Kỳ vọng:** chỉ khác bản của O đúng ở dòng RW-A1.

**A3 · D — hạ cánh P7-T01 + P7-T04 (DEC-131).**
- Ghép lại `director/p7-t01-t04-composed` lên tip.
- Chạy toàn bộ test: lint, `make test` (chỉ lỗi DEC-113), `make test-db`.
- Merge, rồi đặt hai hàng về `done`.

**A4 · D — dựng G2**, từ worktree Director, chỉ đọc CSDL:
```bash
PYTHONPATH=backend /project/project/AI_Support_SOC_1_2/.venv/bin/python eval/build_gold.py \
  --g2 --lab-windows eval/lab_windows.csv --g2-target 150 --g2-floor 100 \
  --env-file /project/project/AI_Support_SOC_1_2/.env --out-dir eval
```
- **Kỳ vọng:** exit 0. Đọc `eval/gold_coverage.md`:
  - G2 ≥ 100 cụm trong phạm vi, trên 8 loại; loại nào 0 cụm thì in thành **dòng 0**, không bao giờ bịa;
  - dòng benign ≥ 20;
  - tổng `in_window_unexpected` được in ra.
- Exit 3 nghĩa là còn một head trong cửa sổ vẫn mang `source='wazuh'` (chưa gắn), hoặc hai cửa sổ chồng
  nhau: quay lại A1/A2, **không** chỉnh tay.
- Commit `eval/gold_candidates.csv`, `eval/gold_coverage.md`, `eval/lab_windows.csv`. Không bao giờ commit
  `eval/g1_*` (DEC-111).

**A5 · O — đưa tất cả vào chạy**, từ checkout chính, sau khi D báo "A2–A4 xong":
```bash
cd /project/project/AI_Support_SOC_1_2
git restore eval/lab_windows.csv                 # bản cục bộ; bản đã chuẩn hoá nằm trên nhánh (A2)
git merge --ff-only director/lab-rebuild-0925
docker compose up -d app worker                  # KHÔNG phải restart: áp mount ./eval (DEC-135) + code P7-T01
docker compose ps                                # app, worker: Up
docker compose logs --since 3m worker | tail -5  # worker đã nhận job
docker compose exec app ls /srv/eval/gold_candidates.csv
```
- **Kỳ vọng:** fast-forward sạch; hai container `Up`; worker ghi log job; lệnh `ls` in ra đường dẫn.
- Kiểm vòng pull (DEC-136), chỉ đọc, không in DSN:
  `set -a; . ./.env; set +a; psql "$DATABASE_URL" -Atc "select round(extract(epoch from now()-last_pull_at)), last_error is null from source_cursor"`.
  Kỳ vọng: `<số giây < 300>|t`.

---

## Phần B — 28/09

**B1 · O + A — buổi ký 10 bảng quyết định**, khoảng 90 phút, **trước nhãn đầu tiên** (DEC-132).
- Làm việc từ `docs/plan/kb-review-sheet-2026-09-19.md`. Mỗi bảng: ký nguyên bản nháp, hoặc sửa kèm một
  dòng lý do.
- **Không thêm luật nào dựa trên giá trị riêng của lab**: dải `127.0.0.x`, tên host lab, giờ chạy kịch bản.
- O gửi D: từng bảng ký nguyên hay sửa gì, tên hai người ký, ngày.
- D ghi vào YAML (`reviewed_by`, `reviewed_at` và các sửa đổi), chạy `make test` (có test nhất quán của
  bảng), rồi commit ghi rõ hai người ký.
- O chạy `git merge --ff-only director/lab-rebuild-0925`. Bảng được mount sống và không bị cache, nên worker
  dùng bản đã ký từ alert kế tiếp, không cần restart.
- **Kỳ vọng:** `grep -c 'reviewed_by: null' kb/decision_tables/*.yaml` → mọi tệp đều `0`.
- Không kịp thì P7-T08 vẫn chạy, và báo cáo nói rõ hệ quả (DEC-132 mục 4).

**B2 · O — chụp màn hình `/admin/labels`** khi đang có một ứng viên thật, trước nhãn đầu tiên. Ảnh này dùng
cho đoạn 4 của `docs/demo.md` (DEC-136).

**B3 · O, A — gán nhãn mù.**
- Mỗi người đăng nhập bằng tài khoản admin của mình: `khanh-admin`, `nguyen-admin`.
- Gán **mọi** ứng viên trên `/admin/labels` cho tới khi trang báo xong. Nhãn là `escalate` /
  `false_positive` / `benign`, kèm độ tin cậy.
- Làm **riêng**: không bàn về cụm nào cho tới khi cả hai xong, không nhìn màn hình của nhau, không mở
  các tệp ở mục "Mù với chân lý".
- **Kỳ vọng:** thanh tiến độ của cả hai đạt tổng số ứng viên.

**B4 · D — κ và bất đồng**, từ worktree Director:
```bash
PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python; ENV=/project/project/AI_Support_SOC_1_2/.env
PYTHONPATH=backend $PY eval/label_export.py kappa --env-file "$ENV"          # → eval/kappa_v1.json
PYTHONPATH=backend $PY eval/label_export.py disagreements --env-file "$ENV"  # → eval/adjudication_v1.csv
```
- Nếu `kappa` từ chối vì thấy nhiều hơn hai `labeler_id` (ví dụ một tài khoản thử), chạy lại với
  `--labeler-a <uuid khanh-admin> --labeler-b <uuid nguyen-admin>`.
- D gửi O + A: κ tổng và theo loại; từng người so với chân lý cửa sổ (`vs_truth`, mốc của con người); tệp
  bất đồng.

**B5 · O + A — buổi đối chiếu** (DEC-120).
- Chỉ quyết một câu: **kịch bản nào chạy hỏng?** Ví dụ: rule khai báo không bắn đúng như dự định, hoặc cửa
  sổ bắt nhầm thứ khác.
- Mỗi kịch bản bị loại thành một dòng trong `eval/excluded_scenarios.csv`, header đúng
  `scenario_id,reason,decided_in` (`decided_in` là số DEC do D cấp).
- Người gán nhãn khác chân lý thì **giữ nguyên làm dữ liệu**: đó là số đo mốc của con người, không phải sửa
  chân lý. Ghi `final_label` lên dòng cửa sổ không có tác dụng gì.
- O gửi D danh sách loại, kèm lý do.

**B6 · D — đóng băng.**
- Ghi và commit `eval/excluded_scenarios.csv`, rồi chạy:
  ```bash
  PYTHONPATH=backend $PY eval/label_export.py freeze --env-file "$ENV" --out-dir eval  # → eval/gold_v1.csv + .sha256 + .freeze.json
  PYTHONPATH=backend $PY eval/label_export.py report                                   # → docs/gold-v1-report.md
  sha256sum -c eval/gold_v1.sha256                                                     # → OK
  ```
- Commit `eval/gold_v1.csv`, `eval/gold_v1.sha256`, `eval/gold_v1.freeze.json`, `eval/kappa_v1.json`,
  `eval/adjudication_v1.csv`, `eval/excluded_scenarios.csv`, `docs/gold-v1-report.md`. Không bao giờ commit
  gì dưới `eval/results/`.
- O fast-forward `main`.
- **Kỳ vọng:** `git ls-files --error-unmatch eval/gold_v1.csv eval/gold_v1.sha256` thành công. Từ giờ
  **không sửa `gold_v1.*`**: mọi thay đổi thành `gold_v2` theo version-by-existence.

**Ngày 29/09:** P7-T08 do D chạy (đánh giá trực tiếp), theo card `tasks/P7/P7-T08.prompt.md` và các banner
DEC-127/131/132.
