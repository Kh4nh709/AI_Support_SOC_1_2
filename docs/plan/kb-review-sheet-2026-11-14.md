# Phiếu xét KB · 14/11/2026 · DEC-216

Bản nháp chưa duyệt; số alert không phải nhãn thật. Không bảng nào cho phép FP.

## impact

§3 FP: 110229 User Logoff Event chỉ ghi đăng xuất thông thường nếu raw_log và mẫu tương quan phù hợp; T1531 không tự chứng minh mất quyền. Dừng ứng dụng hoặc xoá registry khi gỡ phần mềm chỉ nghiêng vô hại khi có ngữ cảnh tương ứng được cung cấp.

§4 THẬT: Lệnh dừng dịch vụ hàng loạt, xoá dữ liệu hoặc tước quyền kèm thất bại truy cập trong mẫu là dấu hiệu thật; 751/597 mang nhiều tag, phải đọc đối tượng thay vì suy diễn từ T1485.

- `imp-1`: playbook impact.md:27; §3 41 alerts: 110229 ×20 (level 3), 112524 ×15 (5), 751 ×2 (5), 597 ×2 (5), 60778 ×2 (5); bad-IoC policy, not a measured verdict.
- `imp-2`: playbook impact.md:28; §3 41 alerts: 110229 ×20 (level 3), 112524 ×15 (5), 751 ×2 (5), 597 ×2 (5), 60778 ×2 (5); DEC-053 critical band, including unseen future rules.
- `imp-3`: playbook impact.md:22 and :35; §3 41 alerts: 110229 ×20 (level 3), 112524 ×15 (5), 751 ×2 (5), 597 ×2 (5), 60778 ×2 (5); content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `imp-1` IoC xấu → escalate; `imp-2` level ≥12 → escalate; `imp-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## collection

§3 FP: Sao lưu thư hoặc lập chỉ mục có nguồn, đích, lệnh và ngữ cảnh công việc khớp nhau trong dữ liệu được gửi. Tìm file đơn lẻ không chứng minh đã lấy dữ liệu.

§4 THẬT: PowerShell đọc hàng loạt email, gom file nhạy cảm vào thư mục tạm hoặc nén để chuyển đi, nhất là sau truy cập bất thường. Thu thập chưa đồng nghĩa đã exfiltrate.

- `col-1`: playbook collection.md:27; §3 15 alerts: 110903 ×13 (level 8), 91820 ×2 (4); bad-IoC policy, not a measured verdict.
- `col-2`: playbook collection.md:28; §3 15 alerts: 110903 ×13 (level 8), 91820 ×2 (4); DEC-053 critical band, including unseen future rules.
- `col-3`: playbook collection.md:22 and :35; §3 15 alerts: 110903 ×13 (level 8), 91820 ×2 (4); content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `col-1` IoC xấu → escalate; `col-2` level ≥12 → escalate; `col-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## lateral_movement

§3 FP: Công cụ triển khai được mô tả trong context chạy đúng lệnh/đường dẫn và mẫu quản trị. NTLMv1 có thể là cấu hình cũ nhưng không phải bằng chứng an toàn.

§4 THẬT: File lạ được chuyển rồi chạy qua dịch vụ từ xa; WinRM mới bật kèm đăng nhập hoặc tái dùng hash. 92650 level 12 cần chuyển xử lý ngay; chỉ bật WinRM chưa chứng minh di chuyển thành công.

- `lat-1`: playbook lateral_movement.md:27; §3 17 alerts: 92217 ×10 (level 6), 110814 ×3 (8), 110243 ×2 (8), 92650 ×2 (12); bad-IoC policy, not a measured verdict.
- `lat-2`: playbook lateral_movement.md:28; §3 17 alerts: 92217 ×10 (level 6), 110814 ×3 (8), 110243 ×2 (8), 92650 ×2 (12); DEC-053 critical band, including unseen future rules.
- `lat-3`: playbook lateral_movement.md:22 and :35; §3 17 alerts: 92217 ×10 (level 6), 110814 ×3 (8), 110243 ×2 (8), 92650 ×2 (12); content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `lat-1` IoC xấu → escalate; `lat-2` level ≥12 → escalate; `lat-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## persistence

§3 FP: Updater hoặc agent quản trị đã biết chạy từ đường dẫn cài đặt phù hợp, action/trigger và ngữ cảnh quản trị khớp nhau. Khoảng 1,000 alert task/BITS là tín hiệu cần phân biệt, không phải 1,000 tấn công; tên quen không đủ.

§4 THẬT: Task trỏ thư mục người dùng ghi được, lệnh encoded, script host hoặc DLL hijack có nội dung đáng ngờ; đặc biệt 111828/110437 level 12. Đường dẫn ghi được là dấu hiệu cần đối chiếu, không tự nó xác nhận.

- `per-1`: playbook persistence.md:27; §3 1,119 alerts: 112438 ×496 (level 5), 112533 ×201 (5), 92154 ×124 (4), 111810 ×56 (5), 111828 ×56 (12), 112430 ×50 (5), 110798 ×41 (8), 110437 ×22 (12); 11 other rules ×73, unspecified; bad-IoC policy, not a measured verdict.
- `per-2`: playbook persistence.md:28; §3 1,119 alerts: 112438 ×496 (level 5), 112533 ×201 (5), 92154 ×124 (4), 111810 ×56 (5), 111828 ×56 (12), 112430 ×50 (5), 110798 ×41 (8), 110437 ×22 (12); 11 other rules ×73, unspecified; DEC-053 critical band, including unseen future rules.
- `per-3`: playbook persistence.md:22 and :35; §3 1,119 alerts: 112438 ×496 (level 5), 112533 ×201 (5), 92154 ×124 (4), 111810 ×56 (5), 111828 ×56 (12), 112430 ×50 (5), 110798 ×41 (8), 110437 ×22 (12); 11 other rules ×73, unspecified; content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `per-1` IoC xấu → escalate; `per-2` level ≥12 → escalate; `per-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## defense_evasion

§3 FP: Giải nén, dọn file tạm hoặc đổi quyền theo tác vụ quản trị phù hợp với context và lệnh cụ thể. Remove-Item và Decompress có cả công dụng thường ngày; thiếu lookup không chứng minh lành tính.

§4 THẬT: Xoá dấu vết sau lệnh đáng ngờ, cấp quyền rộng cho payload, reflection nạp mã lạ hoặc giả tên dịch vụ hệ thống. WMIC nạp thư viện script phải đối chiếu CommandLine, không kết luận chỉ vì tag T1220.

- `dfe-1`: playbook defense_evasion.md:27; §3 370 alerts: 110665 ×152 (level 8), 112519 ×50 (8), 110753 ×49 (3), 112466 ×34 (5), 110810 ×25 (8), 110915 ×22 (8), 92021 ×11 (3), 112520 ×6 (8); 6 other rules ×21, unspecified; bad-IoC policy, not a measured verdict.
- `dfe-2`: playbook defense_evasion.md:28; §3 370 alerts: 110665 ×152 (level 8), 112519 ×50 (8), 110753 ×49 (3), 112466 ×34 (5), 110810 ×25 (8), 110915 ×22 (8), 92021 ×11 (3), 112520 ×6 (8); 6 other rules ×21, unspecified; DEC-053 critical band, including unseen future rules.
- `dfe-3`: playbook defense_evasion.md:22 and :35; §3 370 alerts: 110665 ×152 (level 8), 112519 ×50 (8), 110753 ×49 (3), 112466 ×34 (5), 110810 ×25 (8), 110915 ×22 (8), 92021 ×11 (3), 112520 ×6 (8); 6 other rules ×21, unspecified; content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `dfe-1` IoC xấu → escalate; `dfe-2` level ≥12 → escalate; `dfe-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## execution

§3 FP: WMI kiểm kê, build tool hoặc dịch vụ chạy lệnh phù hợp ngữ cảnh quản trị được gửi. Một module được nạp chưa chứng minh mã độc; không có mẫu tấn công/benign đo riêng cho category này.

§4 THẬT: Ứng dụng văn phòng sinh shell rồi tải/chạy payload; WMI/service chạy lệnh encoded hoặc file lạ và có dấu vết tiếp nối. Chuỗi chỉ được viện dẫn khi các mắt xích có trong raw_log hoặc mẫu tương quan.

- `exe-1`: playbook execution.md:27; §3 0 alerts (no trial alert — ATT&CK only); lab-scenarios.md:476-527 describes malware execution, not an execution-labelled measurement; bad-IoC policy, not a measured verdict.
- `exe-2`: playbook execution.md:28; §3 0 alerts (no trial alert — ATT&CK only); lab-scenarios.md:476-527 describes malware execution, not an execution-labelled measurement; DEC-053 critical band, including unseen future rules.
- `exe-3`: playbook execution.md:22 and :35; §3 0 alerts (no trial alert — ATT&CK only); lab-scenarios.md:476-527 describes malware execution, not an execution-labelled measurement; content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `exe-1` IoC xấu → escalate; `exe-2` level ≥12 → escalate; `exe-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có alert execution; cần cặp attack/benign riêng trước khi đo. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## initial_access

§3 FP: Tài liệu có macro phục vụ công việc được mô tả trong context, nguồn và hành vi phù hợp. Chỉ tạo file mà chưa thấy chạy là giới hạn bằng chứng, không đủ tự đóng.

§4 THẬT: Office sinh shell, tải payload hoặc macro ghi/chạy mã từ thư mục tạm; nguồn lạ kèm chuỗi thực thi làm mạnh giả thuyết truy cập ban đầu.

- `ina-1`: playbook initial_access.md:27; §3 19 alerts: 110464 ×19 (level 5); bad-IoC policy, not a measured verdict.
- `ina-2`: playbook initial_access.md:28; §3 19 alerts: 110464 ×19 (level 5); DEC-053 critical band, including unseen future rules.
- `ina-3`: playbook initial_access.md:22 and :35; §3 19 alerts: 110464 ×19 (level 5); content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `ina-1` IoC xấu → escalate; `ina-2` level ≥12 → escalate; `ina-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## resource_development

§3 FP: 110256 Windows Update Error level 3 có mã lỗi và ngữ cảnh cập nhật bình thường: T1584 không chứng minh hạ tầng bị chiếm. Compiler/updater tạo executable với lệnh và đích phù hợp ngữ cảnh công việc cũng có thể lành tính.

§4 THẬT: Tiến trình lạ tạo payload, nén/đóng gói rồi chuyển hoặc triển khai trong mẫu; bằng chứng công cụ bị sửa và dùng tiếp làm mạnh giả thuyết. Một executable mới tạo không đủ quy kết phát triển mã độc.

- `rsd-1`: playbook resource_development.md:27; §3 50 alerts: 112431 ×33 (level 5), 110256 ×17 (3); bad-IoC policy, not a measured verdict.
- `rsd-2`: playbook resource_development.md:28; §3 50 alerts: 112431 ×33 (level 5), 110256 ×17 (3); DEC-053 critical band, including unseen future rules.
- `rsd-3`: playbook resource_development.md:22 and :35; §3 50 alerts: 112431 ×33 (level 5), 110256 ×17 (3); content needed to distinguish routine/attack, so review below critical without bad IoC.

Thứ tự: `rsd-1` IoC xấu → escalate; `rsd-2` level ≥12 → escalate; `rsd-3` level <12 và IoC not_found/clean/skipped → needs_review. `escalate` được nạp thành `true_positive`.

Câu hỏi chưa chốt: mẫu quản trị nào đủ bằng chứng để xác nhận nhánh §3? Chưa có nhãn analyst/gold cho nhóm này; chưa biết tỷ lệ thật. Các rule khác chỉ có tổng gộp, không suy diễn nội dung.

- [ ] signed

## Ba bẫy của §3

1. Tên nghiêm trọng, sự kiện thường: impact §3 giải thích logoff 110229; resource_development §3 giải thích Windows Update Error 110256. Đọc mục tiêu/lệnh/mã lỗi và mẫu, không suy từ tag.
2. Task/BITS: persistence §2–§4 đối chiếu action, trigger, đường dẫn và tiến trình gọi; updater/agent cần ngữ cảnh chứng thực, task trỏ nơi ghi được/lệnh encoded/script host cần điều tra.
3. Execution không có data: banner và header ghi implemented, not measured; chỉ suy từ ATT&CK trong mapping và chuỗi malware ở lab-scenarios.md:476-527. Không gọi đây là measurement execution.

## Khi sitting đã ký

Chỉ sau khi hai người xét/sửa và đồng ý, sửa đúng hai dòng trong từng bảng đã ký:

```yaml
reviewed_by: "<name>"
reviewed_at: "<ISO date>"
```

Không điền placeholder vào file thực. Giữ null cho mọi bảng chưa ký. Chạy lại kiểm tra loader/grid và test review gate:

```bash
PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python
$PY -m pytest -c backend/pyproject.toml backend/tests/test_kb_lookup.py -q
$PY -c 'import sys; sys.path.insert(0,"backend"); from app.kb.lookup import get_decision_table,check_consistency; t=get_decision_table("impact"); assert t.reviewed; assert not check_consistency(t)'
```

Thay `impact` bằng từng category đã ký; lệnh assert reviewed phải thất bại với bản nháp hiện tại. Test loader chứng minh hai trường đủ tạo cờ reviewed; không chứng minh chất lượng phán quyết của người ký. Việc đưa rule id tới ① và tái phân loại alert cũ là công việc riêng (§9).
