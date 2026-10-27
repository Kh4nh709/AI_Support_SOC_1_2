# Playbook · `credential_access` · `credential_access_v1`

> **agent-drafted 27/10 (S1), not reviewed** — bản nháp cho alert đánh cắp thông tin đăng nhập trên Windows (rule 111923, T1003). Chưa có chữ ký của Chủ đồ án và giảng viên; bảng `credential_access.yaml` để trống `reviewed_by`.

> Có thứ gì đó đọc bộ nhớ của `lsass.exe` — nơi Windows giữ hash, vé Kerberos và đôi khi cả mật khẩu của mọi tài khoản đang đăng nhập — MITRE ATT&CK **T1003 OS Credential Dumping** (T1003.001 LSASS Memory). Một lần dump thành công không dừng ở máy này: nó trao cho kẻ tấn công **mọi tài khoản đã từng đăng nhập vào máy**.

## 1 · Ba câu phân định

1. **Tiến trình nào** mở `lsass.exe`, và nó là công cụ bảo mật/hệ thống đã biết hay một tiến trình lạ?
2. Truy cập đó có **đọc được bộ nhớ** (đã dump, đã ghi ra file `.dmp`) hay chỉ là một lần thử bị chặn?
3. Sau đó các tài khoản trên máy có **bị dùng ở nơi khác** không?

## 2 · Kiểm gì — cụ thể

- `raw_log` là thông điệp sự kiện Windows (Sysmon 10 — ProcessAccess): đọc `SourceImage`, `TargetImage` (phải là `lsass.exe`), `GrantedAccess`, `CallTrace`.
- `GrantedAccess` có quyền đọc bộ nhớ (ví dụ `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`) khác hẳn quyền chỉ truy vấn thông tin.
- `CallTrace` chứa `dbghelp.dll`/`dbgcore.dll` (MiniDumpWriteDump) hoặc `UNKNOWN` (mã nạp thẳng vào bộ nhớ) là dấu hiệu dump có chủ đích.
- Dòng lệnh và tiến trình cha của `SourceImage` (Sysmon 1): `procdump … lsass`, `rundll32 comsvcs.dll, MiniDump`, `sekurlsa::`, tên công cụ lạ.
- File `.dmp` mới xuất hiện (Sysmon 11), đặc biệt ở `Temp`, `Public`, `ProgramData` hay thư mục người dùng; file đó có bị nén hoặc gửi đi không.
- `alert_user` chạy tiến trình; tiến trình bật `SeDebugPrivilege` bằng cách nào.
- Alert của cùng `agent_name` trong 24 giờ trước và sau: `malware`, `privilege_escalation`, `suspicious_login`, `c2_beacon`, `data_exfiltration`.
- Máy bật LSA Protection (RunAsPPL) hay Credential Guard không — nếu bật, truy cập hỏng là dấu hiệu bị chặn, không phải bằng chứng vô hại.

## 3 · Nghiêng về FALSE POSITIVE khi

- Phần mềm bảo mật hoặc EDR đã đăng ký truy cập `lsass.exe` đúng cách: đường dẫn cài đặt chuẩn, chữ ký hợp lệ, lặp đều theo nhịp cố định.
- Quản trị viên chủ đích tạo dump để chẩn đoán sự cố (Task Manager, `procdump`): có phiếu yêu cầu, đúng giờ, từ máy quản trị, và file `.dmp` được cất hoặc xoá đúng quy trình.
- Cơ chế báo lỗi của hệ điều hành (`WerFault.exe`) hoặc công cụ giám sát đã biết chạm vào tiến trình hệ thống.
- Diễn tập hoặc kiểm thử xâm nhập có kế hoạch, trùng lịch đã đăng ký — đối chiếu lịch trước khi kết luận.

## 4 · Nghiêng về THẬT khi

- Tiến trình **không phải công cụ bảo mật** mở `lsass.exe` với quyền đọc bộ nhớ.
- Công cụ dump quen thuộc hoặc dòng lệnh dạng `comsvcs.dll, MiniDump`, chạy từ thư mục người dùng hoặc thư mục tạm.
- Có file `.dmp` mới ở nơi lạ, hoặc ngay sau đó là nén file và kết nối ra ngoài.
- Ngay sau đó tài khoản từng đăng nhập trên máy xuất hiện ở **máy khác** (đăng nhập qua mạng, 4648, 4672) — dùng lại thông tin vừa lấy.
- Trước đó có `privilege_escalation` hoặc `malware` trên cùng máy; tiến trình thường bỗng có `SeDebugPrivilege`.
- `ioc_context` báo `malicious`/`suspicious` cho hash của tiến trình hoặc IP máy này kết nối.

## 5 · Ngữ cảnh làm đổi kết luận

- `asset_context.criticality = high` (nhất là máy điều khiển miền) → hạ ngưỡng; `unknown` (không có trong kiểm kê) → **không** kết luận vô hại, xử lý như `high` cho tới khi kiểm kê trả lời.
- `identity_context.is_privileged = true` cho tài khoản đang đăng nhập trên máy → nâng mức: tài khoản đó coi như đã lộ nếu dump thành công.
- Alert loại này thường không có IP nên `ioc_context` hay là `skipped`; `lookup_status` thiếu **không** phải bằng chứng vô hại.
- Dump đã thành công = **mọi tài khoản từng đăng nhập vào máy** coi như lộ, kể cả sau khi máy được dọn.

## 6 · Chưa kết luận được thì cần thêm

- Nhật ký Sysmon của `agent_name` trong ±1 giờ: sự kiện 1 (tạo tiến trình), 10 (truy cập tiến trình), 11 (tạo file).
- Danh sách tài khoản đã đăng nhập vào máy trong 7 ngày trước.
- Đăng nhập (4624/4648/4672) của các tài khoản đó trên máy khác trong 24 giờ sau.
- Phiếu yêu cầu hoặc lịch kiểm thử xâm nhập tương ứng.
