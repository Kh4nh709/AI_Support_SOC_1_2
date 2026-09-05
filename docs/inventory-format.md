# Định dạng ba tệp inventory (`conf/`)

Ba tệp dưới đây do **người vận hành viết tay**. Chúng là nguồn duy nhất của ngữ cảnh
nội bộ mà hệ thống dùng để làm giàu cảnh báo: host quan trọng đến mức nào, tài khoản
có đặc quyền không, chỉ dấu (IoC) nào đã biết là xấu.

| Tệp | Bảng trong CSDL | Nội dung |
|---|---|---|
| `conf/inventory.yaml` | `assets` | danh sách host của hệ thống |
| `conf/identities.yaml` | `identities` | tài khoản xuất hiện trong cảnh báo |
| `conf/iocs.csv` | `iocs` | IP/tên miền đã biết, kèm hạn dùng |

Đường dẫn do khóa cấu hình `INVENTORY_PATHS` trong `.env` quyết định; giá trị mặc định
là một **mảng JSON** đúng ba đường dẫn trên:

```
INVENTORY_PATHS=["conf/inventory.yaml","conf/identities.yaml","conf/iocs.csv"]
```

Sai JSON, hoặc JSON không phải mảng chuỗi, là **lỗi cấu hình** — trình kiểm tra báo tên
khóa `INVENTORY_PATHS` chứ không âm thầm quay về mặc định. Chỉ khi biến không được đặt
(hoặc rỗng) thì ba đường dẫn mặc định mới được dùng.

Ba tệp thật nằm ngoài git (`.gitignore`); ba tệp `*.example` đi kèm repo là bản mẫu để
sao chép. Tệp được nhận dạng **theo nội dung**, không theo tên: đổi tên tệp vẫn kiểm tra
đúng, đổi thứ tự trong `INVENTORY_PATHS` cũng không sao.

---

## 1. `conf/inventory.yaml` — tài sản (`assets`)

```yaml
version: 1
assets:
  - hostname: user1-IA1803
    criticality: medium
    owner: "Nguyen Van A"
    role: "lab workstation"
```

| Trường | Kiểu | Bắt buộc | Giá trị cho phép |
|---|---|---|---|
| `version` | số nguyên | có (ở mức trên cùng) | `1` |
| `hostname` | chuỗi | **có** | khớp với `alerts.agent_name`, sau đó `alerts.origin_host`; là khóa chính, **không được trùng** trong cùng tệp |
| `criticality` | chuỗi | **có** | `high` \| `medium` \| `low` \| `unknown` |
| `owner` | chuỗi | không | văn bản tự do, tối đa 200 ký tự |
| `role` | chuỗi | không | văn bản tự do, tối đa 200 ký tự |

Bốn giá trị của `criticality` là **đúng một bộ từ vựng duy nhất**: bộ này dùng chung cho
tệp YAML, cho CHECK của cột `assets.criticality` trong CSDL (DEC-004) và cho trường
`structured_basis.asset_criticality` trong lược đồ đầu ra của mô hình (§6.2). Vì cả ba
chỗ dùng chung một bộ, **không có bảng ánh xạ nào cả** — bước 2 của gate so sánh thẳng
từng trường giữa câu trả lời của mô hình và dữ liệu CSDL. Bộ giá trị bốn mức của v1 đã bị
DEC-004 bỏ; nếu chép lại từ tài liệu cũ, trình kiểm tra sẽ báo lỗi và nhắc tên DEC-004.

### `unknown` khác với việc bỏ host ra khỏi tệp

Cả hai trường hợp đều cho mô hình thấy `asset_criticality: unknown`, nhưng với G8′ chúng
**khác nhau**: host **không có** trong inventory là một chốt chặn cứng — cảnh báo của nó
không bao giờ được tự động đóng; host **có mặt** với `criticality: unknown` thì không bị
chặn vì lý do đó. Vậy nên: dùng `unknown` cho host thuộc hệ thống nhưng **chưa kịp đánh
giá**, và chỉ bỏ host ra khỏi tệp khi nó thật sự **không phải của mình**. Ghi thiếu một
host là an toàn (chặn nhiều hơn); ghi nhầm nó thành `unknown` thì nới rộng tự động đóng
một cách âm thầm.

### `owner` và `role` đi vào prompt

Hai trường này là văn bản tự do và **được đưa tới mô hình chỉ bên trong khối
`<untrusted_data nonce=…>`** (§7.1), không bao giờ nằm ngoài khối. Người viết chúng nên
biết chỗ chúng đi tới: đừng đặt vào đó mật khẩu, khóa, hay chỉ dẫn dạng câu lệnh.

---

## 2. `conf/identities.yaml` — tài khoản (`identities`)

```yaml
version: 1
identities:
  - username: user1
    is_privileged: false
```

| Trường | Kiểu | Bắt buộc | Ghi chú |
|---|---|---|---|
| `version` | số nguyên | có (ở mức trên cùng) | `1` |
| `username` | chuỗi | **có** | khớp với `alerts.alert_user`; khóa chính, **không được trùng** |
| `is_privileged` | boolean | không (mặc định `false`) | viết `true` / `false` **không đặt trong nháy** |

`is_privileged: "false"` (có nháy) là một **chuỗi**, không phải boolean — đây là cái bẫy
quen thuộc của YAML và trình kiểm tra báo lỗi cho nó. Bỏ trống trường này nghĩa là
`false`, đúng như giá trị mặc định của cột trong CSDL; tài khoản có đặc quyền là một
chốt chặn cứng của G8′ nên hãy ghi `true` một cách tường minh.

Chỉ có đúng hai cột này. Không thêm tên hiển thị, phòng ban… — CSDL không có chỗ chứa.

---

## 3. `conf/iocs.csv` — chỉ dấu (`iocs`)

```
value,reputation,expires_at,source
203.0.113.10,malicious,2030-12-31T00:00:00Z,manual
```

| Cột | Kiểu | Bắt buộc | Giá trị cho phép |
|---|---|---|---|
| `value` | chuỗi | **có** | IP hoặc tên miền; khóa chính, **không được trùng** |
| `reputation` | chuỗi | **có** | `malicious` \| `suspicious` \| `clean` |
| `expires_at` | chuỗi | **có** | ISO-8601 **có múi giờ**, ví dụ `2030-12-31T00:00:00Z` |
| `source` | chuỗi | không | nguồn của chỉ dấu, văn bản tự do |

Truy vấn làm giàu là `... WHERE value IN ($srcip,$dstip) AND expires_at > now()`, nên một
dòng đã hết hạn là **vô hình** chứ không phải sai. Trình kiểm tra vẫn báo dòng đó, với
tiền tố `warning:`, để nó không mục ruỗng trong tệp mà không ai biết.

`not_found` và `skipped` là hai chuyện khác nhau (§6.2): giá trị **không có** trong tệp
này cho ra `not_found`, còn phép tra cứu **không được thực hiện** cho ra `skipped`. G8′
chỉ chặn tự động đóng với `malicious` và `suspicious`.

**Chú thích trong CSV là hợp lệ** (DEC-007): dòng trống và dòng có ký tự đầu tiên (bỏ qua
khoảng trắng) là `#` đều bị bỏ qua khi nạp. Dấu `#` nằm trong một trường có nháy kép là
một phần của giá trị, không phải chú thích. Hãy giữ **dòng tiêu đề ở ngay dòng đầu tệp**
để các công cụ CSV thông thường (bảng tính, `csv.DictReader`) đọc được; phần ghi chú đặt
bên dưới dữ liệu, như trong `conf/iocs.csv.example`.

---

## 4. Khi nạp lại (P2)

Việc nạp vào CSDL do P2 làm, qua `POST /api/admin/reload-inventory`. Khi đó mỗi dòng được
upsert kèm `source` (tên tệp), `loaded_at` và `active = true`. Dòng **biến mất khỏi tệp**
sẽ bị đánh dấu `active = false`, **không bị xóa** — lịch sử làm giàu của các cảnh báo cũ
vẫn truy được. Xóa một host khỏi `conf/inventory.yaml` vì thế cũng có nghĩa là từ lúc đó
host ấy trở lại trạng thái "không có trong inventory" đối với G8′.

## 5. Lệnh tự kiểm tra

Chạy ở thư mục gốc của repo, **không cần CSDL**:

```bash
python3 -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print('\n'.join(validate()) or 'OK')"
```

In ra `OK` nghĩa là ba tệp dùng được. Ngược lại, mỗi dòng là một vấn đề, luôn nêu **tên
tệp**, **vị trí** (chỉ số phần tử hoặc tên khóa) và **giá trị được mong đợi**. Dòng bắt
đầu bằng `warning:` là cảnh báo (ví dụ IoC đã hết hạn): tệp vẫn nạp được, nhưng gần như
chắc chắn không phải điều người viết muốn — danh sách trả về vẫn khác rỗng.
