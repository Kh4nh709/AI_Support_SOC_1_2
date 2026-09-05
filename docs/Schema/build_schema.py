# -*- coding: utf-8 -*-
"""build_schema.py — ghép migrations NNN_*.sql thành schema.sql.

Header của schema.sql viện dẫn tệp này từ đầu, nhưng nó chưa từng tồn tại trong
repo — nghĩa là schema.sql đã được ghép bằng tay và câu "KHÔNG SỬA TRỰC TIẾP"
không có gì bảo đảm. Tệp này làm câu đó thành sự thật.

Chạy:  python3 build_schema.py          # ghi schema.sql
       python3 build_schema.py --check  # chỉ kiểm, exit 1 nếu schema.sql đã lệch

`--check` là thứ đặt được vào CI: nó bắt đúng ca "ai đó sửa thẳng schema.sql".
"""
import pathlib, re, sys, difflib

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "schema.sql"
PAT = re.compile(r"^(\d{3})_.*\.sql$")

HEADER = """BEGIN;
-- ============================================================================
-- schema.sql — AI Support SOC · toàn bộ schema PostgreSQL
--
-- TỆP NÀY ĐƯỢC SINH TỰ ĐỘNG bằng cách ghép migrations/*.sql theo thứ tự.
-- KHÔNG SỬA TRỰC TIẾP — sửa migration rồi chạy lại build_schema.py.
--   Kiểm trong CI:  python3 build_schema.py --check
--
-- Nguồn : {nguon}
-- Đích  : PostgreSQL 16 (đã chạy thử trên 16.15)
-- Dùng  : psql -d <db> -v ON_ERROR_STOP=1 -f schema.sql
--
-- Mọi giá trị trong tệp này truy được về một dòng cụ thể trong bộ đặc tả
-- Phase 1-7 + kiến trúc tổng quát. Bảng truy vết đầy đủ: schema-notes.md.
-- ============================================================================

"""

KHUNG = """
-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ NGUỒN: migrations/{ten}
-- └──────────────────────────────────────────────────────────────────────────┘
"""


def than(sql: str) -> str:
    """Bỏ BEGIN;/COMMIT; của từng migration — schema.sql bọc bằng MỘT transaction.

    BEGIN; không nhất thiết nằm ở dòng đầu: migration mở bằng một khối comment.
    Nên bỏ theo NỘI DUNG dòng, không theo vị trí — và chỉ bỏ dòng đứng riêng,
    để không đụng vào chữ BEGIN trong thân một khối plpgsql.
    """
    lines = sql.splitlines()
    da_bo_begin = False
    giu = []
    for l in lines:
        s = l.strip().upper()
        if s == "BEGIN;" and not da_bo_begin:
            da_bo_begin = True
            continue
        giu.append(l)
    while giu and giu[-1].strip().upper() in ("COMMIT;", ""):
        giu.pop()
    return "\n".join(giu)


def dung() -> str:
    tep = sorted(p for p in HERE.iterdir() if PAT.match(p.name))
    if not tep:
        print("Không tìm thấy migration nào (NNN_*.sql)", file=sys.stderr)
        raise SystemExit(2)
    phan = [HEADER.format(nguon=", ".join(p.name for p in tep))]
    for p in tep:
        phan.append(KHUNG.format(ten=p.name))
        phan.append(than(p.read_text(encoding="utf-8")))
        phan.append("\n")
    phan.append("\nCOMMIT;\n")
    return "".join(phan)


def main() -> int:
    moi = dung()
    if "--check" in sys.argv:
        cu = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if cu == moi:
            print(f"schema.sql khớp migrations · {len(moi.splitlines())} dòng")
            return 0
        print("schema.sql ĐÃ LỆCH khỏi migrations. Khác biệt:")
        for l in list(difflib.unified_diff(cu.splitlines(), moi.splitlines(),
                                           "schema.sql (trên đĩa)", "ghép từ migrations",
                                           lineterm=""))[:40]:
            print("  " + l)
        print("\nSửa: python3 build_schema.py")
        return 1
    OUT.write_text(moi, encoding="utf-8")
    print(f"đã ghi {OUT.name} · {len(moi.splitlines())} dòng · "
          f"{len([p for p in HERE.iterdir() if PAT.match(p.name)])} migration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
