#!/usr/bin/env python3
"""Quét 8 tệp đặc tả, truy vết mỗi tên cột về tệp:dòng.
Chạy TRƯỚC khi viết DDL. Không đoán: cột nào không tìm thấy nguồn -> báo đỏ."""
import re, json, pathlib, collections

SRC = pathlib.Path("/mnt/user-data/uploads")
PROJ = pathlib.Path("/mnt/project")
FILES = [
    ("KT",  SRC / "kien-truc-tong-quat-va-chi-tiet.md"),
    ("P1",  SRC / "phase-1-tiep-nhan-chuan-hoa.md"),
    ("P2",  SRC / "phase-2-chong-trung-lap.md"),
    ("P3",  SRC / "phase-3-auto-close.md"),
    ("P4",  SRC / "phase-4-enrichment.md"),
    ("P5",  SRC / "phase-5-auto-triage.md"),
    ("P6",  SRC / "phase-6-tier1.md"),
    ("P7",  SRC / "phase-7-tier2.md"),
    ("HTML", PROJ / "luong-du-lieu-theo-package.html"),
]

# Danh sách cột ứng viên, gom theo bảng. Rút ra từ lần đọc thủ công cả 8 tệp.
CANDIDATES = {
"alerts": """alert_id rule_id rule_level severity description category categories
 resolved_by mapping_version srcip dstip src_port dst_port alert_user agent_id
 agent_name agent_ip decoder mitre_ids rule_groups alert_time event_time raw_log
 srcip_is_private dstip_is_private raw_log_truncated source is_synthetic status
 event_bucket_hash duplicate_of occurrence_count risk_score risk_score_components
 triage_status triaged_count case_id acknowledged_at acknowledged_by closed_at
 sealed_at close_reason autoclose_rule_id asset_context identity_context
 ioc_context lookup_status raw_payload received_at first_seen_at last_seen_at""".split(),
"cases": """case_id title status severity created_by created_at conclusion_reason
 concluded_by concluded_at last_analyzed_at""".split(),
"case_alerts": "case_id alert_id added_by added_at".split(),
"jobs": "job_id job_type subject_id status scheduled_at locked_at attempts last_error".split(),
"audit_events": "event_type subject_id actor_id actor_role payload created_at".split(),
"llm_runs": """run_id pipeline subject_type subject_id system_prompt user_message
 agent_trace result injection_findings citation_warnings input_tokens output_tokens
 latency_ms created_at""".split(),
"assets": "hostname criticality".split(),
"identities": "username is_privileged".split(),
"iocs": "value reputation expires_at".split(),
"autoclose_rules": "rule_id name enabled match reason created_by created_at".split(),
"rejected_alerts": "payload reason source_ip".split(),
}

lines = {}
for tag, p in FILES:
    lines[tag] = p.read_text(encoding="utf-8").splitlines()

def find(col):
    """Trả về [(tag, lineno, text)] cho mọi lần xuất hiện như một định danh."""
    pat = re.compile(r'(?<![A-Za-z0-9_.])' + re.escape(col) + r'(?![A-Za-z0-9_])')
    hits = []
    for tag, _ in FILES:
        for i, ln in enumerate(lines[tag], 1):
            if pat.search(ln):
                hits.append((tag, i, ln.strip()[:110]))
    return hits

report = {}
for table, cols in CANDIDATES.items():
    report[table] = {}
    for col in cols:
        report[table][col] = find(col)

# In bảng truy vết
out = []
missing = []
single = []
for table, cols in report.items():
    out.append(f"\n=== {table} ({len(cols)} cột) ===")
    for col, hits in cols.items():
        tags = sorted({t for t, _, _ in hits})
        n = len(hits)
        if n == 0:
            missing.append(f"{table}.{col}")
            out.append(f"  !! {col:26s} KHÔNG TÌM THẤY")
            continue
        if len(tags) == 1:
            single.append(f"{table}.{col} -> chỉ {tags[0]}")
        first = hits[0]
        out.append(f"  {col:26s} {n:3d} lần · {','.join(tags):22s} · đầu: {first[0]}:{first[1]}")

print("\n".join(out))
print("\n\n### CỘT KHÔNG TRUY ĐƯỢC VỀ TỆP NÀO ###")
print("\n".join(missing) if missing else "(không có)")
print("\n### CỘT CHỈ XUẤT HIỆN Ở ĐÚNG MỘT TỆP ###")
print("\n".join(single) if single else "(không có)")

json.dump({t: {c: [[h[0], h[1], h[2]] for h in hs] for c, hs in cs.items()}
           for t, cs in report.items()},
          open("/home/claude/trace.json", "w"), ensure_ascii=False, indent=1)
print(f"\nTổng số cột ứng viên: {sum(len(c) for c in CANDIDATES.values())}")
print(f"alerts: {len(CANDIDATES['alerts'])} cột")
