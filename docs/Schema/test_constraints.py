#!/usr/bin/env python3
"""Thử vi phạm TỪNG ràng buộc. Mỗi ca phải bị DB chặn.
Ca nào lọt qua = ràng buộc chỉ là quy ước, không phải cưỡng chế."""
import subprocess, hashlib, textwrap, os

H = hashlib.sha256(b"x").hexdigest()
BASE = """alert_id,rule_id,rule_level,severity,description,agent_name,alert_time,
category,resolved_by,mapping_version,event_bucket_hash,raw_payload"""

def cols_vals(**over):
    d = dict(alert_id="'T-@N@'", rule_id="'40112'", rule_level="12",
             severity="'critical'", description="'x'", agent_name="'a1'",
             alert_time="now()", category="'ssh_brute_force'", resolved_by="'mitre'",
             mapping_version="'v1'", event_bucket_hash=f"'{H}'", raw_payload="'{}'::jsonb")
    d.update(over)
    return ",".join(d.keys()), ",".join(d.values())

CASES = []
def case(ten, rang_buoc, sql):
    CASES.append((ten, rang_buoc, sql))

def ins(n, **over):
    c, v = cols_vals(**over)
    return f"INSERT INTO alerts ({c}) VALUES ({v.replace('@N@', str(n))});"

# ── G4 (KT:380) ─────────────────────────────────────────────────────────────
case("G4 · srcip = NULL", "not-null srcip", ins(1, srcip="NULL"))
case("G4 · dstip = NULL", "not-null dstip", ins(2, dstip="NULL"))

# ── C2 (KT:418) ─────────────────────────────────────────────────────────────
case("C2 · src_port = NULL", "not-null src_port", ins(3, src_port="NULL"))
case("C2 · dst_port = NULL", "not-null dst_port", ins(4, dst_port="NULL"))

# ── G3 (KT:379) · 5 trạng thái terminal, thiếu closed_at ────────────────────
# 'duplicate' CỐ Ý không nằm trong vòng này. ck_alerts_ban_sao_phai_seal_va_tro_goc
# đòi (duplicate_of IS NOT NULL AND closed_at IS NOT NULL AND sealed_at IS NOT NULL),
# tức nó MẠNH HƠN HẲN G3 ở nhánh 'duplicate' và luôn nổ trước. G3 không cô lập được ở
# đó — ca dưới đây kiểm đúng ràng buộc thật sự chặn, thay vì gán nhầm công cho G3.
for i, st in enumerate(["auto_closed","closed_fp","closed_benign","closed_confirmed"]):
    case(f"G3 · status='{st}' mà closed_at NULL",
         "ck_alerts_g3_terminal_phai_co_closed_at",
         ins(10+i, status=f"'{st}'", sealed_at="now()"))

case("P2 · duplicate không có closed_at (G3 bị bao trùm ở nhánh này)",
     "ck_alerts_ban_sao_phai_seal_va_tro_goc",
     ins(14, status="'duplicate'", sealed_at="now()", duplicate_of="NULL"))

# ── H2 (P6:263) · đóng bởi người mà không seal ───────────────────────────────
for i, st in enumerate(["closed_fp","closed_benign","closed_confirmed"]):
    case(f"H2 · status='{st}' có closed_at nhưng sealed_at NULL",
         "ck_alerts_h2_dong_boi_nguoi_phai_seal",
         ins(20+i, status=f"'{st}'", closed_at="now()"))

# ── 021 · DEC-212 · 'archived' là trạng thái terminal MỚI của alerts ─────────
# Nó chịu G3 (phải có closed_at) VÀ H2 (phải có sealed_at): một đầu cụm bị lưu trữ thôi hút bản sao.
case("021 · G3 · status='archived' mà closed_at NULL",
     "ck_alerts_g3_terminal_phai_co_closed_at",
     ins(15, status="'archived'", sealed_at="now()"))
case("021 · H2 · status='archived' có closed_at nhưng sealed_at NULL",
     "ck_alerts_h2_dong_boi_nguoi_phai_seal",
     ins(23, status="'archived'", closed_at="now()"))
case("021 · status = 'archive' (gõ thiếu một chữ)", "ck_alerts_status",
     ins(24, status="'archive'", closed_at="now()", sealed_at="now()"))

# ── H3 (P6:264) · escalate mà lại seal ──────────────────────────────────────
case("H3 · escalated_tier2 có sealed_at", "ck_alerts_h3_escalate_khong_seal",
     ins(30, status="'escalated_tier2'", sealed_at="now()"))

# ── P2:255 · bản sao thiếu sealed_at / thiếu duplicate_of ────────────────────
case("P2 · duplicate không có sealed_at", "ck_alerts_ban_sao_phai_seal_va_tro_goc",
     ins(40, status="'duplicate'", closed_at="now()",
         duplicate_of="(SELECT alert_id FROM alerts WHERE duplicate_of IS NULL LIMIT 1)"))
case("P2 · duplicate không có duplicate_of", "ck_alerts_ban_sao_phai_seal_va_tro_goc",
     ins(41, status="'duplicate'", closed_at="now()", sealed_at="now()"))

# ── Tập giá trị ─────────────────────────────────────────────────────────────
case("M-A · alerts.status = 'concluded_fp' (giá trị của CASES)", "ck_alerts_status",
     ins(50, status="'concluded_fp'", closed_at="now()", sealed_at="now()"))
case("M-B · triage_status = 'done' (chữ cũ ở P3:178)", "ck_alerts_triage_status",
     ins(51, triage_status="'done'"))
case("severity ngoài 4 giá trị", "ck_alerts_severity", ins(52, severity="'urgent'"))

# ── Ràng buộc số / định dạng ────────────────────────────────────────────────
case("E2 · risk_score = 101 (trần 100, P4:168)", "ck_alerts_risk_score_0_100",
     ins(60, risk_score="101"))
case("E2 · risk_score = -1", "ck_alerts_risk_score_0_100", ins(61, risk_score="-1"))
case("C1/B6 · event_bucket_hash không phải sha256 hex 64", "ck_alerts_hash_sha256_hex",
     ins(62, event_bucket_hash="'khong-phai-hash'"))
case("D3 · occurrence_count = 0", "ck_alerts_occurrence_toi_thieu_1",
     ins(63, occurrence_count="0"))
case("D6 · last_seen_at < first_seen_at", "ck_alerts_last_seen_khong_lui",
     ins(64, first_seen_at="now()", last_seen_at="now() - interval '1 hour'"))
case("Tự tham chiếu · duplicate_of = alert_id", "ck_alerts_khong_tu_tro",
     ins(65, status="'duplicate'", closed_at="now()", sealed_at="now()",
         duplicate_of="'T-65'"))
case("C3 · raw_log vượt 1.024.000 byte", "ck_alerts_raw_log_tran_1000kb",
     ins(66, raw_log="repeat('a', 1024001)"))

# ── cases ───────────────────────────────────────────────────────────────────
case("cases · kết luận mà không có concluded_at",
     "ck_cases_ket_luan_phai_co_moc",
     "INSERT INTO cases (case_id,title,status,severity,created_by) VALUES "
     "('00000000-0000-4000-8000-00000000dead','t','confirmed_incident','high',"
     "'00000000-1111-4000-8000-000000000001');")
# Phải cấp ĐỦ ba cột mốc, nếu không ck_cases_ket_luan_phai_co_moc nổ trước và
# ck_cases_status không bao giờ được kiểm.
case("cases · status ngoài 5 giá trị", "ck_cases_status",
     "INSERT INTO cases (case_id,title,status,severity,created_by,"
     "concluded_at,concluded_by,conclusion_reason) VALUES "
     "('00000000-0000-4000-8000-00000000beef','t','closed_fp','high',"
     "'00000000-1111-4000-8000-000000000001',now(),"
     "'00000000-1111-4000-8000-000000000001','r');")

# ── 021 · DEC-212 · cases.status = 'archived' ───────────────────────────────
# Một case bị lưu trữ không do ai kết luận: concluded_by được phép NULL, và CHỈ nó. Mốc kết luận
# và lý do thì vẫn bắt buộc; ba kết luận của người giữ nguyên luật cũ (đủ cả ba cột).
CASE_U = "'00000000-1111-4000-8000-000000000001'"
case("021 · case 'archived' mà không có concluded_at",
     "ck_cases_ket_luan_phai_co_moc",
     "INSERT INTO cases (case_id,title,status,severity,created_by,conclusion_reason) VALUES "
     f"('00000000-0000-4000-8000-00000000d001','t','archived','high',{CASE_U},'DEC-212');")
case("021 · case 'archived' mà không có conclusion_reason",
     "ck_cases_ket_luan_phai_co_moc",
     "INSERT INTO cases (case_id,title,status,severity,created_by,concluded_at) VALUES "
     f"('00000000-0000-4000-8000-00000000d002','t','archived','high',{CASE_U},now());")
for i, st in enumerate(["concluded_fp", "concluded_policy_violation", "confirmed_incident"]):
    case(f"021 · case '{st}' mà concluded_by NULL (chỉ 'archived' được miễn)",
         "ck_cases_ket_luan_phai_co_moc",
         "INSERT INTO cases (case_id,title,status,severity,created_by,concluded_at,"
         "conclusion_reason) VALUES "
         f"('00000000-0000-4000-8000-00000000d01{i}','t','{st}','high',{CASE_U},now(),'r');")

# ── llm_runs ────────────────────────────────────────────────────────────────
def LR(rid, pipe, subt, res):
    return ("INSERT INTO llm_runs (run_id,pipeline,subject_type,subject_id,"
            "system_prompt,user_message,result) VALUES "
            f"('{rid}','{pipe}','{subt}','s','p','u',{res});")
case("M-C · pipeline sai cặp: triage trên subject_type='case'",
     "ck_llm_runs_pipeline_khop_subject",
     LR("00000000-0000-4000-8000-00000000aa01","triage","case","NULL"))
case("P5-5 · suggested_action ngoài tập ba giá trị",
     "ck_llm_runs_suggested_action",
     LR("00000000-0000-4000-8000-00000000aa02","triage","alert",
        """'{\"suggested_action\":\"close\"}'::jsonb"""))
# ── 022 · DEC-213 · ① đổi tên `escalate` thành `true_positive` ──────────────────────────────
# Tập ba giá trị của ① là chặt: `false_positive | needs_review | true_positive`. Tên cũ không còn
# vào được (CSDL cũ đã xóa; 022 từ chối chạy khi còn một run `triage` ghi `escalate`).
case("022 · suggested_action = 'escalate' (tên cũ của ①) không còn vào được",
     "ck_llm_runs_suggested_action",
     LR("00000000-0000-4000-8000-00000000aa04","triage","alert",
        """'{\"suggested_action\":\"escalate\"}'::jsonb"""))
case("022 · suggested_action = 'true_positive ' (thừa một dấu cách) không vào được",
     "ck_llm_runs_suggested_action",
     LR("00000000-0000-4000-8000-00000000aa05","triage","alert",
        """'{\"suggested_action\":\"true_positive \"}'::jsonb"""))
case("P7 · suggested_conclusion ngoài tập bốn giá trị",
     "ck_llm_runs_suggested_conclusion",
     LR("00000000-0000-4000-8000-00000000aa03","investigate","case",
        """'{\"suggested_conclusion\":\"maybe\"}'::jsonb"""))
# event_type phải HỢP LỆ ở đây: từ migration 008, 'x' sẽ bị ck_audit_event_type
# chặn trước và ca này sẽ đỏ vì SAI ràng buộc — ca kiểm phải cô lập đúng một cái.
case("audit_events · actor_role lạ", "ck_audit_actor_role",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) "
     "VALUES ('alert.auto_closed','y','robot');")
case("jobs · job_type ngoài {enrich,triage}", "ck_jobs_job_type",
     "INSERT INTO jobs (job_type,subject_id) VALUES ('cleanup','x');")
case("assets · criticality lạ", "ck_assets_criticality",
     "INSERT INTO assets (hostname,criticality) VALUES ('h','vip');")
case("iocs · reputation lạ", "ck_iocs_reputation",
     "INSERT INTO iocs (value,reputation,expires_at) VALUES ('1.2.3.4','bad',now());")


# ── 008/009/010/012 · ràng buộc thêm sau vòng chốt của người chủ trì (28/08) ──
case("R-D5-1 · event_type gõ sai một ký tự vẫn vào được (lớp lỗi D5 sinh ra để chặn)",
     "ck_audit_event_type",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) "
     "VALUES ('tier1.decidedd','y','system');")
case("021 · event_type gõ thiếu một chữ ('alert.archive') không vào được",
     "ck_audit_event_type",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) "
     "VALUES ('alert.archive','y','system');")
# ── 023 · DEC-213 · job `knowledge_embed`, và `rag_results.failure_kind` ─────────────────────
# failure_kind chỉ có nghĩa khi lookup `failed`, và chỉ là một trong sáu loại đóng.
RR = ("INSERT INTO rag_results (lookup_id,subject_kind,subject_id,status,failure_kind) VALUES "
      "('00000000-0000-4000-8000-00000000e0@N@','alert','a1',{st},{fk});")
case("023 · failure_kind trên dòng 'ok' (chỉ 'failed' mới có lý do)",
     "ck_rag_results_failure_kind", RR.format(st="'ok'", fk="'rate_limit'").replace("@N@", "a1"))
case("023 · failure_kind trên dòng 'empty'",
     "ck_rag_results_failure_kind", RR.format(st="'empty'", fk="'timeout'").replace("@N@", "a2"))
case("023 · failure_kind trên dòng 'budget'",
     "ck_rag_results_failure_kind", RR.format(st="'budget'", fk="'auth'").replace("@N@", "a3"))
case("023 · failure_kind ngoài sáu loại đóng trên dòng 'failed'",
     "ck_rag_results_failure_kind", RR.format(st="'failed'", fk="'network'").replace("@N@", "a4"))
case("023 · job_type 'knowledge_embedd' (gõ thừa một chữ) không vào được", "ck_jobs_job_type",
     "INSERT INTO jobs (job_type,subject_id) VALUES ('knowledge_embedd','x');")
# ── 024 · DEC-213 · lab_runs, lab_labels, và hai event `lab.*` ───────────────────────────────
# Một run của lab là cửa sổ [starts_at, ends_at): kết thúc phải SAU bắt đầu, và hai cửa sổ không bao giờ
# chồng nhau (EXCLUDE trên tstzrange '[)'). Mỗi alert có tối đa một nhãn TP/FP.
LAB_U = "'00000000-1111-4000-8000-000000000001'"
def LRUN(sfx, name="'r'", purpose="'test'", st="'2026-11-05 09:00+00'", en="'2026-11-05 11:00+00'"):
    return ("INSERT INTO lab_runs (run_id,name,purpose,starts_at,ends_at,created_by) VALUES "
            f"('00000000-0000-4000-8000-00000000f0{sfx}',{name},{purpose},{st},{en},{LAB_U});")
# ── 025 · phiếu phản hồi SOAR (soar_reviews) và hai event `soar.*` ───────────────────────────
# Tập đóng của kind/status, và một hàng 'processing' phải có đủ ba cột của khóa.
def SREV(id_, kind="'review'", status="'open'", extra=""):
    cols = "id,kind,status,created_at,last_sent_at,raw" + (extra and "," + extra.split("=")[0])
    vals = f"'{id_}',{kind},{status},now(),now(),'{{}}'::jsonb" + (extra and "," + extra.split("=")[1])
    return f"INSERT INTO soar_reviews ({cols}) VALUES ({vals});"
case("025 · soar_reviews kind='ticket' (ngoài review|notice)", "ck_soar_reviews_kind",
     SREV("S1", kind="'ticket'"))
case("025 · soar_reviews status='processing ' (thừa dấu cách)", "ck_soar_reviews_status",
     SREV("S2", status="'processing '"))
case("025 · soar_reviews status='processing' không có khóa", "ck_soar_reviews_processing_lock",
     SREV("S3", status="'processing'"))
case("025 · soar_reviews prev_status='processing'", "ck_soar_reviews_prev_status",
     SREV("S4", extra="prev_status='processing'"))
# ── 026 · Threat Intel (ti_ioc, ti_import_log) ───────────────────────────────────────────────
# Ba nguồn của abuse.ch (tập đóng), confidence 0..100 hoặc NULL, hit_count và các số đếm không âm,
# trạng thái một lần chạy, và khóa duy nhất (source, type, value).
def TIOC(source="'threatfox'", type_="'domain'", value="'a.example.com'", extra=""):
    cols = "source,type,value,last_seen,imported_at,expires_at" + (extra and "," + extra.split("=")[0])
    vals = f"{source},{type_},{value},now(),now(),now()" + (extra and "," + extra.split("=")[1])
    return f"INSERT INTO ti_ioc ({cols}) VALUES ({vals});"
def TLOG(status="'ok'", **dem):
    d = dict(rows_total=0, rows_new=0, rows_updated=0, rows_error=0)
    d.update(dem)
    return ("INSERT INTO ti_import_log (file,started_at,finished_at,rows_total,rows_new,rows_updated,"
            "rows_error,status) VALUES ('ioc_2026-11-17.csv',now(),now(),"
            f"{d['rows_total']},{d['rows_new']},{d['rows_updated']},{d['rows_error']},{status});")
case("026 · ti_ioc source='virustotal' (ngoài ba nguồn)", "ck_ti_ioc_source",
     TIOC(source="'virustotal'"))
case("026 · ti_ioc confidence=101", "ck_ti_ioc_confidence", TIOC(extra="confidence=101"))
case("026 · ti_ioc confidence=-1", "ck_ti_ioc_confidence", TIOC(extra="confidence=-1"))
case("026 · ti_ioc hit_count=-1", "ck_ti_ioc_hit_count", TIOC(extra="hit_count=-1"))
case("026 · ti_ioc trùng (source, type, value)", "uq_ti_ioc_key", TIOC() + TIOC())
case("026 · ti_import_log status='done' (ngoài ok|partial|failed)", "ck_ti_import_log_status",
     TLOG(status="'done'"))
case("026 · ti_import_log rows_error=-1", "ck_ti_import_log_rows_error",
     TLOG(rows_error=-1))
case("024 · run lab có ends_at = starts_at", "ck_lab_runs_ends_after_starts",
     LRUN("01", st="'2026-11-05 09:00+00'", en="'2026-11-05 09:00+00'"))
case("024 · run lab có ends_at < starts_at", "ck_lab_runs_ends_after_starts",
     LRUN("02", st="'2026-11-05 11:00+00'", en="'2026-11-05 09:00+00'"))
case("024 · run lab có purpose ngoài {kb,test}", "ck_lab_runs_purpose",
     LRUN("03", purpose="'train'"))
case("024 · run lab có tên rỗng", "ck_lab_runs_name_length", LRUN("04", name="''"))
case("024 · run lab có tên 81 ký tự", "ck_lab_runs_name_length", LRUN("05", name="repeat('x',81)"))
case("024 · hai run lab trùng tên", "lab_runs_name_key",
     LRUN("06", name="'dup'") +
     LRUN("07", name="'dup'", st="'2026-11-06 09:00+00'", en="'2026-11-06 11:00+00'"))
case("024 · hai run lab có cửa sổ chồng nhau", "ex_lab_runs_no_overlap",
     LRUN("08", name="'a'") +
     LRUN("09", name="'b'", st="'2026-11-05 10:59+00'", en="'2026-11-05 12:00+00'"))
case("024 · run lab nằm trọn trong cửa sổ của run khác", "ex_lab_runs_no_overlap",
     LRUN("0a", name="'a'") +
     LRUN("0b", name="'b'", st="'2026-11-05 09:30+00'", en="'2026-11-05 10:00+00'"))
case("024 · nhãn lab ngoài {true_positive,false_positive}", "ck_lab_labels_label",
     ins(70) + LRUN("0c") +
     "INSERT INTO lab_labels (alert_id,run_id,label,labeled_by) VALUES "
     f"('T-70','00000000-0000-4000-8000-00000000f00c','benign',{LAB_U});")
case("024 · một alert hai nhãn lab", "lab_labels_pkey",
     ins(71) + LRUN("0d") +
     "INSERT INTO lab_labels (alert_id,run_id,label,labeled_by) VALUES "
     f"('T-71','00000000-0000-4000-8000-00000000f00d','true_positive',{LAB_U}),"
     f"('T-71','00000000-0000-4000-8000-00000000f00d','false_positive',{LAB_U});")
case("024 · nhãn lab cho alert không có", "lab_labels_alert_id_fkey",
     LRUN("0e") +
     "INSERT INTO lab_labels (alert_id,run_id,label,labeled_by) VALUES "
     f"('khong-co-alert','00000000-0000-4000-8000-00000000f00e','true_positive',{LAB_U});")
case("024 · nhãn lab cho run không có", "lab_labels_run_id_fkey",
     ins(72) +
     "INSERT INTO lab_labels (alert_id,run_id,label,labeled_by) VALUES "
     f"('T-72','00000000-0000-4000-8000-00000000ffff','true_positive',{LAB_U});")
case("024 · event_type 'lab.labelled' (gõ thừa một chữ) không vào được", "ck_audit_event_type",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) "
     "VALUES ('lab.labelled','y','system');")
case("009 · actor_role='system' mà CÓ actor_id", "ck_audit_actor_id_theo_role",
     "INSERT INTO audit_events (event_type,subject_id,actor_role,actor_id) "
     "VALUES ('alert.auto_closed','y','system','00000000-1111-4000-8000-000000000001');")
case("009 · actor_role='analyst' mà THIẾU actor_id", "ck_audit_actor_id_theo_role",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) "
     "VALUES ('tier1.decided','y','analyst');")
case("R-D0-1 · ① (triage) có vòng tool — vi phạm chốt P5-6",
     "ck_llm_runs_v1_mot_pipeline_khong_tool",
     "INSERT INTO llm_runs (run_id,pipeline,subject_type,subject_id,system_prompt,"
     "user_message,agent_trace) VALUES "
     "('00000000-0000-4000-8000-00000000cc01','triage','alert','s','p','u',"
     """'{\"rounds\":[{\"tool\":\"get_alert_detail\"}]}'::jsonb);""")
case("010 · enrich_cache.trang_thai lạ", "ck_enrich_cache_trang_thai",
     "INSERT INTO enrich_cache (cache_key,dich,ket_qua,trang_thai,expires_at) "
     "VALUES ('k','cmdb','{}'::jsonb,'maybe',now());")
case("010 · enrich_cache.dich ngoài bốn đích đã khai", "ck_enrich_cache_dich",
     "INSERT INTO enrich_cache (cache_key,dich,ket_qua,trang_thai,expires_at) "
     "VALUES ('k','shodan','{}'::jsonb,'found',now());")
case("R-D7-1 · hai job cùng loại cùng chủ thể cùng SỐNG",
     "ux_jobs_mot_job_song_moi_subject",
     "INSERT INTO jobs (job_type,subject_id,status) VALUES ('enrich','a1','pending');"
     "INSERT INTO jobs (job_type,subject_id,status) VALUES ('enrich','a1','running');")
case("011 · users thiếu password_hash", "not-null password_hash",
     "INSERT INTO users (user_id,username,display_name,role) VALUES "
     "('00000000-2222-4000-8000-000000000002','u2','U2','tier1');")

# ── CA ĐỐI CHỨNG: phải ĐƯỢC PHÉP, không được chặn nhầm ──────────────────────
POSITIVE = [
    ("009 · actor_role='admin' có actor_id (vai mới của migration 009)",
     "INSERT INTO audit_events (event_type,subject_id,actor_role,actor_id) VALUES "
     "('admin.autoclose_rule_toggled','r1','admin','00000000-1111-4000-8000-000000000001');"),
    ("009 · 'llm' KHÔNG actor_id — ① chạy tự động, không có người",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) VALUES "
     "('triage.suggested','a1','llm');"),
    ("009 · 'llm' CÓ actor_id — ② do analyst bấm (phase-7:286). Hai ca NGƯỢC nhau cùng hợp lệ",
     "INSERT INTO audit_events (event_type,subject_id,actor_role,actor_id) VALUES "
     "('case.analyzed','c1','llm','00000000-1111-4000-8000-000000000001');"),
    ("R-D0-1 · ② (investigate) CÓ vòng tool là hợp lệ — P7-8",
     "INSERT INTO llm_runs (run_id,pipeline,subject_type,subject_id,system_prompt,"
     "user_message,agent_trace) VALUES "
     "('00000000-0000-4000-8000-00000000cc02','investigate','case','s','p','u',"
     """'{\"rounds\":[{\"tool\":\"get_playbook\"}]}'::jsonb);"""),
    ("R-D7-1 · job cũ ĐÃ XONG không cản job mới (partial, không unique toàn bảng)",
     "INSERT INTO jobs (job_type,subject_id,status) VALUES ('enrich','a2','succeeded');"
     "INSERT INTO jobs (job_type,subject_id,status) VALUES ('enrich','a2','pending');"),
    ("021 · alert 'archived' có CẢ closed_at LẪN sealed_at",
     ins(95, status="'archived'", closed_at="now()", sealed_at="now()")),
    ("021 · case 'archived' có concluded_at + lý do, KHÔNG có concluded_by (không ai kết luận)",
     "INSERT INTO cases (case_id,title,status,severity,created_by,concluded_at,"
     "conclusion_reason) VALUES ('00000000-0000-4000-8000-00000000d0a1','t','archived','high',"
     "'00000000-1111-4000-8000-000000000001',now(),'DEC-212');"),
    ("021 · audit alert.archived và case.archived, actor_role='system', KHÔNG actor_id",
     "INSERT INTO audit_events (event_type,subject_id,actor_role) VALUES "
     "('alert.archived','a1','system'),('case.archived','c1','system');"),
    ("023 · lookup 'failed' với failure_kind='rate_limit' (một trong sáu loại đóng)",
     RR.format(st="'failed'", fk="'rate_limit'").replace("@N@", "b1")),
    ("023 · lookup 'failed' không có failure_kind (dòng 020 đã viết trước khi cột có)",
     RR.format(st="'failed'", fk="NULL").replace("@N@", "b2")),
    ("023 · lookup 'ok' không có failure_kind",
     RR.format(st="'ok'", fk="NULL").replace("@N@", "b3")),
    ("023 · job 'knowledge_embed' (chủ thể là uuid của entry)",
     "INSERT INTO jobs (job_type,subject_id) VALUES "
     "('knowledge_embed','00000000-0000-4000-8000-00000000e0b4');"),
    ("024 · hai run lab liền kề: cái sau bắt đầu đúng lúc cái trước kết thúc (cửa sổ nửa mở)",
     LRUN("a1", name="'a'", st="'2026-11-05 09:00+00'", en="'2026-11-05 11:00+00'") +
     LRUN("a2", name="'b'", st="'2026-11-05 11:00+00'", en="'2026-11-05 13:00+00'")),
    ("024 · run lab purpose='kb' và purpose='test', tên 80 ký tự",
     LRUN("a3", name="repeat('x',80)", purpose="'kb'") +
     LRUN("a4", name="'t'", st="'2026-11-07 09:00+00'", en="'2026-11-07 11:00+00'")),
    ("024 · nhãn lab true_positive cho một alert có thật, trong một run",
     ins(96) + LRUN("a5") +
     "INSERT INTO lab_labels (alert_id,run_id,label,labeled_by) VALUES "
     f"('T-96','00000000-0000-4000-8000-00000000f0a5','true_positive',{LAB_U});"),
    ("024 · audit lab.run_created và lab.labeled, actor_role='admin' CÓ actor_id",
     "INSERT INTO audit_events (event_type,subject_id,actor_role,actor_id) VALUES "
     f"('lab.run_created','r1','admin',{LAB_U}),('lab.labeled','a1','admin',{LAB_U});"),
    ("025 · phiếu 'processing' có đủ locked_by, locked_at, prev_status",
     "INSERT INTO soar_reviews (id,kind,status,created_at,last_sent_at,raw,locked_by,locked_at,prev_status) "
     "VALUES ('S5','review','processing',now(),now(),'{}'::jsonb,'alice',now(),'open');"),
    ("025 · audit soar.review_received (system, KHÔNG actor_id) và soar.review_decided (analyst CÓ actor_id)",
     "INSERT INTO audit_events (event_type,subject_id,actor_role,actor_id) VALUES "
     f"('soar.review_received','K7QM2XHP','system',NULL),('soar.review_decided','K7QM2XHP','analyst',{LAB_U});"),
    ("026 · cùng value dưới nguồn khác và dưới loại khác; confidence và first_seen NULL; confidence 0 và 100",
     TIOC() + TIOC(source="'urlhaus'") + TIOC(type_="'ip:port'") +
     TIOC(value="'b.example.com'", extra="confidence=0") + TIOC(value="'c.example.com'", extra="confidence=100")),
    ("026 · ti_import_log 'failed' với mọi số đếm 0",
     TLOG(status="'failed'")),
    ("M4 · auto_closed có closed_at, sealed_at NULL (cụm còn hút)",
     ins(90, status="'auto_closed'", closed_at="now()")),
    ("D-C5 · escalated_tier2 không seal",
     ins(91, status="'escalated_tier2'")),
    ("B1 · srcip='' và dstip='' (rule FIM)", ins(92, srcip="''", dstip="''")),
    ("C4 · srcip_is_private = NULL (không khẳng định được)",
     ins(93, srcip_is_private="NULL")),
    ("P5 · triage_status='unavailable', status không đổi",
     ins(94, triage_status="'unavailable'")),
    ("P5-5 · suggested_action='needs_review' (giá trị hợp lệ)",
     LR("00000000-0000-4000-8000-00000000bb01","triage","alert",
        """'{\"suggested_action\":\"needs_review\"}'::jsonb""")),
    ("022 · suggested_action='true_positive' (tên mới của ①)",
     LR("00000000-0000-4000-8000-00000000bb03","triage","alert",
        """'{\"suggested_action\":\"true_positive\"}'::jsonb""")),
    ("022 · suggested_action='false_positive' vẫn hợp lệ sau khi siết tập",
     LR("00000000-0000-4000-8000-00000000bb04","triage","alert",
        """'{\"suggested_action\":\"false_positive\"}'::jsonb""")),
    ("T6 · llm_runs ghi được cả ca model hỏng (result NULL)",
     LR("00000000-0000-4000-8000-00000000bb02","triage","alert","NULL")),
]

CT = os.environ.get("SOC_PG_CONTAINER", "soc-transitions")

def run(sql):
    """SQL đi qua stdin, KHÔNG qua -c, để dấu " trong JSON không đóng sớm tham số shell.

    Dùng cùng một cơ chế với output/verify_transitions.py: `docker exec` vào container
    Postgres của dự án. Bản trước dùng `su postgres` (Postgres cài local) — ở môi trường
    không có user `postgres` thì MỌI ca đều lỗi kết nối, và vòng A đếm lỗi kết nối thành
    "đã bị chặn", cho ra điểm 34/34 hoàn toàn giả.
    """
    p = subprocess.run(["docker","exec","-i",CT,"psql","-U","postgres","-d","soc",
                        "-v","ON_ERROR_STOP=1","-q","-f","-"],
                       input=f"BEGIN;\n{sql}\nROLLBACK;\n",
                       capture_output=True, text=True)
    return p.returncode, (p.stderr or p.stdout).strip()


# Dấu hiệu DB THẬT SỰ từ chối, phân biệt với lỗi kết nối / lỗi cú pháp / bảng chưa có.
DAU_HIEU_TU_CHOI = (
    "violates check constraint", "violates not-null constraint",
    "violates foreign key constraint", "violates unique constraint",
    "violates exclusion constraint", "null value in column",
)

def la_bi_db_tu_choi(err, rang_buoc):
    """Ca âm chỉ được tính là ĐẠT khi DB từ chối vì đúng ràng buộc, không phải vì lỗi khác."""
    if not any(d in err for d in DAU_HIEU_TU_CHOI):
        return False
    if rang_buoc.startswith("ck_") or rang_buoc.startswith("uq_") or rang_buoc.startswith("fk_"):
        return rang_buoc in err          # phải đúng TÊN ràng buộc dự kiến
    return True


def tien_kiem():
    """Không có DB thì DỪNG HẲN. Im lặng cho ra 34/34 giả còn tệ hơn là báo lỗi."""
    p = subprocess.run(["docker","exec","-i",CT,"psql","-U","postgres","-d","soc",
                        "-v","ON_ERROR_STOP=1","-q","-t","-A"],
                       input="SELECT count(*) FROM information_schema.tables "
                             "WHERE table_name IN ('alerts','cases','jobs','llm_runs');",
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(f"DỪNG · không nối được container '{CT}'.")
        print((p.stderr or p.stdout).strip()[:300])
        print("\nDựng lại:  docker run -d --name soc-transitions -e POSTGRES_PASSWORD=soc "
              "-e POSTGRES_DB=soc postgres:16")
        print("           docker cp docs/Schema/schema.sql soc-transitions:/tmp/ && \\")
        print("           docker exec soc-transitions psql -U postgres -d soc "
              "-v ON_ERROR_STOP=1 -f /tmp/schema.sql")
        print("Đổi container khác:  SOC_PG_CONTAINER=<tên> python3 test_constraints.py")
        raise SystemExit(2)
    n = (p.stdout or "").strip()
    if n != "4":
        print(f"DỪNG · container '{CT}' nối được nhưng schema chưa nạp đủ "
              f"(thấy {n}/4 bảng nền). Nạp docs/Schema/schema.sql trước.")
        raise SystemExit(2)
    # S8 · seed user cố định — cases.created_by có FK tới users từ migration 007; password_hash
    # NOT NULL từ migration 011 (021 cần user thật cho ca đối chứng của case 'archived').
    # uuid lấy từ tập ANALYSTS của gen_data.py, không tự bịa.
    subprocess.run(["docker","exec","-i",CT,"psql","-U","postgres","-d","soc","-q"],
        input="INSERT INTO users (user_id, username, display_name, role, password_hash) VALUES "
              "('00000000-1111-4000-8000-000000000001','soc.admin','SOC Admin','admin','x') "
              "ON CONFLICT (user_id) DO NOTHING;",
        capture_output=True, text=True)
    print(f"Tiền kiểm: container '{CT}' · 4/4 bảng nền có mặt · user fixture đã seed.\n")


tien_kiem()

print("=" * 78)
print("A · CA VI PHẠM — mỗi ca PHẢI bị DB chặn")
print("=" * 78)
ok = fail = 0
for ten, rb, sql in CASES:
    rc, err = run(sql)
    if rc != 0 and la_bi_db_tu_choi(err, rb):
        line = [l for l in err.splitlines() if "ERROR" in l]
        msg = line[0] if line else err.splitlines()[0]
        msg = msg.replace("ERROR:  ", "").split("\n")[0][:58]
        print(f"  CHẶN   {ten[:52]:52s} · {msg}")
        ok += 1
    elif rc != 0:
        # Có lỗi, nhưng KHÔNG phải DB từ chối vì ràng buộc dự kiến.
        line = [l for l in err.splitlines() if "ERROR" in l] or err.splitlines() or [""]
        print(f"  !!SAI LỖI {ten[:50]:50s} · chờ {rb} · nhận: {line[0][:52]}")
        fail += 1
    else:
        print(f"  !!LỌT  {ten[:52]:52s} · KHÔNG BỊ CHẶN ({rb})")
        fail += 1

print()
print("=" * 78)
print("B · CA ĐỐI CHỨNG — mỗi ca PHẢI được chấp nhận (chống chặn nhầm)")
print("=" * 78)
ok2 = fail2 = 0
for ten, sql in POSITIVE:
    rc, err = run(sql)
    if rc == 0:
        print(f"  CHO QUA  {ten}")
        ok2 += 1
    else:
        m = [l for l in err.splitlines() if "ERROR" in l]
        print(f"  !!CHẶN NHẦM  {ten} · {m[0] if m else err[:80]}")
        fail2 += 1

print()
print(f"Vi phạm bị chặn : {ok}/{len(CASES)}")
print(f"Đối chứng cho qua: {ok2}/{len(POSITIVE)}")
raise SystemExit(1 if (fail or fail2) else 0)
