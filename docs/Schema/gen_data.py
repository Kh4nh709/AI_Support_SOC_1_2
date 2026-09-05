#!/usr/bin/env python3
"""Sinh ~500.000 dòng alerts với phân bố gần thực tế, xuất ra TSV cho COPY.

Phân bố bám theo đặc tả, không bịa:
  - P3:314  5.000 alert nhiễu -> 1 dòng auto_closed + 4.999 dòng duplicate
            => đuôi nặng: vài cụm rất lớn, phần lớn cụm chỉ 1-3 dòng
  - P2:81   MAX_CLUSTER_SIZE = 1000 -> không cụm nào vượt 1000
  - P4:224  "một agent bận với 3.000 alert trong 4 giờ" -> dựng đúng một agent
            như vậy để tái lập phép đo P4-2
  - KT B3   phân bố status theo máy trạng thái
"""
import hashlib, json, random, datetime as dt, os

random.seed(20260823)
# Đường ra cứng cũ (/home/claude/build/data) không tồn tại ngoài máy của tác giả.
# Ghi đè bằng:  SOC_DATA_OUT=/duong/dan python3 gen_data.py
OUT = os.environ.get("SOC_DATA_OUT", "/home/claude/build/data")
os.makedirs(OUT, exist_ok=True)

N_TARGET      = 500_000
N_RULES       = 500
N_AGENTS      = 2_000
N_SRCIP       = 8_000
N_USERS       = 3_000
N_AUTOCLOSE_R = 12

T0 = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).replace(microsecond=0)  # 30 ngày trước NOW
SPAN_S = 30 * 24 * 3600

rules   = [str(40000 + i) for i in range(N_RULES)]
agents  = [f"host-{i:05d}" for i in range(N_AGENTS)]
srcips  = [f"{random.randint(1,223)}.{random.randint(0,255)}."
           f"{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(N_SRCIP)]
users   = [f"user{i}" for i in range(N_USERS)]

# ── S8 · tập analyst CỐ ĐỊNH ────────────────────────────────────────────────
# Trước: `acknowledged_by` là uuid ngẫu nhiên MỖI DÒNG, nên 500.000 alert sinh ra
# tới hàng chục nghìn "người" không tồn tại — `fk_alerts_acknowledged_by` không
# bao giờ VALIDATE được. Một tập cố định làm FK đó validate được, và làm hai bộ
# test dùng chung đúng những uuid này thay vì tự bịa.
# ANALYSTS[0] giữ nguyên uuid mà cases.tsv và autoclose_rules.tsv đang dùng.
ANALYSTS = [("00000000-1111-4000-8000-000000000001", "soc.admin",  "SOC Admin",  "admin")] + [
    (f"{i:08x}-1111-4000-8000-000000000001", f"analyst{i:02d}", f"Analyst {i:02d}",
     "tier2" if i % 5 == 0 else "tier1")
    for i in range(1, 20)
]
ADMIN_UUID = ANALYSTS[0][0]
ANALYST_UUIDS = [u for u, _, _, _ in ANALYSTS]
cats    = ["ssh_brute_force","web_attack","suspicious_login","malware","recon",
           "policy_violation","c2_beacon","data_exfiltration","privilege_escalation",
           "ransomware","unknown"]
sevs    = ["low","medium","high","critical"]
sev_w   = [0.55, 0.28, 0.13, 0.04]
decoders= ["sshd","apache","windows_eventchannel","suricata",None]

ac_rule_ids = [f"{i:08x}-0000-4000-8000-{random.randint(0,2**48-1):012x}"
               for i in range(N_AUTOCLOSE_R)]

def esc(s):
    if s is None: return r"\N"
    return (str(s).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\n", "\\n").replace("\r", "\\r"))

def ts(d): return d.strftime("%Y-%m-%d %H:%M:%S.%f+00")

def bucket_hash(rule_id, srcip, dstip, agent, when):
    b = int(when.timestamp()) // 300
    return hashlib.sha256(f"{rule_id}|{srcip}|{dstip}|{agent}|{b}".encode()).hexdigest()

def payload(alert_id, rule_id, agent, srcip, user, when, level):
    """~600 byte, giữ hình dạng envelope Wazuh thật của P1:337-382."""
    return json.dumps({
        "_index": f"wazuh-alerts-4.x-{when:%Y.%m.%d}",
        "_id": hashlib.md5(alert_id.encode()).hexdigest()[:20],
        "_version": 1, "_score": None,
        "_source": {
            "predecoder": {"hostname": agent, "program_name": "sshd",
                           "timestamp": when.strftime("%b %d %H:%M:%S")},
            "input": {"type": "log"},
            "agent": {"ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.5",
                      "name": agent, "id": f"{random.randint(1,999):03d}"},
            "manager": {"name": "IA1803"},
            "data": {"srcip": srcip, "dstuser": user, "srcport": str(random.randint(1024,65535))},
            "rule": {"mail": False, "level": level,
                     "pci_dss": ["10.2.4","10.2.5","11.4"], "hipaa": ["164.312.b"],
                     "tsc": ["CC6.1","CC6.8","CC7.2","CC7.3"],
                     "description": "Multiple authentication failures followed by a success.",
                     "groups": ["syslog","attacks"],
                     "nist_800_53": ["AU.14","AC.7","SI.4"],
                     "frequency": 2, "gdpr": ["IV_35.7.d","IV_32.2"], "firedtimes": 1,
                     "mitre": {"technique": ["Valid Accounts","Brute Force"],
                               "id": ["T1078","T1110"],
                               "tactic": ["Defense Evasion","Persistence",
                                          "Privilege Escalation","Initial Access",
                                          "Credential Access"]},
                     "id": rule_id, "gpg13": ["7.1","7.8"]},
            "location": "journald",
            "decoder": {"parent": "sshd", "name": "sshd"},
            "id": alert_id,
            "full_log": f"{when:%b %d %H:%M:%S} {agent} sshd[{random.randint(1000,99999)}]: "
                        f"Accepted password for {user} from {srcip} port "
                        f"{random.randint(1024,65535)} ssh2",
            "timestamp": when.isoformat()},
        "fields": {"timestamp": [when.isoformat()]},
        "sort": [int(when.timestamp() * 1000)]}, separators=(",", ":"))

# ── Phân bố status của DÒNG GỐC (cụm) · KT B3 ────────────────────────────────
HEAD_STATUS = [
    ("auto_closed",     0.34),
    ("queued_tier1",    0.20),
    ("closed_fp",       0.16),
    ("closed_benign",   0.08),
    ("escalated_tier2", 0.05),
    ("closed_confirmed",0.04),
    ("tier1_active",    0.04),
    ("enriching",       0.05),
    ("received",        0.04),
]
hs_names = [s for s, _ in HEAD_STATUS]
hs_w     = [w for _, w in HEAD_STATUS]

def cluster_size():
    """Đuôi nặng: phần lớn cụm nhỏ, một số ít rất lớn (chặn ở 1000 = MAX_CLUSTER_SIZE)."""
    r = random.random()
    if r < 0.72:  return 1
    if r < 0.90:  return random.randint(2, 5)
    if r < 0.975: return random.randint(6, 40)
    if r < 0.996: return random.randint(41, 300)
    return random.randint(301, 1000)

fa = open(f"{OUT}/alerts_heads.tsv", "w")
fd = open(f"{OUT}/alerts_dups.tsv", "w")
fc = open(f"{OUT}/cases.tsv", "w")

COLS = ("alert_id rule_id rule_level severity description agent_name alert_time "
        "agent_id agent_ip alert_user decoder event_time raw_log srcip dstip "
        "src_port dst_port mitre_ids rule_groups category categories resolved_by "
        "mapping_version srcip_is_private dstip_is_private raw_log_truncated source "
        "is_synthetic status event_bucket_hash duplicate_of occurrence_count case_id "
        "autoclose_rule_id received_at first_seen_at last_seen_at acknowledged_at "
        "acknowledged_by closed_at sealed_at close_reason triage_status triaged_count "
        "risk_score risk_score_components asset_context identity_context ioc_context "
        "lookup_status raw_payload").split()

def row(d):
    return "\t".join(esc(d.get(c)) for c in COLS) + "\n"

n_rows = 0
n_heads = 0
case_rows = []
seq = 0

# ── Agent bận: 3.000 alert trong 4 giờ (P4:224) để tái lập phép đo P4-2 ──────
BUSY_AGENT = "host-00042"
BUSY_T = T0 + dt.timedelta(days=15)

def make_head(agent=None, when=None, force_srcip=None):
    global seq, n_rows, n_heads
    seq += 1
    aid = f"{1786900000 + seq}.{seq:06d}"
    rule = random.choice(rules)
    agent = agent or random.choice(agents)
    # 12% alert không có srcip (rule FIM/rootcheck/syscollector) -> '' (B1, P2:345)
    srcip = force_srcip if force_srcip is not None else (
        "" if random.random() < 0.12 else random.choice(srcips))
    dstip = "" if random.random() < 0.85 else random.choice(srcips)
    when = when or (T0 + dt.timedelta(seconds=random.randint(0, SPAN_S)))
    sev = random.choices(sevs, sev_w)[0]
    level = {"low": 3, "medium": 6, "high": 9, "critical": 13}[sev]
    user = None if random.random() < 0.25 else random.choice(users)
    cat = random.choice(cats)
    st = random.choices(hs_names, hs_w)[0]
    if sev == "critical" and st == "auto_closed":
        st = "queued_tier1"                       # G8/A1: critical không bao giờ auto-close
    n = cluster_size()
    last = when + dt.timedelta(seconds=random.randint(0, 900) if n > 1 else 0)

    closed = sealed = ack = ackby = cid = acr = reason = None
    if st == "duplicate":
        raise AssertionError
    if st == "auto_closed":
        closed = last; acr = random.choice(ac_rule_ids)
        reason = "Máy quét lỗ hổng nội bộ"
        if random.random() < 0.20: sealed = last   # sweeper đã niêm (B4)
    elif st in ("closed_fp", "closed_benign", "closed_confirmed"):
        ack = when + dt.timedelta(seconds=random.randint(30, 3600))
        ackby = random.choice(ANALYST_UUIDS)
        closed = ack + dt.timedelta(seconds=random.randint(20, 1800))
        sealed = closed
        reason = "Đã xác minh" if st != "closed_confirmed" else "Sự cố xác nhận"
        if st == "closed_confirmed":
            cid = f"{random.randint(0,2**32-1):08x}-2222-4000-8000-{seq:012x}"
            case_rows.append((cid, st, sev, closed))
    elif st == "escalated_tier2":
        ack = when + dt.timedelta(seconds=random.randint(30, 3600))
        ackby = random.choice(ANALYST_UUIDS)
        cid = f"{random.randint(0,2**32-1):08x}-2222-4000-8000-{seq:012x}"
        case_rows.append((cid, "investigating", sev, None))
    elif st == "tier1_active":
        ack = when + dt.timedelta(seconds=random.randint(30, 3600))
        ackby = random.choice(ANALYST_UUIDS)

    enriched = st not in ("received", "enriching")
    risk = None
    if enriched:
        base = {"critical": 70, "high": 50, "medium": 28, "low": 10}[sev]
        risk = min(100, base + min(25, random.randint(0, 40)))
    tst = "pending"
    if enriched:
        tst = random.choices(["ready", "unavailable", "pending"], [0.88, 0.05, 0.07])[0]

    d = dict(
        alert_id=aid, rule_id=rule, rule_level=level, severity=sev,
        description="Multiple authentication failures followed by a success.",
        agent_name=agent, alert_time=ts(when),
        agent_id=f"{random.randint(1,999):03d}",
        agent_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.5",
        alert_user=user, decoder=random.choice(decoders),
        event_time=ts(when - dt.timedelta(seconds=1)),
        raw_log=f"{when:%b %d %H:%M:%S} {agent} sshd: Accepted password for {user} from {srcip}",
        srcip=srcip, dstip=dstip,
        src_port=random.randint(1024, 65535), dst_port=random.choice([0, 22, 443, 3389]),
        mitre_ids="{T1078,T1110}", rule_groups="{syslog,attacks}",
        category=cat, categories="{" + cat + "}", resolved_by="mitre",
        mapping_version="v1",
        srcip_is_private=(None if srcip == "" else ("t" if srcip.startswith("10.") else "f")),
        dstip_is_private=(None if dstip == "" else "f"),
        raw_log_truncated="f", source="wazuh", is_synthetic="f",
        status=st, event_bucket_hash=bucket_hash(rule, srcip, dstip, agent, when),
        duplicate_of=None, occurrence_count=n, case_id=cid, autoclose_rule_id=acr,
        received_at=ts(when), first_seen_at=ts(when), last_seen_at=ts(last),
        acknowledged_at=ts(ack) if ack else None, acknowledged_by=ackby,
        closed_at=ts(closed) if closed else None,
        sealed_at=ts(sealed) if sealed else None, close_reason=reason,
        triage_status=tst,
        triaged_count=(n if st in ("closed_fp", "closed_benign", "closed_confirmed") else 0),
        risk_score=risk,
        risk_score_components=(json.dumps({"base": base, "context": risk - base})
                               if risk is not None else None),
        asset_context=(json.dumps({"hostname": agent, "criticality": "normal"})
                       if enriched else None),
        identity_context=(json.dumps({"username": user, "is_privileged": False})
                          if enriched and user else None),
        ioc_context=(json.dumps({"hits": []}) if enriched else None),
        lookup_status=(json.dumps({"asset": "found", "identity": "not_found",
                                   "ioc": "skipped"}) if enriched else None),
        raw_payload=payload(aid, rule, agent, srcip, user or "-", when, level),
    )
    fa.write(row(d))
    n_rows += 1; n_heads += 1
    return d, n, when, last

def make_dups(head, n, when, last):
    """Bản sao: closed_at VÀ sealed_at đặt ngay lúc INSERT (P2:236)."""
    global seq, n_rows
    for k in range(n - 1):
        seq += 1
        aid = f"{1786900000 + seq}.{seq:06d}"
        w = when + dt.timedelta(seconds=random.randint(0, max(1, int((last - when).total_seconds()))))
        d = dict(head)
        d.update(alert_id=aid, status="duplicate", duplicate_of=head["alert_id"],
                 occurrence_count=1, alert_time=ts(w), received_at=ts(w),
                 first_seen_at=ts(w), last_seen_at=ts(w),
                 closed_at=ts(w), sealed_at=ts(w),
                 acknowledged_at=None, acknowledged_by=None,
                 case_id=None, triaged_count=0, triage_status="pending",
                 risk_score=None, risk_score_components=None,
                 event_bucket_hash=bucket_hash(head["rule_id"], head["srcip"],
                                               head["dstip"], head["agent_name"], w),
                 raw_payload=payload(aid, head["rule_id"], head["agent_name"],
                                     head["srcip"], head["alert_user"] or "-", w, head["rule_level"]))
        fd.write(row(d))
        n_rows += 1

# 1) Agent bận — 3.000 alert trong 4 giờ, trải trên nhiều cụm
busy_made = 0
while busy_made < 3000:
    w = BUSY_T + dt.timedelta(seconds=random.randint(0, 4 * 3600))
    h, n, when, last = make_head(agent=BUSY_AGENT, when=w)
    make_dups(h, n, when, last)
    busy_made += n

# 2) Phần còn lại
while n_rows < N_TARGET:
    h, n, when, last = make_dups.__self__ if False else make_head()
    make_dups(h, n, when, last)

fa.close(); fd.close()

seen = set()
for cid, st, sev, at in case_rows:
    if cid in seen: continue
    seen.add(cid)
    concluded = st in ("closed_fp", "closed_benign", "closed_confirmed")
    cstatus = "confirmed_incident" if st == "closed_confirmed" else "investigating"
    fc.write("\t".join([
        cid, "Điều tra cụm alert", cstatus, sev,
        ADMIN_UUID,
        ts(T0), r"\N",
        "Đã xác nhận sự cố" if concluded else r"\N",
        ADMIN_UUID if concluded else r"\N",
        ts(at) if concluded and at else r"\N"]) + "\n")
fc.close()

with open(f"{OUT}/autoclose_rules.tsv", "w") as f:
    for i, rid in enumerate(ac_rule_ids):
        f.write("\t".join([rid, f"Rule nhiễu {i}", "t",
                           json.dumps([{"field": "rule_id", "op": "eq", "value": rules[i]}]),
                           "Máy quét lỗ hổng nội bộ",
                           ADMIN_UUID, ts(T0)]) + "\n")

# ── S8 · users.tsv — phải COPY TRƯỚC cases/case_alerts/autoclose_rules/alerts ──
with open(f"{OUT}/users.tsv", "w") as f:
    for uid, uname, disp, role in ANALYSTS:
        f.write("\t".join([uid, uname, disp, role, "t", ts(T0)]) + "\n")

print(f"users         : {len(ANALYSTS)}")
print(f"dòng gốc (cụm): {n_heads:,}")
print(f"tổng dòng     : {n_rows:,}")
print(f"cases         : {len(seen):,}")
print(f"agent bận     : {BUSY_AGENT}, {busy_made:,} alert trong 4 giờ quanh {BUSY_T}")
print("COLS =", len(COLS))
