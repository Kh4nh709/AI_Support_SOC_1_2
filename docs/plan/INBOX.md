# INBOX — decision requests and blockers for the Director

Anyone (Coder, Reviewer, Planner) appends here. The Director resolves each item, moves the outcome to `DECISIONS.md`, and marks it here as resolved. Never delete items.

Format:

```
## <date> · <TASK_ID or phase> · <type: DECISION_REQUEST | BLOCKER | QUESTION>
From: <role>
Summary: one sentence
Details: what is needed, why, what breaks otherwise
Options: A) … B) … (recommended: …)
Frozen contract affected: none | <name>
Resolved: <date> · <DECISIONS.md id> | open
```

---

## 2026-09-05 · P0 · QUESTION
From: Owner
Summary: `Final-Project` parser / `category_resolver` / `prompt_guard` all still run on the §8 sample alert, but only the category mapping table and the injection detector are reusable as-is; parser and wrapper must be rewritten for v3.
Details: Ran the three modules against the context-pack §8 document (`PYTHONPATH=~/Documents/Final-Project/backend`, Python 3.12, pydantic 2.13, no other deps, no DB).
  - `app/services/wazuh_ingest.parse_wazuh_alert` → runs, returns 12 of the 20 §8 fields. Missing: `manager_id`, `origin_host`, `agent_id`, `agent_ip`, `rule_level`, `categories`, `event_time`, `srcip_is_private`. Wrong: `alert_time` comes from `_source.timestamp` (`2026-08-17T00:56:56.130+0700`) instead of `fields.timestamp[0]` (`2026-08-16T17:56:56.130Z`).
  - `app/services/category_resolver` → runs; mapping tables (technique/group/decoder/port → category) are good and match the phase-1 5-layer scale, but resolution follows the order of `rule.mitre.id`, so the sample yields `primary_category = suspicious_login` while C5 requires `ssh_brute_force` (T1110 outranks T1078). The explicit priority table of phase-1 §Block 5 is missing.
  - `app/security/prompt_guard` → runs (stdlib only). `detect_injection` is directly reusable for gate step 5 / `security/detector.py`: detection-only, returns findings, never mutates. `wrap_untrusted` does not satisfy G6′: delimiter is `<<<UNTRUSTED_DATA[label:nonce]>>>` not `<untrusted_data nonce=… source=…>`, nonce is `token_hex(4)` not `(8)`, no NFKC, no HTML-escape, no nonce stripping inside content, no `[truncated]` marker, no typed builder.
Options: A) Port the category mapping tables + `detect_injection` into `ingest/category.py` and `security/detector.py` and write `ingest/wazuh_parser.py` + `security/wrap.py` fresh against §7.1/§8 (recommended). B) Port all three modules and patch them. C) Write everything from scratch, keep `Final-Project` as reference only.
Frozen contract affected: none
Resolved: open

## 2026-09-05 · P0 / P2 · BLOCKER
From: Owner (preparation session)
Summary: The read-only indexer user `soc_ro` cannot be created — no account with permission to write OpenSearch security config is available.
Details: Verified on IA1803 with root. The OpenSearch admin credential is stored in the Logstash keystore as `opensearch_username` / `opensearch_password`; the Logstash keystore CLI offers only `create/list/add/remove` and cannot read values back, so root does not recover it. It is not present in `/etc/default/logstash` or `/etc/logstash/startup.options`. `admin:admin` returns 401. What is already done: `conf/root-ca.pem` is copied and TLS verification against `https://127.0.0.1:9400` is clean (401 = CA correct, credential missing); `.env` carries the `INDEXER_*` block with `INDEXER_USER`/`INDEXER_PASSWORD` left empty.
Blocks: `eval/indexer_probe.py` being run for real (P0 exit gate), the retention check that sizes G1, and the whole P2 puller path from 06/09. P0 task authoring, P1-T01 smoke test, and Planner P0 are NOT blocked.
Options: A) Owner supplies the OpenSearch admin password (set at install, typically `OPENSEARCH_INITIAL_ADMIN_PASSWORD`) — no change to existing security config (recommended). B) Use the admin TLS certificate with `securityadmin.sh` — the supported route when the password is lost; requires locating `admin.pem`/`admin-key.pem`. C) Reset the admin password via a new bcrypt hash in `internal_users.yml` applied with `securityadmin.sh` — risks breaking the Logstash ingest account if Logstash authenticates as `admin`.
Frozen contract affected: none
Resolved: open
