# DECISIONS — ADR-lite log

One entry per decision. Only the Director (tactical) or the Owner (scope, contracts, model, evaluation validity) writes here. Reference the id from STATE.md, task reports and commit messages.

Format:

```
## DEC-<nnn> · <date> · <title>
Scope: tactical | contract | scope-cut | model | evaluation
Decided by: Director | Owner
Context: two sentences
Decision: one sentence
Consequences: what changes, what tests/contract files are updated
Supersedes: DEC-<nnn> | —
```

---

## DEC-000 · 2026-09-04 · Baseline
Scope: scope-cut
Decided by: Owner
Context: Architecture v3 (`docs/kien-truc-v3-14-ngay.html`) and `docs/chot-v3-14-ngay.md` incl. section F are the accepted baseline for the 14-day build.
Decision: Build exactly the D1–D20 + F1–F8 scope; cuts C1–C10 stand; cut order per context pack §10.
Consequences: All later decisions reference this baseline.
Supersedes: —

## DEC-001 · 2026-09-05 · Indexer environment corrected to the real IA1803 host
Scope: contract
Decided by: Owner
Context: The docs assumed the stock Wazuh layout (a `wazuh-indexer` service, CA at `/etc/wazuh-indexer/certs/root-ca.pem`). Verified on IA1803: `wazuh-indexer.service` is `inactive`/`disabled`; the alert store is a plain OpenSearch listening on `https://127.0.0.1:9400`; the manager's `alerts.json` is shipped by **Logstash** (`/etc/logstash/conf.d/wazuh-opensearch.conf`) into `wazuh-alerts-4.x-YYYY.MM.dd`; the root CA is `/etc/logstash/opensearch-certs/root-ca.pem` (world-readable, OpenSearch's bundled demo CA `CN = Example Com Inc. Root CA`, valid to 2034-02-17); `/var/ossec/logs/alerts/alerts.json` is not readable without root.
Decision: Correct the environment assumptions in place; no config key, index pattern, invariant or D-item changes.
Consequences: Context pack §6.3 gains a verified-environment note and `INDEXER_CA` now points at `conf/root-ca.pem`; §11 and `HUONG-DAN-VAN-HANH.md` §0.5 name the real CA path and OpenSearch instead of `wazuh-indexer`; `prompts/P2.md` calls it the OpenSearch root CA; `kien-truc-v3-14-ngay.html` §3 and §5 carry the same correction. `INDEXER_INDEX="wazuh-alerts-*"` is unchanged and still matches. Two follow-ups: the demo CA is a limitation to record in `docs/limitations.md` during P8, and the D3/F2 `alerts.json` file fallback is unavailable to the app user, so the puller is the only path to history. The `Final-Project` reuse QUESTION still open in INBOX becomes DEC-002.
Supersedes: —
