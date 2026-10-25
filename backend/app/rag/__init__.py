"""Learned knowledge and RAG for ① and ② (DEC-210).

The package holds the database-only parts and, as the later tasks arrive, the DeepSeek parts
(ranking, drafting, publishing). It imports `infra`, `audit`, `security`, `llm`, `kb` and `domain`;
`tier1`, `tier2` and `web` import it; it imports no tier and no `web`
(`backend/tests/test_import_rules.py`).

What is here (P13-T02), all of it a database search or plain code, with no model:

* `subject`: what a `rag_lookup` or `knowledge_draft` job is about (`alert:<id>` / `case:<uuid>`);
* `tags` and `tags.yaml`: the closed tag vocabulary and the rule-group -> tag map;
* `generalise`: placeholders for what identifies one event (`placeholderise`) and the V3 check that
  none is left (`literal_findings`);
* `fingerprint`: the closed fields and generalised log of an alert or a case;
* `history`: the decision history of a subject, its key levels and its self-exclusion;
* `entries`: the `knowledge_entries` row, its hash, its published file and its Markdown;
* `candidates`: the at most 20 active entries the ranking agent chooses from.

What is here (P13-T03), the DeepSeek part of a lookup and the job that runs it:

* `agent`: one call that must answer a schema of `schemas.json`, linted before it is sent, with at
  most one repair (`call_json`); `Tape`, which keeps what was sent and paid for;
* `match`: the ranking agent (`rank`), its prompt, and V-R1's membership and V-R2 (`validate_matches`);
* `budget`: the RAG's sub-cap and the global cap, which stop a call;
* `runs`: the `llm_runs` row of a RAG call (`write_rag_run`);
* `lookup`: the `rag_lookup` job (`run_lookup_job`), the newest stored lookup of a subject
  (`latest_lookup`) and what ① and ② may put in a prompt from it (`prompt_material`).

What is here (P13-T04), the drafts that a conclusion proposes:

* `draft`: the source record of a closed alert or a concluded case (`source_record`), the checks V1-V5 on
  a draft (`validate_draft`) and the `knowledge_draft` job (`run_draft_job`), which writes a `pending`
  `knowledge_drafts` row an admin reviews, merging or flagging a draft against the entries it matches.

Operations (P13-T09): the second compose file `docker-compose.rag.yml` runs this package in the
`rag-worker` service and mounts `kb_learned/`; the steps, checks and rollback are in `docs/runbook.md`,
"Learned knowledge and RAG (DEC-210)".
"""
