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
* `candidates`: the at most 20 active entries the database search finds, and (P14-T06) `by_ids` and `hybrid`,
  which merge them with the vector search's hits (at most 40).

What is here (P13-T03), the DeepSeek part of a lookup and the job that runs it:

* `agent`: one call that must answer a schema of `schemas.json`, linted before it is sent, with at
  most one repair (`call_json`); `Tape`, which keeps what was sent and paid for;
* `match`: (P14-T06 replaced the LLM ranker that was here) the Voyage rerank's selection, `score`, `keep`,
  `level_for` and `Match` with its `score` and `pct`, and `entry_digest`;
* `draft_rank`: the P13 ranking agent, moved from `match` unchanged and kept for the draft job's merge rule
  only (`rank`, its prompt, V-R1's membership and V-R2); the lookup never calls it;
* `budget`: the RAG's sub-cap and the global cap, which stop a call;
* `runs`: the `llm_runs` row of a RAG call (`write_rag_run`);
* `lookup`: the `rag_lookup` job (`run_lookup_job`: Voyage embeddings, a vector search, the hybrid merge, Voyage
  rerank; P14-T06), the newest stored lookup of a subject (`latest_lookup`, `latest_status`, `lookup_failure`)
  and what ① and ② may put in a prompt from it (`prompt_material`, with each match's percentage).

What is here (P13-T04), the drafts that a conclusion proposes:

* `draft`: the source record of a closed alert or a concluded case (`source_record`), the checks V1-V5 on
  a draft (`validate_draft`) and the `knowledge_draft` job (`run_draft_job`), which writes a `pending`
  `knowledge_drafts` row an admin reviews, merging or flagging a draft against the entries it matches.

What is here (P14-T05, DEC-213), Voyage embeddings in an independent pgvector, replacing the LLM ranker on the
read path (P14-T06) and keeping the index true on the write path:

* `failures`: the six closed failure kinds, `TRANSIENT_KINDS` and `RagUnavailable` (its text is its kind);
* `voyage`: the REST client over `httpx` (`embed`, `rerank`, `cost_usd`), one failure kind for every way a
  call can fail and nothing the provider wrote kept;
* `vector_store`: the one table `entry_vectors` of `vectordb` (`connect`, `ensure_schema`, `upsert`,
  `delete`, `stored`, `nearest`), a derived index of the approved entries;
* `vector_index`: `python -m app.rag.vector_index --check | --rebuild`.

The `knowledge_embed` job that keeps the index current is `web/rag_handlers/embed.py`; `publish` (approve,
retire) and `draft` (the merge) enqueue it in the same transaction as the write that changed an entry.

Operations (P13-T09): the second compose file `docker-compose.rag.yml` runs this package in the
`rag-worker` service and mounts `kb_learned/`; the steps, checks and rollback are in `docs/runbook.md`,
"Learned knowledge and RAG (DEC-210)".
"""
