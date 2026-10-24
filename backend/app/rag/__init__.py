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
"""
