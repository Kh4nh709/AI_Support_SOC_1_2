"""Learned knowledge and RAG for ① and ② (DEC-210).

The package holds the database-only parts (fingerprint, history, entries, candidates) and the
DeepSeek parts (ranking, drafting, publishing). It imports `infra`, `audit`, `security`, `llm`,
`kb` and `domain`; `tier1`, `tier2` and `web` import it; it imports no tier and no `web`
(`backend/tests/test_import_rules.py`). This file holds only this docstring until the first
module arrives.
"""
