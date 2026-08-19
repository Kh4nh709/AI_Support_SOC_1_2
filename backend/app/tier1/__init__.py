"""
tier1/ - TIER: triage queue and the analyst decision.

Holds the queue, LLM pipeline (1) auto-triage, and the Tier 1 decision:
false positive / benign / escalate. The LLM only ever SUGGESTS; the analyst
decides, and both are recorded so they can be compared.

Escalation does NOT call into tier2. It goes through domain.escalate(), which
changes state, opens a case, and enqueues a job. See design section 3.2.
"""
