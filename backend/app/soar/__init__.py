"""
soar/ - TIER: deterministic enrichment and automation.

Runs the enrichment stage chain (asset, identity, IoC), correlates the alert
against related alerts, computes the risk score, and applies auto-close rules
- all BEFORE any LLM sees the alert. Enrichment is deterministic on purpose:
the same alert must always produce the same context.

`review_notice` and `reviews` (SR-T1) are the one thing here that is not before the LLM: the SOAR's review tickets, pushed by
n8n and decided by an analyst on the web, which write no alert and call no model (`review_notice` reads and stores a ticket,
`reviews` serves and decides it, and reads the alerts of a case). They import `infra` and `audit` only.

Import rule: may import infrastructure packages. MUST NOT import another tier.
"""
