"""
soar/ - TIER: deterministic enrichment and automation.

Runs the enrichment stage chain (asset, identity, IoC), correlates the alert
against related alerts, computes the risk score, and applies auto-close rules
- all BEFORE any LLM sees the alert. Enrichment is deterministic on purpose:
the same alert must always produce the same context.

Import rule: may import infrastructure packages. MUST NOT import another tier.
"""
