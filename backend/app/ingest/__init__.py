"""
ingest/ - TIER: alert intake.

Receives Wazuh alert documents, parses them into the internal Alert schema,
resolves the internal category, and computes the dedup fingerprint.

Import rule: may import infrastructure packages (domain, infra, audit,
enrichment). MUST NOT import another tier package (soar, tier1, tier2).
See docs/plan/00-context-pack.md §4.
"""
