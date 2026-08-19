"""
tier2/ - TIER: case investigation.

A case gathers MULTIPLE correlated alerts. Holds LLM pipeline (2), the
investigation assistant: attack chain, scope, MITRE coverage, hypotheses with
evidence for AND against, and the open questions the analyst should check next.

Import rule: may import infrastructure packages. MUST NOT import another tier.
"""
