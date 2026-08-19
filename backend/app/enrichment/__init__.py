"""
enrichment/ - Asset, identity and IoC context lookups.

Answers: how critical is this host, is this account privileged, is this
indicator known bad. Deterministic lookups, not model calls.

Note: identity here means the USER NAMED IN THE ALERT (AD-style context).
The analyst operating the system is infra/auth. Two different notions.

Import rule: infrastructure. MUST NOT import any tier package.
"""
