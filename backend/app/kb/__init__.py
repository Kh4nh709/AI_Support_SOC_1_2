"""
kb/ - Playbook lookup and minimal retrieval.

Deterministic category lookup is the PRIMARY path: the playbook an alert needs
is decided by alert.category, which ingest already resolved deterministically.
Semantic search is the fallback for categories that could not be resolved.

This ordering is the central technical correction behind the rebuild - see
design section 1.

Import rule: infrastructure. MUST NOT import any tier package.
"""
