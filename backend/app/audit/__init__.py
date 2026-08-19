"""
audit/ - Append-only record of what happened and why.

Two concerns: every human decision (who, when, on what, concluded what) and
every LLM call (prompt actually sent, tool trace, result, injection findings,
tokens, latency).

Together these make the feedback loop possible without a separate table: what
the model suggested and what the human decided share a subject id, so the
agreement rate is one JOIN away.

Nothing here is ever updated or deleted.

Import rule: infrastructure. MUST NOT import any tier package.
"""
