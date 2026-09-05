# DECISIONS — ADR-lite log

One entry per decision. Only the Director (tactical) or the Owner (scope, contracts, model, evaluation validity) writes here. Reference the id from STATE.md, task reports and commit messages.

Format:

```
## DEC-<nnn> · <date> · <title>
Scope: tactical | contract | scope-cut | model | evaluation
Decided by: Director | Owner
Context: two sentences
Decision: one sentence
Consequences: what changes, what tests/contract files are updated
Supersedes: DEC-<nnn> | —
```

---

## DEC-000 · 2026-09-04 · Baseline
Scope: scope-cut
Decided by: Owner
Context: Architecture v3 (`docs/kien-truc-v3-14-ngay.html`) and `docs/chot-v3-14-ngay.md` incl. section F are the accepted baseline for the 14-day build.
Decision: Build exactly the D1–D20 + F1–F8 scope; cuts C1–C10 stand; cut order per context pack §10.
Consequences: All later decisions reference this baseline.
Supersedes: —
