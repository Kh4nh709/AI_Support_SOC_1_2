# P11-T20 — Minor findings parked for the whole-branch fix round

The independent reviews found these Minors and approved without them, so none of them blocks a merge. The Director parks them here so that one fix round, with an independent re-review, closes them before P11 ends. Each line names its source review.

## Backend

| # | Source | Item |
|---|---|---|
| 1 | P11-T01 r2 | `_schema_without_019` copies every migration except 019; it should copy only migrations numbered below 019, with `before` from that count |
| 2 | P11-T01 r2 | the `records_itself` tests of 013–018 read the shared database built from `schema.sql`, so they are blind to a missing self-record. Live is unaffected |
| 3 | P11-T01 r2 | `scripts/migrate.sh` reads a failed `schema_migrations` lookup as "not applied", and fails loudly. Pre-existing |
| 4 | P11-T05 r2 | `test_admin_overview.py:879` counts `admin.job_retried` events without a subject filter, so it depends on test order |
| 5 | P11-T05 r2 | `admin_overview.py:38` has a docstring line of 150 characters |
| 6 | P11-T03 r2 N3 | the audit change entry should carry `stored` when the effective value was clamped |
| 7 | P11-T03 r2 N1 | the `infra/settings.py` docstrings still say "two sends"; DEC-202's amendment says ① makes up to four |
| 8 | P11-T02 r2 n1 | pin `reason: "actor_no_longer_admin"` in the stale-actor test |
| 9 | P11-T02 r2 n2 | pin `("text/x+json", False)` in the content-type list |
| 10 | P11-T02 r1 m4 | stale actor on create, reset, unlock and display-name-only PATCH. This needs an actor lock and a lock-order analysis |
| 11 | P11-T09 r1 dev. 5 | reserve the usernames `system` and `llm` in P11-T02's create validation |
| 12 | P11-T09 r1 F2 | cap `ConcludeIn.reason` on `/api/tier2/.../conclude` (500 characters, as tier1 does) |
| 13 | P11-T07 r1 F5 | FastAPI decodes a malformed JSON body before the role check: a 422 with no `authz.denied`. Record it in limitations, or add a body-reading dependency order |
| 14 | P11-T04 r1 m1 | `pct` floored (`ROUND_DOWN`) so that `pct >= 100` exactly when `spent >= cap`; update `test_month_pct_and_projection_on_a_frozen_now` |
| 15 | P11-T04 r1 m2 | bound the `stopped` key (`length <= 32` else `other`), with a test |
| 16 | P11-T04 r1 m3 | the projection floored at one day (`max(elapsed_s, 86400)`) |
| 17 | P11-T04 r1 m4 | three tests: `with_result` against `stopped_by`, more than 200 quota users, and the `limits_out` failure degrading |
| 18 | P11-T04 r1 m5 | the calendar-month test made independent of the day of the month |
| 19 | P11-T04 r1 obs. | an index on `llm_runs (created_at)`: a later migration. It mainly helps `month_spend_usd` before every model attempt |
