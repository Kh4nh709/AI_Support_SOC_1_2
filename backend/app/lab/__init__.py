"""lab/ - the lab runs and the hand labels of Part C (DEC-213, spec §6).

`runs` records an attack run of the lab (a name, a purpose `kb` or `test`, and a half-open window
`[starts_at, ends_at)` that never overlaps another's) and finds the run a moment falls in. `labels` stores
an admin's TP or FP label of one alert, in the run its `received_at` falls in, and lists a run's alerts for
the admin to label them blind (`tier1.visibility.strip(..., mode="labeling")`: none of ①'s output).

It reads and writes the two tables of migration 024 (`lab_runs`, `lab_labels`), reads `alerts`, and writes
`lab.run_created` and `lab.labeled` through `audit.events`. It imports `infra`, `audit` and `tier1`; only
`web` imports it. The measurement tool (`eval/lab_measure.py`, P14-T11) is a composition root and reads the
same tables.
"""
