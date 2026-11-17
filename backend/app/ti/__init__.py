"""Threat Intel (DEC-224): the abuse.ch indicators the host's daily script collects, as the database holds them.

`importer` reads one day's CSV and upserts it into `ti_ioc`, writing one `ti_import_log` row per run (migration
026); the read queries of the API come in a later task. The package imports `infra` at most and is imported by
`web` alone (the layering test, `tests/test_import_rules.py`).
"""
