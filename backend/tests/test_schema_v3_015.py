"""Migration 015 — `triage_labels`, `autoclose_reviews`, `case_notes`, `eval_runs`
and `system_health` (context pack §6.1).

Every test runs against the database the `db` fixture migrates, so each one
asserts on the migration as `scripts/migrate.sh` actually applies it, not on
the text of the file.

Two columns get no CHECK on purpose, per the task card:

* `triage_labels.confidence` is a human labeller's confidence, not the model's
  `triage_v2.confidence` (§6.2) — §6.1 gives it no closed set.
* `eval_runs.gold_set` names G1/G2/G3 today (§13) but §6.1 lists no closed set
  for it; `config` does get one (`B0..B4`) and is tested below.
"""

import uuid

import psycopg
import pytest

HASH64 = "0" * 64

TRIAGE_LABEL_SOURCES = ["gold_offline", "digest", "disagreement", "lab"]
TRIAGE_LABELS = ["false_positive", "benign", "escalate"]
AUTOCLOSE_VERDICTS = ["correct", "wrong", "unsure"]
EVAL_CONFIGS = ["B0", "B1", "B2", "B3", "B4"]

EVAL_RUNS_COLUMNS = [
    "eval_run_id",
    "prompt_version",
    "model_id",
    "gold_set",
    "config",
    "metrics",
    "created_at",
]


def rejects(db, sql, params=None):
    """Run `sql` expecting the database to reject it; return the psycopg error.

    The statement is wrapped in a savepoint so the caller's connection stays
    usable afterwards — several tests assert a rejection and then an
    acceptance on the same connection.
    """
    with db.cursor() as cur:
        cur.execute("SAVEPOINT expect_rejection")
        try:
            cur.execute(sql, params)
        except psycopg.Error as exc:
            cur.execute("ROLLBACK TO SAVEPOINT expect_rejection")
            return exc
    raise AssertionError(f"statement was accepted but should have been rejected: {sql}")


def _make_alert(cur, alert_id, **overrides):
    """INSERT one row into `alerts` filling every NOT NULL column with no default."""
    row = {
        "alert_id": alert_id,
        "rule_id": "40112",
        "rule_level": 12,
        "severity": "critical",
        "description": "x",
        "agent_name": "a1",
        "alert_time": "2026-09-06T00:00:00+00:00",
        "category": "ssh_brute_force",
        "resolved_by": "mitre",
        "mapping_version": "v1",
        "event_bucket_hash": HASH64,
        "raw_payload": "{}",
    }
    row.update(overrides)
    columns = ", ".join(row)
    placeholders = ", ".join(["%s"] * len(row))
    cur.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", list(row.values()))


def _make_user(cur, user_id, **overrides):
    """INSERT one row into `users` filling every NOT NULL column with no default."""
    row = {
        "user_id": user_id,
        "username": f"u-{user_id}",
        "display_name": "U",
        "role": "tier1",
        "password_hash": "x",
    }
    row.update(overrides)
    columns = ", ".join(row)
    placeholders = ", ".join(["%s"] * len(row))
    cur.execute(f"INSERT INTO users ({columns}) VALUES ({placeholders})", list(row.values()))


def _make_case(cur, case_id, created_by, **overrides):
    """INSERT one row into `cases` filling every NOT NULL column with no default."""
    row = {
        "case_id": case_id,
        "title": "t",
        "severity": "critical",
        "created_by": created_by,
    }
    row.update(overrides)
    columns = ", ".join(row)
    placeholders = ", ".join(["%s"] * len(row))
    cur.execute(f"INSERT INTO cases ({columns}) VALUES ({placeholders})", list(row.values()))


def _uuid():
    return str(uuid.uuid4())


def columns_present(db, table, names):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = ANY(%s) ORDER BY 1",
            (table, list(names)),
        )
        return [name for (name,) in cur.fetchall()]


@pytest.mark.db
def test_migration_015_records_itself_in_schema_migrations(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM schema_migrations "
            "WHERE version = '015_labels_reviews_notes_eval_health'"
        )
        (count,) = cur.fetchone()

    assert count == 1


@pytest.mark.db
def test_all_five_tables_exist(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT to_regclass('public.triage_labels'), to_regclass('public.autoclose_reviews'), "
            "to_regclass('public.case_notes'), to_regclass('public.eval_runs'), "
            "to_regclass('public.system_health')"
        )
        row = cur.fetchone()

    assert all(row)


# ── triage_labels ────────────────────────────────────────────────────────────


@pytest.mark.db
def test_ck_triage_labels_source_admits_the_four_sources_and_rejects_a_fifth(db):
    with db.cursor() as cur:
        alert_id = "a-tl-source"
        labeler_id = _uuid()
        _make_alert(cur, alert_id)
        _make_user(cur, labeler_id)

        for source in TRIAGE_LABEL_SOURCES:
            cur.execute(
                "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
                "VALUES (%s, %s, %s, 'benign')",
                (alert_id, labeler_id, source),
            )
        cur.execute(
            "SELECT source FROM triage_labels WHERE alert_id = %s ORDER BY source", (alert_id,)
        )
        stored = [value for (value,) in cur.fetchall()]

        error = rejects(
            db,
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES (%s, %s, 'made_up', 'benign')",
            (alert_id, labeler_id),
        )

    assert stored == sorted(TRIAGE_LABEL_SOURCES)
    assert "ck_triage_labels_source" in str(error)


@pytest.mark.db
def test_ck_triage_labels_label_admits_the_three_labels_and_rejects_a_fourth(db):
    with db.cursor() as cur:
        alert_id = "a-tl-label"
        labeler_id = _uuid()
        _make_alert(cur, alert_id)
        _make_user(cur, labeler_id)

        # One distinct `source` per label — the PK is (alert_id, labeler_id, source).
        for source, label in zip(TRIAGE_LABEL_SOURCES, TRIAGE_LABELS):
            cur.execute(
                "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
                "VALUES (%s, %s, %s, %s)",
                (alert_id, labeler_id, source, label),
            )
        cur.execute(
            "SELECT label FROM triage_labels WHERE alert_id = %s ORDER BY label", (alert_id,)
        )
        stored = [value for (value,) in cur.fetchall()]

        error = rejects(
            db,
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES (%s, %s, 'lab', 'made_up')",
            (alert_id, labeler_id),
        )

    assert stored == sorted(TRIAGE_LABELS)
    assert "ck_triage_labels_label" in str(error)


@pytest.mark.db
def test_pk_triage_labels_admits_two_rows_that_differ_only_in_source(db):
    with db.cursor() as cur:
        alert_id = "a-tl-pk"
        labeler_id = _uuid()
        _make_alert(cur, alert_id)
        _make_user(cur, labeler_id)

        cur.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES (%s, %s, 'gold_offline', 'benign')",
            (alert_id, labeler_id),
        )
        cur.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES (%s, %s, 'digest', 'escalate')",
            (alert_id, labeler_id),
        )
        cur.execute(
            "SELECT count(*) FROM triage_labels WHERE alert_id = %s AND labeler_id = %s",
            (alert_id, labeler_id),
        )
        (count,) = cur.fetchone()

        error = rejects(
            db,
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES (%s, %s, 'gold_offline', 'escalate')",
            (alert_id, labeler_id),
        )

    assert count == 2
    assert "pk_triage_labels" in str(error)


@pytest.mark.db
def test_triage_labels_confidence_has_no_closed_set(db):
    # §6.1 gives `confidence` no closed set — the model's `triage_v2.confidence`
    # (low|medium|high) is a different field entirely. Any text must be accepted.
    with db.cursor() as cur:
        alert_id = "a-tl-conf"
        labeler_id = _uuid()
        _make_alert(cur, alert_id)
        _make_user(cur, labeler_id)

        cur.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence) "
            "VALUES (%s, %s, 'lab', 'benign', %s)",
            (alert_id, labeler_id, "whatever-the-labeller-writes"),
        )
        cur.execute(
            "SELECT count(*) FROM pg_constraint WHERE conrelid = 'triage_labels'::regclass "
            "AND pg_get_constraintdef(oid) LIKE '%confidence%'"
        )
        (constraints,) = cur.fetchone()

    assert constraints == 0


@pytest.mark.db
def test_fk_triage_labels_alert_rejects_an_orphan(db):
    with db.cursor() as cur:
        labeler_id = _uuid()
        _make_user(cur, labeler_id)

        error = rejects(
            db,
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            "VALUES ('does-not-exist', %s, 'lab', 'benign')",
            (labeler_id,),
        )

    assert "fk_triage_labels_alert" in str(error)


@pytest.mark.db
def test_fk_triage_labels_labeler_rejects_an_orphan(db):
    with db.cursor() as cur:
        alert_id = "a-tl-orphan-labeler"
        _make_alert(cur, alert_id)

        error = rejects(
            db,
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label) "
            f"VALUES ('{alert_id}', %s, 'lab', 'benign')",
            (_uuid(),),
        )

    assert "fk_triage_labels_labeler" in str(error)


# ── autoclose_reviews ────────────────────────────────────────────────────────


@pytest.mark.db
def test_ck_autoclose_reviews_verdict_admits_the_three_verdicts_and_rejects_a_fourth(db):
    with db.cursor() as cur:
        reviewer_id = _uuid()
        _make_user(cur, reviewer_id)

        for verdict in AUTOCLOSE_VERDICTS:
            alert_id = f"a-ar-{verdict}"
            _make_alert(cur, alert_id)
            cur.execute(
                "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
                "VALUES (%s, %s, %s)",
                (alert_id, reviewer_id, verdict),
            )
        cur.execute(
            "SELECT verdict FROM autoclose_reviews WHERE reviewer_id = %s ORDER BY verdict",
            (reviewer_id,),
        )
        stored = [value for (value,) in cur.fetchall()]

        alert_id = "a-ar-bad"
        _make_alert(cur, alert_id)
        error = rejects(
            db,
            "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
            "VALUES (%s, %s, 'made_up')",
            (alert_id, reviewer_id),
        )

    assert stored == sorted(AUTOCLOSE_VERDICTS)
    assert "ck_autoclose_reviews_verdict" in str(error)


@pytest.mark.db
def test_pk_autoclose_reviews_rejects_a_second_review_of_the_same_alert(db):
    with db.cursor() as cur:
        alert_id = "a-ar-pk"
        reviewer_id = _uuid()
        _make_alert(cur, alert_id)
        _make_user(cur, reviewer_id)

        cur.execute(
            "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
            "VALUES (%s, %s, 'correct')",
            (alert_id, reviewer_id),
        )

        error = rejects(
            db,
            "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
            "VALUES (%s, %s, 'wrong')",
            (alert_id, reviewer_id),
        )

    assert "autoclose_reviews_pkey" in str(error) or "pk_autoclose_reviews" in str(error)


@pytest.mark.db
def test_fk_autoclose_reviews_alert_rejects_an_orphan(db):
    with db.cursor() as cur:
        reviewer_id = _uuid()
        _make_user(cur, reviewer_id)

        error = rejects(
            db,
            "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
            "VALUES ('does-not-exist', %s, 'correct')",
            (reviewer_id,),
        )

    assert "fk_autoclose_reviews_alert" in str(error)


@pytest.mark.db
def test_fk_autoclose_reviews_reviewer_rejects_an_orphan(db):
    with db.cursor() as cur:
        alert_id = "a-ar-orphan-reviewer"
        _make_alert(cur, alert_id)

        error = rejects(
            db,
            "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) "
            f"VALUES ('{alert_id}', %s, 'correct')",
            (_uuid(),),
        )

    assert "fk_autoclose_reviews_reviewer" in str(error)


# ── case_notes ───────────────────────────────────────────────────────────────


@pytest.mark.db
def test_case_notes_note_id_is_identity_not_serial(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT is_identity FROM information_schema.columns "
            "WHERE table_name = 'case_notes' AND column_name = 'note_id'"
        )
        (is_identity,) = cur.fetchone()

    assert is_identity == "YES"


@pytest.mark.db
def test_case_notes_note_id_generates_by_default(db):
    with db.cursor() as cur:
        author_id = _uuid()
        case_id = _uuid()
        _make_user(cur, author_id)
        _make_case(cur, case_id, author_id)

        cur.execute(
            "INSERT INTO case_notes (case_id, author_id, body) VALUES (%s, %s, 'x') "
            "RETURNING note_id",
            (case_id, author_id),
        )
        (note_id,) = cur.fetchone()

    assert isinstance(note_id, int)


@pytest.mark.db
def test_fk_case_notes_case_rejects_an_orphan(db):
    with db.cursor() as cur:
        author_id = _uuid()
        _make_user(cur, author_id)

        error = rejects(
            db,
            "INSERT INTO case_notes (case_id, author_id, body) VALUES (%s, %s, 'x')",
            (_uuid(), author_id),
        )

    assert "fk_case_notes_case" in str(error)


@pytest.mark.db
def test_fk_case_notes_author_rejects_an_orphan(db):
    with db.cursor() as cur:
        author_id = _uuid()
        case_id = _uuid()
        _make_user(cur, author_id)
        _make_case(cur, case_id, author_id)

        error = rejects(
            db,
            "INSERT INTO case_notes (case_id, author_id, body) VALUES (%s, %s, 'x')",
            (case_id, _uuid()),
        )

    assert "fk_case_notes_author" in str(error)


# ── eval_runs ────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_eval_runs_has_exactly_the_seven_columns_in_order(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'eval_runs' ORDER BY ordinal_position"
        )
        columns = [name for (name,) in cur.fetchall()]

    assert columns == EVAL_RUNS_COLUMNS


@pytest.mark.db
def test_ck_eval_runs_config_admits_b0_through_b4(db):
    with db.cursor() as cur:
        for config in EVAL_CONFIGS:
            cur.execute(
                "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, "
                "config, metrics) VALUES (gen_random_uuid(), 'v1', 'm', 'G1', %s, '{}'::jsonb)",
                (config,),
            )
        cur.execute("SELECT count(DISTINCT config) FROM eval_runs")
        (count,) = cur.fetchone()

    assert count == len(EVAL_CONFIGS)


@pytest.mark.db
def test_ck_eval_runs_config_rejects_b5(db):
    error = rejects(
        db,
        "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, config, "
        "metrics) VALUES (gen_random_uuid(), 'v1', 'm', 'G1', 'B5', '{}'::jsonb)",
    )

    assert "ck_eval_runs_config" in str(error)


@pytest.mark.db
def test_eval_runs_gold_set_has_no_closed_set(db):
    # §13 names G1/G2/G3 today but §6.1 lists no closed set for `gold_set` —
    # P7 may run a combined or sliced set, so any text must be accepted.
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, config, "
            "metrics) VALUES (gen_random_uuid(), 'v1', 'm', 'G1+G2_slice_7', 'B0', '{}'::jsonb)"
        )
        cur.execute(
            "SELECT count(*) FROM pg_constraint WHERE conrelid = 'eval_runs'::regclass "
            "AND pg_get_constraintdef(oid) LIKE '%gold_set%'"
        )
        (constraints,) = cur.fetchone()

    assert constraints == 0


@pytest.mark.db
def test_eval_run_id_has_no_default(db):
    # `llm_runs.run_id` is app-assigned with no DEFAULT (schema.sql:392);
    # `eval_run_id` follows the same rule, so a bare INSERT omitting it fails
    # with a NOT NULL violation, not a generated value.
    error = rejects(
        db,
        "INSERT INTO eval_runs (prompt_version, model_id, gold_set, config, metrics) "
        "VALUES ('v1', 'm', 'G1', 'B0', '{}'::jsonb)",
    )

    assert "eval_run_id" in str(error)


# ── system_health ────────────────────────────────────────────────────────────


@pytest.mark.db
def test_pk_system_health_rejects_a_second_row_at_the_same_checked_at(db):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO system_health (checked_at, checks, ok) "
            "VALUES ('2026-09-06T00:00:00+00:00', '{}'::jsonb, true)"
        )

        error = rejects(
            db,
            "INSERT INTO system_health (checked_at, checks, ok) "
            "VALUES ('2026-09-06T00:00:00+00:00', '{}'::jsonb, false)",
        )

    assert "pk_system_health" in str(error)


# ── constraint naming and count (acceptance items 3, 5, 6, 7 belong to the ────
# shell commands in the report; this covers what pytest is best placed for) ──


@pytest.mark.db
def test_exactly_six_foreign_keys_across_the_three_fk_bearing_tables(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM pg_constraint WHERE conrelid IN "
            "('triage_labels'::regclass, 'autoclose_reviews'::regclass, "
            "'case_notes'::regclass) AND contype = 'f'"
        )
        (count,) = cur.fetchone()

    assert count == 6
