"""The setting of the SOAR review API tests (SR-T1): a scratch database, three signed-in users, a fake n8n, and what a second
connection sees.

`test_soar_reviews_read_api.py` and `test_soar_reviews_decision_api.py` each own a scratch database (`scratch_database`:
built through `scripts/migrate.sh`, dropped when the module ends), so what these tests COMMIT (a decision commits in the middle
of a request, by design, and writes audit rows) never reaches the shared session database: `audit_events` is append-only, and a
committed row there would break every later file that assumes the table empty.

The route runs as in production: `deps.get_conn` itself (commit on a 2xx, rollback on a raise), pointed at the scratch
database; only the signed-in user, the configuration and the n8n client are overridden. Everything a test reads back it reads on
a connection of its own: committed data, not an open transaction.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from typing import Any

import psycopg
from app.infra.auth import Claims
from app.infra.config import Config
from app.web import deps, main
from app.web.routers import soar_reviews as soar_reviews_router
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from tests import conftest
from tests import soar_review_data as data
from tests.fakes.n8n import FakeN8n
from tests.scratch_db import INSERT_ALERT, insert_user

SECRET = "approval-SECRET-zzz"
N8N_URL = "http://n8n.test:5678/webhook/soar-approval"
REVIEWS = "/api/soar/reviews"
JSON = {"content-type": "application/json"}


class World:
    """The scratch database `dsn`, one user per role, the fake n8n, and the configuration the app is given."""

    def __init__(
        self, dsn: conftest.Dsn
    ) -> None:  # not str: a plain str prints a password in a report
        self.dsn = dsn
        self.fake = FakeN8n()
        self.cfg: Config = replace(Config(), N8N_APPROVAL_URL=N8N_URL, N8N_APPROVAL_SECRET=SECRET)
        with psycopg.connect(dsn) as setup:
            self.users: dict[str, tuple[str, str]] = {}
            for role in ("tier1", "tier2", "admin"):
                user_id = insert_user(setup, role)
                (username,) = setup.execute(
                    "SELECT username FROM users WHERE user_id = %s", (user_id,)
                ).fetchone()
                self.users[role] = (user_id, username)

    # ── clients ─────────────────────────────────────────────────────────────────────────────

    def _wire(self) -> None:
        main.app.dependency_overrides[deps.get_config] = lambda: self.cfg
        main.app.dependency_overrides[soar_reviews_router.get_approval_client_factory] = (
            lambda: self.fake.client_factory
        )

    def claims(self, role: str) -> Claims:
        user_id, username = self.users.get(role, (self.users["tier1"][0], f"x-{role}"))
        return Claims(user_id=user_id, username=username, role=role, iat=0.0, exp=0.0)

    def _signed_in(self, request: Request) -> Claims:
        """The caller, named by the `x-test-role` header of the request: so two requests at once can be two users."""
        role = request.headers.get("x-test-role")
        if role is None:
            raise HTTPException(status_code=401, detail="not authenticated")
        return self.claims(role)

    def client(self, role: str = "tier2") -> TestClient:
        """A client signed in as the user of `role` (any other text is a role no list names)."""
        self._wire()
        main.app.dependency_overrides[deps.current_user] = self._signed_in
        return TestClient(main.app, raise_server_exceptions=False, headers={"x-test-role": role})

    def anonymous(self) -> TestClient:
        """A client with no token: the real `current_user` answers."""
        self._wire()
        main.app.dependency_overrides.pop(deps.current_user, None)
        return TestClient(main.app, raise_server_exceptions=False)

    def unwire(self) -> None:
        for dependency in (
            deps.current_user,
            deps.get_config,
            soar_reviews_router.get_approval_client_factory,
        ):
            main.app.dependency_overrides.pop(dependency, None)

    # ── what a second connection sees ───────────────────────────────────────────────────────

    def rows(self, query: str, params: tuple = ()) -> list[tuple]:
        with psycopg.connect(self.dsn) as conn:
            return conn.execute(query, params).fetchall()

    def execute(self, query: str, params: tuple = ()) -> None:
        with psycopg.connect(self.dsn) as conn:
            conn.execute(query, params)

    def row(self, review_id: str) -> dict[str, Any] | None:
        found = self.rows("SELECT to_jsonb(t) FROM soar_reviews t WHERE id = %s", (review_id,))
        return found[0][0] if found else None

    def events(self, review_id: str, event_type: str | None = None) -> list[dict[str, Any]]:
        query = (
            "SELECT event_type, actor_role, actor_id::text, payload FROM audit_events "
            "WHERE subject_id = %s"
        )
        params: tuple = (review_id,)
        if event_type is not None:
            query += " AND event_type = %s"
            params += (event_type,)
        found = self.rows(query + " ORDER BY audit_id", params)
        return [
            {"event_type": t, "actor_role": r, "actor_id": a, "payload": p} for t, r, a, p in found
        ]

    def denied(self, role: str) -> list[dict[str, Any]]:
        """The `authz.denied` events of the user of `role`, oldest first."""
        user_id = self.users[role][0]
        found = self.rows(
            "SELECT subject_id, payload FROM audit_events WHERE event_type = 'authz.denied' "
            "AND actor_id = %s ORDER BY audit_id",
            (user_id,),
        )
        return [{"subject_id": s, "payload": p} for s, p in found]

    # ── what a test puts in ─────────────────────────────────────────────────────────────────

    def put(self, **over: Any) -> str:
        """A ticket, committed; its id."""
        with psycopg.connect(self.dsn) as conn:
            review_id = data.insert_row(conn, **over)
        return review_id

    def put_locked(
        self, *, by: str = "someone", age_s: float = 5, prev: str = "open", **over: Any
    ) -> str:
        """A ticket another person is holding (`processing`), locked `age_s` seconds ago (a lock is stale after 120)."""
        review_id = self.put(**over)
        self.execute(
            "UPDATE soar_reviews SET prev_status = %s, status = 'processing', locked_by = %s, "
            "locked_at = now() - make_interval(secs => %s) WHERE id = %s",
            (prev, by, age_s, review_id),
        )
        return review_id

    def put_alert(
        self,
        alert_id: str,
        case_number: Any,
        *,
        alert_time: datetime | None = None,
        description: str = "p-alert",
        agent_name: str = "agent-1",
        occurrence_count: int = 1,
    ) -> None:
        """An alert whose `raw_payload` carries `enrichment.case.case_number = case_number` (omitted when `MISSING`)."""
        payload: dict[str, Any] = {"enrichment": {"case": {"case_number": case_number}}}
        if case_number is data.MISSING:
            payload = {"enrichment": {"case": {}}}
        statement = INSERT_ALERT.replace("'{}'::jsonb", "%s::jsonb")
        with psycopg.connect(self.dsn) as conn:
            conn.execute(
                statement, (alert_id, alert_id, json.dumps(payload), "log", True, "received")
            )
            conn.execute(
                "UPDATE alerts SET alert_time = COALESCE(%s, alert_time), description = %s, "
                "agent_name = %s, occurrence_count = %s WHERE alert_id = %s",
                (alert_time, description, agent_name, occurrence_count, alert_id),
            )

    def get(self, role: str, path: str, **params: Any):
        return self.client(role).get(path, params=params)

    def post_decision(
        self, role: str, review_id: str, body: Any, *, headers: dict[str, str] | None = None
    ):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return self.client(role).post(
            f"{REVIEWS}/{review_id}/decision",
            content=raw,
            headers=JSON if headers is None else headers,
        )
