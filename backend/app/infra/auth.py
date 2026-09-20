"""Login, JWT issuance and verification, and the tier1/tier2/admin role check.

Pure by the import rule (context pack §4: `infra` imports nothing from the app),
so this module knows passwords, tokens and the `users` table and nothing about
HTTP: the FastAPI dependencies that turn its exceptions into status codes — and
the one audit event a refusal writes — live in `web/deps.py` (P4-tasks.md
planning decision 2).

Passwords are argon2id with migration 011's parameters. Tokens are HS256 with
`JWT_SECRET`, eight hours, and every use is checked against the `users` row
(active, role, not logged out since — planning decision 8): the token's `role`
claim is carried for the client's convenience and never trusted. `iat`/`exp`
are floats so a logout and a new login inside one second do not collide.

Control timestamps (`locked_until`, `sessions_invalid_before`) are the database's
`now()` (§9); the token's `iat` is the application's clock by necessity and is
compared against the row's epoch.

The module doubles as the seed CLI: `python3 -m app.infra.auth seed-users …`.
A password never travels on argv — it comes from `SEED_PASSWORD_<USERNAME>` or
a prompt — and nothing here ever prints a password, a hash, a token or a DSN.
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import os
import sys
import time
import uuid
from datetime import datetime

import jwt
import psycopg
from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from psycopg.types.json import Jsonb

from app.infra import config, db
from app.infra.config import Config
from app.infra.errors import ConfigError

ROLES = ("tier1", "tier2", "admin")

# Migration 011: argon2id, time_cost=3 · memory_cost=64 MiB · parallelism=4.
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

_TOKEN_CLAIMS = ("sub", "role", "iat", "exp")


def hash_password(password: str) -> str:
    return HASHER.hash(password)


def verify_password(hash: str, password: str) -> bool:
    """`True` only when `password` matches `hash`.

    A mismatch, a malformed stored hash (migration 011's backfill value, or
    garbage) and any other argon2 failure are all "no", never an exception:
    `InvalidHashError` is a `ValueError`, not an `Argon2Error`, in
    argon2-cffi 25.1.0 — measured — so it is named here explicitly.
    """
    try:
        return HASHER.verify(hash, password)
    except (argon2_exceptions.Argon2Error, argon2_exceptions.InvalidHashError):
        return False


# Verified against every unknown username so that the "no such user" path costs
# what a wrong password costs (a timing-safe shape). Computed once, at import.
DUMMY_HASH = hash_password("")


@dataclasses.dataclass(frozen=True)
class Claims:
    user_id: str
    username: str
    role: str
    iat: float
    exp: float


class LoginFailed(Exception):
    """`reason` ∈ unknown_user | bad_password | inactive. The API answers all three
    with the same body; the reason exists for tests and logs."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AccountLocked(Exception):
    def __init__(self, locked_until: datetime) -> None:
        super().__init__(f"locked until {locked_until.isoformat()}")
        self.locked_until = locked_until


class Unauthorized(Exception):
    """`reason` ∈ missing | malformed | expired | unknown_user | inactive | logged_out."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthDisabled(Exception):
    """`JWT_SECRET` is empty: fail closed (DEC-040's shape), never "no auth"."""


def login(conn: psycopg.Connection, username: str, password: str, cfg: Config) -> Claims:
    """Check the password, maintain the lockout counter, return the claims to sign.

    The failed-login `UPDATE` is left uncommitted for the caller: an HTTP layer
    whose connection rolls back on exceptions must commit *before* it raises the
    `401`/`423` (planning decision 3), or the fifth wrong password never locks.
    """
    if cfg.JWT_SECRET == "":
        raise AuthDisabled()
    row = conn.execute(
        """
        SELECT user_id, username, role, is_active, password_hash, failed_logins, locked_until,
               (locked_until IS NOT NULL AND locked_until > now()) AS locked
        FROM users
        WHERE username = %s
        FOR UPDATE
        """,
        (username,),
    ).fetchone()
    if row is None:
        verify_password(DUMMY_HASH, password)
        raise LoginFailed("unknown_user")
    user_id, row_username, role, is_active, password_hash, _failed, locked_until, locked = row
    if locked:
        raise AccountLocked(locked_until)
    if not is_active:
        raise LoginFailed("inactive")
    if not verify_password(password_hash, password):
        _failed, locked_until, locked = conn.execute(
            """
            UPDATE users
            SET failed_logins = failed_logins + 1,
                locked_until = CASE
                    WHEN failed_logins + 1 >= %s THEN now() + (%s || ' minutes')::interval
                    ELSE locked_until
                END
            WHERE user_id = %s
            RETURNING failed_logins, locked_until,
                      (locked_until IS NOT NULL AND locked_until > now()) AS locked
            """,
            (cfg.LOGIN_MAX_FAILS, cfg.LOCKOUT_MINUTES, user_id),
        ).fetchone()
        if locked:
            raise AccountLocked(locked_until)
        raise LoginFailed("bad_password")
    conn.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE user_id = %s", (user_id,)
    )
    iat = time.time()
    return Claims(
        user_id=str(user_id),
        username=row_username,
        role=role,
        iat=iat,
        exp=iat + cfg.JWT_TTL_HOURS * 3600,
    )


def issue_token(claims: Claims, cfg: Config) -> str:
    payload = {"sub": claims.user_id, "role": claims.role, "iat": claims.iat, "exp": claims.exp}
    return jwt.encode(payload, cfg.JWT_SECRET, algorithm="HS256")


def verify(conn: psycopg.Connection, token: str, cfg: Config) -> Claims:
    """Decode, then one `SELECT` by primary key: the returned `role` and the
    active/logged-out state are the row's, on every request."""
    if cfg.JWT_SECRET == "":
        raise AuthDisabled()
    try:
        payload = jwt.decode(
            token, cfg.JWT_SECRET, algorithms=["HS256"], options={"require": list(_TOKEN_CLAIMS)}
        )
    except jwt.ExpiredSignatureError as exc:  # a subclass of InvalidTokenError: first
        raise Unauthorized("expired") from exc
    except jwt.InvalidTokenError as exc:
        raise Unauthorized("malformed") from exc
    try:
        user_id = str(uuid.UUID(str(payload["sub"])))
        iat = float(payload["iat"])
        exp = float(payload["exp"])
    except (ValueError, TypeError) as exc:
        raise Unauthorized("malformed") from exc
    row = conn.execute(
        """
        SELECT username, role, is_active, sessions_invalid_before,
               EXTRACT(EPOCH FROM sessions_invalid_before)
        FROM users
        WHERE user_id = %s
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        raise Unauthorized("unknown_user")
    username, role, is_active, invalid_before, invalid_epoch = row
    if not is_active:
        raise Unauthorized("inactive")
    if invalid_before is not None and iat <= float(invalid_epoch):
        raise Unauthorized("logged_out")
    return Claims(user_id=user_id, username=username, role=role, iat=iat, exp=exp)


def logout(conn: psycopg.Connection, user_id: str) -> None:
    """Every token issued before now is dead (`verify` compares `iat` against this)."""
    conn.execute("UPDATE users SET sessions_invalid_before = now() WHERE user_id = %s", (user_id,))


def create_user(
    conn: psycopg.Connection, *, username: str, display_name: str, role: str, password: str
) -> str:
    """Insert the user and its `admin.user_created` audit row; return the new `user_id`."""
    if role not in ROLES:
        raise ValueError(f"role: must be one of {'|'.join(ROLES)}, got {role!r}")
    (user_id,) = conn.execute(
        """
        INSERT INTO users (user_id, username, display_name, role, password_hash)
        VALUES (gen_random_uuid(), %s, %s, %s, %s)
        RETURNING user_id
        """,
        (username, display_name, role, hash_password(password)),
    ).fetchone()
    # The same statement `audit.events.write_event` runs, duplicated here because
    # G1 forbids `infra` importing `audit` (`ALLOWED["infra"]` is empty). The two
    # CHECKs (`actor_role='system'` ⇒ `actor_id IS NULL`, the event-type set) are
    # the database's and hold here exactly as they hold there.
    conn.execute(
        """
        INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload)
        VALUES ('admin.user_created', %s, NULL, 'system', %s)
        """,
        (str(user_id), Jsonb({"username": username, "role": role})),
    )
    return str(user_id)


def set_password(conn: psycopg.Connection, username: str, password: str) -> bool:
    """`False` when no such user."""
    cursor = conn.execute(
        "UPDATE users SET password_hash = %s WHERE username = %s",
        (hash_password(password), username),
    )
    return cursor.rowcount == 1


def deactivate(conn: psycopg.Connection, username: str) -> bool:
    """Deactivate and kill every token at the same moment. `False` when no such user."""
    cursor = conn.execute(
        "UPDATE users SET is_active = false, sessions_invalid_before = now() WHERE username = %s",
        (username,),
    )
    return cursor.rowcount == 1


# --------------------------------------------------------------------------
# CLI — python3 -m app.infra.auth {seed-users,set-password,deactivate}
# --------------------------------------------------------------------------

_EXIT_INPUT = 1  # a bad role, an empty credential, an unknown user
_EXIT_DSN = 2  # cannot connect


def _env_key(username: str) -> str:
    return f"SEED_PASSWORD_{username.upper().replace('-', '_')}"


def _read_password(username: str) -> str:
    """`SEED_PASSWORD_<USERNAME>` (`-` → `_`) when set and non-empty, else a prompt.
    Never argv."""
    value = os.environ.get(_env_key(username))
    if value:
        return value
    return getpass.getpass(f"password for {username}: ")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--env-file",
        default=".env",
        help="where DATABASE_URL is read from when --dsn is not given (default: .env)",
    )
    common.add_argument(
        "--dsn", default=None, help="connect here instead of DATABASE_URL (never printed)"
    )
    parser = argparse.ArgumentParser(
        prog="python3 -m app.infra.auth",
        description="Manage the users table. A credential is never an argument: "
        "it is read from SEED_PASSWORD_<USERNAME> (with '-' as '_') or prompted for.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    seed = subparsers.add_parser(
        "seed-users",
        parents=[common],
        help="create the accounts that do not exist yet; existing usernames are skipped",
        description="Create each --user that does not exist yet. An existing username is "
        "reported as 'exists, skipped' and left exactly as it is. Each credential comes from "
        "SEED_PASSWORD_<USERNAME> or a prompt.",
    )
    seed.add_argument(
        "--user",
        action="append",
        nargs=3,
        metavar=("USERNAME", "ROLE", "DISPLAY_NAME"),
        required=True,
        help="an account to create; ROLE is tier1, tier2 or admin (repeatable)",
    )
    set_pw = subparsers.add_parser(
        "set-password",
        parents=[common],
        help="replace one user's password (read from SEED_PASSWORD_<USERNAME> or a prompt)",
    )
    set_pw.add_argument("username")
    deact = subparsers.add_parser(
        "deactivate",
        parents=[common],
        help="set is_active = false and kill the user's sessions",
    )
    deact.add_argument("username")
    return parser


def _connect(args: argparse.Namespace) -> psycopg.Connection:
    dsn = args.dsn
    if dsn is None:
        dsn = config.load(env_file=args.env_file).DATABASE_URL
    return db.connect(dsn)


def _seed_users(conn: psycopg.Connection, users: list[list[str]], out) -> int:
    for username, role, display_name in users:
        exists = conn.execute("SELECT 1 FROM users WHERE username = %s", (username,)).fetchone()
        if exists is not None:
            print(f"exists, skipped: {username}", file=out)
            continue
        password = _read_password(username)
        if not password:
            print(f"error: empty password for {username}", file=sys.stderr)
            return _EXIT_INPUT
        create_user(
            conn, username=username, display_name=display_name, role=role, password=password
        )
        conn.commit()  # one transaction per user, committed as it goes
        print(f"created: {username} ({role})", file=out)
    return 0


def _set_password(conn: psycopg.Connection, username: str, out) -> int:
    password = _read_password(username)
    if not password:
        print(f"error: empty password for {username}", file=sys.stderr)
        return _EXIT_INPUT
    if not set_password(conn, username, password):
        print(f"error: no such user: {username}", file=sys.stderr)
        return _EXIT_INPUT
    conn.commit()
    print(f"password set: {username}", file=out)
    return 0


def _deactivate(conn: psycopg.Connection, username: str, out) -> int:
    if not deactivate(conn, username):
        print(f"error: no such user: {username}", file=sys.stderr)
        return _EXIT_INPUT
    conn.commit()
    print(f"deactivated: {username}", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "seed-users":
        for _username, role, _display_name in args.user:
            if role not in ROLES:
                print(
                    f"error: role must be one of {'|'.join(ROLES)}, got {role!r}", file=sys.stderr
                )
                return _EXIT_INPUT
    try:
        conn = _connect(args)
    except (psycopg.OperationalError, ConfigError) as exc:
        # `str(exc)` names the failure (a missing database, a refused password),
        # never the DSN — libpq does not echo the connection string.
        print(f"error: cannot connect to the database: {exc}", file=sys.stderr)
        return _EXIT_DSN
    try:
        if args.command == "seed-users":
            return _seed_users(conn, args.user, sys.stdout)
        if args.command == "set-password":
            return _set_password(conn, args.username, sys.stdout)
        return _deactivate(conn, args.username, sys.stdout)
    finally:
        conn.close()


if __name__ == "__main__":  # pragma: no cover — exercised through subprocess in test_auth.py
    sys.exit(main())
