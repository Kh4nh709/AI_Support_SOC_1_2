"""web/live.py — the real-time channel's server half (DEC-162, P10-T05).

Three pieces, wired at the application's edge:

    alerts (row trigger, migration 018)
        └─ NOTIFY alerts_changed '{"alert_id": "...", "op": "INSERT"|"UPDATE"}'
             └─ run_listener   ONE LISTEN connection per app process
                  └─ Hub       coalesces, then fans out to every socket
                       └─ Subscription   one per connected `/api/ws` socket

Two properties are pinned by the tests and matter more than the plumbing.

**Ids only (DEC-101).** A message is `{"type": "alerts.changed", "ids": [...]}` or
`{"type": "alerts.changed", "many": true}` — never a field of an alert. The blind arm
hides content from the analyst; a channel that every logged-in browser reads must not
carry any. The client that wants a row refetches it through the API, which applies the
arm.

**One refetch per burst (Review Focus 2).** A pull of 500 alerts is 500 NOTIFYs. Each
subscription collects them for `coalesce_ms` (500 ms by default) and sends one message,
`ids` sorted, or `many` when more than `many_cap` (200) distinct alerts changed. The
pending set therefore never grows past `many_cap`, whatever the burst. A reader that has
stopped reading (a background browser tab) holds ONE merged unread message, never a
backlog.

Threads. `Hub.publish` is safe from any thread: each subscription is bound to the event
loop it was created on and receives through `call_soon_threadsafe`. That is the shape
production has (one loop) and the shape `TestClient` has (one loop per connection, on
its own thread, while the test publishes from another).

Secrets. The listener logs the exception's CLASS and nothing else. A libpq/psycopg error
message can quote the connection string, DSN password included, so `str(exc)` is never
logged from here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections.abc import Iterator

import psycopg

log = logging.getLogger(__name__)

CHANNEL = "alerts_changed"

COALESCE_MS = 500
MANY_CAP = 200
BACKOFF_FIRST_S = 1
BACKOFF_CAP_S = 30

Message = dict


class Subscription:
    """One socket's view of the hub. Created, read and closed on ONE event loop; only
    `Hub.publish` / `Hub.publish_many` reach it from other threads, and only through
    `call_soon_threadsafe`."""

    def __init__(
        self,
        hub: Hub,
        loop: asyncio.AbstractEventLoop,
        coalesce_s: float,
        many_cap: int,
    ) -> None:
        self._hub = hub
        self._loop = loop
        self._coalesce_s = coalesce_s
        self._many_cap = many_cap
        self._queue: asyncio.Queue[Message] = asyncio.Queue()
        self._pending: set[str] = set()
        self._pending_many = False
        self._timer: asyncio.TimerHandle | None = None
        self._closed = False

    # -- called from any thread -----------------------------------------------------

    def _post(self, callback, *args) -> bool:
        """Run `callback` on the subscription's loop; False when that loop is gone."""
        try:
            self._loop.call_soon_threadsafe(callback, *args)
        except RuntimeError:  # the loop closed: its socket is gone with it
            return False
        return True

    # -- run on the subscription's loop ---------------------------------------------

    def _on_changed(self, alert_id: str) -> None:
        if self._closed:
            return
        if not self._pending_many:
            self._pending.add(alert_id)
            if len(self._pending) > self._many_cap:
                self._go_many()
        self._arm()

    def _on_many(self) -> None:
        if self._closed:
            return
        self._go_many()
        self._arm()

    def _go_many(self) -> None:
        self._pending_many = True
        self._pending.clear()

    def _arm(self) -> None:
        if self._timer is None:
            self._timer = self._loop.call_later(self._coalesce_s, self._flush)

    def _flush(self) -> None:
        self._timer = None
        if self._closed or not (self._pending or self._pending_many):
            return
        many, ids = self._pending_many, set(self._pending)
        self._pending_many, self._pending = False, set()
        # A reader that has not read the last message yet gets ONE merged message.
        if not self._queue.empty():
            unread = self._queue.get_nowait()
            if unread.get("many"):
                many = True
            else:
                ids |= set(unread["ids"])
        if not many and len(ids) > self._many_cap:
            many = True
        if many:
            message: Message = {"type": "alerts.changed", "many": True}
        else:
            message = {"type": "alerts.changed", "ids": sorted(ids)}
        self._queue.put_nowait(message)

    async def next_message(self) -> Message:
        """The next coalesced message. Waits for one; a closed subscription never gets any."""
        return await self._queue.get()

    def close(self) -> None:
        """Leave the hub and drop whatever was pending. Idempotent; call it on the
        subscription's own loop (the socket handler's `finally`)."""
        self._closed = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self._pending.clear()
        self._pending_many = False
        while not self._queue.empty():
            self._queue.get_nowait()
        self._hub._discard(self)


class Hub:
    def __init__(self, *, coalesce_ms: int = COALESCE_MS, many_cap: int = MANY_CAP) -> None:
        self._coalesce_s = coalesce_ms / 1000
        self._many_cap = many_cap
        self._lock = threading.Lock()
        self._subs: list[Subscription] = []

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    def subscribe(self) -> Subscription:
        """A new subscription bound to the RUNNING event loop; call it from a coroutine."""
        sub = Subscription(self, asyncio.get_running_loop(), self._coalesce_s, self._many_cap)
        with self._lock:
            self._subs.append(sub)
        return sub

    def _discard(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def _snapshot(self) -> list[Subscription]:
        with self._lock:
            return list(self._subs)

    def publish(self, alert_id: str) -> None:
        """One alert changed. Safe from any thread; never raises."""
        for sub in self._snapshot():
            if not sub._post(sub._on_changed, alert_id):
                self._discard(sub)

    def publish_many(self) -> None:
        """Something changed that the hub cannot name (the LISTEN connection was down):
        every socket is told to refetch. Safe from any thread; never raises."""
        for sub in self._snapshot():
            if not sub._post(sub._on_many):
                self._discard(sub)


# The process-wide hub the sockets subscribe to and the listener publishes into. Tests that
# need a different window replace this attribute; both users read it through the module.
HUB = Hub()


# --------------------------------------------------------------------------------------
# The LISTEN connection
# --------------------------------------------------------------------------------------


def backoff_delays(first: float = BACKOFF_FIRST_S, cap: float = BACKOFF_CAP_S) -> Iterator[float]:
    """1, 2, 4, 8, 16, 30, 30, ... seconds."""
    delay = first
    while True:
        yield delay
        delay = min(delay * 2, cap)


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _relay(hub: Hub, payload: str) -> None:
    """One notification into the hub. An unreadable one is dropped (and counted in the
    log by class, never by content): the channel must keep listening."""
    try:
        data = json.loads(payload)
    except ValueError:
        log.warning("alerts listener: dropped an unreadable notification")
        return
    alert_id = data.get("alert_id") if isinstance(data, dict) else None
    if not isinstance(alert_id, str) or not alert_id:
        log.warning("alerts listener: dropped a notification without an alert_id")
        return
    hub.publish(alert_id)


async def run_listener(hub: Hub, dsn: str) -> None:
    """LISTEN alerts_changed on one dedicated connection, forever.

    A dropped connection is retried with a 1 s → 30 s backoff (reset by a successful
    connect). Notifications sent while it was down are gone, so after every RECONNECT —
    never after the first connect — the hub tells every socket `many`. Cancel it to stop.
    """
    delays = backoff_delays()
    reconnect = False
    while True:
        try:
            async with await psycopg.AsyncConnection.connect(
                dsn,
                autocommit=True,
                connect_timeout=10,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=3,
            ) as conn:
                await conn.execute(f"LISTEN {CHANNEL}")
                delays = backoff_delays()
                if reconnect:
                    hub.publish_many()
                log.info("alerts listener: listening on %s", CHANNEL)
                async for notification in conn.notifies():
                    _relay(hub, notification.payload)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — every failure means "retry"
            # The class only: a libpq message can quote the DSN, password included.
            log.warning("alerts listener: connection lost (%s); retrying", type(exc).__name__)
        reconnect = True
        await _sleep(next(delays))
