"""P10-T05 — `app.web.live`: the hub between the LISTEN connection and the sockets.

Pure: no database, no server, no test-only marker — `make test` runs all of it. Each test
drives its own event loop with `asyncio.run`.

Review Focus 2 of the plan lives here: a pull of 500 alerts arrives as 500 NOTIFYs, and the
queue must refetch about once per burst, not once per alert. The client half is P10-T09's;
this file pins the server half — many publishes, one message.

The blind arm (DEC-101): a message carries the alert ids and a `many` flag, never a field
of the alert. `test_messages_never_carry_more_than_type_ids_many` fixes the key set.
"""

from __future__ import annotations

import asyncio
import logging
import threading

import psycopg
import pytest
from app.web import live
from app.web.live import Hub


def test_burst_is_coalesced_into_one_message():
    async def scenario():
        hub = Hub(coalesce_ms=50)
        sub = hub.subscribe()
        for i in range(50):
            hub.publish(f"a{i}")
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg["type"] == "alerts.changed" and len(msg["ids"]) == 50
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.2)

    asyncio.run(scenario())


def test_ids_are_sorted_and_deduplicated():
    async def scenario():
        hub = Hub(coalesce_ms=20)
        sub = hub.subscribe()
        for alert_id in ("b", "a", "c", "a", "b"):
            hub.publish(alert_id)
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "ids": ["a", "b", "c"]}

    asyncio.run(scenario())


def test_past_the_cap_the_message_says_many():
    async def scenario():
        hub = Hub(coalesce_ms=20, many_cap=10)
        sub = hub.subscribe()
        for i in range(11):
            hub.publish(f"a{i}")
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "many": True}
        assert "ids" not in msg

    asyncio.run(scenario())


def test_at_the_cap_the_message_still_lists_the_ids():
    async def scenario():
        hub = Hub(coalesce_ms=20, many_cap=10)
        sub = hub.subscribe()
        for i in range(10):
            hub.publish(f"a{i}")
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg["type"] == "alerts.changed" and len(msg["ids"]) == 10
        assert "many" not in msg

    asyncio.run(scenario())


def test_a_burst_of_thousands_stays_one_small_message():
    """500 pulled alerts, then some: the pending set never grows past the cap."""

    async def scenario():
        hub = Hub(coalesce_ms=30, many_cap=200)
        sub = hub.subscribe()
        for i in range(5000):
            hub.publish(f"a{i}")
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "many": True}
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.2)

    asyncio.run(scenario())


def test_messages_never_carry_more_than_type_ids_many():
    async def scenario():
        hub = Hub(coalesce_ms=20, many_cap=3)
        sub = hub.subscribe()
        seen = []
        hub.publish("a1")
        seen.append(await asyncio.wait_for(sub.next_message(), 1))
        for i in range(5):
            hub.publish(f"b{i}")
        seen.append(await asyncio.wait_for(sub.next_message(), 1))
        hub.publish_many()
        seen.append(await asyncio.wait_for(sub.next_message(), 1))
        assert len(seen) == 3
        for msg in seen:
            assert set(msg) <= {"type", "ids", "many"}
            assert msg["type"] == "alerts.changed"
            assert ("ids" in msg) != ("many" in msg)  # exactly one of the two

    asyncio.run(scenario())


def test_closed_subscription_gets_nothing():
    async def scenario():
        hub = Hub(coalesce_ms=20)
        sub = hub.subscribe()
        sub.close()
        hub.publish("a1")
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.2)

    asyncio.run(scenario())


def test_closing_before_the_flush_drops_the_pending_burst():
    async def scenario():
        hub = Hub(coalesce_ms=50)
        sub = hub.subscribe()
        hub.publish("a1")
        await asyncio.sleep(0)  # the publish reaches the subscription; the flush is scheduled
        sub.close()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.2)

    asyncio.run(scenario())


def test_close_removes_the_subscription_from_the_hub():
    async def scenario():
        hub = Hub()
        first, second = hub.subscribe(), hub.subscribe()
        assert hub.subscribers == 2
        first.close()
        first.close()  # closing twice is harmless
        assert hub.subscribers == 1
        second.close()
        assert hub.subscribers == 0

    asyncio.run(scenario())


def test_every_subscription_gets_its_own_copy():
    async def scenario():
        hub = Hub(coalesce_ms=20)
        first, second = hub.subscribe(), hub.subscribe()
        hub.publish("a1")
        one = await asyncio.wait_for(first.next_message(), 1)
        two = await asyncio.wait_for(second.next_message(), 1)
        assert one == two == {"type": "alerts.changed", "ids": ["a1"]}
        first.close()
        hub.publish("a2")
        assert await asyncio.wait_for(second.next_message(), 1) == {
            "type": "alerts.changed",
            "ids": ["a2"],
        }

    asyncio.run(scenario())


def test_two_bursts_are_two_messages():
    async def scenario():
        hub = Hub(coalesce_ms=30)
        sub = hub.subscribe()
        hub.publish("a1")
        assert await asyncio.wait_for(sub.next_message(), 1) == {
            "type": "alerts.changed",
            "ids": ["a1"],
        }
        hub.publish("a2")
        assert await asyncio.wait_for(sub.next_message(), 1) == {
            "type": "alerts.changed",
            "ids": ["a2"],
        }

    asyncio.run(scenario())


def test_nothing_is_delivered_before_the_coalescing_window_ends():
    async def scenario():
        hub = Hub(coalesce_ms=300)
        sub = hub.subscribe()
        hub.publish("a1")
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.1)
        assert (await asyncio.wait_for(sub.next_message(), 1))["ids"] == ["a1"]

    asyncio.run(scenario())


def test_a_stalled_reader_holds_one_merged_message_not_a_backlog():
    """A browser tab in the background stops reading. Flushes must merge into the one
    unread message, or the queue grows for as long as the tab sleeps."""

    async def scenario():
        hub = Hub(coalesce_ms=20, many_cap=200)
        sub = hub.subscribe()
        for round_ in range(5):
            hub.publish(f"a{round_}")
            await asyncio.sleep(0.06)  # each round flushes; nobody reads
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "ids": ["a0", "a1", "a2", "a3", "a4"]}
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.next_message(), 0.2)

    asyncio.run(scenario())


def test_a_stalled_reader_merging_past_the_cap_becomes_many():
    async def scenario():
        hub = Hub(coalesce_ms=20, many_cap=4)
        sub = hub.subscribe()
        for round_ in range(3):
            hub.publish(f"a{round_}x")
            hub.publish(f"a{round_}y")
            await asyncio.sleep(0.06)
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "many": True}

    asyncio.run(scenario())


def test_publish_many_tells_every_subscription_to_refetch():
    """After a LISTEN reconnect the hub cannot know what it missed."""

    async def scenario():
        hub = Hub(coalesce_ms=20)
        first, second = hub.subscribe(), hub.subscribe()
        hub.publish_many()
        for sub in (first, second):
            assert await asyncio.wait_for(sub.next_message(), 1) == {
                "type": "alerts.changed",
                "many": True,
            }

    asyncio.run(scenario())


def test_publish_from_another_thread_is_delivered():
    """The socket's loop is not the caller's thread in every test (and would not be if a
    second producer were ever added): publish must be safe from any thread."""

    async def scenario():
        hub = Hub(coalesce_ms=20)
        sub = hub.subscribe()
        worker = threading.Thread(target=hub.publish, args=("from-thread",))
        worker.start()
        worker.join()
        msg = await asyncio.wait_for(sub.next_message(), 1)
        assert msg == {"type": "alerts.changed", "ids": ["from-thread"]}

    asyncio.run(scenario())


def test_publish_after_its_loop_closed_drops_the_subscription_quietly():
    hub = Hub(coalesce_ms=20)
    holder = {}

    async def scenario():
        holder["sub"] = hub.subscribe()

    asyncio.run(scenario())  # the loop is closed when this returns
    hub.publish("a1")  # must not raise
    assert hub.subscribers == 0


def test_publish_with_no_subscriber_is_a_no_op():
    hub = Hub()
    hub.publish("a1")
    hub.publish_many()
    assert hub.subscribers == 0


# --------------------------------------------------------------------------------------
# run_listener — reconnect with a 1 s → 30 s backoff, and the DSN never logged
# --------------------------------------------------------------------------------------


def test_backoff_doubles_from_one_second_and_stops_at_thirty():
    delays = live.backoff_delays()
    assert [next(delays) for _ in range(9)] == [1, 2, 4, 8, 16, 30, 30, 30, 30]


def test_listener_retries_with_backoff_and_never_logs_the_dsn(monkeypatch, caplog):
    secret = "hunter2-P10T05-secret"
    dsn = f"postgresql://someone:{secret}@127.0.0.1:9/db"
    sleeps: list[float] = []
    attempts = {"n": 0}

    async def connect(conninfo, **kwargs):
        attempts["n"] += 1
        # libpq/psycopg errors can quote the conninfo they choked on.
        raise psycopg.OperationalError(f"could not connect using {conninfo}")

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 7:
            raise asyncio.CancelledError

    monkeypatch.setattr(live.psycopg.AsyncConnection, "connect", connect)
    monkeypatch.setattr(live, "_sleep", fake_sleep)

    async def scenario():
        with (
            caplog.at_level(logging.DEBUG, logger="app.web.live"),
            pytest.raises(asyncio.CancelledError),
        ):
            await live.run_listener(Hub(), dsn)

    asyncio.run(scenario())

    assert attempts["n"] == 7
    assert sleeps == [1, 2, 4, 8, 16, 30, 30]
    logged = caplog.text
    assert "OperationalError" in logged  # the failure is visible ...
    assert (
        secret not in logged and "127.0.0.1" not in logged and dsn not in logged
    )  # ... the DSN is not
