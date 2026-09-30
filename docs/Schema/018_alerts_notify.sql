-- ============================================================================
-- 018_alerts_notify.sql — AI Support SOC
-- DEC-162: the real-time queue. A row trigger on `alerts` sends one NOTIFY per changed
-- alert; the application holds one LISTEN per process and fans the ids out to the
-- browsers' WebSockets (`GET /api/ws`, backend/app/web/live.py).
-- Runs after 017, as the database owner. KHÔNG sửa 001-017: chúng đã áp.
--
-- Channel `alerts_changed`. The payload is JSON text and EXACTLY two keys:
--
--     {"alert_id": "<alert_id>", "op": "INSERT" | "UPDATE"}
--
-- Ids only, never content (DEC-101, the blind arm): the channel is read by every
-- logged-in browser's socket, and `raw_log`, `description` and the rest of the row are
-- exactly what the blind arm is built not to show. A subscriber that wants a field
-- refetches the alert through the API, which applies the arm.
--
-- Delivery semantics that the application relies on:
--   * NOTIFY is delivered at COMMIT: a rolled-back write is never announced, and a
--     listener that reads the row on notification sees the committed state.
--   * Identical (channel, payload) pairs inside ONE transaction are delivered once, so
--     a batch that touches the same alert twice is one message.
--   * A LISTENing connection that is down misses what was sent meanwhile — the
--     application says "many" to every socket after it reconnects (live.run_listener).
--
-- The blind arm has one more silence (R12, in the function): a blind, undecided alert
-- whose only change is `triage_status` — ① finishing — is not announced.
--
-- Only the columns the queue and the alert page render wake listeners
-- (`UPDATE OF`): a write to any other column (the enrichment payload, the LLM columns,
-- `updated_at` on its own) does not chatter on the channel. `UPDATE OF` fires when the
-- column is NAMED in the UPDATE's SET list, whether or not the value changed; the
-- workers that write these columns write them because they changed.
--
-- The function runs with the writer's own rights (no SECURITY DEFINER): `pg_notify` is
-- executable by PUBLIC, so `app_rw` needs no extra grant.
-- ============================================================================
BEGIN;

CREATE OR REPLACE FUNCTION notify_alerts_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- DEC-101, Director ruling R12: ① finishing on a blind, undecided alert must not wake
  -- the sockets. ①'s only write to `alerts` names `triage_status` and `triaged_count`;
  -- a message "alert X changed" right then would tell the analyst that ① ran on X, which
  -- `tier1/visibility.py` forbids ("a blind row must not even say ① ran"). So an UPDATE
  -- is silent when ALL of these hold: the alert is blind (`NOT suggestion_visible`), it is
  -- not decided (the status is outside `visibility.SHOW_STATES` — keep the two lists in
  -- step; test_schema_v3_018 compares them), and every other watched column is unchanged
  -- (only `triage_status` moved). A blind alert still notifies on any other change.
  IF TG_OP = 'UPDATE'
     AND NOT NEW.suggestion_visible
     AND NEW.status NOT IN ('closed_fp', 'closed_benign', 'closed_confirmed',
                            'escalated_tier2', 'auto_closed')
     AND (NEW.status, NEW.occurrence_count, NEW.last_seen_at, NEW.acknowledged_by,
          NEW.closed_at, NEW.case_id, NEW.risk_score)
         IS NOT DISTINCT FROM
         (OLD.status, OLD.occurrence_count, OLD.last_seen_at, OLD.acknowledged_by,
          OLD.closed_at, OLD.case_id, OLD.risk_score)
  THEN
    RETURN NULL;
  END IF;
  PERFORM pg_notify('alerts_changed',
                    json_build_object('alert_id', NEW.alert_id, 'op', TG_OP)::text);
  RETURN NULL;  -- AFTER ROW: the return value is ignored
END $$;

CREATE TRIGGER trg_alerts_notify
AFTER INSERT OR UPDATE OF status, occurrence_count, last_seen_at, triage_status,
                          acknowledged_by, closed_at, case_id, risk_score
ON alerts FOR EACH ROW EXECUTE FUNCTION notify_alerts_changed();

INSERT INTO schema_migrations (version) VALUES ('018_alerts_notify');

COMMIT;
