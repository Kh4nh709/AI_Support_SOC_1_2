# UI v1.0: real logs and real attacks (04–06/10/2026)

This is the test-day log for the React UI v1.0 (spec `docs/superpowers/specs/2026-09-30-react-ui-v1-design.md` §7, DEC-163).

**Who does what:**
- The Owner runs the lab attack scenarios, normal activity, and every container write.
- The Director watches read-only, through queries and the UI.

**Defects:**
- Every defect gets a row in the log below, with its steps, expected result, actual result and severity.
- Each one becomes a fix card with a Coder and a Reviewer, and is re-tested the same day where possible.
- Attack windows are tagged with `lab_tag.py`, run by the Owner, so the pilot figures can separate attack-day decisions from live traffic.

## 1. Checks the automated suites cannot cover

Some things the unit tests (jsdom) and the e2e suite (`vite preview` on a scratch stack) never see. The main ones are nginx, the CSP, and a real screen. Tick each one on the deployed `ui` service at `http://127.0.0.1:8080/`.

| # | Check | How | Expected | Result |
|---|---|---|---|---|
| C1 | nginx upgrades `/api/ws`, and the CSP `connect-src 'self'` allows the socket | Log in as tier1 and open the queue. | The header shows "Trực tiếp". The browser console has no CSP or WebSocket error. | |
| C2 | Real-time through nginx | Keep the queue open. The Owner lets a real alert arrive, or runs a lab scenario. | The new row appears within about 2 s, with no reload. | |
| C3 | An idle socket survives nginx's 1 h `proxy_read_timeout` | Leave the queue open for more than 1 h with no alerts, then let one arrive. | Still "Trực tiếp", and the row appears. | |
| C4 | Fallback when the socket drops | Restart only the `app` container (Owner). | The indicator shows "Mất kết nối" and the page polls every 30 s. It returns to "Trực tiếp" by itself, and the queue refetches once. | |
| C5 | Blind arm, live (DEC-101, R12, R17) | On a blind, undecided alert, watch the queue row and the alert page while ① runs. | Nothing changes: no ⟳, no jump up the queue, no AI state other than "ẩn — nhánh mù". After the decision, ① shows. | |
| C6 | Times in +07 | Compare a row's time with the Wazuh event time. | The same wall-clock time, in +07. | |
| C7 | Large log | Open an alert with a very long `raw_log`. | The page stays responsive. The log scrolls inside its box and shows the truncation note when truncated. | |
| C8 | Match to the canvas | Compare the queue, alert, case and login pages with the `Queue`, `Main`, `Case` and `Login` artboards. | Two columns, with the ① column about 520 px and the ② column about 560 px, the violet AI tokens, and legible contrast. | |
| C9 | Count guard (R19) | Acknowledge a noisy alert, and type a reason while the cluster grows by more than 20. | "N → M" shows. Submitting gives the 409 message, and the second submit works. | |
| C10 | Token expiry while typing | Let the session expire, or log out in another window, while typing a reason. Then submit, log in again, and return. | The draft is still in the box, and only one decision is recorded. | |
| C11 | Tier-2 flow on a real escalation | Escalate a real alert, then open the case as tier2 and analyze it. | The case appears, and ② runs to done with evidence marks. The left column updates when ② ends. | |
| C12 | Jinja retirement gate (spec §8) | The Owner uses the React Tier-1 flow end to end. | The Owner confirms. Only then does P10-T13 retire the Jinja Tier-1/Tier-2 pages. | |

## 2. Known v1.0 seams (not defects)

- The admin signs in separately on port 8000 for the Jinja admin pages (spec §7).
- The ① "unavailable" state shows generic text without `stopped_by`, because the alert view does not carry it (P10-T10).
- Escalating one alert sweeps its correlated open alerts into the case (A11b). A swept alert's page still shows a "Khớp" row, but the pilot report has no decision row for it. The report is the metric of record (P10-T10).
- A slow logout POST that reaches the server after a re-login in the same window ends the new session once. It fails closed (P10-T08, R14).
- For an escalation, the pilot report's ① may include a run that was in flight at the moment of the decision. The export prints this caveat (P10-T06).
- When a stalled ② job later finishes, the case page's left column updates only after a reload (P10-T11). This is parked for the final fix batch.

## 3. Defect log

| # | Date | Page | Steps | Expected | Actual | Severity | Fix card | Re-tested |
|---|---|---|---|---|---|---|---|---|
