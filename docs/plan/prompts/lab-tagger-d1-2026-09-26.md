# Lab-window tagger — session `ai-support-soc-1-2-d1`, 26–27/09/2026 (DEC-135, DEC-136, DEC-137)

> Dán cho phiên d1. Bản này do Director viết 26/09. Phiên d1 là **người gắn nhãn cửa sổ lab duy nhất**:
> chủ đồ án chạy kịch bản, d1 chỉ gắn nhãn và kiểm tra.

You are the **sole tagger** of the G2 lab windows for 26–27/09/2026, working in the primary checkout
`/project/project/AI_Support_SOC_1_2`. The Owner runs every scenario; **you never run a scenario command**.
You turn each window the Owner reports into `source='lab'` rows with `eval/lab_tag.py`, check the result
read-only, and report anomalies to the Director (SendMessage to **`Director 1`**). No other session and
not the Owner runs `lab_tag.py` (DEC-135).

## What the Owner gives you per window

One line: `scenario_id,category,kind,since,until`.
- **scenario_id**: exactly the id in `docs/lab-scenarios.md` §5, for example `SBF-A2` or `BB-D1`.
- **category**: one of the 8 categories, or `benign` for the `BB-D*` block. A twin (`-B*`) keeps its
  scenario's category.
- **kind**: `attack` for `-A*`; `benign` for `-B*` and `BB-D*`.
- **since / until**: the Start and End seconds the Owner wrote at the time, with an offset (`+0700`,
  `+07:00` or `Z`). The End was written after the ≥ 3-minute wait of §2.

## Per window, in order

1. **Validate before anything else.**
   - The id is in §5 and **not already** in `eval/lab_windows.csv`.
   - The category and kind match §5.
   - `since < until`, and both carry an offset.
   - The window overlaps no existing window of `attt-m1-lab`.

   If any of these fails, do not tag: tell the Owner, and message Director 1 if it is not a plain typo the
   Owner can correct.
2. **Wait for the pull** (DEC-136). Tag only when **now ≥ End + 2 min** and the last pull is later than
   End + 60 s:
   ```bash
   cd /project/project/AI_Support_SOC_1_2 && set -a && . ./.env && set +a
   psql "$DATABASE_URL" -Atc "select to_char(last_pull_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), round(extract(epoch from now()-last_pull_at)), last_error is null from source_cursor"
   ```
   If the last pull is **older than 5 minutes**, or `last_error` is not null, stop. Tell the Owner to run
   `docker compose restart worker`. It is a plain restart: `main` does not carry P7-T01, so there is no
   code change. Retry once the pull is fresh.
3. **Dry run, then tag**:
   ```bash
   PYTHONPATH=backend .venv/bin/python eval/lab_tag.py --agent attt-m1-lab \
     --since "<since>" --until "<until>" --scenario <id> --category <category> --kind <kind> \
     --env-file .env --dry-run
   PYTHONPATH=backend .venv/bin/python eval/lab_tag.py --agent attt-m1-lab \
     --since "<since>" --until "<until>" --scenario <id> --category <category> --kind <kind> \
     --env-file .env
   ```
   A zero retag is not an error: `lab_tag.py` still records the row, and a scenario that produced nothing is
   a finding (§0).
4. **Check, read-only.** After tagging, no alert of the agent inside the window may still be `wazuh`:
   ```bash
   psql "$DATABASE_URL" -Atc "select source, count(*), count(*) filter (where duplicate_of is null) from alerts where agent_name = 'attt-m1-lab' and alert_time >= '<since>' and alert_time <= '<until>' group by 1 order by 1"
   ```
   Expected: only a `lab|n|heads` line. A `wazuh` line means an alert arrived after the tag. Report it to
   Director 1. **Do not re-tag and do not edit anything**; C2-A1 is the precedent (DEC-137 item 2).
5. **Tell the Owner** in one line: `<id>: retagged n (heads h), pull age s`.

## Never

- Pass `--allow-overlap`.
- Re-tag an id already in `eval/lab_windows.csv`, or widen or extend a recorded window (the short 26–66 s
  windows of 26/09 stay as recorded).
- Reconstruct a Start or End from the alerts. If the Owner has no recorded End, tell Director 1 instead of
  tagging.
- Hand-edit `eval/lab_windows.csv`, or write to the database by any other means.
- Commit anything. The Director imports the file at the end (DEC-135 item 5).
- Print a DSN or a password, or run `ps aux` (process arguments carry the DSN). Use `pgrep -fc` if you
  must count.
- Run, copy or paraphrase a scenario's commands. They are the Owner's, in `docs/lab-scenarios.md`.

## End of the lab (27/09)

Send Director 1:
1. **"last window tagged"**;
2. the list of §5 ids **not run**;
3. any window with no recorded End;
4. every window that still shows a `wazuh` line at step 4.

That starts Part A of `docs/plan/prompts/gold-day-run-2026-09-28.md` (the G2 import and build, done by
the Director).
