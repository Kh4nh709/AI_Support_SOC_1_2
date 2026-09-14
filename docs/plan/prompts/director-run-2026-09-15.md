# Director — order of work for the next run (written 2026-09-14 23:00, for the 15/09 morning run)

**Invocation (the Owner pastes this, nothing else):**

```
Read docs/plan/prompts/director-optimized.md and act as the Director. Then read
docs/plan/prompts/director-run-2026-09-15.md and execute it in order — it is this run's
INBOX pointer plus the morning run, batched (DEC-048).
```

Your standing prompt governs. This note only tells you what happened after your 22:19 commit
(`ae62d51 director: 2026-09-14 pm`), which files changed under you, and which of tonight's
questions the Owner has already answered. Written by the Support Agent at the Owner's
instruction; every figure below was measured by command on 14/09 at 22:15 — re-measure with
the commands in §0 before you record any of it. Do not use the 08/09 commands (`/var/ossec`,
`sg wazuh`, port 9400): they are known dead and measure nothing.

## 0 · The Owner's answer to DEC-061, part 1 — the stack moved, it was not removed

The Owner reports: *the current Wazuh output is `/data/wazuh/logs/alerts/alerts.json`.*
Measured on 14/09 22:15 as `user1` (INBOX 2026-09-14 · P2 / host · BLOCKER — Owner's answer,
part 1, `INBOX.md:267-280`):

| fact | measured value | command |
|---|---|---|
| `/var/ossec` | still absent | `ls -ld /var/ossec` |
| `/data/wazuh/` | `root:root`, created 19:55, holds **only `logs/`** — no `etc/`, no `ossec.conf`, no `rules/` | `ls -la /data/wazuh /data/wazuh/logs` |
| `/data/wazuh/logs/alerts/alerts.json` | mode **777**, uid/gid **999** (no local name), 2,624 lines 12:56:30Z–15:15:36Z, first line `rule 502 "Wazuh server started"`; readable by `user1` | `stat -c '%U:%G %a %s' …alerts.json; head -c 160 …alerts.json` |
| `logs/alerts/2026/`, `logs/archives/` | `drwxr-x---` gid 999 — **not readable by `user1`** | `ls /data/wazuh/logs/alerts/2026/` → Permission denied |
| group `wazuh` | gone (`id` still lists a bare `124`) | `getent group wazuh; getent group 124` |
| `rule.id 100999` in the new file | **0** over 2 h 19 min (`<frequency>600</frequency>` would give ≈ 13) → the DEC-059 stanza is **not** on this manager; rules `1003xx` also 0 | `grep -c '"id":"100999"' /data/wazuh/logs/alerts/alerts.json` |
| `manager.name` | `wazuh.manager` in 2,629/2,629 documents (08/09: `IA1803`) | `grep -o '"manager":{"name":"[^"]*"' …alerts.json \| sort \| uniq -c` |
| agents | 000 `wazuh.manager` 186 · 001 `user1-IA1803` 370 · **002 `HR-computer` 2,068 (79 %)** — `conf/inventory.yaml:10,17` lists `IA1803` and `user1-IA1803` only | `grep -o '"agent":{"id":"[0-9]*","name":"[^"]*"' …alerts.json \| sort \| uniq -c` |
| ports | 1514, 1515, 55000 listening (a manager); **`*:9200` listening, 9400 not** | `ss -ltn` |
| `https://127.0.0.1:9200/` | 401 unauthenticated (an OpenSearch with security); certificate `CN = 79.79.79.11`, issuer `CN = Graylog CA`, **not verifiable with `conf/root-ca.pem`** (verify code 19); `.env`'s `soc_ro` → 401 "Authentication finally failed" | `curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:9200/`; `openssl s_client -connect 127.0.0.1:9200 -CAfile conf/root-ca.pem </dev/null 2>&1 \| grep -E 'Verify return code\|^issuer='` |
| `/home/user1/archive/alerts-2026-08-08_09-07.jsonl` | intact, 113,379,904 bytes | `ls -la /home/user1/archive/` |
| `docker ps` | permission denied (as in DEC-061) | — |

If the heartbeat count is ≥ 1 when you run it, the Owner re-applied the stanza overnight —
record the timestamps (`grep '"id":"100999"' … | grep -o '"timestamp":"[^"]*"'`), not the
count alone; two hits 600 s apart is the periodic proof (DEC-059).

**Consequence for DEC-061 (`DECISIONS.md:935`):** every measurement in it still holds; its
premise "no manager, no indexer" was incomplete — there is a manager, and there is an
OpenSearch that is **not the project's cluster** (different CA, no `soc_ro`, ships-from-manager
unmeasured). Nothing that needs a live indexer is unblocked yet. Everything that runs on
`source='replay'` never was blocked.

## 1 · Read these before you write anything — they changed after your commit, in your tree

All nine are uncommitted in the primary checkout; your session's buffers predate them. Run
`git status --short` and `git diff --stat` first, read each diff, and do not overwrite.

| file | what changed |
|---|---|
| `docs/plan/INBOX.md:267-280` | the Owner's-answer entry above — `Resolved: open`, waiting for your DEC |
| `docs/plan/00-context-pack.md:123` | §6.3 annotation gains dated state (3) inside DEC-060's comment — same line, line count unchanged, nothing struck |
| `docs/plan/tasks/P2/P2-T11.prompt.md:112-152` | design note 9 rewritten: mechanism of record per DEC-059 (`localfile` `full_command`), the 14/09 host state, verification (a) on the file first, (b) on the indexer once `.env` names a real cluster; history 06/09 `0` → 08/09 `3` → 14/09 `0`. Two test-design lines: "wodle" → "heartbeat stanza" |
| `docs/plan/tasks/P2/P2-T13.prompt.md` (scope-out, note 2, note 3 `:49-87`, acceptance 3) | the CLI refuses `/data/wazuh/` as well as `/var/ossec/`, by prefix before `stat`; the Owner export procedure re-derived for gid 999 and no `wazuh` group — `sudo sh -c '…'` reads, user1's shell writes (so acceptance 3's `sudo sh -c` grep matches the procedure again, which it did not since DEC-051); a second export is optional, the 08/08–07/09 file IS G1 |
| `docs/plan/tasks/P2/P2-T15.prompt.md:13` | scope-out names the new unreadable path |
| `docs/plan/prompts/owner-assist.md` §1, `docs/plan/prompts/detection-author.md` §2 | dated supersession notes above the 08/09 capability tables — every `sg wazuh` form fails now |
| `docs/plan/HUONG-DAN-VAN-HANH.md:14` | in-line note: the read-only-user step must be redone on the `:9200` cluster once the Owner settles it; line count unchanged |
| `docs/wazuh-manager-changes.md` | new §0: the manager §1–§4 describe no longer exists; §4.1 must not be run as written. **Outside `docs/plan/` — not yours to commit; list it under Owner actions** |

`make lint` and `make test` were run after these edits: lint clean, **349 passed, 1 skipped,
3 xfailed**. `superseded.yaml` has no `open` row pointing at any of them; no `fixed` pattern was
re-introduced (checked: DEC-001's service-name token, the DEC-014-05 sentence, the two
heartbeat-wodle rows).

## 2 · Record it — one DEC, then propagate

Run `python3 scripts/dec_overlaps.py` first (standing rule). Then write **DEC-063** as an
amendment to DEC-061, not a retraction — DEC-059's own form ("this entry adds a later
measurement; it does not overturn an earlier one"). It must carry:

- the §0 table, re-measured by you, with commands;
- what changes in DEC-061's consequences: "G2 cannot be generated at all" → "not until the
  Owner re-applies `conf/local_rules.xml` and the DEC-059 stanza on the new manager"; "the
  indexer half is unreachable" → "unreachable until the Owner answers question (3)"; what does
  not change: the archive is intact, the evaluation spine runs on `source='replay'`;
- what it conditions, written into `Propagated to:` so the reporter sees the seam (DEC-044):
  **DEC-058** (its option B was argued for a vanished host, `DESKTOP-MIRSO17`, 23 archive
  clusters — it does not transfer to `HR-computer`, a live agent producing 79 % of the stream;
  G8′ will pin `needs_review` on `HR-computer` and on `wazuh.manager`, since both miss
  `lookup_asset` by `agent_name` and by `origin_host` — `P2-T04.prompt.md:43` makes
  `origin_host` fall back to `manager.name`), **DEC-059** (the 14/09 count is measurable on
  the file: 0), **DEC-060** (state (3) is already on `00-context-pack.md:123`), **DEC-061**;
- the five questions only the Owner can answer, each with the cost of waiting, replacing the
  single question at `STATE.md:70`:
  1. deliberate or not; does the manager run in a container — which, and how is it restarted?
  2. where are the new manager's `ossec.conf` and `etc/rules/`; will the Owner re-apply
     `conf/local_rules.xml` + the DEC-059 stanza there? Proof: `grep -c '"id":"100999"'
     /data/wazuh/logs/alerts/alerts.json` ≥ 2 after 20 min. Bites the lab day, 15/09.
  3. is the OpenSearch on `:9200` the intended alert store; does the manager ship into it; who
     owns it (`Graylog CA`); will a read-only account and CA be created for the app? This
     changes `INDEXER_URL`, `INDEXER_CA`, `INDEXER_USER`/`INDEXER_PASSWORD` — §6.3 values, the
     Owner's; `.env.example` regenerates from `config.py`. Bites P2-T11's live smoke and the
     indexer half of the P2 gate; the code does not wait for it.
  4. do the old manager's dailies for 08/09–14/09 exist anywhere, and do they enter G1?
     DEC-053 fixed G1 at the 08/08–07/09 export (30 days, 3,070 clusters); adding days is an
     evaluation-validity decision. Bites P6 sizing.
  5. do `HR-computer` and `wazuh.manager` enter `conf/inventory.yaml`? Bites P2-T08/T09's
     acceptance on real data and the auto-close yield (DEC-012, DEC-058).
- propagation: `STATE.md:59` (blocker row text — moved, not gone; what stays blocked),
  `STATE.md:70` (the five questions), `STATE.md:48` (P2-T11: dispatchable on code once T02 is
  in `main`; only the one live smoke line waits on (3) — the card already says "the live path
  is not claimed"), the P2-T13 row's Owner-action cell (procedure re-derived; second export
  optional), `prompts/P8.md`'s limitations list (heartbeat mechanism; host relocation; the
  `HR-computer` pending item), the 15/09 gate-log row. `superseded.yaml` candidates, your call:
  a `fixed` row for the `sg wazuh -c 'zcat -f /var/ossec/logs/alerts` procedure (it must not <!-- superseded-ok: DEC-063 — this line is the instruction that created the row -->
  come back into a forward-looking artifact) and rows for the prompts' "`user1` is in group
  `wazuh`" claims.
- commit: `docs/plan/` only, by name, never `git add -A` — `director: 2026-09-15 am`. That
  commit carries the Support Agent's eight `docs/plan/` files too.

## 3 · Unblock what needs no Owner answer — one batch, in this order (DEC-048)

**a. P2-T02 — execute DEC-050 (`DECISIONS.md:764`), both halves in this run.** The Coder's
half is on the branch: `978f895` "make the ConfigError test hermetic", touching
`backend/tests/test_db.py` (+13/−1), the report and its STATE row (`git show --stat 978f895`).
Verify it is the fix DEC-050 asked for — it must disable the **`.env` file path** as well as the
environment variable, or the test is green only in a worktree that has no `.env`. Then, on
`main`: `git revert 18e82d5` (touches only `STATE.md`) → `git merge --no-ff task/P2-T02` →
`make test`, `make test-db` → `grep -c "^def \|^    def " backend/app/infra/db.py` must be
> 0 (it is 0 on `main` today; 2 on the branch). Green → `done`. Do not merge first and
revert after: measured in DEC-050, that leaves `db.py` at 0 defs with a conflict elsewhere.

**b. P2-T16 — `review` on `main` (`STATE.md:53`), no Reviewer round consumed yet.** E1 checks:
`git log main..task/P2-T16 --oneline` → 2 commits (`19c4667`, `f10646a`); `git diff
main...task/P2-T16 --stat` must touch only `backend/app/ingest/category.py`,
`backend/tests/test_category.py` and the report. There is **no card** — DEC-055
(`DECISIONS.md:859`) is the acceptance contract by its own ruling (precedent DEC-018, DEC-032),
so give the Owner this exact Reviewer sentence: *"Review P2-T16 on `task/P2-T16` against the
acceptance contract in `DECISIONS.md` DEC-055 (`:859`), items (1)–(6); there is no
`P2-T16.prompt.md` by DEC-055's ruling. Item (6) reads
`/home/user1/archive/alerts-2026-08-08_09-07.jsonl`, present."* On APPROVE, merge it in
the same batch as (a); it touches no file T02 touches.

**c. P2-T04 — `changes`, bucket (a), one docstring line (`STATE.md:41`).** Give the Owner the
Coder sentence: *"P2-T04: fix the one docstring line at `backend/tests/test_wazuh_parser.py:157`
per `docs/plan/tasks/P2/P2-T04.review.md` — Python 3.12's `datetime.fromisoformat` accepts
`+0700`, the parser's normalisation stays; touch no code; then `git merge main` (the only
conflict is `docs/plan/STATE.md` — keep `main`'s rows and your own row), re-run acceptance,
report."*

**d. Dispatch — worktrees before names (DEC-045), ≤ 3 running, disjoint files.** Once (a) is
in `main`, P2-T11 is dispatchable (depends on T02 only, `STATE.md:48`); once (a) and (c) are
in, P2-T05, T06, T08, T09 are (all depend on T02 + T04, `STATE.md:42-46`). T10 needs all five
plus T11; T13 needs T11; T15 needs T10 — so T11 heads the longest chain and takes a slot first.
Remaining `must` per `P2-tasks.md:385-448`: T05 3.5 · T06 4 · T08 3 · T09 3.5 · T11 3.5 · T10
4 · T13 2 · T15 2.5 h (DEC-062). Before each dispatch, E5 the card by command:
`grep -n "/var/ossec\|sg wazuh\|9400" docs/plan/tasks/P2/<id>.prompt.md` — the only hits
allowed are the dated history sentences in T11 note 9 and T13 note 3 and T13's
nonexistent-path acceptance case; and for T08/T09, add the one-line DEC-058 pointer if the
card lacks it (`grep -c DEC-058` is 0 on both today — they carry G8′ but not the ruling).

## 4 · Do not

- Do not decide the §10 cut (DEC-062 escalated it), the indexer, or the inventory content —
  the Owner's; keep `STATE.md:71` as it is.
- Do not restate DEC-061's "no manager, no indexer"; do not delete or rewrite any 08/09
  measurement (DEC-059's rule).
- Do not run `sg wazuh`, anything under `/var/ossec`, or `curl` to `:9400`; do not retry
  `soc_ro` against `:9200` — it was rejected once and will be until the Owner creates the
  account.
- Do not edit the §6.3 values (`INDEXER_URL`, `INDEXER_CA`, the account) or `.env.example` —
  annotate only; the values change by an Owner DEC after question (3).
- Do not let a Reviewer or a report claim P2-T11's live path proven: the card says it is not
  claimed until (b) in note 9 returns N ≥ 1 on a real cluster.
- Do not commit `docs/wazuh-manager-changes.md` (outside `docs/plan/`).

## 5 · Owner actions you print (≤ 7, each with the cost of waiting)

1. The five questions of §2, as one item pointing at DEC-063 — the one that bites first is (2),
   the lab day 15/09.
2. The §10 cut, unchanged from `STATE.md:71` (DEC-062) — every day unanswered is one of four.
3. Dispatch the Reviewer for P2-T16 (sentence in §3b) and paste the Coder sentence for P2-T04
   (§3c) — T02, T04 and T16 landing unblocks five `todo` tasks.
4. Commit or strike `docs/wazuh-manager-changes.md` (§0 added by the Support Agent; outside
   `docs/plan/`, `HUONG-DAN-VAN-HANH.md:186`).
5. Choose the canonical Director prompt (`STATE.md:72`) — costs nothing until your next
   `/clear`.

## 6 · Output

Morning-run format from your standing prompt, ≤ 25 lines, headings verbatim. Under
**Changed**, name the nine files of §1 as edits you did not make and read first. If (a) or (b)
merges in this run, append the three-line result-intake block. End with the commit
`director: 2026-09-15 am` and every INBOX item answered — `INBOX.md:267` included.
