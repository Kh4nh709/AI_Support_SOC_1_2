# Secrets remediation — a 32 MB database dump with user credential hashes is on a public GitHub remote

**Invocation (the Owner pastes this, nothing else — session name `secrets-remediation`):**

```
Read docs/plan/prompts/secrets-remediation-run-2026-09-25.md and act as the Secrets
Remediation agent. Start with §1. Nothing in §4 is yours to run.
```

You prepare, verify and record. **Every command that rewrites history, force-pushes or rotates a
credential is the Owner's** (§4) — you hand it over as one block with its expected output and you
record what came back. Written by the Support Agent at the Owner's instruction, 25/09 15:40; every
figure in §1 was measured then.

## 1 · The finding, measured

| fact | measurement |
|---|---|
| file | `backups/latest.dump`, **32,978,015 bytes**, a PostgreSQL custom-format dump of `soc_dev` |
| tracked | **yes** — `git ls-files` matches it; `.gitignore:28` ignores `backups/*` and **`.gitignore:29` un-ignores this one file** (`!backups/latest.dump`) — the exposure is a deliberate line, not an oversight |
| in history | one commit: **`5b1deb1`, 20/09** ("infra: the database, app and worker run under docker compose") |
| on the remote | **yes** — `git cat-file -e origin/main:backups/latest.dump` succeeds |
| remote visibility | **public** — `https://api.github.com/repos/Kh4nh709/AI_Support_SOC_1_2` answers **200** unauthenticated |
| what it carries | `pg_restore -l` lists **`TABLE DATA public users`** (item 3701) and `TABLE DATA public identities`, plus every `alerts`/`intake` table — i.e. the real 30-day estate corpus |
| credentials inside | the four pilot accounts were created **2026-09-20 07:27–07:28 UTC** (`khanh`/tier1, `nguyen`/tier2, `khanh-admin`/admin, `nguyen-admin`/admin); the dump was committed **20/09 14:06 UTC**, so it was taken **after** they existed. The live table stores `$argon2id$v=…` hashes. **Treat the four hashes as published.** The verification deliberately stopped at the table list — extracting the rows would materialise the credentials, and it is not needed to reach this conclusion |
| not yet worse | local `main` is **15 commits ahead of `origin/main`** and `backups/latest.dump` is **modified in the working tree** — an ordinary `git push` or `git commit -a` would publish a **second** 32 MB blob |

**Severity, stated plainly:** argon2id is a slow hash, so the passwords are not trivially
recoverable — but they are offline-attackable at the attacker's leisure, and the same dump
publishes the estate's real alert corpus, hostnames, identities and IOC rows. For a thesis whose
subject is a SOC, this is also a finding about the project's own hygiene, and the evaluation
chapter is better off naming it than having a reader find it.

## 2 · Do this yourself, now — stop the bleeding without touching history

These are additive and safe; none of them rewrites anything:

```bash
cd /project/project/AI_Support_SOC_1_2
git status --short                      # confirm `M backups/latest.dump` is still uncommitted
cp backups/latest.dump /home/user1/soc-backups-keep/latest-2026-09-25.dump   # mkdir -p first; outside the repo
git restore backups/latest.dump         # drop the working-tree modification — do NOT commit it
```

Then prepare, **but do not commit** (`.gitignore` is a P0-T01 deliverable, so it is outside
`docs/plan/` and the Owner commits it — HUONG-DAN:186):

- delete `.gitignore:29` (`!backups/latest.dump`) so the `backups/*` rule covers it again;
- add `.claude/` and `.codegraph/` — measured 25/09: **both untracked and not ignored**, so any
  `git add -A` sweeps them in;
- `git rm --cached backups/latest.dump` staged, file kept on disk.

Show the Owner `git status --short` and the one-line `.gitignore` diff, and stop.

## 3 · The decision only the Owner can take — put both routes on the table with their real cost

**Route A — rewrite history, then force-push.** `git filter-repo --path backups/latest.dump
--invert-paths` (or BFG), then `git push --force-with-lease`. Removes the blob from the branch.
Costs: every clone and every worktree must be re-based on the rewritten history — **there are four
live task worktrees** (`P6-T02`, `P4-T03`, `P3-T11`, `P6-T06`) plus a locked support worktree, and
rewriting under them mid-phase is exactly the class of accident that eats a day you do not have.
And it is **not** a guarantee: GitHub keeps unreferenced blobs reachable by SHA until it garbage
collects, so the dump may stay fetchable after the rewrite unless GitHub Support is asked to purge
it.

**Route B — leave history alone, rotate and record.** Untrack it going forward (§2), **rotate the
four pilot passwords** with P4-T01's seed CLI (no need to read the old ones), and name the exposure
in `docs/limitations.md`. Costs: the 20/09 blob stays public and must be assumed compromised
forever.

**Recommendation, once:** **B now, A only if the Owner wants it and only after the four worktrees
have merged** — because B's security value is delivered by the rotation, not by the rewrite, and A
run today endangers the critical path five days before the deadline for a blob that may survive the
rewrite anyway. If the repository can be made **private** instead, do that first: it is one setting,
it removes anonymous access immediately, and it does not touch a single commit.

## 4 · The Owner's commands — hand each over, record what comes back

1. **Make the repo private** (if acceptable): GitHub → Settings → Danger Zone → Change visibility.
   Verify: `curl -s -o /dev/null -w '%{http_code}\n' https://api.github.com/repos/Kh4nh709/AI_Support_SOC_1_2` → **404**.
2. **Commit §2's staged changes** (`.gitignore`, the `git rm --cached`) — outside `docs/plan/`, so
   the Owner's commit.
3. **Rotate the four accounts** with P4-T01's seed CLI (`P4-T01.prompt.md` has the invocation).
   Verify, per account: a wrong-password `POST /login` → **401**, the new password → **303**. Do
   not print any password into this session.
4. **Only on Route A**: the rewrite, the force-push, re-basing the four worktrees, and a request to
   GitHub Support to purge the unreferenced blob.

## 5 · What you record

Append **one** INBOX entry, `2026-09-25 · security / public dump · BLOCKER`, carrying §1's table
verbatim, what §2 changed, the Owner's chosen route with the reason they gave, and the verification
output of every step in §4 that ran. Then hand the Director two sentences for
`docs/limitations.md` — one naming the exposure and its window (20/09 → the date it is closed), one
naming what was rotated. **Never** paste a hash, a password, or a row from the dump into any file.

## 6 · Hard limits

- No `git filter-repo`, no `push`, no `push --force`, no history rewrite, no repository setting
  change — all §4, all the Owner's.
- No extraction of any row from the dump; the table list is as deep as this investigation goes.
- No commit outside `docs/plan/`; `STATE.md` and `DECISIONS.md` are the Director's.
- Do not delete `backups/latest.dump` from disk — §2 keeps a copy outside the repo first, and the
  restore drill in P8 needs a dump.
