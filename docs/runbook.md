# Runbook — AI Support SOC v3
This file is P8's deliverable (`docs/plan/prompts/P8.md`): P4-T07 created it with the `## Pilot` section only; P8-T03 extended it on 26/09/2026 with the five operating sections before `## Pilot` (start and stop, environment keys, backup and restore, what to watch, common failures). Coder P5-T13 (Director 1, DEC-151 wave 3) added **Alarms**, **Restore drill (P8)** and the **② operations** stub on 29/09/2026, once P5-T11 (health/notify) and P5-T12 (backup/restore) had merged.

Every command in those five sections runs **from the primary checkout**, in one shell that has sourced `.env` — never from an agent's worktree, which has no `.env` and whose `docker compose` addresses a different compose project: `cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; echo "${DATABASE_URL:+env ok}"` → `env ok`. No value from `.env` is restated here (DEC-070). *(not run by the agent)* marks an expected output only the live stack can give; every other one was measured by P8-T03 on this host, on a private `soc_p8t03_*_test` database standing in for `soc_dev` (`docs/plan/tasks/P8/P8-T03.report.md`). **P5-T13's own additions and edits — `## Alarms`, `## Restore drill (P8)`, and the touched parts of `## Start and stop`/`## What to watch` — follow a different methodology, stated once here rather than on every line: every `docker compose …`/`make run-…` command in them was checked *statically* against the code, `docker-compose.yml` or `Makefile` it names, not run (P5-T13 has neither `docker` nor a `soc_dev` connection). Every `psql` first-look command in `## Alarms` was, however, run read-only against `soc_dev` by the Reviewer, at review round 1 — see the dated snapshot in `## Alarms` itself.

## Start and stop

`db` is PostgreSQL 16 on port `55432` (`DB_PORT`, volume `pgdata`), `app` is uvicorn on port `8000`, `worker` runs the `pull`, `pipeline`, `triage`, `health`, `digest` and `investigate` jobs (`backend/app/web/handlers/`, discovered by `iter_handlers()`; `investigate` is ②'s single-shot analysis, **② operations** below). **Every worker start re-arms three self-scheduling chains** — `pull` and `health` (`enqueue`, idempotent through the jobs table's partial unique index) and `digest` (`digest.ensure_scheduled`) — so a chain that died is repaired by `docker compose restart worker` alone, no other action (**Alarms**, below). The stack publishes both ports on every interface of the host (`docs/limitations.md` (xxxv)). `ui` is the React UI on port `8080`, loopback only (**UI (service `ui`)** below), and it is the only console, the admin console included (**Admin console** below). Port `8000` serves `/api/*`, `POST /webhook/alerts` and `GET /health`, and renders no page: the Jinja analyst pages went in P10-T13, the Jinja admin pages, the sign-in page and the session cookie in P11-T19 (DEC-205).

| action | command | expected |
|---|---|---|
| start everything | `make up` | `db`, `app`, `worker` up (`docker compose up -d`). **Only on an empty `pgdata` volume**, `db` first runs `db/init/01-roles.sh` (creates `app_rw`) and `02-restore.sh`, which restores `backups/latest.dump`: `docker compose logs db \| grep 'init:'` ends `init: restored — N migrations recorded, default privileges for app_rw set`, N being what the dump holds: **17** for the tracked `backups/latest.dump` (26/09), which predates `018_alerts_notify.sql` (`pg_restore -l backups/latest.dump \| grep -ci notify` → `0`). Later starts reuse the volume and never read the dump. `make migrate` then brings the database to **20**, and it goes **before** `app` and `worker` run the v1.1 code, which reads what 019 creates (**Admin console v1.1 — deploy**, below), so on an empty volume the order is `make db-up`, `make migrate`, `make up`: `migrate: 3 applied, 17 already present` on that dump (it applies 018, 019 and 020), `migrate: 2 applied, 18 already present` on a dump taken after 018 (it applies 019 and 020), `migrate: 1 applied, 19 already present` on a dump taken after 019 or on the live database before learned knowledge (it applies `020_learned_knowledge.sql`, DEC-210), `migrate: 0 applied, 20 already present` after that. *(`make up`, `logs`: not run by the agent)* |
| stop everything | `make down` | the containers removed, the `pgdata` volume kept. **Never `docker compose down -v`**: it deletes the database, and the next `make up` restores `backups/latest.dump` in its place. *(not run by the agent)* |
| start one part | `make db-up` · `make run-app` · `make run-worker` | `up -d --wait`: returns once `db` is healthy · `db` and `app` are up · `db` and `worker` are up. *(not run by the agent)* |
| restart | after a merge under `backend/app`, or a hang: `docker compose restart worker` (or `app`); the admin console v1.1 merge is the one exception, it goes in the order of **Admin console v1.1 — deploy** below (migrate first) · after an `.env` edit: `docker compose up -d --force-recreate app worker` · after a `backend/requirements.txt` change: `docker compose build app worker && docker compose up -d app worker` | code, `conf/` and `kb/` are bind-mounted, so a merge needs a restart, not a build (DEC-099); `.env` is read when a container is created, so `restart` never sees an edit. *(not run by the agent)* |
| native fallback (`make help`: "the 05–20/09 way") | `docker compose stop app worker`; then `make run-app-native` and `make run-worker-native`, each in its own terminal, in a shell that has **not** sourced `.env` | the same two processes on the host, on the same database. They read `.env` themselves; sourcing strips the quotes inside `INVENTORY_PATHS=[…]`, and `config.load()` then refuses the value (measured on a scratch `.env`). Never a host worker beside a container worker: two pullers on one `source_cursor` (`docs/db-docker.md`). Back: `Ctrl-C` both, `make up`. *(not run by the agent)* |
| **up?** the containers | `docker compose ps` | `db`, `app`, `worker`, each `Up …`; `db` also `(healthy)` *(not run by the agent)* |
| **up?** `db` | `pg_isready -h 127.0.0.1 -p "${DB_PORT:-55432}"` | `127.0.0.1:55432 - accepting connections` |
| **up?** `app` | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/auth/me` | `401`: the app answers and the request is routed; there is no session. (`/login` on `8000` was the check until P11-T19 removed the page: it is a `404` now, never a sign of a dead app.) *(not run by the agent)* |
| **up?** `worker` | `docker compose logs --tail=5 worker` | lines such as `{"job_id": …, "job_type": "pull", "outcome": "succeeded", "ms": …}`, a `pull` about once a minute; then **What to watch**, first row *(not run by the agent)* |

## UI (service `ui`)

`ui` (P10-T07) is nginx serving the built React single-page app and proxying `/api/` and the WebSocket `/api/ws` to `app` on the **same origin** — the browser only ever talks to port `8080`. It is where tier1 and tier2 work the queue, the alert page and the case page. P10-T13 retired the Jinja versions of those pages, and P11-T19 the Jinja admin pages (`/admin/labels`, `/admin/rules`, `/admin/digest`) and the sign-in pages (`/login`, `/logout`, `/`): port `8000` renders no page at all. `/`, `/login`, `/logout`, `/queue`, `/alerts/…`, `/cases…` and `/admin/…` answer `404` there for everyone; `/api/*`, `/webhook/alerts` and `/health` answer. The admin console v1.1 is the React app served here at `http://127.0.0.1:8080/admin` (`/admin/overview`, `/admin/users`, `/admin/llm`, `/admin/rules`, `/admin/digest`, `/admin/labels`, `/admin/audit`), behind the same sign-in; the Jinja admin pages that shared port `8000` with it went with the retire step (P11-T19, DEC-205: **Admin console** and **Admin console v1.1 — deploy** below). Every command below runs from the primary checkout; *(not run by the agent)* — the agent runs no `docker` command.

| what | command | expected |
|---|---|---|
| where it listens | `docker-compose.yml`, service `ui`: `ports: ["127.0.0.1:8080:80"]` | loopback only, **plain HTTP** (no TLS, so the password typed at sign-in and the Bearer token the UI keeps in the tab's `sessionStorage` cross the network in clear wherever the Owner's tunnel does not encrypt them: **Pilot** §7). It is reached the way `app` is, through the Owner's tunnel. **Exposing it on a LAN interface is the Owner's decision, made by editing that `ports` line in `docker-compose.yml`**, then `docker compose up -d ui`. Nothing in the application names this port since P11-T19 removed the page on `8000` that linked to it: publish another host port and only the address the Owner types changes. |
| **up?** `ui` | `docker compose ps ui` · `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/` · `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/auth/me` | `ui` `Up …` · `200` (the page) · `401` without a session (the proxy reached `app`; `502` means it did not, below). |
| after a **frontend change** (anything under `frontend/`) | `docker compose up -d --build ui` | the image holds the build, it is **not** a mount: `restart ui` and a plain `up -d ui` keep serving the old build. Reload the page; `index.html` is served `no-cache`, and an old tab's hashed chunks are gone after the redeploy (a `404`, never `index.html`), so an open tab may need a reload. |
| after a **compose change** (`ports`, `restart`, `depends_on` of `ui`) | `docker compose up -d ui` | the container is recreated with the new settings, no build. |
| after a **backend-only change** | `docker compose restart app` | `ui` is not touched: it resolves `app` again at every request (`resolver 127.0.0.11 valid=10s` in `frontend/nginx.conf`), so a recreated `app` gets a new address without `ui` being restarted. `502` on `/api/` for a few seconds while `app` starts is that, not a fault; one that lasts: `docker compose ps app`. |
| the WebSocket `/api/ws` | `location /api/ws` in `frontend/nginx.conf` passes `Upgrade` and `Connection: upgrade` (HTTP/1.1) and sets `proxy_read_timeout 1h` · a browser's Network tab, filter *WS*: `/api/ws` | status `101`, then the frames `ready` and `alerts.changed`. The token is the first frame, never the URL (`web/routers/live_ws.py`), so nothing to look for in an access log. Closed with `4401` → the UI sends the user to sign in again; anything else → it falls back to polling (`frontend/src/live/poll.ts`) and the queue still refreshes, only slower. Traffic that passes through another proxy in front of `ui` must forward the same two headers, or the socket never opens. |
| the CSP | `curl -sI http://127.0.0.1:8080/ \| grep -i '^content-security-policy'` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` — set in `frontend/nginx.conf` on every response (`always`) and pinned verbatim by `frontend/src/deploy.test.ts`. No inline script, no CDN, no external font or API. A *"Refused to load …"* message in the browser console means the page tried to reach something else: fix the page, do not loosen the header. Port `8000` renders no page since P11-T19, so it has no such header to carry. |
| the logs | `docker compose logs --tail=50 ui` · `docker compose logs --tail=50 app` | nginx's access and error lines go to the container's own stdout and stderr — no log file in the repository, and the SPA writes none (an error in the page shows only in the browser's console). The API's side of any `/api/*` call is in the `app` log. |
| the browser suite | `make ui-e2e` | named here only: it is P10-T12's Playwright run, set up and described in that card's report. `make ui-test` and `make ui-lint` run the unit tests and the checks with no stack. |
| **rollback** of P11-T19 (the Jinja admin pages, the sign-in page and the session cookie back on `8000`) | on `main`: (1) revert every commit after `0c6d7b9`, newest first (list them with `git log --format=%h 0c6d7b9..`, then `git revert --no-edit <sha>` for each); (2) `git revert --no-edit -m 2 0c6d7b9`; (3) `docker compose restart app worker` (`0c6d7b9` is the merge commit of the retire branch, parents: its own side and the v1.1 tip `17ae66c`; the second parent as mainline undoes exactly what the retire branch added to v1.1) | the code is bind-mounted, so a restart is enough — no build, and `ui` is not touched: the React UI keeps working on `8080` beside the Jinja pages. Nothing in the database changed. **A rollback of P10-T13 (the Jinja Tier-1 and Tier-2 pages) comes only after this one**: those pages rendered through `web/templating.py` and `web/templates/`, which P11-T19 deleted, so reverting P10-T13 alone leaves an `app` that does not start. |

## Admin console

The admin console is the React UI: **`http://<host>:8080/admin`** (`http://127.0.0.1:8080/admin` on the lab host; how `ui` is published is under **UI (service `ui`)** above). An admin signs in with the React sign-in form and has seven pages: `/admin/overview`, `/admin/users`, `/admin/llm`, `/admin/rules`, `/admin/digest`, `/admin/labels` and `/admin/audit`. Each calls `/api/admin/*` through the same-origin proxy of `ui`; none is a page of port `8000`.

**Port `8000` serves `/api/*`, `POST /webhook/alerts` and `GET /health`, and renders no page.** Since P11-T19 (the retire step of **Admin console v1.1 — deploy** below) `/login`, `/logout`, `/`, `/admin/rules`, `/admin/digest` and `/admin/labels` answer `404` on it for everyone, and **no cookie exists**: `POST /api/auth/login` answers the token in its body and sets nothing, and a request is signed in by `Authorization: Bearer <token>` alone (the React UI keeps the token in the tab's `sessionStorage`). A request that carries only the old `soc_session` cookie is a `401`. The connection is plain HTTP (**Pilot** §7).

| what | command | expected |
|---|---|---|
| **up?** the console | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/admin` · `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/admin/overview` | `200` (the single-page app: nginx answers any path with `index.html`) · `401` without a session (the proxy reached `app`). *(not run by the agent)* |
| port `8000` renders no page *(after the retire step)* | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/login` | `404`. Before the retire step it is `200`: that is the Jinja sign-in page, which the retire step removes. *(not run by the agent)* |

**How the console is released** is one procedure, under **Admin console v1.1 — deploy (DEC-205)** below: the Owner's two steps, the v1.1 deploy (five rows, migrate first) and, after using the React pages, the retire step that removes the Jinja pages and the cookie. This section describes the console as it is once both are done.

## Admin console v1.1 — deploy (DEC-205)

The admin console v1.1 is released by **two steps of the Owner's**, in this order (DEC-205 item 2): the **v1.1 deploy** (the five-row table below), then, once the Owner has used the React pages, the **retire step** (after the rollback note). Both are the Owner's own: no agent merges to `main`, runs `make migrate` or touches `docker`.

The admin console v1.1 is the React app that `ui` serves at `http://127.0.0.1:8080/admin` (Overview, Users, LLM, Rules, Digest, Labels, Audit). It needs **migration `019_admin_console.sql`** (the `settings` table, `users.last_login_at` and one more audit event name, DEC-200): the new code reads all three, so **the order below is part of the release: the database moves before any container runs the new code.** The Jinja admin pages (`/admin/rules`, `/admin/digest`, `/admin/labels`) and the `soc_session` cookie stay on port `8000` until the retire step (P11-T19, branch `director/admin-v1-1-retire`, DEC-205 item 2), which the Owner takes after using the React pages. Every command runs from the primary checkout, in a shell that has sourced `.env`; *(not run by the agent)*.

| step | command | expected |
|---|---|---|
| 1 · fast-forward `main` | `git merge --ff-only director/admin-v1-1` (on `main`) | `Fast-forward`. Do not restart or recreate any container yet. |
| 2 · migrate | `set -a; . ./.env; set +a; make migrate PY=.venv/bin/python` | `migrate: 1 applied, 18 already present` (it applies `019_admin_console.sql`: the tip this release merges, `director/admin-v1-1`, holds migrations up to 019). `migrate: no DSN` means `.env` was not sourced (DEC-106). |
| 3 · check | `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` | `19`. **Do not go on before this holds**; less → run step 2 again and read what it printed. |
| 4 · the UI | `docker compose up -d --build ui` | `ui` rebuilt and recreated with the React console; `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/admin/overview` → `200` (the page shell; signing in is the page's own). This step can recreate `app` too (`ui` depends on it), and a recreated `app` starts on the new code at once: that is why it comes after step 3. |
| 5 · app and worker | `docker compose restart app worker` | both `Up` in `docker compose ps`; `docker compose logs --tail=5 worker` shows a `pull` with `"outcome": "succeeded"`. The code is a live mount, so `restart` is enough (DEC-099). |

Then sign in at `http://127.0.0.1:8080/admin` as an admin and use the pages. Using them is the gate of spec §8 ("the Owner has used the React admin pages"): the retire step waits for it, and the Jinja pages answer on port `8000` meanwhile, as before.

**This block ends at migration 019.** The counts above are those of the v1.1 tip, which has no later migration. Learned knowledge (DEC-210) is a separate release with `020_learned_knowledge.sql` and its own block, steps and counts: **Learned knowledge and RAG (DEC-210)**, below. On a tree that already holds 020, `make migrate` applies it as well: `2 applied, 18 already present` on a database at 018, and step 3 then reads `20`. That is not a fault; the rest of 020's release (the directory, the second compose file, the two switches, both `false` by default) is in its own block, and nothing there is needed for v1.1.

**What an app restart before step 2 breaks.** The new code on the 018 schema fails closed: every login fails (`users.last_login_at` is missing: an HTTP 500), every ① run in that window is recorded `stopped_by='cap'` (the limits cannot be read, so the cap check refuses) and its alert loses its suggestion, ② answers 503, and the `monthly_cost` health check fails and raises its alarm. So never `restart app`, `up -d` or `up -d --build ui` before step 3 reads `19`; the ① runs of such a window stay recorded as stopped.

**Rollback.** `019` stays under the old code (one new table, one nullable column and a wider CHECK, none of which the v1.0 code reads), so there is no down-migration: put `main` back on the commit before step 1 and repeat steps 4 and 5. Limits saved on the web are then ignored, because the v1.0 code never reads `settings`, and the cap falls back to `.env` (`LLM_MONTHLY_USD_CAP`, `ANALYZE_QUOTA_PER_USER_DAY`, `LLM_TIMEOUT_S`), whatever the Limits form last showed. (This is the rollback of the v1.1 deploy; the retire step has its own, below.)

**The retire step (P11-T19, DEC-205 item 2).** The Jinja admin pages, the sign-in pages and the session cookie go. The branch `director/admin-v1-1-retire` is stacked on the v1.1 tip, so it carries all of v1.1: take it only after the deploy above, on a database where `select count(*) from schema_migrations` reads `19` (the retire branch has no migration of its own, and on an 018 database its code would fail closed as the paragraph above says).

| step | command | expected |
|---|---|---|
| **retire step** | `git merge --ff-only director/admin-v1-1-retire` (on `main`) · then `docker compose restart app worker` | a code-only change on the live mount (`backend/app` is bind-mounted, DEC-099): **no migration and no `ui` rebuild**. Then `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/login` → `404` (it was `200`: the Jinja sign-in page), and `http://127.0.0.1:8080/admin` still works: the React UI never used the cookie. A browser tab that was signed in on `8000` through the cookie is signed out; a script that relied on the cookie gets `401` and must send the token. *(not run by the agent)* |

**Rollback of the retire step.** On `main`, in this order: (1) revert every commit after `0c6d7b9`, newest first: list them with `git log --format=%h 0c6d7b9..` and run `git revert --no-edit <sha>` for each (there is none if nothing came after the merge); (2) `git revert --no-edit -m 2 0c6d7b9`; (3) `docker compose restart app worker`. `0c6d7b9` is the merge commit of the retire branch, the one that put v1.1 under the retire changes: its parents are the retire branch's own side and the v1.1 tip `17ae66c`, and `-m 2` makes the v1.1 tip the mainline, so the revert undoes exactly what the retire branch added to v1.1 and leaves the tree equal to `17ae66c`'s. A plain `git revert 0c6d7b9` is refused for want of a mainline, and the other mainline would take out v1.1 itself. The same is in the **rollback** row of **UI (service `ui`)**. No database change to undo. A rollback of P10-T13 comes only after it.

## Learned knowledge and RAG (DEC-210)

Learned knowledge lets ① and ② read, beside the signed decision tables, what past human decisions were: the decision history of the alerts and cases like the one in hand, and the entries an admin approved from earlier conclusions. A Tier-1 close or a Tier-2 conclusion may propose a **draft** (`KNOWLEDGE_DRAFT_ENABLED`); an admin approves it into an **entry** whose Markdown file is published in `kb_learned/` (the database holds the content, the file is its copy); a **lookup** (`RAG_ENABLED`) finds the history and up to three similar entries for each alert and case and puts them in the prompt as a reference, never as a rule and never as a reason to close. Both jobs, `rag_lookup` and `knowledge_draft`, run in their own service, `rag-worker`, and call DeepSeek only. **Both switches default to `false`**: merging the code changes nothing, and with `RAG_ENABLED=false` ①'s prompt and behaviour stay byte-identical (spec §7.1).

Releasing it is **three blocks, in this order**, and the steps below number straight through: the database moves first (migration 020), then the directory, the second compose file and the containers, then the switches, drafts before the lookup. The files are `docker-compose.rag.yml` (the override that adds `rag-worker` and the `kb_learned/` mount; `docker-compose.yml` is not touched) and `kb_learned/` (its `README.md` is the one tracked file). Every command runs from the primary checkout, in a shell that has sourced `.env`; *(not run by the agent)*. No value from `.env` is restated here.

### Migration 020 (the database moves first)

`020_learned_knowledge.sql` (DEC-210) creates `knowledge_drafts`, `knowledge_entries` and `rag_results`, adds `llm_runs.rag_lookup_id` and the pipelines `rag_lookup` and `knowledge_draft`, widens the job types (6 → 8) and the audit event names (28 → 35), and adds one index. It runs before any container runs the new code, as 019 did for v1.1.

| step | command | expected |
|---|---|---|
| 1 · fast-forward `main` | `git merge --ff-only director/rag-knowledge` (on `main`) | `Fast-forward`. Do not restart or recreate any container yet. |
| 2 · migrate | `set -a; . ./.env; set +a; make migrate PY=.venv/bin/python` | `migrate: 1 applied, 19 already present` on a database already at 019 (it applies `020_learned_knowledge.sql`); `migrate: 2 applied, 18 already present` on one still at 018 (019 and 020). `migrate: no DSN` means `.env` was not sourced (DEC-106). |
| 3 · check | `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` | `20`. **Do not go on before this holds**; less → run step 2 again and read what it printed. |

**What a restart before step 2 breaks.** The new code reads and writes what 020 creates (`llm_runs.rag_lookup_id`, `knowledge_drafts`, `knowledge_entries`, `rag_results`): on the 019 schema the overview's knowledge counts and the health job's RAG checks (`knowledge_queue`, `knowledge_integrity`, `rag_budget`) fail, and a ① or ② run that records its `llm_runs` row can fail with them. So never `restart`, `up -d` or `up -d --force-recreate` any container before step 3 reads `20`; this is the same rule as for 019 (**Admin console v1.1 — deploy**, above).

### The directory, the second compose file and the containers

| step | command | expected |
|---|---|---|
| 4 · the directory | `mkdir kb_learned && ls -ldn kb_learned` (as the user that runs `docker compose`) | `drwxr-xr-x … <uid> <gid> … kb_learned`, the uid and gid being the user the containers run as: `HOST_UID` and `HOST_GID` in `.env`, 1000 and 1000 by default (`docs/db-docker.md`); make it as that user, not with `sudo`. It must exist **before** step 6: when it is missing, Docker creates it as `root`, and `app`, which runs as that user, cannot write an entry file, so approving a draft would fail. Made as `root` already: `sudo chown "$(id -u):$(id -g)" kb_learned` and read the line again. |
| 5 · the second compose file | `grep -c '^COMPOSE_FILE=' .env` (`0`), then `echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml' >> .env`, then `docker compose config --services` | `docker compose config --services` lists `db`, `app`, `worker`, `rag-worker` and `ui`. Never plain `docker compose config`: it prints the interpolated environment, passwords included. Compose reads `COMPOSE_FILE` from `.env`, so from now on **every** `docker compose` command and `make up`, `make down` and `make run-*` in this checkout read both files. `make db-restore` needs a hand (**After `make db-restore`**). The line comes out again in **Rollback**. |
| 6 · up | `docker compose up -d` · `docker compose restart worker` | `app` recreated (its mounts changed), `rag-worker` created and started, `db` and `ui` `Running`. The restart puts the merged code in `worker` (a live mount is not reloaded, DEC-099); `rag-worker` starts on it. No build: `rag-worker` is `app`'s image. `docker compose ps` shows `rag-worker` `Up`; `docker compose logs --tail=5 rag-worker` has no traceback (it logs one JSON line per job it runs, and with both switches `false` nothing enqueues one). Then the **mounts** check below. |

### The switches: drafts first, the lookup after the first entries

Both switches live in `.env` only (not web settings), and `.env` is read when a container is created, so every change is `docker compose up -d --force-recreate app worker rag-worker`: `restart` never sees an edit. **`KNOWLEDGE_DRAFT_ENABLED` goes first and `RAG_ENABLED` only after the first approved entries.** Drafts change nothing for ① and ② and cost one DeepSeek call each; the lookup delays every ① run by `RAG_TRIAGE_DELAY_S` and, with no entry to offer, has only the decision history to show for it.

| step | command | expected |
|---|---|---|
| 7 · drafts on | set `KNOWLEDGE_DRAFT_ENABLED=true` in `.env`, then `docker compose up -d --force-recreate app worker rag-worker` | `docker compose exec -T app printenv KNOWLEDGE_DRAFT_ENABLED` → `true`. From now on a Tier-1 close or a Tier-2 conclusion enqueues a `knowledge_draft` job, and `rag-worker` writes a `pending` draft for an admin to review; ① and ② are unchanged (no lookup yet). **`rag_budget`:** while both `RAG_ENABLED` and `KNOWLEDGE_DRAFT_ENABLED` are `false` that health check reports `n/a — RAG off`; this step ends that, and the draft calls count against `RAG_MONTHLY_USD_CAP` and, inside it, the global `LLM_MONTHLY_USD_CAP`. |
| 8 · the first entries | an admin approves the first drafts in the admin console (rejects the others with a reason), then `psql "$DATABASE_URL" -Atc "select count(*) from knowledge_entries where status = 'active'"` · `ls kb_learned/entries/*/` | at least `1`, and one `.md` file per entry under `kb_learned/entries/<category>/`, written by `app` as the host user. How many entries are enough before the lookup is worth switching on is the Owner's call; do not go to step 9 with none. |
| 9 · lookup on | set `RAG_ENABLED=true` in `.env`, then `docker compose up -d --force-recreate app worker rag-worker` | `docker compose exec -T app printenv RAG_ENABLED` → `true`. **A change the analysts can see:** every new alert now enqueues a `rag_lookup` and its `triage` starts `RAG_TRIAGE_DELAY_S` seconds later (45 by default) so the lookup can finish; ① uses the lookup if it is ready and runs without the block if it is not, and ② never waits. Each lookup is one more DeepSeek call, counted against `RAG_MONTHLY_USD_CAP` (3 by default) and inside the global `LLM_MONTHLY_USD_CAP`: when either is spent, ① and ② go on without the block and `rag_budget` alarms. |

### Checks

| check | command | expected |
|---|---|---|
| switches | `docker compose exec -T app printenv RAG_ENABLED KNOWLEDGE_DRAFT_ENABLED` · the same with `rag-worker` and with `worker` in place of `app` | two lines each, `true` or `false` as `.env` says. The variables are named on purpose: a bare environment dump prints `DATABASE_URL`, the LLM key and `JWT_SECRET`. A line missing or the old value: the container was not recreated after the edit. |
| mounts | `docker compose exec -T app sh -c 'touch /srv/kb_learned/.probe && rm /srv/kb_learned/.probe && echo writable'` · `docker compose exec -T rag-worker sh -c 'touch /srv/kb_learned/.probe'` · `docker compose exec -T worker ls /srv/kb_learned` | `writable` · `touch: cannot touch '/srv/kb_learned/.probe': Read-only file system` · `ls: cannot access '/srv/kb_learned': No such file or directory`. `app` writes the entry files, `rag-worker` only reads them (it checks their hash), and `worker` must not see them at all (it answers ① from the database). Any other answer: `docker-compose.rag.yml` was not read (step 5) or the containers were not recreated. |
| lookups | `psql "$DATABASE_URL" -Atc "select status, count(*) from rag_results where created_at > now() - interval '24 hours' group by status order by status"` | no row while `RAG_ENABLED=false`. Then `ok\|N` (matches found), `empty\|N` (nothing similar; the history may still be there), `failed\|N` (the DeepSeek call failed after its repair or its retries) and `budget\|N` (a cap was spent). Many `failed` or `budget` rows: **Alarms**, then `docker compose logs --tail=50 rag-worker`. |
| `llm_runs` per pipeline | `psql "$DATABASE_URL" -Atc "select pipeline, count(*) from llm_runs where created_at > now() - interval '24 hours' group by pipeline order by pipeline"` | `investigate\|N` and `triage\|N` as before; `knowledge_draft\|N` only after step 7; `rag_lookup\|N` only after step 9: about one per alert and one per case at its escalation, plus a refresh after `RAG_CASE_REFRESH_H` hours. |
| knowledge counts | `psql "$DATABASE_URL" -Atc "select status, count(*) from knowledge_drafts group by status order by status"` · `psql "$DATABASE_URL" -Atc "select status, count(*) from knowledge_entries group by status order by status"` · the admin console's Overview, `http://127.0.0.1:8080/admin/overview` | drafts `pending`, `approved`, `rejected` and `merged`; entries `active` and `retired`. The Overview's `knowledge` section shows `pending` (the drafts waiting for an admin) and `conflicts` (the pending ones that contradict an entry): `pending` equals the first query's. |
| the job loop | `docker compose ps rag-worker` · `docker compose logs --tail=5 rag-worker` | `Up`; lines such as `{"job_id": …, "job_type": "rag_lookup", "outcome": "succeeded", "ms": …}` or `"job_type": "knowledge_draft"`, and no traceback. The main `worker` claims neither type, and `rag-worker` claims nothing else. |
| the health checks | **Alarms**, the first look at each | `knowledge_queue` alarms when the pending drafts exceed `KNOWLEDGE_QUEUE_MAX` (200); `knowledge_integrity` when an entry's file changed or went missing after approval (`rag.integrity_failed` in the last 24 hours; repair with `--rebuild`, **After `make db-restore`**); `rag_budget` when the month's RAG spend reaches `RAG_MONTHLY_USD_CAP`, and `n/a — RAG off` while both switches are `false`. |

### Rollback

**Rollback.** Set `RAG_ENABLED=false` and `KNOWLEDGE_DRAFT_ENABLED=false` in `.env` (the lookup first, if both are on), then `docker compose up -d --force-recreate app worker rag-worker`. ① and ② are then what they were before: no lookup is enqueued, `triage` is not delayed, no block is added (spec §7.9), and no draft is proposed. **Entries stay: no data is removed**, neither the three tables, the drafts and approved entries, the `rag_results` and `llm_runs` rows, nor the files in `kb_learned/`; what was stored is only no longer read. `rag-worker`, which stays up, has only the jobs already queued left to run; `docker compose stop rag-worker` leaves them waiting (the main `worker` claims neither type). 020 stays under the old code too (new tables, a nullable column and wider CHECKs, none of which the v1.1 code reads), so there is no down-migration. To take the second compose file out as well, delete the `COMPOSE_FILE` line from `.env` and run `docker compose up -d --remove-orphans`: `rag-worker` goes and `app` is recreated without the mount; the files stay on the host. Switching the feature on again is steps 7 to 9, and the entries are in force again at once.

### After `make db-restore`

`make db-restore` brings the rows back and not the files: a backup is `pg_dump` only, and `kb_learned/` is git-ignored. Until the files are rewritten every active entry fails its hash check at the next lookup: it is left out, `rag.integrity_failed` is written and the `knowledge_integrity` alarm fires. And `make db-restore` stops `app` and `worker` only, so a running `rag-worker` keeps a connection to the database being replaced and its drop step fails (`FAILED at drop`). With the second compose file in use, the order is:

```bash
docker compose stop rag-worker
make db-restore FILE=backups/soc-<UTC stamp>.dump        # the dump that just rehearsed clean (Backup and restore)
docker compose exec -T app python -m app.rag.publish --rebuild
docker compose up -d rag-worker
```

→ `db-restore: … (N migrations)` and `app` and `worker` started again by the make target; then one JSON line on stdout, `{"rebuilt": N, "root": "/srv/kb_learned"}`, N being the active entries (`select count(*) from knowledge_entries where status = 'active'`); an entry it cannot rewrite is a `{"rebuild": "skipped", …}` line on stderr (its content no longer hashes to its `content_sha256`, or its path leaves the root); then `rag-worker` `Up`. It runs in `app` because that container mounts `kb_learned/` read-write and runs as the host user; the same command on the host (`PYTHONPATH=backend .venv/bin/python -m app.rag.publish --rebuild`) writes the checkout's `kb_learned/`, and `--rebuild --root PATH` writes another directory. A dump that predates 020 needs `make migrate` first (**Migration 020** above), and then `rebuilt` is `0`. The same command repairs one file that was edited or deleted by hand (the `knowledge_integrity` alarm). It reads the database and writes files; it changes no row. *(not run by the agent)*

## Environment keys

The 74 keys of `.env.example`, one row each, no values. `.env.example` is generated from context pack §6.3 (`scripts/gen_env_example.py`, checked by `make lint`) and frozen: a new key is a decision (DEC-003), never an edit. **Who sets it:** *Owner* — a private or host-specific value, in `.env` only; *default* — `.env.example`'s value, changed only by a DEC. **Secret:** *yes* — `.env` only, never `.env.example`, a commit, a chat or a command line. *Compose* keys are read by `docker-compose.yml` and `db/init/*.sh` only, never by the application; *read by nothing* is a §6.3 key whose reader was cut or never built.

| key | what it controls | who sets it | secret |
|---|---|---|---|
| `DATABASE_URL` | the role the app and the worker use, `app_rw` (the containers get it with `db:5432` from `docker-compose.yml`) | Owner | yes |
| `DATABASE_URL_OWNER` | the owner role: `make migrate`, `backup.sh`, `restore.sh`, `make db-restore`, `make db-shell` | Owner | yes |
| `TEST_DATABASE_URL` | `make test-db`; the database name must end in `_test` | Owner | yes |
| `MAX_PAYLOAD_BYTES` | the largest intake body accepted, checked before parsing | default | no |
| `RAW_LOG_MAX_BYTES` | `raw_log` is truncated beyond this | default | no |
| `PROMPT_LOG_MAX_BYTES` | how much raw log a ① prompt carries | default | no |
| `DEDUP_IDLE_GAP_MINUTES` | dedup: the idle gap after which a cluster takes no more duplicates | default | no |
| `MAX_CLUSTER_AGE_HOURS` | dedup: the oldest a cluster may grow | default | no |
| `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES` | dedup: the same, for an auto-closed cluster | default | no |
| `MAX_CLUSTER_SIZE` | dedup: the most occurrences one cluster takes | default | no |
| `DEDUP_ENABLED` | dedup: `true` (default) groups alerts into clusters, `false` makes every alert its own queue row and its own `triage` job (DEC-165); forward-only, clusters already open are left as they are; after a change the Owner recreates the containers, `docker compose up -d --force-recreate app worker` (**Grouping switch (DEC-165)**, below) | Owner | no |
| `PULL_ENABLED` | the indexer pull: `true` (default) seeds and re-arms the `pull` job, `false` seeds none and a `pull` row already pending ends after one run (DEC-207); alerts then arrive by `POST /webhook/alerts` only; recreate the containers after a change, `docker compose up -d app worker` (**SOAR intake (DEC-207)**, below) | Owner | no |
| `AUTOCLOSE_ENABLED` | auto-close: `true` (default) loads and evaluates the rules, `false` loads none and every non-duplicate alert is queued for Tier 1, the G8′ hard blocks with the rules (DEC-207); the rules page and the tables stay; recreate the containers after a change (**SOAR intake (DEC-207)**, below) | Owner | no |
| `ENRICHMENT_ENABLED` | internal enrichment: `true` (default) looks the asset, account and addresses up, `false` reads no `assets`, `identities` or `iocs` row, the context comes from the payload's `enrichment` (DEC-208), else the unknown context, and the `inventory_empty` check reads `ok` (DEC-207); recreate the containers after a change (**SOAR intake (DEC-207)**, below) | Owner | no |
| `INDEXER_URL` | the indexer the puller reads; its host name must match the certificate | Owner | no |
| `INDEXER_USER` | the read-only indexer account | Owner | no |
| `INDEXER_PASSWORD` | that account's password | Owner | yes |
| `INDEXER_CA` | the CA every indexer connection is verified against (`conf/root-ca.pem`, mode 0400, git-ignored); there is no unverified mode | Owner | no |
| `INDEXER_INDEX` | the index pattern pulled | default | no |
| `PULL_INTERVAL_S` | seconds between two pulls | default | no |
| `PULL_OVERLAP_S` | each pull starts this far before the cursor; the overlap's duplicates are dropped | default | no |
| `PULL_PAGE` | hits per indexer page | default | no |
| `PULL_START` | where the first pull starts when `source_cursor` is empty | default | no |
| `HEARTBEAT_RULE_ID` | the manager heartbeat's rule: recorded in `intake`, never an alert | default | no |
| `HEARTBEAT_MAX_AGE_MIN` | the health job's `heartbeat` check: how old `source_heartbeat` may be before it alarms, minutes (**Alarms**) | default | no |
| `SILENCE_WARN_HOURS` | read by nothing; no check detects a silent source | default | no |
| `JOB_MAX_ATTEMPTS` | attempts per job; then `failed` and a `job.exhausted` event | default | no |
| `JOB_BACKOFF` | seconds before each retry | default | no |
| `JOB_LOCK_TIMEOUT_S` | a `running` job locked longer than this is re-queued by the worker | default | no |
| `N_WORKER` | read by nothing; `docker-compose.yml` runs one worker | default | no |
| `INVENTORY_PATHS` | the inventory, identity and IOC files enrichment loads | default | no |
| `LLM_BASE_URL` | the model API endpoint | default | no |
| `LLM_API_KEY` | the model API key | Owner | yes |
| `LLM_MODEL_PROPOSER` | ①'s model; empty turns ① off (every alert `unavailable`) | default | no |
| `LLM_MODEL_VERIFIER` | the verifier's model; empty means the proposer's | default | no |
| `LLM_TIMEOUT_S` | the wall-clock deadline of one model call | default | no |
| `LLM_RETRY` | retries inside one call, on a network error or a 5xx | default | no |
| `LLM_THINKING` | the model's thinking mode, `disabled` \| `enabled` | default | no |
| `LLM_MONTHLY_USD_CAP` | the month's spend at which ① stops (`stopped_by='cap'`) | default | no |
| `LLM_PRICE_IN_PER_M` | USD per million input tokens (`llm_runs.cost_usd`) | default | no |
| `LLM_PRICE_OUT_PER_M` | USD per million output tokens | default | no |
| `PROMPT_TOTAL_BUDGET_TOKENS` | ①'s prompt budget | default | no |
| `CASE_PROMPT_BUDGET_TOKENS` | ②'s dossier budget, in estimated tokens (`tier2/dossier.py`); over it the dossier is cut and each cut is recorded (**② operations**) | default | no |
| `ANALYZE_QUOTA_PER_USER_DAY` | the analyses one user may start per day (`web/routers/tier2_runs.py`, which the case page of the React UI calls); over it the API answers 429 (**② operations**) | default | no |
| `NEVER_AUTOCLOSE_AGENTS` | agents whose alerts are never auto-closed | default | no |
| `AUTOCLOSE_RULE_WIDTH_PCT` | an auto-close rule that closes more than this share of a week's alerts is reported as too wide | default | no |
| `REVIEW_DELTA_TOLERANCE` | a decision is refused (409) when the alert grew by more occurrences than this since it was seen | default | no |
| `MAX_ALERTS_PER_CASE` | the most alerts one case or one correlation takes | default | no |
| `JWT_SECRET` | signs login sessions; empty → the login answers 503 | Owner | yes |
| `JWT_TTL_HOURS` | session lifetime | default | no |
| `LOGIN_MAX_FAILS` | failed logins before a lockout | default | no |
| `LOCKOUT_MINUTES` | the lockout's length | default | no |
| `WEBHOOK_API_KEY` | the webhook intake's key; empty → `503 webhook disabled` | Owner | yes |
| `WEBHOOK_IP_ALLOWLIST` | the addresses allowed to post to the webhook; empty → none | Owner | no |
| `RETENTION_DAYS` | read by nothing (data retention not built); the backup count is `BACKUP_KEEP` in `backup.sh` | default | no |
| `BACKUP_HOUR` | the nightly backup's hour, written into `conf/soc-backup.cron` as `0 2 * * *`; the key itself is read by nothing at run time | default | no |
| `EVAL_BLIND_FRACTION` | the share of alerts whose ① suggestion is hidden (the blind branch) | default | no |
| `DISPLAY_TZ` | the timezone of the times on the pages | default | no |
| `NOTIFY_TELEGRAM_BOT_TOKEN` | the health job's alarm sink (`infra/notify.py`): set together with the chat id → Telegram; either empty → the log sink (**Alarms**) | Owner | yes |
| `NOTIFY_TELEGRAM_CHAT_ID` | the Telegram chat an alarm is sent to — the same condition as `NOTIFY_TELEGRAM_BOT_TOKEN` | Owner | yes |
| `RAG_ENABLED` | learned knowledge: `false` (default) enqueues no `rag_lookup`, delays no `triage` and adds no block to ①'s prompt or ②'s dossier, which stay byte-identical (DEC-210); `true` makes the lookup of approved entries and decision history for every alert and case; `.env` only, not a web setting; recreate the containers after a change | Owner | no |
| `KNOWLEDGE_DRAFT_ENABLED` | learned knowledge: `false` (default) enqueues no `knowledge_draft` on a conclusion; `true` proposes a draft entry for an admin to review (DEC-210); `.env` only; recreate the containers after a change | Owner | no |
| `RAG_MODEL` | the model of the lookup's ranking call and the draft call; empty means `LLM_MODEL_PROPOSER` (DEC-210) | default | no |
| `RAG_TRIAGE_DELAY_S` | how long a new alert's `triage` waits for its lookup, seconds; 0 waits not at all (DEC-210) | default | no |
| `RAG_CASE_REFRESH_H` | the analysis of a case also enqueues a new lookup when the case's newest one is older than this, hours, or when there is none (DEC-210) | default | no |
| `RAG_HISTORY_DAYS` | how far back the decision history looks, days (DEC-210) | default | no |
| `RAG_MONTHLY_USD_CAP` | the month's spend at which the lookup and draft calls stop; counted inside `LLM_MONTHLY_USD_CAP`, so it can take at most this much from ① and ② (DEC-210) | default | no |
| `KNOWLEDGE_QUEUE_MAX` | the number of pending drafts above which the `knowledge_queue` health check alarms (DEC-210) | default | no |
| `POSTGRES_USER` | Compose: the `db` superuser, owner of every object | default | no |
| `POSTGRES_PASSWORD` | Compose: its password; `docker compose` refuses to start without it | Owner | yes |
| `POSTGRES_DB` | Compose: the database name | default | no |
| `DB_PORT` | Compose: `db`'s port on the host | default | no |
| `APP_RW_PASSWORD` | Compose: `app_rw`'s password, set by `01-roles.sh` on a first start | Owner | yes |
| `INDEXER_HOST_IP` | Compose: the indexer's address as the containers see it; empty means `host-gateway`, this host | Owner | no |

### Grouping switch (DEC-165)

`DEDUP_ENABLED` is a §6.3 key, a `.env.example` line and a row of the table above. `true` (the default, and what a `.env` without the line gets) groups alerts into clusters as before: a repeat of an open head's rule, source IP, destination IP and agent is a `duplicate` that only bumps the head's `occurrence_count`. `false` (**the Owner's decision of 30/09**) stops grouping: every alert is its own queue row and its own `triage` job, with its own enrichment and `risk_score`. The queue then shows a **User** and an **IP nguồn** column, so each row says whose alert it is and where it came from. The value is read as `true|false` (also `1|0`, `yes|no`, `on|off`); anything else stops the worker at startup with a message naming `DEDUP_ENABLED`, never a silent default.

To turn grouping off, from the primary checkout, in a shell that has sourced `.env` *(not run by the agent)*: put the line `DEDUP_ENABLED=false` in `.env` (edit it, do not paste the file anywhere), then

```
docker compose up -d --force-recreate app worker
docker compose exec -T worker printenv DEDUP_ENABLED
```

The second command prints `false`. A plain `docker compose restart worker` is **not** enough: the container keeps the environment it was created with. To turn grouping back on, set `DEDUP_ENABLED=true` (or delete the line) and recreate the same way.

What to expect once it is off:

- Two identical alerts a second apart are two rows, each `occurrence_count` 1, neither a `duplicate`. An alert that matches an auto-close rule is auto-closed on its own, and no cluster lock is taken. **The queue is longer and ① runs once per alert** — the spend row of **What to watch** against `LLM_MONTHLY_USD_CAP` is the number to look at in the first days.
- The same `alert_id` received twice is **still** refused (`409 duplicate` on the webhook, one `intake` row): that is receipt idempotency, upstream of grouping, and the switch does not touch it.
- **The switch is forward-only.** Clusters already open are left exactly as they are: nothing is split, closed or re-counted, their `occurrence_count` stays where it was, and they keep their place in the queue until an analyst decides them — they just stop receiving new members. Nothing that arrived before the restart is regrouped or ungrouped.
- Turning it back on is forward-only too: new alerts group again under any open head still inside `DEDUP_IDLE_GAP_MINUTES`, `MAX_CLUSTER_AGE_HOURS` and `MAX_CLUSTER_SIZE`, the rows made while it was off included. Rows that were already separate are not merged.

To check it worked, an hour after the restart *(not run by the agent)*: `psql "$DATABASE_URL" -Atc "select count(*) from alerts where received_at > now() - interval '1 hour' and (status = 'duplicate' or duplicate_of is not null)"` prints `0`.

### SOAR intake (DEC-207)

When the alerts arrive from the team's SOAR stream (n8n), which has already enriched, grouped and closed them and posts each finished alert to `POST /webhook/alerts`, this system stops doing those four things. Four switches, **all `true` by default**: merging the change alters nothing, and behaviour changes only when the Owner edits `.env`. Each is a §6.3 key, a `.env.example` line and a row of the table above, read as `true|false` (also `1|0`, `yes|no`, `on|off`); anything else stops the worker at startup with a message naming the key.

- `DEDUP_ENABLED=false`: no grouping; every alert is its own queue row and its own `triage` job (**Grouping switch (DEC-165)**, above).
- `PULL_ENABLED=false`: the worker seeds no `pull` job; one already pending ends after one run and is not re-armed. The `backfill` and `replay` commands of `app.infra.puller` do not read the flag.
- `AUTOCLOSE_ENABLED=false`: no rule is loaded or evaluated; every non-duplicate alert takes the `received` path to `queued_tier1`, with a `triage` job. The G8′ hard blocks go with the rules: SOAR owns the decision to close.
- `ENRICHMENT_ENABLED=false`: no `SELECT` on `assets`, `identities` or `iocs`; the context comes from the payload's `enrichment` (DEC-208: `asset.criticality`, `asset.in_inventory`, `asset.user_is_admin`, the worst `ti` / `ioc` verdict), else the unknown context (`asset_present` false, `criticality` `unknown`, privilege `null`, IoC reputation and all three `lookup_status` `skipped`). The risk score still runs.

The code of all four, the `enrichment/` and auto-close modules and the tables `assets`, `identities`, `iocs` and `autoclose_rules` stay: Tier 2's dossier and the admin pages still read them, and removing any is a later, separate decision (DEC-207 item 5).

**Before switching** *(not run by the agent)*: `make backup`, and copy `.env` and `docker-compose.yml` aside. The tag `checkpoint/pre-soar-intake` marks the commit before this change.

**How to switch** *(not run by the agent)*: put the lines in `.env` (edit it, do not paste the file anywhere), e.g. `PULL_ENABLED=false`, `AUTOCLOSE_ENABLED=false`, `ENRICHMENT_ENABLED=false` and, as DEC-165, `DEDUP_ENABLED=false`; then recreate the containers. **`up -d`, not `restart`**: a restart keeps the environment the container was created with.

```
docker compose up -d app worker
docker compose exec -T worker sh -c 'printenv | grep -E "^(DEDUP|PULL|AUTOCLOSE|ENRICHMENT)_ENABLED="'
```

The second command prints `KEY=value` for each switch the container has; the four you turned off read `false`. A switch that `.env` does not name is not in the container's environment and means `true`. If a value is still the old one, repeat the first command with `--force-recreate`. Merging this change itself is code-only and goes in with the usual `docker compose restart app worker` (the **restart** row, above); the switches do nothing until `.env` names them.

What to expect with all four off:

- **Alerts** reach the queue as the webhook receives them, each its own head, `queued_tier1`, with a `triage` job. Receipt idempotency still holds: the same `alert_id` twice is a `409`.
- **The context comes from the payload's `enrichment` (DEC-208), else the unknown context.** A payload with a valid block (schema `1.x`) gives the asset's criticality and inventory flag, whether the account is an admin and the worst IoC verdict; a payload with no block, or with any field outside its vocabulary, gets the unknown context, whole, and the log names the field. Three consequences hold for an alert with the unknown context (`docs/limitations.md`, DEC-207 item 3): gate step 4 forces every ① `false_positive` to `needs_review`, because `asset_criticality = unknown` is one of its blocks; the risk score is the severity base alone (28 for `medium`), with no asset, account or IoC addend; and the auto-close digest is empty (it is for every alert in this mode, as nothing is auto-closed), while the rules page stays. An alert SOAR enriched also has an unknown occurrence count (`occurrence_count: không rõ`, DEC-208 item 4), so ① cannot keep a `false_positive` for it whatever its asset says. An unknown or absent context never opens a path to a closed alert (DEC-207 item 4).
- **The heartbeat**, only when `PULL_ENABLED=false`, is stamped by every alert the webhook accepts (not by a `409`, and not by a body that is refused), so the `heartbeat` alarm stays green on a flowing stream even though the pull no longer moves it. With the pull on, the default, the webhook stamps nothing, exactly as before: a pull that died still turns the `heartbeat` alarm red beside a webhook that keeps receiving. A stream that carries no alert and no heartbeat document for `HEARTBEAT_MAX_AGE_MIN` minutes still alarms. The `inventory_empty` alarm reads `ok`, detail `n/a — enrichment off`, whatever `assets` holds.
- **The blind arm and the admin pages** are unchanged (DEC-101, DEC-206): no ① suggestion shows on a blind, undecided alert, in the queue, on the alert page, in the audit list or in the usage list; the overview and the digest answer and render with no auto-closed alert and no inventory.
- **The spend** moves the other way from DEC-165: ① still runs once per alert, so the `LLM_MONTHLY_USD_CAP` row of **What to watch** is the number to look at in the first days.

**Rollback**, three levels, each only as deep as needed *(not run by the agent)*:

1. **The flags.** Restore the lines in `.env` (`true`, or delete them) and `docker compose up -d app worker`, then the same `printenv`. Nothing else was changed, and alerts already received stay as they are. **Turning `PULL_ENABLED` back on is not just "the behaviour of before": the pull catches up, and after SOAR mode it re-ingests every alert SOAR already posted.** `source_cursor.last_sort` did not move while the pull was off, so the first pull starts at `last_sort - PULL_OVERLAP_S × 1000` (`last_sort` is in milliseconds, `PULL_OVERLAP_S` in seconds) and reads every alert the indexer indexed during the whole off-window. The pull keys an alert on the indexer's own `(manager name, Wazuh id)`; the alerts SOAR posts carry other keys (the team's samples, `docs/plan/tasks/P12/soar-payload-sample*.json`, have `id` = `gl-…` and `manager.name` = `graylog`), so **none** of what SOAR already posted is recognised as received: every one comes in again as a new alert. Each one that is not grouped as a duplicate gets a ① run, the auto-closed ones included (D8), so every alert of the off-window gets a **second ① run**, and with auto-close on again the closed ones also fill the next 08:00 digest. After days in SOAR mode that is a flood in the Tier-1 queue, in the digest and in the model spend. **Unless the Owner wants that re-ingest, the cursor must be moved to the switch-back time before the pull is turned on.** Read it first *(not run by the agent)*: `psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at from source_cursor"` (`last_sort` is the indexer's sort value in milliseconds since the epoch, `last_pull_at` the last pull that ran, from before SOAR mode). Moving the cursor is the Owner's decision, recorded, and never done silently by anyone else; this runbook gives no statement for it. While the pull is off the **What to watch** row "a pull in the last 5 min, no error" reads `f|…`, first column false, because `last_pull_at` goes stale: `f|t` if the last pull before the switch succeeded, `f|f` if it ended on an error. That is expected, and no alarm of its own (the `heartbeat` alarm reads `source_heartbeat`, which the webhook keeps moving with the pull off).
2. **The code.** Revert the merge of this change, or, by the Owner only, `git reset --hard checkpoint/pre-soar-intake`; then `docker compose restart app worker`.
3. **The data.** `make db-restore FILE=backups/soc-<timestamp>.dump`, **only if data was damaged**. There is no migration in this change, so levels 1 and 2 never need level 3.

## Alarms

`infra/health.py` runs ten checks every 5 minutes (the `health` job, re-armed by every worker start — see "Noticing a dead chain" below) and writes one `system_health` row per run. **The alarm state is the set of currently-failing check names, not a single ok/alarm flag.** A notification goes out whenever that set changes in either direction — a new failure, a recovery, or both together — but `audit_events.health.alarm` (payload `{"failing": […], "new": […]}`) is written only when a name is **new** to the failing set that tick; a tick that only recovers (the set shrinks, nothing new joins) still notifies but writes no `health.alarm` row. The daily 08:05 `DISPLAY_TZ` summary notifies the same way and never writes `health.alarm` either — it is a roll-up, not an event.

| check | threshold | what it means | first look | what to do |
|---|---|---|---|---|
| `heartbeat` | `HEARTBEAT_MAX_AGE_MIN` = 30 min (§6.3 default) | **no successful pull for the threshold — not "the manager went quiet".** `source_heartbeat.last_seen_at` is stamped at the end of every successful `pull_once`, whether or not that pull actually saw a rule-`100999` document (`infra/puller.py:_update_heartbeat`, called unconditionally) — so this alarms when the indexer is down or rejecting, or the `pull` chain/worker is dead, never specifically because the manager stopped sending. **A manager gone silent behind a live, reachable indexer is detected by no check here** — `SILENCE_WARN_HOURS` is read by nothing (Environment keys). | `psql "$DATABASE_URL" -Atc "select extract(epoch from (now() - max(last_seen_at)))/60 from source_heartbeat"` · `psql "$DATABASE_URL" -Atc "select now() - max(received_at) from intake where outcome = 'heartbeat'"` (a heartbeat document arrives about every 10 min; compare the two — fresh pulls with a stale or absent heartbeat document is the gap the check above cannot see) | Common failures, "Indexer down, or its certificate rejected" |
| `intake_backlog` | 5 min (module constant, no §6.3 key) | the oldest unprocessed `intake` row has waited past the threshold — the `pipeline` job is not draining intake (breaks G12) | `psql "$DATABASE_URL" -Atc "select coalesce(extract(epoch from (now() - min(received_at)))/60, 0) from intake where processed_at is null and error is null"` (`coalesce`d to match the check's own reading: empty = nothing waiting = `0`, not a blank row) | What to watch, "pending jobs by type"; then restart the worker |
| `job_backlog` | 10 min (module constant) | a due `pending` job has waited past the threshold — the worker loop is not claiming jobs | `psql "$DATABASE_URL" -Atc "select coalesce(extract(epoch from (now() - min(scheduled_at)))/60, 0) from jobs where status='pending' and scheduled_at <= now()"` (same `coalesce` reasoning) | Common failures, "Worker stuck" |
| `llm_null_ratio` | 30% of the last hour's `llm_runs` (module constant) | more than three in ten model calls in the last hour came back with a null result | `psql "$DATABASE_URL" -Atc "select count(*) filter (where result is null), count(*) from llm_runs where created_at > now() - interval '1 hour'"` | Common failures, "Model API down" |
| `triage_unavailable` | 10% of the last 24h's `alerts` (module constant) | more than one alert in ten received in the last day ended `triage_status='unavailable'` — ① gave up on it | `psql "$DATABASE_URL" -Atc "select count(*) filter (where triage_status='unavailable'), count(*) from alerts where received_at > now() - interval '24 hours'"` | Common failures, "Model API down"; or the `monthly_cost` row below if the cap was hit |
| `monthly_cost` | 80% of `LLM_MONTHLY_USD_CAP` (§6.3 default $30 → **ok at exactly 80%**, `pct <= 80`; alarms once spend goes **above** $24, not "at" it) | this month's `llm_runs.cost_usd` has reached the threshold; ① stops entirely (`stopped_by='cap'`) at 100% | `psql "$DATABASE_URL" -Atc "select round(coalesce(sum(cost_usd),0),2) from llm_runs where date_trunc('month', created_at) = date_trunc('month', now())"` | Common failures, "Monthly cap reached" — expected near month-end on a low cap, not a defect |
| `backup_age` | 36h (module constant) | the newest `backups/soc-*.dump` (falling back to `latest.dump`) is older than the threshold, or there is none. Reads `/srv/backups` **inside** the app/worker containers — `./backups:/srv/backups:ro`, added to `docker-compose.yml` at the P5-T11 merge; a mount change needs `docker compose up -d`, not `restart` | `ls -lt backups/soc-*.dump 2>/dev/null \| head -1` (host) or `docker compose exec -T worker sh -c 'ls -lt /srv/backups/soc-*.dump \| head -1'` (the check runs inside `worker`, not `app`; `exec` alone has no shell to expand the glob, hence `sh -c`) | Backup and restore, above — check the schedule is armed, run `bash scripts/backup.sh` by hand |
| `inventory_empty` | `assets` count > 0 (literal) | the inventory table is completely empty — says nothing about coverage, only that it is not zero | `psql "$DATABASE_URL" -Atc "select count(*) from assets"` | `POST /api/admin/reload-inventory` as `admin`, or Pilot §1 row c |
| `digest_unreviewed` | 0 misses; only evaluated from 17:00 `DISPLAY_TZ` onward (`ok` unconditionally before that — module constant hour) | at least one of yesterday's auto-closed, non-synthetic alerts still has no `autoclose_reviews` row after 17:00 local | `/admin/digest`, or `psql "$DATABASE_URL" -Atc "select count(*) from alerts a left join autoclose_reviews r on r.alert_id=a.alert_id where a.status='auto_closed' and not a.is_synthetic and a.closed_at >= date_trunc('day', now(), 'Asia/Ho_Chi_Minh') - interval '1 day' and a.closed_at < date_trunc('day', now(), 'Asia/Ho_Chi_Minh') and r.alert_id is null"` | review the digest page (P5-T09); nothing to do before 17:00 |
| `disk_free` | 20% free (module constant) | less than a fifth of the filesystem under the working directory (`/srv` in the containers, checked inside `worker`) is free. **`df`'s own `Use%` is not exactly this check's complement** — `statvfs` reserves a slice of blocks that `df` excludes from `Use%`'s denominator — so the alarm fires around **79% `Use%`**, not 80% | `docker compose exec -T worker df -h /srv`, or on the host `df -h --output=pcent . \| tail -1` | prune beyond the 14 kept dumps (should not be needed — `backup.sh` already prunes), check other growth, grow the volume |

**What it looks like on this host today — 29/09/2026 14:13 UTC** (review round 1: the Reviewer ran all
nine `psql` first-look statements above read-only against `soc_dev`; none failed). All ten checks `ok`:
`heartbeat` 0.3 min, `backup_age` 19.2 h, `inventory_empty` 8 assets, `disk_free` 68.7% free, `monthly_cost`
$0.48 of $30, and `digest_unreviewed` `ok` because 0 auto-close rules exist yet, so 0 alerts are auto-closed
and there is nothing to miss. `health.alarm` has never been written on this host — 0 rows. This is a dated
snapshot, not a guarantee: it goes stale the moment anything changes, so read `GET /health` (below) for the
live state — it is here as what "normal" looks like, not a number to compare against later.

**What is expected, and what would be news, in general** (so this paragraph does not go stale the day the
numbers above do). `backup_age` should read `ok` as long as the crontab armed on 26/09 (Backup and restore,
above) keeps firing; `crontab -l | grep -c backup.sh` reading `0` explains an alarm here without being a
code defect. `inventory_empty` should read `ok` once `assets` is non-empty (reloaded after the 25/09 reset,
DEC-113 — Pilot §1 row c is the same precondition the pilot checks, not a claim this happened back on
15/09) — but a non-empty inventory says nothing about coverage: an asset outside `conf/inventory.yaml` also
reads `unknown` and is hard-blocked from auto-close (G8′), silently, which this check cannot see
(`docs/limitations.md`). `digest_unreviewed` reads `ok` all day until 17:00 local, and is expected `ok` for
as long as no auto-close rule exists — the rules page (`http://<host>:8080/admin/rules`) is merged; the first rule is the Owner's
action, so until then: no rule, no auto-closed alerts, nothing to miss. `monthly_cost` should stay well
under 80% for most of a month on the default cap. The other six — `heartbeat`, `intake_backlog`,
`job_backlog`, `llm_null_ratio`, `triage_unavailable`, `disk_free` — are expected `ok` whenever the stack is
healthy; any of them firing is news, and the matching Common failures row is where to start.

**Noticing a dead chain.** None of the three self-scheduling chains (`pull`, `health`, `digest`) raises an
alarm of its own when it dies — each shows up only as an absence, not a red check. Check all three
directly: `psql "$DATABASE_URL" -Atc "select job_type, status from jobs where job_type in ('pull','health','digest') and status in ('pending','running') order by 1"`
— a healthy system shows **three rows**, one per chain; a **missing** row means that chain's re-arm never
ran or was lost. What each dead chain actually looks like: a dead `health` chain shows only as a stale
`checked_at` — the `health` job re-enqueues itself every 300 s, so if it alone died (an exception past its
retries) or the worker process is down, no new `system_health` row is written and no check ever fires,
because nothing runs to fire it; read `checked_at` from `GET /health` (below), or
`psql "$DATABASE_URL" -Atc "select now() - checked_at from system_health order by checked_at desc limit 1"`
— under about ten minutes is healthy (the job runs every 5 minutes), older than that means the chain
stopped. A dead `pull` chain surfaces **indirectly**, through the `heartbeat` alarm above, once
`source_heartbeat.last_seen_at` goes stale — there is no separate "pull chain dead" alarm. A dead `digest`
chain shows only as the next `08:00` local run never happening (no new digest, no `health.alarm`, nothing
red). **The repair is the same for all three**: every worker start re-arms them — `web/worker.py`'s
`main()` runs `enqueue(conn, "pull", "indexer")`, `enqueue(conn, "health", "system")` and
`digest.ensure_scheduled(conn)`, all idempotent, before the loop starts — so `docker compose restart worker`
re-arms a dead chain with no other action. `docker compose exec -T worker python -m app.tier1.digest --ensure`
*(checked statically)* still exists to re-arm just the `digest` chain by hand, without restarting the
worker — run it **inside** the container, not in a shell that has sourced `.env`: `os.environ` wins over
`--env-file`, and sourcing strips the quotes inside `INVENTORY_PATHS=[…]` the same way it does for
`make run-app-native` (Start and stop, above), so `config.load()` would refuse the value.

**Reading the live state — `GET /health` is loopback-open only *inside* the app container.** Under `docker-compose.yml`, port 8000 is published on `0.0.0.0` through Docker's own `docker-proxy`, so a request from the host itself is **not** loopback and answers `403` without an admin session — even from the Docker host, and even though `make run-app-native`'s bare-host form (`APP_HOST=127.0.0.1`, `Makefile`) makes that exemption work; `make run-app` itself is already the compose form (`docker compose up -d --wait db app`). The command that works under compose:

```bash
docker compose exec -T app python -c "import urllib.request as u;print(u.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

An admin token also works from anywhere: `curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8000/health`, where `TOKEN` is the `token` of an admin's `POST /api/auth/login` (there is no browser session on port `8000` since P11-T19: no cookie, no page, so a browser cannot sign in to it). The body is exactly `{"checked_at": …, "checks": […], "ok": …}` — the newest `system_health` row, no DSN, no secret, no filesystem path.

**Where an alarm goes.** `infra/notify.py` sends to Telegram only when both `NOTIFY_TELEGRAM_BOT_TOKEN` and `NOTIFY_TELEGRAM_CHAT_ID` are set in `.env`; Telegram is optional, and the bot token is never logged (silenced at the `httpx` logger too, not only this module's own). With either unset — the default on this host — every alarm goes to the **log sink** instead: one JSON line per send, `{"notify_sink": "log", "level": "alarm"|"ok", "text": "…"}`. Read them from the worker's own log:

```bash
docker compose logs worker | grep notify_sink
```

## Backup and restore

**Nightly: armed on 26/09/2026 by the Owner.** The cron line's own command, run once that day, printed `backup: ok 2026-09-26T04:49:39Z backups/soc-20260926T044938Z.dump (380K), latest.dump refreshed, kept 1, pruned 0`; the first scheduled run is 27/09 02:00 +07. `conf/soc-backup.cron` is one user-crontab line: at `0 2 * * *` (`BACKUP_HOUR`, host time) it enters the primary checkout, sources `.env` and appends the one line of `scripts/backup.sh --quiet` to `~/soc-backup.log`. It was installed with `(crontab -l 2>/dev/null; cat conf/soc-backup.cron) | crontab -`; **do not run that again**, it appends a second line.

| check | command | expected |
|---|---|---|
| armed | `crontab -l \| grep -c backup.sh` | `1`. `0`: not armed, install as above. `2`: installed twice, `crontab -e` and delete one. |
| ran last night | `ls -t backups/soc-*.dump \| head -1` · `tail -1 ~/soc-backup.log` | a `soc-<yesterday>T19…Z.dump` (names are UTC; 02:00 +07 is 19:00Z) · `backup: ok <UTC> backups/soc-….dump (<size>), latest.dump refreshed, kept N, pruned M`. A failed night is one `backup: FAILED <UTC> at <stage> (exit N)` line: run the next row. |
| by hand | `bash scripts/backup.sh` (`make backup` runs the same) | `backup: wrote backups/soc-<UTC stamp>.dump (<size>, pg_dump (PostgreSQL) 16.…)` · `backup: refreshed backups/latest.dump` · `backup: kept N of at most 14 (BACKUP_KEEP), pruned M` |

`backup.sh` dumps `DATABASE_URL_OWNER` with the server's own major version (`/usr/lib/postgresql/16/bin`; PATH's `pg_dump` 18 writes archives a 16 `pg_restore` rejects), writes a hidden `.partial`, reads it back with `pg_restore --list` and only then renames it. It keeps the 14 newest `soc-*.dump` (`BACKUP_KEEP`), pruning only after a success, and copies the new dump over `backups/latest.dump`: the file a fresh `pgdata` volume restores, and the one file under `backups/` git tracks (commit it at milestones only; the remote is public — `docs/db-docker.md`).

**Restore: rehearse first, always, and never from `backups/latest.dump` as committed** — that copy was dumped on IA1803 and carries `DEFAULT ACL … FOR ROLE user1` entries that fail under `pg_restore --exit-on-error` (P5-T12); name a fresh `backups/soc-*.dump`. **Rehearsal, `scripts/restore.sh`:** restores into a separate, new or empty database and never touches the live one — use it before every real recovery (on the dump you will use), to read old data, and for the drill. **Real recovery, `make db-restore`:** **replaces the live database** — stops `app` and `worker`, drops and recreates the database `DATABASE_URL_OWNER` names, restores, starts them again — use it only when the live database is lost or corrupt, with a dump that has just rehearsed clean.

```bash
DUMP="$(ls -t backups/soc-*.dump | head -1)"
bash scripts/restore.sh "$DUMP" --into soc_restore_rehearsal; echo "exit=$?"
psql "$DATABASE_URL_OWNER" -c 'drop database soc_restore_rehearsal'    # once read
```

→ `restore: record — paste into the drill log`, then date, dump (size, sha256), source, target, `live … — not touched`, `pg_restore exit 0`, `schema_migrations 20` and five table counts; `restore: OK — soc_restore_rehearsal restored and verified`; `exit=0`; `DROP DATABASE`. **Its two refusals**, exit 2, nothing changed: the live name, `--into soc_dev` → `restore: REFUSED — soc_dev is the live database; …`; a target that is not empty → `restore: soc_restore_rehearsal is not empty (N objects) — refusing without --force …` (`--force` drops and recreates it, and only on a name ending in `_test`).

```bash
make db-restore FILE=backups/soc-<UTC stamp>.dump    # the dump that just rehearsed clean
```

→ `db-restore: server 16, /usr/lib/postgresql/16/bin/pg_restore`; compose stops `app` and `worker`; `db-restore: backups/soc-….dump → soc_dev (20 migrations)`; compose starts them *(not run by the agent)*. Before it stops anything it asks the server its major version and reads the dump with that version's `pg_restore` (P8-T07). **Exit 2** (`… nothing was stopped or dropped`): the server did not answer (`make db-up`), the only `pg_restore` is newer than the server, or it cannot read the dump. **`FAILED at drop` or `FAILED at restore`**: the target has already started `app` and `worker` again, on a missing or partial database. Run `docker compose stop app worker` **at once**; repair: rehearse the next-newest `soc-*.dump`, then `make db-restore FILE=<it>`; then `docker compose up -d app worker`.

**With learned knowledge on (the second compose file, DEC-210), `make db-restore` needs a hand on each side.** It stops `app` and `worker` only, so `docker compose stop rag-worker` comes first (a running `rag-worker` holds a connection and the drop fails), and it restores rows, not the `kb_learned/` files: `python -m app.rag.publish --rebuild` writes them back from the database, and `docker compose up -d rag-worker` follows. The order and the checks are in **Learned knowledge and RAG (DEC-210)**, section *After `make db-restore`*. *(not run by the agent)*

The drill's full record is `docs/restore-drill.md` (P8-T02: a `backup.sh` dump of `soc_dev` restored into `soc_restore_drill`, counts before ≤ restored ≤ after).

## Restore drill (P8)

The full, signed record of every drill is `docs/restore-drill.md` (P8-T02's card); this is the quick reference, not a second copy of it.

**How to run one** — back up, then restore the fresh dump into a scratch database, never the live one:

```bash
bash scripts/backup.sh                                          # DSN from DATABASE_URL_OWNER
DUMP="$(ls -t backups/soc-*.dump | head -1)"
bash scripts/restore.sh "$DUMP" --into soc_restore_drill; echo "exit=$?"
```

Verify **before ≤ restored ≤ after** on `schema_migrations` (= 20) and the five tables `restore.sh` itself
prints (`alerts`, `intake`, `llm_runs`, `jobs`, `audit_events`): count each on `soc_dev` before the backup
and again after the restore finishes — the pipeline keeps ingesting during the drill, so the restored count
must sit between the two (equal to both only if nothing landed in the gap, as P8-T02's own drill found).
Then, as `app_rw` (the `DATABASE_URL` role, database name swapped to the target): `select count(*) from
alerts` must equal the restored count — `permission denied` fails the drill outright.

**Last drill: 29/09/2026 13:50 UTC — PASS — signed by the Owner — full record `docs/restore-drill.md`.**

**Clean-up.** The scratch database (`soc_restore_drill`) stays in place until the Owner signs; then
`psql "$DATABASE_URL_OWNER" -c 'drop database soc_restore_drill'` (the same form as the rehearsal above —
a bare `dropdb` reaches libpq's default socket, the wrong server on this host), run by the Owner or by the
Director at the Owner's word — `docs/restore-drill.md`'s own Clean-up section records whether it has been.

## What to watch (manual checks, beyond the ten alarms)

`infra/health.py` now runs the ten checks of **Alarms**, above, automatically every 5 minutes and sends on any change — read `GET /health` or the alarm before reaching for these. The manual checks below still earn their place: for what the ten checks do not cover (the ① `stopped_by` breakdown, per-job-type backlog, another test run on the server) and as a second look when you would rather read the numbers yourself. Run these by hand, each morning and after every change; the last column is the healthy answer.

| watch | command | healthy |
|---|---|---|
| the pull loop: a pull in the last 5 min, no error | `psql "$DATABASE_URL" -Atc "select now() - last_pull_at < interval '5 minutes', last_error is null from source_cursor"` | `t\|t` |
| pending jobs by type, not growing | `psql "$DATABASE_URL" -Atc "select job_type, status, count(*) from jobs where status in ('pending', 'running') group by 1, 2 order by 1, 2"`, twice, five minutes apart | **the three self-scheduling chains each show one row**, `pending` or `running` — `pull\|pending\|1`, `health\|pending\|1`, `digest\|pending\|1` (or `running` for any of them) — both times; the `pipeline` and `triage` counts the same or lower the second time. **Any of the three chains missing: `docker compose restart worker`** re-arms it (Alarms, "Noticing a dead chain"); a missing `pull` row is also the first thing to check when `heartbeat` alarms. |
| failed jobs and `job.exhausted` events | `psql "$DATABASE_URL" -Atc "select (select count(*) from jobs where status = 'failed'), (select count(*) from audit_events where event_type = 'job.exhausted')"` | the same two numbers as last time. If either grew: `psql "$DATABASE_URL" -Atc "select job_type, left(last_error, 120) from jobs where status = 'failed' order by job_id desc limit 5"` |
| ① rows by `stopped_by`, today (+07) | `psql "$DATABASE_URL" -Atc "select coalesce(stopped_by, 'ok'), count(*) from llm_runs where role = 'proposer' and created_at >= date_trunc('day', now(), 'Asia/Ho_Chi_Minh') group by 1 order by 2 desc"` | `ok\|N` first; `schema` rare; no `cap`, `transient` or `linter` row (Common failures) |
| spend this month against `LLM_MONTHLY_USD_CAP` | `psql "$DATABASE_URL" -Atc "select round(coalesce(sum(cost_usd), 0), 2), ${LLM_MONTHLY_USD_CAP:-30} from llm_runs where created_at >= date_trunc('month', now())"` | the first number well below the second; the adapter sums the same rows (the UTC month) before every model call |
| disk use of `backups/` | `ls backups/soc-*.dump \| wc -l; du -sh backups; df -h --output=pcent . \| tail -1` | at most `14` dumps; the filesystem well below `90%` |
| another test run on the server | `pgrep -fc 'migrate.sh\|make test-db'` | `0` before a `make test-db`. Typed at a prompt or on a script line it never counts itself; inside a longer `bash -c "…; …"` (an agent's tool call) the calling shell's own command line matches and adds `1` — the bracketed `'[m]igrate.sh\|[m]ake test-db'` never matches itself. **Never `ps aux`**: `psql`, `migrate.sh` and `pg_restore` receive the DSN, password included, as an argument. |

## Common failures

Every `psql` check below ran on the stand-in; the failure answers `no response`, `000 exit=7`, `000 exit=60` and the two `pull_once` errors were measured on this host against a closed port and a throwaway TLS server. The `docker`, `.env` and live `curl` checks are *(not run by the agent)*.

| symptom | check | fix |
|---|---|---|
| **Indexer down, or its certificate rejected**: `last_pull_at` stale, no new alerts | `psql "$DATABASE_URL" -Atc "select status, left(last_error, 160) from jobs where job_type = 'pull' order by job_id desc limit 1"` → `pending\|` when well; `…\|pull_once: indexer request failed: [Errno 111] Connection refused` (down) or `…[SSL: CERTIFICATE_VERIFY_FAILED]…` (certificate) · `curl -s -o /dev/null -w '%{http_code}' --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/_cluster/health"; echo " exit=$?"` → `200 exit=0` when well | `000 exit=7`, down: the Owner starts the Wazuh stack's indexer container (`docker ps -a --format '{{.Names}}' \| grep indexer`; `docs/wazuh-manager-changes.md` §0′). `000 exit=60`, certificate: the Owner copies that container's `/usr/share/wazuh-indexer/config/certs/root-ca.pem` to `conf/root-ca.pem`, mode 0400, and keeps `INDEXER_URL`'s host the certificate's name. `401 exit=0`: `INDEXER_USER` and `INDEXER_PASSWORD` in `.env`, then `docker compose up -d --force-recreate worker`. Then, if the `pull` job reads `failed`: `docker compose restart worker` — after `JOB_MAX_ATTEMPTS` failed pulls only a worker start queues a new one, which resumes from `source_cursor.last_sort`. |
| **Model API down**: ① rows `transient`, alerts `unavailable` | the ① row of **What to watch** · `psql "$DATABASE_URL" -Atc "select left(last_error, 120) from jobs where job_type = 'triage' and last_error is not null order by job_id desc limit 3"` | Nothing to restart. Each `triage` job is retried (up to `1 + LLM_RETRY` calls an attempt, `JOB_MAX_ATTEMPTS` attempts, `JOB_BACKOFF` apart); the last attempt writes `stopped_by='transient'`, `triage_status='unavailable'` and a `job.exhausted` event. An API that answers 5xx instead ends each job `failed`, with `job.exhausted`, no ① row and the alert left `pending`. Alerts that arrive once the API answers get ①; the others stay as they are, as no re-queue path exists: record the window in `docs/plan/STATE.md`. A `401` in `last_error` is the key, not an outage: `LLM_API_KEY` in `.env`, then `docker compose up -d --force-recreate worker`. |
| **Monthly cap reached**: ① rows `cap` | the spend row of **What to watch**: the first number ≥ the second | ① stays off until the month turns (UTC), or the Owner raises `LLM_MONTHLY_USD_CAP` in `.env` (a DEC) and runs `docker compose up -d --force-recreate worker`. Alerts already `unavailable` stay so. |
| **Worker stuck**: pending jobs growing, a `running` job older than `JOB_LOCK_TIMEOUT_S` | `psql "$DATABASE_URL" -Atc "select job_type, date_trunc('second', now() - locked_at) from jobs where status = 'running' order by locked_at limit 3"` → an age above `00:05:00` | `docker compose restart worker`: the loop re-queues every `running` job locked longer than `JOB_LOCK_TIMEOUT_S` (300 s) and runs the `pull` again; `docker compose logs --tail=5 worker` then shows `"outcome": "succeeded"`. |
| **Database container down**: pages fail, `psql` cannot connect | `docker compose ps db` · `pg_isready -h 127.0.0.1 -p "${DB_PORT:-55432}"` → `127.0.0.1:55432 - no response` | `make db-up` (it returns once `db` is healthy), then `docker compose restart app worker`. Never `docker compose down -v`. |
| **`JWT_SECRET` unset**: the login answers `503` | `grep -c '^JWT_SECRET=.\+' .env` → `0` · `curl -s -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"precheck-nobody","password":"x"}'` → `{"detail":"auth disabled: JWT_SECRET unset"}` | `.venv/bin/python -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env`, never into `.env.example`, a commit or a chat; then `docker compose up -d --force-recreate app`. The same `curl` → `{"detail":"invalid credentials"}`. |

## ② operations

The ② assistant (P5-T04, DEC-151) reads one case and writes an investigation for a Tier-2 analyst. It is advice, and it stops at classification: **`confirmed_incident` records an incident, and the system contains nothing and remediates nothing** — `docs/phase-7-tier2.md` names it the thesis's scope stop (Tier 3 is designed, not built; the system detects and classifies, it does not respond). Every claim below was read out of the merged code. No live model call was made writing this section, so every model-side outcome is described from the code and its fake-model tests, not seen. Commands the agent did not run are marked *(not run by the agent)*.

### Running an analysis

On a case page, a **tier2** or **admin** session sees the ② panel, titled `PHÂN TÍCH AI ②` (`frontend/src/strings.ts`, `case.aiHeading`). The case page is the React UI (`http://127.0.0.1:8080/`, **UI (service `ui`)** above); the Jinja case page this section was first written against retired in P10-T13, and the React panel uses the same state texts (`frontend/src/strings.ts`). The panel moves through four states:

| state | what the page says | what you can do |
|---|---|---|
| idle | `Chưa có phân tích nào cho case này.` | press **Phân tích** |
| running | `Đang phân tích…`; the panel re-fetches itself every 3 s | wait: the button is hidden while a job is live |
| done | the result: conclusion, confidence, summary, narrative, hypotheses, evidence with its marks, next steps, and the recorded snapshot beside the current alert count | read it; press **Phân tích** again for a fresh run |
| failed | `Phân tích thất bại — có thể thử lại`, and the last finished run's result underneath if there was one | press **Phân tích** |

The same through the API (a tier2 or admin bearer token) *(not run by the agent)*: `POST /api/tier2/cases/{id}/analyze` answers `202 {run_id, job_id}`, then `GET /api/tier2/runs/{run_id}` answers `running` until the job finishes and `done` with `{status, result, evidence_check, citation_warnings, stopped_by}` after. A `404` on that `GET` means no such run: the page treats a job that ended without a run row as **failed**, the API cannot tell it from an unknown id.

The refusals, in the order the API checks them:

| answer | when | on the page |
|---|---|---|
| `404` | no such case | — |
| `409` `case đã kết luận` | the case is no longer `investigating` | the button is not drawn: `Case đã kết luận — không thể phân tích thêm` |
| `429` `analyze quota exceeded for today` | the user already made `ANALYZE_QUOTA_PER_USER_DAY` (default 30) analyses in the last day | the panel says `Đã dùng hết lượt phân tích trong 24 giờ gần nhất` (the 429 carries no count, so the sentence gives none) |
| `409` `an investigation is already running for this case` | a job for this case is `pending` or `running` (one live job per case, by the jobs table's partial unique index) | `Đang có một lượt phân tích chạy cho case này` |

The quota counts `case.analyzed` rows in `audit_events` for that user, at request time. The count and the insert are two steps, not one: two requests racing at the limit can both pass, so a user can end **one over** the limit (N14, accepted, P5-T04 review).

### What ② does

One press builds the nine-block dossier from the database alone (case facts, representative alerts and logs, timeline, entities, correlation, Tier-1 decisions, playbooks, analyst notes and the previous ② result, and the scope block), inside an estimated budget of `CASE_PROMPT_BUDGET_TOKENS` (default 60,000; the estimate is characters over four); if it is over, it cuts in a fixed order — raw logs to 4 KB, representatives to 15 clusters, the timeline — and records each step. It lints the prompt (G6') before anything is sent, then makes **one** model call with no tools, plus **at most one** repair call when the answer breaks the schema. It scans each dossier block for prompt injection, checks the cited evidence against the case's alerts, and writes a single `llm_runs` row. **It changes no case or alert status (G7): the only writes are `llm_runs` and `cases.last_analyzed_at`**; the route adds the `case.analyzed` audit event. The snapshot, the cut steps (`agent_trace.truncations`) and `estimated_tokens` are stored in that row's `agent_trace`.

### What `need_more_data` means

Two different things wear the same label. It is **the model's own answer** when it says it lacks data. Or it is an **overrule**: ② replaced the model's conclusion because (a) **no cited evidence verified**, or (b) the dossier held a **high-severity injection finding** and the model had said `false_positive`. On an overrule the panel shows a warning line, `Mô hình đề xuất <original> nhưng kết luận đã bị hạ xuống need_more_data: <reason>`, and the row keeps `evidence_check.original_conclusion` (and `forced_by = high_severity_injection_finding` for (b)). Read the original before acting on the label: an overruled `confirmed_incident` is a real lead the check could not back with a log line.

### The evidence marks

Each cited item is marked **`Đã kiểm chứng`** (verified) or **`Chưa kiểm chứng`** with a reason. **Verified** means the quote is a verbatim substring of the `raw_log` or the description of an alert in this case, after Unicode NFKC and whitespace collapsing, in either the plain or the HTML-escaped form the model was shown; an alert that is a duplicate of a case alert counts as that alert. The rejections:

| reason | on screen | means |
|---|---|---|
| `not_in_case` | `alert này không thuộc case` | the `alert_id` is not in the case, nor a duplicate of one |
| `quote_not_found` | `trích dẫn không có trong log hay mô tả của alert` | the alert is in the case, the text is not in it |
| `quote_too_short` | `trích dẫn ngắn hơn 8 ký tự …` | under `8` characters after normalising: too short to prove anything |

### Cost and failures

**Every paid call is costed**, into whichever row that attempt writes, including a failed attempt's. A job that is retried leaves one row per non-final attempt with `stopped_by = 'transient'` under an attempt-scoped `run_id`, so the month's spend (`LLM_MONTHLY_USD_CAP`, default 30, summed over all `llm_runs`) never loses a call. The outcomes of a run:

| `stopped_by` | when |
|---|---|
| (empty) | a valid result was recorded |
| `cap` | the monthly cap was already reached when the run started: **0 model calls** were made |
| `permanent` | the API answered a 4xx, which the adapter never retries (a rejected key, a malformed request, a prompt past the model's context window): retrying changes nothing |
| `linter` | the dossier failed the safety lint before sending |
| `schema` | the answer broke the schema, and the one repair broke it again |
| `transient` | the model timed out or answered 5xx |

`LLMTimeout` is not retried inside the model adapter: the job is retried instead, up to `JOB_MAX_ATTEMPTS` (3) attempts, `JOB_BACKOFF` apart (10 s, then 60 s). A job that exhausts them ends `failed` with a `job.exhausted` event. What the page then says depends on the last attempt: after a model timeout or 5xx it wrote the `transient` row and the page says `Phân tích không có kết quả: <reason>`; if it died on anything else there is no row and the page says `Phân tích thất bại — có thể thử lại`. The same `Phân tích không có kết quả: <reason>` line is what `cap`, `permanent`, `linter` and `schema` show, because those runs finish normally with a row and no result. A case's investigate runs, read only *(not run by the agent)*:

```
psql "$DATABASE_URL" -Atc "select created_at, stopped_by, cost_usd, run_id from llm_runs where pipeline = 'investigate' and subject_id = '<case_id>' order by created_at"
```

`stopped_by` is empty for a recorded result and `transient` for a non-final attempt. `<case_id>` is the case id from the page's address, not an alert id.

### Operating notes

- The `investigate` handler runs on the `jobs` queue in the existing `worker` container (found by `iter_handlers()`, nothing to enable). Its statements carry a `5 s` statement timeout, and its first statement raises the idle-in-transaction timeout from `10 s` to `JOB_LOCK_TIMEOUT_S`, since the transaction is open across the model call.
- **`2 × LLM_TIMEOUT_S < JOB_LOCK_TIMEOUT_S`** must hold (240 s against 300 s by default): a send and its one repair must both finish before `reclaim_stale` re-queues a job it thinks is dead. Nothing enforces it in `.env`. Raise one, raise the other.
- With `LLM_MODEL_PROPOSER` empty the job completes without reading the case and writes nothing (no row, no status change). The page then says `Phân tích thất bại — có thể thử lại` while it is polling and `Chưa có phân tích nào cho case này.` after a reload.
- A merge that changes ② is a code-only change: `docker compose restart app worker` *(not run by the agent)*; the code is a live mount. A compose or mount change is `docker compose up -d`.
- **If the worker is down, a queued job stays `pending` and the page keeps saying `Đang phân tích…` and re-fetching every 3 s.** There is no stale-job state and no timeout on the page (P5-T05 open question 1). Check `docker compose ps worker` and the pending-jobs row of **What to watch**; `docker compose restart worker` starts the job. A job locked for longer than `JOB_LOCK_TIMEOUT_S` is re-queued by the worker's loop (**Worker stuck**, above).

### Limitations

- ② is **built but not measured**. The frozen gold set was run through ① only (P7); no figure exists for how often ② is right. Treat its conclusion as a starting point for the analyst, not a verdict.
- The `[truncated] N bytes dropped` marker the dossier puts in a cut block reads to the injection scan as a **medium** finding (the truncation flag is not carried to it). Only **high** overrules a `false_positive`, so this is noise, not a wrong conclusion.
- The quota can be exceeded by one per race (above).
- The polling, the four states and the overrule text were exercised against a fake model and a probe of the htmx swap; the panel was not driven in a real browser (P5-T05 open question 3).

## Pilot

> **26/09/2026 (P8-T03).** Not run. The Tier-1 console this procedure needs (P4-T03/T05/T06) was deprioritized and cut (DEC-116), so no human-decision pilot took place. The procedure is kept as designed. What ran instead is recorded in `docs/results/operations.md` (P8-T01/T06).

> **30/09/2026 (P10-T13).** The Jinja queue and alert pages this procedure names (`/queue`, `/alerts/{id}`, P4-T05) are retired; the Tier-1 console is now the React UI on port `8080` (**UI (service `ui`)** above). Where a step below has the analyst open the queue, or an alert, in a browser on `127.0.0.1:8000`, read `http://127.0.0.1:8080/`. `http://127.0.0.1:8000/login` still answers `200` and `GET /` there points a signed-in analyst to port `8080`. The step prose is otherwise kept as designed. What was rewritten so the pilot can start on the React UI (P10-T13, fix round 1): rows **h**, **h′** and the new row **ui** (§1), the one sentence in the opening paragraph and the two in §8 that had the app in a terminal (it is a container now, `make run-app` = `docker compose up -d --wait db app`), and §7's first two bullets — the `409` count comes from `docker compose logs app`, not from a `~/pilot-app.log` that nothing writes any more. Fix round 2 (P10-T13) put the labels the analyst sees in §2, §4 and row **g** into the words the React UI shows (`frontend/src/strings.ts`: the button is *"Nhận xử lý"*, not the Jinja page's), and `backend/tests/test_runbook_pilot.py` now fails when a quoted label of this section is not a string in that file.

> **01/10/2026 (P10-T17).** §0 and §2 name the React UI on port `8080`, where they still had `8000`; §6 names `eval/ops_export.py` with its flags, says lab alerts are split by source and reopened alerts are excluded, and §7's `409` count holds only with `DEDUP_ENABLED=true`; row **b** expects `18` migrations.

> **20/10/2026 (P11-T19).** The Jinja sign-in page and the session cookie are gone: on port `8000`, `/login`, `/logout` and `/` answer `404` (this supersedes the 30/09 note's sentence that `/login` still answers `200`), and a request is signed in by its `Authorization: Bearer` header alone. Row **h** checks the app with `GET /api/auth/me` (`401`) instead of `/login` (`200`); the pilot signs in on the React UI only (§2). The Admin console section above has the Owner's two steps for the release.

Addressed to the two people who run it — the Owner and the advisor (context pack §11: no agent starts the pilot, seeds an account, or tells the advisor the rule). Every command below is pasted **from the primary checkout** (`/project/project/AI_Support_SOC_1_2`, branch `main`, `.env` present); an agent's worktree has no `.env` and must never be the place these run. Commands, not prose: the seconds are the deliverable (`docs/lab-run-log.md`).

Open one shell for the checks and keep it for the whole pilot:

```bash
cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; echo "${DATABASE_URL:+env ok}"
```

→ `env ok`. Every `psql "$DATABASE_URL"` and `curl … "$INDEXER_URL"` below reads that shell's variables; nothing here restates a value from `.env` (DEC-070). The app and the React UI run as containers (`make run-app` and `docker compose up -d --build ui`, rows **h** and **ui**), so they need no terminal of their own. The worker runs the way the Owner Assist starts it — detached, log and pidfile under `/home/user1/soc-logs/` (`docs/plan/prompts/owner-assist-P6-run-2026-09-19.md` §0) — or, if you prefer, in its own terminal with `make run-worker`; row **d1** covers both.

### 0 · What this pilot is — and is not

Two analysts work the Tier-1 queue in a browser on `127.0.0.1:8080` (the React UI): the Owner signed in as `tier1`, the advisor as `tier2`; each also holds an `admin` account, which is P6's labelling account and is not used to decide alerts. Half of the alerts (`EVAL_BLIND_FRACTION=0.5`, chosen per alert by `sha256(alert_id)` at intake, `soar/pipeline.py`) show **no** ① suggestion — the **blind branch** — and the suggestion is removed at the API, not in the page, so no role and no page can see it before the alert is decided; the report (P8) compares decisions **by branch and by person**. Nothing in this pilot is a controlled experiment — architecture §6: *"Thí điểm trực tuyến … là mô tả, không phải kiểm định"* — the numbers are descriptive, and the section that reports them says so in its first sentence.

**Dates.** The pilot runs from the day P4-T05 merges (23/09 evening at the earliest — `docs/plan/tasks/P4/P4-tasks.md` §10 item 5) until P8 closes it. The start day and time are written into `docs/plan/STATE.md` by the Owner (§2 below); no other date counts.

### 1 · Preconditions — each with the command that proves it

Run top to bottom; stop at the first row whose `expected` does not hold. The **in `main` before** column names the task whose merge the row waits for (`git log --oneline main | grep -c 'Merge branch .task/<id>'` → `1`).

| # | check | command | expected |
|---|---|---|---|
| a | `.env` carries a `JWT_SECRET` (in `main` before: P4-T01 ✓ 20/09) | `grep -c '^JWT_SECRET=.\+' .env` | `1`. If `0`: `python3 -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env` — never into `.env.example`, never into chat. Until it is set the login answers `503 auth disabled: JWT_SECRET unset`. Re-run the shell prelude after editing `.env`. |
| b | migrations current | `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` | `20` (the 17 of 26/09, `018_alerts_notify.sql` of P10-T05, `019_admin_console.sql` of P11-T01, DEC-200, and `020_learned_knowledge.sql` of P13-T01, DEC-210). Less → `make migrate` from the primary checkout, then re-check. |
| c | inventory loaded (DEC-083) | `psql "$DATABASE_URL" -Atc "select (select count(*) from assets), (select count(*) from identities)"` | `4\|2` (`HR-computer`, `IA1803`, `user1-IA1803`, `wazuh.manager`; `root`, `user1`). If `0\|0`: `PYTHONPATH=backend python3 -c "from app.infra.db import connect; from app.enrichment.inventory import load; c = connect(); print(load(c)); c.commit()"` — or `POST /api/admin/reload-inventory` signed in as `admin`. |
| d1 | worker process alive | `pgrep -af 'python3 -m app.web.worker'` | one line ending `-m app.web.worker` (a `sh -c` wrapper may show as a second line — same worker). None → start it from the primary checkout, detached with a log outside the repo: `mkdir -p /home/user1/soc-logs && PYTHONUNBUFFERED=1 nohup setsid make run-worker > /home/user1/soc-logs/worker-$(date +%F).log 2>&1 & sleep 2; pgrep -f 'make run-worker' > /home/user1/soc-logs/worker.pid` (the pidfile is the process-group leader; stop with `kill -- -$(cat /home/user1/soc-logs/worker.pid)` — DEC-102) — or, simpler, `make run-worker` in its own terminal. Leave it running: the puller is the `pull` job the worker enqueues for itself every `PULL_INTERVAL_S=60`. Both were **down from the 16/09 reboot to 19/09** (DEC-089) — this row is not a formality. **Restart the worker after every merge that touches `backend/app/web/worker.py`, `soar/` or `infra/puller.py`** (P3-T10, P3-T11 do) — a running process never picks up a new handler. |
| d2 | puller pulling — cursor advances | `psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at, last_error from source_cursor"` — run it, wait two minutes (`sleep 120`), run it again | `last_pull_at` later on the second run; `last_error` empty (a third field printed blank). A non-empty `last_error` names the indexer problem — fix that, not the worker. |
| d3 | live alerts arriving | `psql "$DATABASE_URL" -Atc "select count(*) from alerts where source='wazuh'"` | rising from **3,941** (the 19/09 figure, unchanged since 15/09). ≈ 3,400 live documents wait in the indexer, so the first minutes after `make run-worker` are catch-up — a jump of thousands is expected, not a fault. |
| d4 | intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | falling to `0` and staying near it (G12: every intake row gets `processed_at` or `error` within 60 s while the worker is alive). |
| e | manager alive — through the indexer, **never the file** (DEC-091) | `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}}}'` | `{"count":N,…}` with `N` rising by **one every 10 minutes** (the heartbeat is a 600 s `full_command` stanza — DEC-068). Run it twice ten minutes apart if in doubt. An exit code `60` means `INDEXER_CA` does not match `INDEXER_URL`; `401` means the read-only account — both are `.env` facts, not pilot facts. |
| f | the seed CLI is in this checkout (in `main` before: P4-T01 ✓ 20/09), then **run block 1f below once** | `PYTHONPATH=backend python3 -m app.infra.auth seed-users --help >/dev/null && echo cli ok` | `cli ok`; then block **1f** prints four `created: <username> (<role>)` lines and exits `0`. |
| f′ | the `users` table shows the four accounts | `psql "$DATABASE_URL" -Atc "select username, role, is_active from users order by 1"` | four rows — one `tier1`, one `tier2`, two `admin` — each `\|t`. |
| g | ① is running (in `main` before: **P3-T10**, and the worker **restarted after that merge** — DEC-102 option A; live suggestions need **P3-T11**'s live run) | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where role='proposer'"` | `> 0`, and rising as the worker's `triage` handler drains the pending `triage` jobs (≈ 500 at 20/09). `0` with P3-T10 in `main` → the worker predates the merge: stop it (`kill -- -$(cat /home/user1/soc-logs/worker.pid)`, or `Ctrl-C` in its terminal) and start it again as in row **d1**. **If `0` the pilot can still start** — every alert on the visible branch then shows *"chưa có"* in the queue's ① cell and *"Đang phân tích…"* on the alert page, and the blind branch measures nothing yet; say so in `STATE.md` beside the start time, and P8 dates the ① coverage from the first `llm_runs` row. |
| h | the app is up (in `main` before: P4-T04 for the JSON API on `8000` — its `/login` page is gone since P11-T19; the queue and alert pages the pilot works in are the React UI, row **ui** — P4-T05's Jinja `/queue` and `/alerts/{id}` are retired, P10-T13) | from the primary checkout: `make run-app` (`docker compose up -d --wait db app`: detached, returns once the containers are up, no terminal to keep) — then, in the checks shell: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/auth/me` | `401` (no session: the app answers). uvicorn's access log is the container's own stdout: `docker compose logs app` is where §7's `409` count reads it; there is no `~/pilot-app.log`. *(not run by the agent)* |
| h′ | the app loaded `JWT_SECRET` | `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"precheck-nobody","password":"x"}'` | `401` (invalid credentials for a user that does not exist — it counts against no account). `503` means the app was created before row **a** was done: `docker compose up -d --force-recreate app` (`.env` is read when a container is created, so `restart` never sees the edit), then re-check. |
| ui | the React UI is up and reaches the app (the Tier-1 console this pilot runs on, P10-T07/T13) | `docker compose up -d --build ui` — then `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/` and `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/auth/me` | `200` (the page) · `401` (no token: the proxy reached `app`; `502` means it did not — `docker compose ps app`, then **UI (service `ui`)** above). *(not run by the agent)* |

**Block 1f — the seed command** (row **f**; once, from the primary checkout; `.env`'s `DATABASE_URL` is the `app_rw` DSN, and migration 017 lets it insert into `users`):

```bash
PYTHONPATH=backend python3 -m app.infra.auth seed-users --env-file .env \
  --user <OWNER_T1_USERNAME> tier1 "<Owner display name>" \
  --user <ADVISOR_T2_USERNAME> tier2 "<Advisor display name>" \
  --user <OWNER_ADMIN_USERNAME> admin "<Owner display name>" \
  --user <ADVISOR_ADMIN_USERNAME> admin "<Advisor display name>"
```

**Each password is typed at the `password for <username>:` prompt the CLI opens** (`getpass`) — never on the command line, and never as an inline `SEED_PASSWORD_<USERNAME>` assignment in front of the command: that lands in shell history (Director at E5, DEC-095; the env form exists for non-interactive tests only). A re-run prints `exists, skipped: <username>` four times and changes nothing (an existing hash is never overwritten). The four usernames must stay distinct after upper-casing with `-` → `_` — the CLI refuses a collision. The two `admin` accounts are P6's labelling accounts (26–27/09); write the four usernames into `STATE.md`'s "20/09 — KIỂM 2/2" line.

Rows **a–f′** can be done today; **g** waits for P3-T10; **h** and **ui** wait for nothing that is not merged, and **ui** is the last thing before §2.

### 2 · The start — one action

The Owner opens `http://127.0.0.1:8080/` (the React UI's own sign-in form; the Jinja sign-in page that was on port `8000` is gone, P11-T19), signs in with the `tier1` account, opens the first alert in the queue, presses **"Nhận xử lý"**, and decides it (*"Đóng — dương tính giả"* or *"Đóng — lành tính"* with a reason in *"Lý do"*, sent with *"Ghi quyết định"*, or *"Chuyển tier 2"*). **That first decision is the pilot start.** Write the date and time (`date '+%F %T'` in the checks shell) into `docs/plan/STATE.md` under the P4 phase row, commit from the primary checkout — nothing else counts as the start: not `make run-app`, not the login, not a decision by the advisor.

### 3 · The rule for the advisor — say it aloud, before the first alert

Vietnamese: **"Quyết trước; không bao giờ mở `llm_runs`, không hỏi ① đã nói gì, trước khi bấm quyết định. Khoảng một nửa alert không hiện gợi ý — đó là thiết kế, không phải lỗi."**

English: **"Decide first; never open `llm_runs` or ask what ① said before you press decide. About half the alerts show no suggestion — by design, not a bug."**

The same rule binds the Owner. The consequence (the Director's incident table, `docs/plan/prompts/director.md`): an alert whose ① output was seen before it was decided — in `llm_runs`, in a digest, in a chat — has its decision **discarded from the blind-branch analysis**, and the case is recorded in a DEC. Say when it happens; it is a recorded exclusion, not a fault.

### 4 · What day 1 looks like — and why nobody "fixes" it

- **(a) The queue opens with the 383 replayed heads** (`replay` 307 + `wazuh` 76 at 19/09). Every one was enriched **before** the inventory was loaded on 15/09, so all 383 carry `asset = unknown` / `lookup_status.asset = not_found`, and G8′'s asset block pinned every one of them to the queue (DEC-083 — enrichment is written at the A5/A6 edge and there is no `queued_tier1 → enriching` transition, so no supported path changes it). They are **real alerts with a known enrichment gap**: decide them normally, on what the raw log and the correlation say. **Do not re-enrich, do not delete, do not skip them.** P8 names them as a limitation and reports them in or out per its chapter (§6).
- **(b) New live alerts are enriched correctly** (the inventory has been loaded since 15/09) — and ≈ **79 %** of them come from one Windows endpoint, `HR-computer` (SCA / EventChannel noise; 79.4 % of the 14/09 sample — DEC-066). This is the estate, not a defect, and it is **not a reason to add a filter** (`docs/plan/prompts/planner-run-P4-2026-09-19.md` §2): a filtered pilot would measure the filter. Decide the noise as noise — that is what the false-positive half of the evaluation is for.
- **(c) The risk column (*"Mức"*) is a band, never a number** — *"Thấp"* · *"Vừa"* · *"Cao"* · *"Rất cao"* (`docs/phase-4-enrichment.md:198-207`). The score is not on the page by design.
- **(d) ⚑ beside a suggestion** means the gate forced the verdict (`gate.forced`; the alert page says which step: *"Cổng kiểm soát"* reads *"Bị ép"*, then *"Ép bởi"* and the steps). Expected on this corpus: the 383 heads all miss `asset_criticality`, so ① on them is forced to `needs_review` — the gate working, not ① failing.
- **(e) *"ẩn — nhánh mù"*** in the queue's ① cell, and as the title of the ① panel (*"PHÂN TÍCH AI ①"*) on the alert page, is the blind branch: whatever ① said — or has not yet said — about that alert is hidden until it is decided, and so is whether ① ran at all (`triage_status` and `run_id` are stripped with the suggestion — DEC-101). It is never worded *"chưa có"*, which would say ① has nothing to tell. *"chưa có"* in the queue cell (*"Đang phân tích…"* on the alert page) appears only on the visible branch and means ① has not run on that alert yet (row **g**); *"Không có gợi ý ①"* means it ran and gave no proposal.

### 5 · Daily checks — two minutes, each morning

In the checks shell (prelude from the top of this section already run):

| check | command | expected | when it is off |
|---|---|---|---|
| ① ran in the last day | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where created_at > now() - interval '1 day' and role='proposer'"` | `> 0` | flat at `0` → the worker's `triage` handler is not wired or the worker is down: `pgrep -af app.web.worker`; if alive, check P3-T10 is in `main` and restart the worker. |
| queue shape | `psql "$DATABASE_URL" -Atc "select triage_status, count(*) from alerts where status='queued_tier1' group by 1"` | mostly `ready`; `pending` shrinking | `pending` growing for a day → same as the row above. `unavailable` rows are alerts on which ① gave up (retries exhausted, budget cap, linter stop — P3-T10) — read why with `psql "$DATABASE_URL" -Atc "select stopped_by, count(*) from llm_runs where role='proposer' and result is null group by 1"` and `psql "$DATABASE_URL" -Atc "select last_error from jobs where job_type='triage' and status='failed' order by created_at desc limit 5"`; do not re-queue by hand. |
| decisions happened | `psql "$DATABASE_URL" -Atc "select count(*) from audit_events where event_type='tier1.decided' and created_at > now() - interval '1 day'"` | `> 0` on a pilot day | `0` → nobody decided yesterday; note the gap in `STATE.md`, do not backfill. |
| intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | ≈ `0` | growing → worker down → `make run-worker` in its terminal (row **d1**); it catches up on its own. |
| manager heartbeat | the `_count` of row **e**; DB-side, `psql "$DATABASE_URL" -Atc "select now() - max(received_at) from intake where outcome='heartbeat'"` and `psql "$DATABASE_URL" -Atc "select now() - last_seen_at from source_heartbeat"` | `_count` rising by one every 10 minutes; the last heartbeat document ingested < `00:12:00` ago (600 s cadence + one pull); `last_seen_at` < `00:02:00` ago (the puller writes it after every successful pull, `PULL_INTERVAL_S=60`) | `last_seen_at` stale → the puller, not the manager: rows **d1**/**d2**. `_count` flat (or the ingested heartbeat old) with `last_seen_at` fresh → the manager or its `full_command` stanza stopped; a manager-side fact for the Owner (context pack §11), not a pilot fault. Decisions continue on what is queued. |
| puller errors | `psql "$DATABASE_URL" -Atc "select count(*) from source_cursor where last_error is not null"` | `0` | `1` → `psql "$DATABASE_URL" -Atc "select last_error from source_cursor"` names the indexer problem (certificate, credentials, index missing); fix `.env` or the indexer, restart the worker. |

### 6 · What P8's export does with the pilot's alerts — and why

P8's export, `eval/ops_export.py`, handles these **itself**; the Owner does not keep them out by hand, does not skip them, and does not decide them differently. The pilot's figures are section 6a of its output, and the file has them only when the pilot's window is given *(not run by the agent)*:

```bash
PYTHONPATH=backend python3 eval/ops_export.py --until <UTC instant> --pilot-start <UTC instant> [--pilot-end <UTC instant>] --env-file .env --out docs/results/operations.md
```

`--pilot-start` is the start written into `STATE.md` (§2), inclusive. `--pilot-end` closes the pilot, exclusive, and needs `--pilot-start`; left out, the end is the database's own `now()`. `--until` is required (without it the export exits 2) and closes the report's own window, which is not the pilot's. Every instant is ISO 8601 and must end in `Z` or `+00:00` — a local time with any other offset is refused, exit 2; `date -u '+%Y-%m-%dT%H:%M:%SZ'` prints the current one. The export is read-only, calls no model and no network; without `--pilot-start` section 6a prints `not measured: pilot start not given`.

- **`source='lab'` rows** — the 22–24/09 lab scenarios on the same host, retagged after each run by `eval/lab_tag.py` from the seconds in `docs/lab-run-log.md` (DEC-085). They are G2's, not the pilot's. The export splits them rather than dropping them: section 6a prints the pilot's figures per arm and per source (`wazuh`, `lab` and all), so the lab alerts have a line of their own and the `wazuh` line is the live traffic. Decide them like any other alert if they reach the queue during the pilot; the tag separates them later.
- **Reopened alerts** — any alert with an `alert.reopened` audit event: the ① verdict was visible in the digest before the second decision, so it is blind no longer (P4 planning decision 7). The export excludes it: it is in no decision figure on either arm, not only the blind-branch agreement, and it is counted apart as `đã mở lại (loại khỏi pilot)` (Q35, DEC-166).
- **Alerts an escalation swept into a case** — the other correlated heads that an escalation takes into its case without a decision of their own (never one that another analyst holds, DEC-166). They are no decision either: counted apart, per arm and source, as `kéo theo (không phải quyết định)` (Q34, DEC-165), and in no decision count, denominator or agreement.
- **The 383 pre-inventory heads** (§4 a) — a named limitation; P8's chapter says whether they are in or out of each table, with the sentence attached.
- **Decisions on the visible branch** are reported as *"có thể thiên lệch"* (`docs/chot-v3-14-ngay.md` §A3; architecture §6): the analyst saw ① before deciding. They are counted, per person, and labelled — never pooled with the blind branch.

### 7 · Limitations of this pilot, stated

- **The connection is plain HTTP** — the app is published on `8000` and `ui` on `127.0.0.1:8080` without TLS, so the password typed at sign-in and the Bearer token the React UI keeps in the tab's `sessionStorage` cross the network in clear wherever the Owner's tunnel does not encrypt them. Until P11-T19 the same login also set a `soc_session` cookie (used by the admin pages on `8000`): `HttpOnly`, `SameSite=Lax`, `Secure` off, and there was no CSRF token beyond `SameSite=Lax`. It sets none now: a request is signed in by its `Authorization: Bearer` header alone, which a page of another site cannot attach. Acceptable for two users on one host; stated for the record (P4 planning decision 8).
- **`REVIEW_DELTA_TOLERANCE=20`** and **`RETRIAGE_FACTOR=10` / `RETRIAGE_ABS_DELTA=200`** are unvalidated v1 constants. The pilot's evidence about them is the number of `409` conflicts on decide, **and only with `DEDUP_ENABLED=true`** (the default; see `Grouping switch (DEC-165)` above): that conflict is a head that gained occurrences after the analyst opened it (`cluster_grew`, `occurrence_count` over `seen_occurrence_count` by more than `REVIEW_DELTA_TOLERANCE`). With it `false` nothing is grouped, every alert keeps `occurrence_count` 1, and no `cluster_grew` can happen — the count measures nothing about the constants, whatever it reads; a `409` that still shows up is `already_decided` or `not_active` (two presses, or two analysts). They are **not audited** — `select count(*) from audit_events where event_type='authz.denied'` counts refused roles, not conflicts — so count them from the app's own log, which is the container's stdout (row **h**): `docker compose logs --no-log-prefix --since '<the start written in STATE.md, YYYY-MM-DDTHH:MM:SS>' app | grep -c '/decide HTTP/[0-9.]*" 409 '`. uvicorn's default access log is on (`docker-compose.yml`'s `command` does not pass `--no-access-log`) and each line ends with the status, `INFO:     <client> - "POST /api/tier1/alerts/<id>/decide HTTP/1.1" 409 Conflict` — the format was measured on a scratch uvicorn with the same defaults, the count itself was not run against the stack. Acknowledge, escalate and reopen answer `409` too: replace `/decide HTTP/[0-9.]*"` with `/api/tier1/.*` to count them all. **The count lives in the container's log**: `docker compose up -d --force-recreate app` or `make down` removes the container and the log with it, so read and write the number down first (or save `docker compose logs --no-log-prefix app > ~/pilot-app-$(date +%F).log`). Note the number in `STATE.md` at the end of the pilot. *(not run by the agent)*
- **The two analysts are the author and the advisor** (`docs/chot-v3-14-ngay.md` §A3): the blind branch controls what they see, not who they are.
- The day-1 queue (§4 a) and the `HR-computer` share of the live stream (§4 b) are limitations of the same pilot and are listed with these in P8 (`P4-tasks.md` §11 item 4).

### 8 · Stop / rollback

- **Pause or stop the pilot:** `docker compose stop app ui` stops the UI and the API and nothing else (read the `409` count first, §7: the log goes when the container is removed, a `stop` keeps it). **Leave the worker running** — it keeps ingesting and ① keeps running, and both are wanted for the lab (22–24/09) and for P8's export. To resume, `make run-app` and `docker compose up -d ui` (rows **h**, **ui**) — sessions survive a restart (they are tokens checked against `users`, not server memory).
- **Nothing in P4 needs a rollback of data.** Every decision is one `tier1.decided` audit row (append-only) plus a status the state machine owns; a wrong decision is corrected the way the design says — reopen when the state machine allows it, or a note in the DEC — never by an `UPDATE`.
- **Stop the worker only for the host, or to restart it after a merge** (row **d1**), never for the pilot: `kill -- -$(cat /home/user1/soc-logs/worker.pid)` for the detached form, `Ctrl-C` in its terminal for the foreground form; starting it again (row **d1**) resumes the puller from `source_cursor.last_sort` (row **d2**) and the pending `triage` jobs from where they were — nothing is lost, nothing is re-done.
