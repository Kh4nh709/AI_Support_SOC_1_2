# kb_learned/

The **published copy** of the learned-knowledge entries (DEC-210). Everything in this directory except
this file is git-ignored: it is written by the application and is never committed.

```
kb_learned/
  README.md                          this file, the only tracked one
  entries/<category>/<entry_id>.md   an approved entry that is in force
  retired/<entry_id>.md              an entry an admin retired (moved here, never deleted)
```

An entry is an analyst's conclusion, generalised (no literal IP, user or host) and approved by an admin.
It sits beside `kb/` and never replaces it: `kb/` is the signed decision tables and playbooks, this is
reference material that ① and ② may quote to themselves, never a rule and never a reason to close.

**The database is the source** (`knowledge_entries.content` and `content_sha256`). The files are a copy
that `app` writes when an admin approves and moves when an admin retires; the lookup re-checks each
file's sha256 against the database before an entry reaches a prompt, so a file changed or lost after
approval is left out of the lookup and raises the `knowledge_integrity` health alarm.

- **Never edit a file here by hand.** An edit is an integrity failure, not a correction: change an entry
  by approving a new version in the admin console.
- **A backup does not contain these files** (`make backup` is `pg_dump` only). After `make db-restore`, or
  to repair a file that was changed or deleted, rewrite them from the database:
  `python -m app.rag.publish --rebuild` (in the `app` container:
  `docker compose exec -T app python -m app.rag.publish --rebuild`; `--root PATH` names another
  directory).
- **The directory must exist on the host before the first `docker compose up -d`**, made by the user that
  runs Compose (otherwise Docker creates it as `root` and `app` cannot write in it).
- **Mounts** (`docker-compose.rag.yml`): `app` read-write, `rag-worker` read-only, `worker` none.

Steps, checks and rollback: `docs/runbook.md`, "Learned knowledge and RAG (DEC-210)". Design:
`docs/superpowers/specs/2026-10-24-learned-knowledge-rag-design.md` §7.2.
