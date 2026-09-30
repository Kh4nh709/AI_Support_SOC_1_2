"""
web/ - Composition root: the FastAPI application, its JSON API and the few pages it still renders.

`web/main.py` is the FastAPI app: the intake webhook (POST /webhook/alerts), the REST API
(`/api/...`) that the React UI (`frontend/`, the `ui` service on port 8080) calls, and the
server-rendered pages that remain: `/login`, `GET /` (each role goes where it belongs; tier 1
and tier 2 get a page that points to the React UI, P10-T13) and the admin pages `/admin/rules`,
`/admin/digest` and `/admin/labels` (Jinja2 + HTMX, no build step). The Jinja Tier-1 and Tier-2
pages are retired.

Import rule: composition root. MAY import every other package. Nothing in
backend/app/ imports web/.
"""
