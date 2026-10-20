"""
web/ - Composition root: the FastAPI application and its JSON API. It renders no page.

`web/main.py` is the FastAPI app: the intake webhook (POST /webhook/alerts), `/health`, and the
REST API (`/api/...`) that the React UI (`frontend/`, the `ui` service on port 8080) calls. The
UI is the only console: the Jinja Tier-1 and Tier-2 pages went in P10-T13, and the Jinja admin
pages, the sign-in pages and the session cookie in P11-T19 (spec §8, DEC-205), so port 8000
answers `/api/*`, `/webhook/alerts` and `/health` (besides FastAPI's own `/docs`, `/redoc` and
`/openapi.json`) and no page of ours. A session is the token a caller sends as
`Authorization: Bearer`.

Import rule: composition root. MAY import every other package. Nothing in
backend/app/ imports web/.
"""
