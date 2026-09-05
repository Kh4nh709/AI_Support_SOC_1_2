"""
web/ - Composition root: the FastAPI application, HTMX routes and Jinja templates.

`web/main.py` (arriving in P2) is the FastAPI app: the intake webhook
(POST /webhook/alerts), the REST API, and the server-rendered analyst UI
(Jinja2 + HTMX, no build step).

Import rule: composition root. MAY import every other package. Nothing in
backend/app/ imports web/.
"""
