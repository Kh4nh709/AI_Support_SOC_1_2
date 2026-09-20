# Backend image for both the `app` and the `worker` compose services.
#
# The build context is the repository ROOT and the repository layout is
# mirrored under /srv: the code lives at /srv/backend/app and runs with
# PYTHONPATH=/srv/backend from WORKDIR /srv — exactly how `make run-app` and
# `make run-worker` ran it natively — so every relative path in the code and in
# .env (conf/, kb/, INDEXER_CA=conf/root-ca.pem, INVENTORY_PATHS) resolves the
# same way in and out of a container. docker-compose.yml bind-mounts conf/, kb/
# and backend/app over the copies below, so a merge needs a restart, not a build.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/srv/backend

WORKDIR /srv

COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt

COPY backend/app /srv/backend/app
COPY kb /srv/kb

# The process never writes into the image; run it unprivileged.
RUN useradd --system --create-home --uid 10001 soc && chown -R soc:soc /srv
USER soc

# No CMD on purpose — docker-compose.yml supplies the command per service.
