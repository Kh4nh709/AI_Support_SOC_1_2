# Backend image for both the `app` and the `worker` compose services.
# The build context is the repository ROOT (see docker-compose.yml) so that
# conf/ and docs/Schema/ can be added or mounted later without moving it.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY backend/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY backend/app /srv/app

# The process never writes into the image; run it unprivileged.
RUN useradd --system --create-home --uid 10001 soc && chown -R soc:soc /srv
USER soc

# No CMD on purpose — docker-compose.yml supplies the command per service.
