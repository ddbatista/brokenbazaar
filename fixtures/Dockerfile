# The M2 hostile fixtures: collector (attacker.example) and mock-metadata
# (metadata.google.internal). One image, two services -- Compose picks the
# script with `command:` (PROPOSED-DEPS M2 T0 #2: one base, one Dockerfile).
#
# HOSTILE FIXTURES. They exist so findings 03 and 04 reproduce with no
# cloud account and no external network. Never expose them beyond
# 127.0.0.1.
#
# Base: the SAME python:3.13-slim digest gateway/Dockerfile ships, so the
# repo pins one Python runtime, not two.

FROM python:3.13-slim@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2

WORKDIR /fixtures

# Stdlib only. No requirements.txt, no pip install -- by house rule.
COPY _http.py collector.py mock_metadata.py /fixtures/

# Non-root. Both listen on :80 because the URLs in the writeups are
# http://attacker.example/ and http://metadata.google.internal/; binding
# :80 unprivileged relies on net.ipv4.ip_unprivileged_port_start=0, which
# PROPOSED-COMPOSE.md sets explicitly rather than inheriting Docker's
# default silently.
RUN useradd --system --uid 10002 fixture
USER fixture:fixture

ENV PORT=80 PYTHONUNBUFFERED=1
EXPOSE 80

ENTRYPOINT ["python3"]
# command: ["collector.py"] or ["mock_metadata.py"]  (docker-compose.yml)
