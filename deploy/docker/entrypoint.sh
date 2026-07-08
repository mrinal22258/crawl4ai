#!/usr/bin/env bash
# entrypoint.sh - resolve the socket-level egress/auth posture before supervisord.
#
# This is the authoritative socket-level guard (gunicorn binds the socket, not
# Python). It must agree with the in-process _resolve_auth() check in server.py.
set -euo pipefail

# --- Redis password: prefer a mounted secret, else an existing env var. ------
if [[ -z "${REDIS_PASSWORD:-}" && -f /run/secrets/redis_password ]]; then
    REDIS_PASSWORD="$(cat /run/secrets/redis_password)"
fi
if [[ -z "${REDIS_PASSWORD:-}" ]]; then
    # Generate an ephemeral in-container password so redis is never open even
    # if the operator forgot to mount one. (Loopback + requirepass.)
    REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    echo "entrypoint: no REDIS_PASSWORD provided; generated an ephemeral one." >&2
fi
export REDIS_PASSWORD

# --- API token: prefer a mounted secret, else an existing env var. -----------
if [[ -z "${CRAWL4AI_API_TOKEN:-}" && -f /run/secrets/api_token ]]; then
    export CRAWL4AI_API_TOKEN="$(cat /run/secrets/api_token)"
fi

# --- Bind resolution: loopback unless a credential is present or insecure bind allowed.
PORT="${CRAWL4AI_PORT:-11235}"
if [[ -n "${CRAWL4AI_API_TOKEN:-}" || "${CRAWL4AI_JWT_ENABLED:-false}" == "true" || "${CRAWL4AI_ALLOW_INSECURE_BIND:-false}" == "1" || "${CRAWL4AI_ALLOW_INSECURE_BIND:-false}" == "true" ]]; then
    # A credential is configured or insecure bind is allowed -> the operator may expose all interfaces.
    # Note: Using 0.0.0.0 instead of [::] to prevent uvicorn.workers.UvicornWorker from mangling into a malformed tcp:// URI
    GUNICORN_BIND="${GUNICORN_BIND:-0.0.0.0:${PORT}}"
else
    # No credential and insecure bind not allowed -> refuse to expose; serve loopback only.
    GUNICORN_BIND="127.0.0.1:${PORT}"
    echo "entrypoint: no CRAWL4AI_API_TOKEN set; binding loopback only (${GUNICORN_BIND})." >&2
fi
export GUNICORN_BIND

exec supervisord -c supervisord.conf
