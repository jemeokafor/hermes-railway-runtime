# Hermes Railway Runtime

This repository packages **Hermes Agent** for Railway.

It builds Hermes directly from a pinned `NousResearch/hermes-agent` ref, runs a small Node wrapper on Railway's injected `PORT`, starts Ollama and the Hermes gateway inside the container, and exposes `/healthz` for Railway healthchecks.

## Runtime Shape

- `src/hermes-server.js` listens on Railway's `PORT` and supervises the Hermes stack.
- `scripts/start-hermes-stack.sh` starts Ollama, ensures required models are available, configures Hermes, and starts the gateway.
- `scripts/configure-hermes.py` writes Hermes configuration under the persistent volume.
- `/healthz` returns healthy only when the wrapper, Ollama, and Hermes gateway are all alive.

## Railway Requirements

- Build with the Dockerfile in this repo.
- Mount a persistent Railway volume at `/data`.
- Enable public networking; the container listens on Railway's injected `PORT`.
- Keep `healthcheckPath = "/healthz"` and `healthcheckTimeout = 1800` in `railway.toml` because first boot can pull models and hydrate the volume.

## Important Paths

- Hermes home: `/data/.hermes`
- Workspace: `/data/workspace`
- Ollama models: `/data/.ollama/models`
- Runtime logs: `/data/.hermes/logs`

## Useful Runtime Checks

```bash
curl -fsS http://127.0.0.1:${PORT}/healthz
ls -la /data/.hermes/logs
hermes --version
```

## Local Smoke Test

```bash
docker build -t hermes-railway-runtime .

docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -v "$(pwd)/.tmpdata:/data" \
  hermes-railway-runtime

curl -fsS http://127.0.0.1:8080/healthz
```

## Upgrading Hermes

Hermes is pinned in `Dockerfile` with `ARG HERMES_GIT_REF=<commit-or-tag>`. Do not switch this back to tracking `main` directly; explicit refs keep Railway builds reproducible and make rollback straightforward.

To upgrade when NousResearch publishes a newer Hermes version:

1. Pick the new upstream tag or commit from `NousResearch/hermes-agent`.
2. Update `ARG HERMES_GIT_REF` in `Dockerfile`.
3. Run `npm run lint` and `npm test`.
4. Commit and push to `main`.
5. Let Railway deploy, then verify `https://hermes-railway-runtime-production.up.railway.app/healthz`.
6. Roll back by reverting the ref bump commit or redeploying the previous successful Railway deployment.

## Operational Notes

- The current pinned Hermes ref is recorded in the image at `/opt/hermes-agent.commit`.
- The Dockerfile patches Hermes defensively only when the upstream `RedactingFormatter` class/import is absent.
- The patch locates the `from typing import ...` line dynamically so upstream import-list changes do not break Railway builds.
- The Dockerfile also patches Hermes' Codex Responses streaming path to recover when the OpenAI SDK `responses.stream` helper crashes on a terminal SSE frame with `response.output = null`.
- Telegram gateway dependencies are installed at image build time so Railway startup does not depend on Hermes lazy installs.
