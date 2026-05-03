# Hermes Railway Runtime

This repository packages **Hermes Agent** for Railway.

It builds Hermes directly from `NousResearch/hermes-agent`, runs a small Node wrapper on Railway's injected `PORT`, starts Ollama and the Hermes gateway inside the container, and exposes `/healthz` for Railway healthchecks.

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

## Operational Notes

- The Dockerfile patches Hermes defensively only when the upstream `RedactingFormatter` class is absent.
- The patch locates the `from typing import ...` line dynamically so upstream import-list changes do not break Railway builds.
- The Railway service was verified healthy after deployment `af95e1f5-2ed8-4bba-8fdc-ed5926975e0a`.
