#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export HOME=/data
export HERMES_HOME=/data/.hermes
export OLLAMA_HOME=/data/.ollama
export OLLAMA_MODELS=/data/.ollama/models
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_CONTEXT_LENGTH=32768
export OLLAMA_KEEP_ALIVE=24h
export PATH="/data/.local/bin:/data/npm/bin:/data/pnpm:/usr/local/bin:/usr/bin:/bin:${PATH}"

OLLAMA_API_KEY_VALUE="${1:-}"

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  ffmpeg \
  git \
  python3 \
  python3-dev \
  python3-venv \
  build-essential \
  libffi-dev \
  ripgrep \
  tini

mkdir -p \
  /data/.cache \
  /data/.local/bin \
  /data/.ollama/models \
  /data/.hermes/logs \
  /data/npm \
  /data/npm-cache \
  /data/pnpm \
  /data/pnpm-store

if [ ! -x /data/.local/bin/uv ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

if [ ! -d /data/.hermes/hermes-agent/.git ]; then
  git clone --branch main https://github.com/NousResearch/hermes-agent.git /data/.hermes/hermes-agent
else
  git -C /data/.hermes/hermes-agent fetch origin main
  git -C /data/.hermes/hermes-agent checkout main
  git -C /data/.hermes/hermes-agent pull --ff-only origin main
fi

cd /data/.hermes/hermes-agent

/data/.local/bin/uv venv venv --python 3.11
export VIRTUAL_ENV=/data/.hermes/hermes-agent/venv
/data/.local/bin/uv pip install -e ".[all]"

ln -sf /data/.hermes/hermes-agent/venv/bin/hermes /data/.local/bin/hermes

if pgrep -f "ollama serve" >/dev/null 2>&1; then
  pkill -f "ollama serve" || true
  sleep 2
fi

nohup ollama serve >/data/.hermes/logs/ollama-bootstrap.log 2>&1 &

for _ in $(seq 1 120); do
  if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS http://127.0.0.1:11434/api/tags >/dev/null

if [ -n "${OLLAMA_API_KEY_VALUE}" ]; then
  OLLAMA_API_KEY="${OLLAMA_API_KEY_VALUE}" ollama pull glm-5.1:cloud
else
  ollama pull glm-5.1:cloud
fi

ollama pull gemma4:e4b

ollama list
/data/.hermes/hermes-agent/venv/bin/hermes --version
