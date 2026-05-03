#!/usr/bin/env bash
set -euo pipefail

export HOME=/data
export HERMES_HOME="${HERMES_HOME:-/data/.hermes}"
export OLLAMA_MODELS="${OLLAMA_MODELS:-/data/.ollama/models}"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-32768}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-24h}"
export HERMES_READY_FILE="${HERMES_READY_FILE:-/tmp/hermes-ready}"
export HERMES_GATEWAY_PID_FILE="${HERMES_GATEWAY_PID_FILE:-/tmp/hermes-gateway.pid}"
export HERMES_OLLAMA_PID_FILE="${HERMES_OLLAMA_PID_FILE:-/tmp/ollama.pid}"
export PATH="/opt/hermes-venv/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH}"

BOOTSTRAP_LOG="${HERMES_HOME}/logs/bootstrap.log"
GATEWAY_LOG="${HERMES_HOME}/logs/gateway.log"
OLLAMA_LOG="${HERMES_HOME}/logs/ollama.log"
MIGRATION_MARKER="${HERMES_HOME}/.migration-complete-v1"

mkdir -p "${HERMES_HOME}/logs" "${OLLAMA_MODELS}" /data/.cache
rm -f "${HERMES_READY_FILE}" "${HERMES_GATEWAY_PID_FILE}" "${HERMES_OLLAMA_PID_FILE}"

log() {
  printf '[bootstrap] %s\n' "$*" | tee -a "${BOOTSTRAP_LOG}"
}

cleanup() {
  rm -f "${HERMES_READY_FILE}"
  if [ -n "${GATEWAY_PID:-}" ] && kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
    kill "${GATEWAY_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${OLLAMA_PID:-}" ] && kill -0 "${OLLAMA_PID}" >/dev/null 2>&1; then
    kill "${OLLAMA_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

dump_gateway_diagnostics() {
  log "gateway diagnostics"
  if [ -f "${GATEWAY_LOG}" ]; then
    tail -n 200 "${GATEWAY_LOG}" || true
  fi
  hermes doctor || true
}

log "starting Ollama"
ollama serve >>"${OLLAMA_LOG}" 2>&1 &
OLLAMA_PID=$!
printf '%s\n' "${OLLAMA_PID}" >"${HERMES_OLLAMA_PID_FILE}"

for _ in $(seq 1 180); do
  if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1

log "ensuring Ollama models are available"
if ! ollama list | grep -q 'glm-5.1:cloud'; then
  ollama pull glm-5.1:cloud >>"${BOOTSTRAP_LOG}" 2>&1
fi

if ! ollama list | grep -q 'gemma4:e4b'; then
  ollama pull gemma4:e4b >>"${BOOTSTRAP_LOG}" 2>&1
fi

if [ ! -f "${MIGRATION_MARKER}" ]; then
  log "running legacy state migration into Hermes"
  hermes claw migrate \
    --source /data/.clawdbot \
    --workspace-target /data/workspace \
    --preset full \
    --yes \
    --overwrite >>"${BOOTSTRAP_LOG}" 2>&1
  touch "${MIGRATION_MARKER}"
fi

log "applying Hermes configuration"
/opt/hermes-venv/bin/python /app/scripts/configure-hermes.py >>"${BOOTSTRAP_LOG}" 2>&1

log "starting Hermes gateway"
/opt/hermes-venv/bin/python -m gateway.run >>"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${HERMES_GATEWAY_PID_FILE}"

sleep 10
if ! kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
  dump_gateway_diagnostics
  exit 1
fi

touch "${HERMES_READY_FILE}"
log "Hermes stack is ready"

wait -n "${OLLAMA_PID}" "${GATEWAY_PID}"
STATUS=$?
log "stack process exited with status ${STATUS}"
dump_gateway_diagnostics
exit "${STATUS}"
