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
STACK_STATE_FILE="${HERMES_HOME}/stack_state.json"
LOG_ROTATE_BYTES="${HERMES_LOG_ROTATE_BYTES:-67108864}"

mkdir -p "${HERMES_HOME}/logs" "${OLLAMA_MODELS}" /data/.cache
rm -f "${HERMES_READY_FILE}" "${HERMES_GATEWAY_PID_FILE}" "${HERMES_OLLAMA_PID_FILE}"

log() {
  printf '[bootstrap] %s\n' "$*" | tee -a "${BOOTSTRAP_LOG}"
}

rotate_log() {
  local file="$1"
  local size

  if [ ! -f "${file}" ]; then
    return
  fi

  size=$(stat -c '%s' "${file}" 2>/dev/null || printf '0')
  if [ "${size}" -le "${LOG_ROTATE_BYTES}" ]; then
    return
  fi

  rm -f "${file}.2"
  if [ -f "${file}.1" ]; then
    mv "${file}.1" "${file}.2"
  fi
  mv "${file}" "${file}.1"
  : >"${file}"
  log "rotated log ${file} size=${size}"
}

rotate_logs() {
  rotate_log "${BOOTSTRAP_LOG}"
  rotate_log "${GATEWAY_LOG}"
  rotate_log "${OLLAMA_LOG}"
  rotate_log "${HERMES_HOME}/logs/agent.log"
  rotate_log "${HERMES_HOME}/logs/errors.log"
}

signal_from_status() {
  local status="$1"
  local sig

  if [ "${status}" -lt 128 ]; then
    return
  fi

  sig=$((status - 128))
  case "${sig}" in
    1) printf 'SIGHUP' ;;
    2) printf 'SIGINT' ;;
    9) printf 'SIGKILL' ;;
    15) printf 'SIGTERM' ;;
    *) printf 'signal-%s' "${sig}" ;;
  esac
}

write_stack_state() {
  local event="$1"
  local child="${2:-}"
  local pid="${3:-}"
  local status="${4:-}"
  local signal="${5:-}"
  local action="${6:-}"

  STACK_STATE_FILE="${STACK_STATE_FILE}" \
  STACK_EVENT="${event}" \
  STACK_CHILD="${child}" \
  STACK_CHILD_PID="${pid}" \
  STACK_CHILD_STATUS="${status}" \
  STACK_CHILD_SIGNAL="${signal}" \
  STACK_ACTION="${action}" \
  GATEWAY_PID="${GATEWAY_PID:-}" \
  OLLAMA_PID="${OLLAMA_PID:-}" \
  GATEWAY_LOG="${GATEWAY_LOG}" \
  OLLAMA_LOG="${OLLAMA_LOG}" \
  BOOTSTRAP_LOG="${BOOTSTRAP_LOG}" \
  /opt/hermes-venv/bin/python - <<'PY' || true
import json
import os
import shutil
import time
from pathlib import Path


def int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_int(path):
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
        if raw == "max":
            return None
        return int(raw)
    except (OSError, ValueError):
        return None


def read_memory_events():
    events = {}
    try:
        for line in Path("/sys/fs/cgroup/memory.events").read_text(encoding="utf-8").splitlines():
            key, value = line.split(maxsplit=1)
            events[key] = int(value)
    except (OSError, ValueError):
        pass
    return events


def log_size(path):
    try:
        return Path(path).stat().st_size
    except OSError:
        return None


state_path = Path(os.environ["STACK_STATE_FILE"])
try:
    state = json.loads(state_path.read_text(encoding="utf-8"))
except Exception:
    state = {}

memory_current = read_int("/sys/fs/cgroup/memory.current")
memory_max = read_int("/sys/fs/cgroup/memory.max")
pids_current = read_int("/sys/fs/cgroup/pids.current")
pids_max = read_int("/sys/fs/cgroup/pids.max")
disk = shutil.disk_usage("/data")
load1, load5, load15 = os.getloadavg()

state.update(
    {
        "event": os.environ.get("STACK_EVENT") or None,
        "action": os.environ.get("STACK_ACTION") or None,
        "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "children": {
            "gatewayPid": int_or_none(os.environ.get("GATEWAY_PID")),
            "ollamaPid": int_or_none(os.environ.get("OLLAMA_PID")),
        },
        "resources": {
            "memoryCurrentMb": round(memory_current / 1048576, 1) if memory_current is not None else None,
            "memoryMaxMb": round(memory_max / 1048576, 1) if memory_max is not None else None,
            "pidsCurrent": pids_current,
            "pidsMax": pids_max,
            "load1": round(load1, 2),
            "load5": round(load5, 2),
            "load15": round(load15, 2),
            "dataUsedPct": round(((disk.total - disk.free) / disk.total) * 100, 2) if disk.total else None,
            "memoryEvents": read_memory_events(),
        },
        "logBytes": {
            "bootstrap": log_size(os.environ.get("BOOTSTRAP_LOG", "")),
            "gateway": log_size(os.environ.get("GATEWAY_LOG", "")),
            "ollama": log_size(os.environ.get("OLLAMA_LOG", "")),
        },
    }
)

child = os.environ.get("STACK_CHILD")
if child:
    state["lastChildExit"] = {
        "child": child,
        "pid": int_or_none(os.environ.get("STACK_CHILD_PID")),
        "status": int_or_none(os.environ.get("STACK_CHILD_STATUS")),
        "signal": os.environ.get("STACK_CHILD_SIGNAL") or None,
        "at": state["updatedAt"],
    }

state_path.parent.mkdir(parents=True, exist_ok=True)
tmp = state_path.with_suffix(state_path.suffix + ".tmp")
tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
tmp.replace(state_path)
PY
}

cleanup() {
  write_stack_state "cleanup" "" "" "" "" "terminate_children"
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

start_ollama() {
  log "starting Ollama"
  ollama serve >>"${OLLAMA_LOG}" 2>&1 &
  OLLAMA_PID=$!
  printf '%s\n' "${OLLAMA_PID}" >"${HERMES_OLLAMA_PID_FILE}"
  write_stack_state "child_started" "" "" "" "" "start_ollama"

  for _ in $(seq 1 180); do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${OLLAMA_PID}" >/dev/null 2>&1; then
      return 1
    fi
    sleep 1
  done

  return 1
}

ensure_ollama_models() {
  log "ensuring Ollama models are available"
  if ! ollama list | grep -q 'glm-5.1:cloud'; then
    ollama pull glm-5.1:cloud >>"${BOOTSTRAP_LOG}" 2>&1
  fi

  if ! ollama list | grep -q 'gemma4:e4b'; then
    ollama pull gemma4:e4b >>"${BOOTSTRAP_LOG}" 2>&1
  fi
}

start_gateway() {
  log "starting Hermes gateway"
  /opt/hermes-venv/bin/python -m gateway.run >>"${GATEWAY_LOG}" 2>&1 &
  GATEWAY_PID=$!
  printf '%s\n' "${GATEWAY_PID}" >"${HERMES_GATEWAY_PID_FILE}"
  write_stack_state "child_started" "" "" "" "" "start_gateway"

  sleep 10
  if ! kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
    dump_gateway_diagnostics
    return 1
  fi
}

supervise_stack() {
  local exited_pid
  local status
  local signal

  while true; do
    exited_pid=""
    set +e
    wait -n -p exited_pid "${OLLAMA_PID}" "${GATEWAY_PID}"
    status=$?
    set -e
    signal="$(signal_from_status "${status}" || true)"

    if [ "${exited_pid}" = "${OLLAMA_PID}" ]; then
      log "Ollama exited status=${status}${signal:+ signal=${signal}}; restarting Ollama without stopping gateway"
      write_stack_state "child_exited" "ollama" "${OLLAMA_PID}" "${status}" "${signal}" "restart_ollama"
      if ! start_ollama; then
        log "Ollama restart failed"
        write_stack_state "child_restart_failed" "ollama" "${OLLAMA_PID}" "1" "" "exit_stack"
        exit 1
      fi
      continue
    fi

    if [ "${exited_pid}" = "${GATEWAY_PID}" ]; then
      log "gateway exited status=${status}${signal:+ signal=${signal}}; restarting stack"
      write_stack_state "child_exited" "gateway" "${GATEWAY_PID}" "${status}" "${signal}" "restart_stack"
      dump_gateway_diagnostics
      exit "${status}"
    fi

    log "unknown child wait result pid=${exited_pid:-none} status=${status}${signal:+ signal=${signal}}; restarting stack"
    write_stack_state "child_exited" "unknown" "${exited_pid:-}" "${status}" "${signal}" "restart_stack"
    dump_gateway_diagnostics
    exit "${status}"
  done
}

rotate_logs
write_stack_state "starting" "" "" "" "" "bootstrap"

if ! start_ollama; then
  log "Ollama failed to start"
  write_stack_state "child_start_failed" "ollama" "${OLLAMA_PID:-}" "1" "" "exit_stack"
  exit 1
fi

ensure_ollama_models

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

if ! start_gateway; then
  write_stack_state "child_start_failed" "gateway" "${GATEWAY_PID:-}" "1" "" "exit_stack"
  exit 1
fi

touch "${HERMES_READY_FILE}"
log "Hermes stack is ready"
write_stack_state "ready" "" "" "" "" "supervise"

supervise_stack
