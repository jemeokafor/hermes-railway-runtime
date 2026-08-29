#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
  printf 'Hermes stack supervisor must run as root\n' >&2
  exit 1
fi

readonly GATEWAY_UID=23102
readonly GATEWAY_GID=23102
readonly EVIDENCE_GID=23103
readonly GATEWAY_HOME=/data/.hermes-home
readonly SUPERVISOR_DATA_DIR=/data/.hermes-supervisor
readonly SUPERVISOR_RUN_DIR=/run/hermes-supervisor

require_identity() {
  local user="$1"
  local expected_uid="$2"
  local expected_gid="$3"

  if [ "$(id -u "${user}" 2>/dev/null || true)" != "${expected_uid}" ] \
    || [ "$(id -g "${user}" 2>/dev/null || true)" != "${expected_gid}" ]; then
    printf 'Runtime identity mismatch for %s\n' "${user}" >&2
    exit 1
  fi
}

require_identity hermes-media 23100 23100
require_identity hermes-acquire 23101 23101
require_identity hermes-gateway "${GATEWAY_UID}" "${GATEWAY_GID}"
if [ "$(getent group "${EVIDENCE_GID}" | cut -d: -f1)" != "hermes-evidence" ]; then
  printf 'Runtime identity mismatch for hermes-evidence\n' >&2
  exit 1
fi

export HOME=/root
export HERMES_HOME=/data/.hermes
export HERMES_MANAGED=Railway
export OLLAMA_MODELS=/data/.ollama/models
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-32768}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-24h}"
export HERMES_READY_FILE="${SUPERVISOR_RUN_DIR}/ready"
export HERMES_GATEWAY_PID_FILE="${SUPERVISOR_RUN_DIR}/gateway.pid"
export HERMES_OLLAMA_PID_FILE="${SUPERVISOR_RUN_DIR}/ollama.pid"
export HERMES_BROKER_PID_FILE="${SUPERVISOR_RUN_DIR}/media-evidence-broker.pid"
export MEDIA_EVIDENCE_READINESS_FILE="${SUPERVISOR_RUN_DIR}/media-evidence-readiness.json"
export MEDIA_EVIDENCE_BROKER_SOCKET=/run/hermes-media/broker.sock
export MEDIA_EVIDENCE_CGROUP_ROOT="${MEDIA_EVIDENCE_CGROUP_ROOT:-/sys/fs/cgroup/hermes-media}"
export MEDIA_EVIDENCE_ROOT=/data/media-evidence
export MEDIA_EVIDENCE_INPUT_ROOTS=/data/workspace:/data/.hermes/cache
export MEDIA_EVIDENCE_WHISPER_MODEL_PATH="${MEDIA_EVIDENCE_WHISPER_MODEL_PATH:-/opt/media-models/base.en}"
export PATH="/opt/hermes-venv/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH}"
export HERMES_PRIMARY_OLLAMA_MODEL="${HERMES_BOOTSTRAP_PRIMARY_MODEL:-glm-5.1:cloud}"
export HERMES_PRIMARY_OLLAMA_DIGEST="${HERMES_PRIMARY_OLLAMA_DIGEST:-sha256:7aea7667808a4aed9488836bd4b2800a57287faf6273f436c8b5fbbe65a441c1}"
export HERMES_DELEGATION_OLLAMA_MODEL="${HERMES_DELEGATION_OLLAMA_MODEL:-gemma4:e4b}"
export HERMES_DELEGATION_OLLAMA_DIGEST="${HERMES_DELEGATION_OLLAMA_DIGEST:-sha256:c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb}"

BOOTSTRAP_LOG="${SUPERVISOR_DATA_DIR}/logs/bootstrap.log"
GATEWAY_LOG="${SUPERVISOR_DATA_DIR}/logs/gateway-stdio.log"
OLLAMA_LOG="${SUPERVISOR_DATA_DIR}/logs/ollama.log"
BROKER_LOG="${SUPERVISOR_DATA_DIR}/logs/media-evidence-broker.log"
MIGRATION_MARKER="${SUPERVISOR_DATA_DIR}/migration-complete-v1"
STACK_STATE_FILE="${SUPERVISOR_DATA_DIR}/stack_state.json"
MODEL_PROVENANCE_FILE="${SUPERVISOR_DATA_DIR}/ollama-model-provenance.json"
LEGACY_MIGRATION_SOURCE="${GATEWAY_HOME}/.legacy-clawdbot"
LOG_ROTATE_BYTES="${HERMES_LOG_ROTATE_BYTES:-67108864}"
CLAMAV_REFRESH_INTERVAL="${MEDIA_EVIDENCE_CLAMAV_REFRESH_INTERVAL:-21600}"

/usr/bin/env -i \
  HOME=/root \
  PATH=/opt/hermes-venv/bin:/usr/local/bin:/usr/bin:/bin \
  /opt/hermes-venv/bin/python /app/scripts/configure-hermes.py --prepare-runtime-layout

rm -f \
  "${HERMES_READY_FILE}" \
  "${HERMES_GATEWAY_PID_FILE}" \
  "${HERMES_OLLAMA_PID_FILE}" \
  "${HERMES_BROKER_PID_FILE}" \
  "${MEDIA_EVIDENCE_READINESS_FILE}" \
  "${MEDIA_EVIDENCE_BROKER_SOCKET}"
touch "${BOOTSTRAP_LOG}" "${GATEWAY_LOG}" "${OLLAMA_LOG}" "${BROKER_LOG}"
chmod 0600 "${BOOTSTRAP_LOG}" "${GATEWAY_LOG}" "${OLLAMA_LOG}" "${BROKER_LOG}"

GATEWAY_PRIVILEGE=(
  /usr/bin/setpriv
  "--reuid=${GATEWAY_UID}"
  "--regid=${GATEWAY_GID}"
  --clear-groups
  --no-new-privs
  --bounding-set=-all
  --inh-caps=-all
  --ambient-caps=-all
  --pdeathsig=SIGTERM
)

GATEWAY_ENV=(
  "HOME=${GATEWAY_HOME}"
  "HERMES_DELEGATION_OLLAMA_MODEL=${HERMES_DELEGATION_OLLAMA_MODEL}"
  "HERMES_HOME=${HERMES_HOME}"
  "HERMES_MANAGED=Railway"
  "HERMES_LEGACY_SOURCE=${LEGACY_MIGRATION_SOURCE}"
  "LANG=C.UTF-8"
  "LC_ALL=C.UTF-8"
  "LOGNAME=hermes-gateway"
  "MEDIA_EVIDENCE_BROKER_SOCKET=${MEDIA_EVIDENCE_BROKER_SOCKET}"
  "OLLAMA_HOST=${OLLAMA_HOST}"
  "PATH=/opt/hermes-venv/bin:/usr/local/bin:/usr/bin:/bin"
  "PYTHONUNBUFFERED=1"
  "SHELL=/bin/sh"
  "TMPDIR=${GATEWAY_HOME}/tmp"
  "USER=hermes-gateway"
  "VIRTUAL_ENV=/opt/hermes-venv"
  "XDG_CACHE_HOME=${GATEWAY_HOME}/.cache"
  "XDG_CONFIG_HOME=${GATEWAY_HOME}/.config"
  "XDG_DATA_HOME=${GATEWAY_HOME}/.local/share"
  "XDG_STATE_HOME=${GATEWAY_HOME}/.local/state"
)

GATEWAY_PASSTHROUGH=(
  ANTHROPIC_API_KEY
  ANTHROPIC_TOKEN
  CEREBRAS_API_KEY
  CORTEX_MCP_BEARER_TOKEN
  DEEPSEEK_API_KEY
  DISCORD_ALLOWED_USERS
  DISCORD_BOT_TOKEN
  ELEVENLABS_API_KEY
  GEMINI_API_KEY
  GOOGLE_API_KEY
  GROQ_API_KEY
  HERMES_API_KEY
  HERMES_BASE_URL
  HERMES_BOOTSTRAP_CORTEX_URL
  HERMES_BOOTSTRAP_OLLAMA_NUM_CTX
  HERMES_BOOTSTRAP_PRIMARY_API_KEY_EXPR
  HERMES_BOOTSTRAP_PRIMARY_BASE_URL
  HERMES_BOOTSTRAP_PRIMARY_CONTEXT_LENGTH
  HERMES_BOOTSTRAP_PRIMARY_MODEL
  HERMES_BOOTSTRAP_PRIMARY_PROVIDER
  HERMES_BOOTSTRAP_REASONING_EFFORT
  HERMES_BOOTSTRAP_TELEGRAM_USER
  HERMES_INFERENCE_MODEL
  HERMES_INFERENCE_PROVIDER
  HERMES_MAX_TOKENS
  HERMES_MODEL
  HERMES_REDACT_SECRETS
  HERMES_SKIP_SSL_GUARD
  MISTRAL_API_KEY
  MEDIA_EVIDENCE_BROKER_TIMEOUT_SECONDS
  NVIDIA_API_KEY
  NOUS_API_KEY
  OLLAMA_API_KEY
  OPENAI_API_KEY
  OPENROUTER_API_KEY
  OPENROUTER_BASE_URL
  RAILWAY_DEPLOYMENT_ID
  SLACK_APP_TOKEN
  SLACK_BOT_TOKEN
  TELEGRAM_ALLOWED_USERS
  TELEGRAM_BOT_TOKEN
  TELEGRAM_HOME_CHANNEL
  TELEGRAM_PROXY
  TOGETHER_API_KEY
  XAI_API_KEY
)
for name in "${GATEWAY_PASSTHROUGH[@]}"; do
  if [[ -v "${name}" ]]; then
    GATEWAY_ENV+=("${name}=${!name}")
  fi
done

READINESS_ENV=(
  "HOME=${GATEWAY_HOME}"
  "HERMES_HOME=${HERMES_HOME}"
  "HERMES_MANAGED=Railway"
  "LANG=C.UTF-8"
  "LC_ALL=C.UTF-8"
  "LOGNAME=hermes-gateway"
  "MEDIA_EVIDENCE_BROKER_SOCKET=${MEDIA_EVIDENCE_BROKER_SOCKET}"
  "MEDIA_EVIDENCE_INPUT_ROOTS=${MEDIA_EVIDENCE_INPUT_ROOTS}"
  "PATH=/opt/hermes-venv/bin:/usr/local/bin:/usr/bin:/bin"
  "PYTHONUNBUFFERED=1"
  "TMPDIR=${GATEWAY_HOME}/tmp"
  "USER=hermes-gateway"
  "VIRTUAL_ENV=/opt/hermes-venv"
  "XDG_CACHE_HOME=${GATEWAY_HOME}/.cache"
  "XDG_CONFIG_HOME=${GATEWAY_HOME}/.config"
  "XDG_DATA_HOME=${GATEWAY_HOME}/.local/share"
  "XDG_STATE_HOME=${GATEWAY_HOME}/.local/state"
)
if [[ -v RAILWAY_DEPLOYMENT_ID ]]; then
  READINESS_ENV+=("RAILWAY_DEPLOYMENT_ID=${RAILWAY_DEPLOYMENT_ID}")
fi

BROKER_ENV=(
  "HOME=/nonexistent"
  "HF_HUB_OFFLINE=1"
  "LANG=C.UTF-8"
  "LC_ALL=C.UTF-8"
  "MEDIA_EVIDENCE_BROKER_SOCKET=${MEDIA_EVIDENCE_BROKER_SOCKET}"
  "MEDIA_EVIDENCE_CGROUP_ROOT=${MEDIA_EVIDENCE_CGROUP_ROOT}"
  "MEDIA_EVIDENCE_INPUT_ROOTS=${MEDIA_EVIDENCE_INPUT_ROOTS}"
  "MEDIA_EVIDENCE_ROOT=${MEDIA_EVIDENCE_ROOT}"
  "MEDIA_EVIDENCE_WHISPER_MODEL_PATH=${MEDIA_EVIDENCE_WHISPER_MODEL_PATH}"
  "PATH=/opt/hermes-venv/bin:/usr/local/bin:/usr/bin:/bin"
  "PYTHONUNBUFFERED=1"
  "TMPDIR=/run/hermes-media/tmp"
  "TRANSFORMERS_OFFLINE=1"
)
if [[ -v MEDIA_EVIDENCE_MIN_FREE_BYTES ]]; then
  BROKER_ENV+=("MEDIA_EVIDENCE_MIN_FREE_BYTES=${MEDIA_EVIDENCE_MIN_FREE_BYTES}")
fi

log() {
  printf '[bootstrap] %s\n' "$*" | tee -a "${BOOTSTRAP_LOG}"
}

refresh_clamav() {
  if ! command -v freshclam >/dev/null 2>&1; then
    log "freshclam unavailable; required media scans will fail closed"
    return
  fi
  if timeout 180 freshclam --quiet >>"${BOOTSTRAP_LOG}" 2>&1; then
    log "ClamAV definitions refreshed"
  else
    log "ClamAV refresh failed; required media scans will verify freshness and fail closed"
  fi
}

clamav_refresh_loop() {
  while sleep "${CLAMAV_REFRESH_INTERVAL}"; do
    refresh_clamav
    if ! check_media_evidence_readiness; then
      rm -f "${HERMES_READY_FILE}"
      return 1
    fi
    rotate_logs
  done
}

check_media_evidence_readiness() {
  local status
  local temporary

  temporary=$(mktemp "${SUPERVISOR_RUN_DIR}/.media-evidence-readiness.XXXXXX")
  set +e
  "${GATEWAY_PRIVILEGE[@]}" \
    /usr/bin/env -i "${READINESS_ENV[@]}" \
    /opt/hermes-venv/bin/python -I /app/scripts/media-evidence-readiness.py \
      --socket "${MEDIA_EVIDENCE_BROKER_SOCKET}" \
      --input-roots "${MEDIA_EVIDENCE_INPUT_ROOTS}" \
      >"${temporary}" 2>>"${BOOTSTRAP_LOG}"
  status=$?
  set -e

  if ! READINESS_RECORD="${temporary}" /opt/hermes-venv/bin/python - <<'PY'
import json
import os
import stat
from pathlib import Path

path = Path(os.environ["READINESS_RECORD"])
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_nlink != 1
    or not 2 <= metadata.st_size <= 1024 * 1024
):
    raise SystemExit(1)
record = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(record, dict) or not isinstance(record.get("ok"), bool):
    raise SystemExit(1)
PY
  then
    rm -f "${temporary}"
    return 1
  fi

  chmod 0600 "${temporary}"
  mv -f "${temporary}" "${MEDIA_EVIDENCE_READINESS_FILE}"
  if [ "${status}" -eq 0 ]; then
    return 0
  fi
  case "${MEDIA_EVIDENCE_REQUIRE_READY:-false}" in
    1|true|TRUE|yes|YES|on|ON) return "${status}" ;;
    *) log "media evidence readiness is degraded but not required"; return 0 ;;
  esac
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
  rotate_log "${BROKER_LOG}"
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
  BROKER_PID="${BROKER_PID:-}" \
  GATEWAY_LOG="${GATEWAY_LOG}" \
  OLLAMA_LOG="${OLLAMA_LOG}" \
  BROKER_LOG="${BROKER_LOG}" \
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
            "brokerPid": int_or_none(os.environ.get("BROKER_PID")),
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
            "broker": log_size(os.environ.get("BROKER_LOG", "")),
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
tmp.chmod(0o600)
tmp.replace(state_path)
state_path.chmod(0o600)
PY
}

stop_child() {
  local pid="${1:-}"
  local _

  if [ -z "${pid}" ] || ! kill -0 "${pid}" >/dev/null 2>&1; then
    return
  fi
  kill "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      wait "${pid}" >/dev/null 2>&1 || true
      return
    fi
    sleep 0.25
  done
  kill -KILL "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
}

cleanup() {
  trap - EXIT
  write_stack_state "cleanup" "" "" "" "" "terminate_children"
  rm -f "${HERMES_READY_FILE}" "${MEDIA_EVIDENCE_READINESS_FILE}"

  # Stop readiness production first, then clients before their privileged services.
  stop_child "${CLAMAV_REFRESH_PID:-}"
  stop_child "${GATEWAY_PID:-}"
  stop_child "${BROKER_PID:-}"
  stop_child "${OLLAMA_PID:-}"

  rm -f \
    "${HERMES_GATEWAY_PID_FILE}" \
    "${HERMES_BROKER_PID_FILE}" \
    "${HERMES_OLLAMA_PID_FILE}" \
    "${MEDIA_EVIDENCE_BROKER_SOCKET}"
}

trap cleanup EXIT

refresh_clamav
clamav_refresh_loop &
CLAMAV_REFRESH_PID=$!

dump_gateway_diagnostics() {
  log "gateway diagnostics"
  if [ -f "${GATEWAY_LOG}" ]; then
    tail -n 200 "${GATEWAY_LOG}" || true
  fi
  "${GATEWAY_PRIVILEGE[@]}" \
    /usr/bin/env -i "${GATEWAY_ENV[@]}" \
    /opt/hermes-venv/bin/hermes doctor || true
}

start_ollama() {
  log "starting Ollama"
  /usr/bin/setpriv --pdeathsig=SIGTERM ollama serve >>"${OLLAMA_LOG}" 2>&1 &
  OLLAMA_PID=$!
  printf '%s\n' "${OLLAMA_PID}" >"${HERMES_OLLAMA_PID_FILE}"
  chmod 0600 "${HERMES_OLLAMA_PID_FILE}"
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
  if ! ollama list | grep -Fq "${HERMES_PRIMARY_OLLAMA_MODEL}"; then
    ollama pull "${HERMES_PRIMARY_OLLAMA_MODEL}" >>"${BOOTSTRAP_LOG}" 2>&1
  fi

  if ! ollama list | grep -Fq "${HERMES_DELEGATION_OLLAMA_MODEL}"; then
    ollama pull "${HERMES_DELEGATION_OLLAMA_MODEL}" >>"${BOOTSTRAP_LOG}" 2>&1
  fi

  MODEL_PROVENANCE_FILE="${MODEL_PROVENANCE_FILE}" /opt/hermes-venv/bin/python - <<'PY'
import json
import os
import urllib.request
from pathlib import Path

with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=30) as response:
    payload = json.load(response)
available = {
    record.get("name"): record.get("digest")
    for record in payload.get("models", [])
    if isinstance(record, dict)
}
expected = {
    os.environ["HERMES_PRIMARY_OLLAMA_MODEL"]: os.environ["HERMES_PRIMARY_OLLAMA_DIGEST"],
    os.environ["HERMES_DELEGATION_OLLAMA_MODEL"]: os.environ["HERMES_DELEGATION_OLLAMA_DIGEST"],
}
for name, digest in expected.items():
    if available.get(name) != digest:
        raise SystemExit(f"Ollama model digest mismatch: {name}")
path = Path(os.environ["MODEL_PROVENANCE_FILE"])
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
path.chmod(0o600)
PY
}

start_media_evidence_broker() {
  log "starting privileged media evidence broker"
  /usr/bin/setpriv --pdeathsig=SIGTERM \
    /usr/bin/env -i "${BROKER_ENV[@]}" \
    /opt/hermes-venv/bin/python -I -m media_evidence.broker \
      --socket "${MEDIA_EVIDENCE_BROKER_SOCKET}" \
      >>"${BROKER_LOG}" 2>&1 &
  BROKER_PID=$!
  printf '%s\n' "${BROKER_PID}" >"${HERMES_BROKER_PID_FILE}"
  chmod 0600 "${HERMES_BROKER_PID_FILE}"
  write_stack_state "child_started" "" "" "" "" "start_media_evidence_broker"

  for _ in $(seq 1 60); do
    if [ -S "${MEDIA_EVIDENCE_BROKER_SOCKET}" ] && [ ! -L "${MEDIA_EVIDENCE_BROKER_SOCKET}" ]; then
      return 0
    fi
    if ! kill -0 "${BROKER_PID}" >/dev/null 2>&1; then
      return 1
    fi
    sleep 1
  done
  return 1
}

start_gateway() {
  log "starting Hermes gateway"
  "${GATEWAY_PRIVILEGE[@]}" \
    /usr/bin/env -i "${GATEWAY_ENV[@]}" \
    /opt/hermes-venv/bin/python -m gateway.run \
    >>"${GATEWAY_LOG}" 2>&1 &
  GATEWAY_PID=$!
  printf '%s\n' "${GATEWAY_PID}" >"${HERMES_GATEWAY_PID_FILE}"
  chmod 0600 "${HERMES_GATEWAY_PID_FILE}"
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
    wait -n -p exited_pid \
      "${OLLAMA_PID}" \
      "${BROKER_PID}" \
      "${GATEWAY_PID}" \
      "${CLAMAV_REFRESH_PID}"
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

    if [ "${exited_pid}" = "${BROKER_PID}" ]; then
      rm -f "${HERMES_READY_FILE}" "${MEDIA_EVIDENCE_READINESS_FILE}"
      log "media evidence broker exited status=${status}${signal:+ signal=${signal}}; restarting stack"
      write_stack_state "child_exited" "media_evidence_broker" "${BROKER_PID}" "${status}" "${signal}" "restart_stack"
      exit 1
    fi

    if [ "${exited_pid}" = "${CLAMAV_REFRESH_PID}" ]; then
      log "ClamAV refresh/readiness loop exited status=${status}${signal:+ signal=${signal}}; restarting stack"
      write_stack_state "child_exited" "clamav_refresh" "${CLAMAV_REFRESH_PID}" "${status}" "${signal}" "restart_stack"
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
  if [ -d "${LEGACY_MIGRATION_SOURCE}" ]; then
    log "running validated legacy state migration into Hermes"
    "${GATEWAY_PRIVILEGE[@]}" \
      /usr/bin/env -i "${GATEWAY_ENV[@]}" \
      /opt/hermes-venv/bin/hermes claw migrate \
        --source "${LEGACY_MIGRATION_SOURCE}" \
        --workspace-target /data/workspace \
        --preset full \
        --yes \
        --overwrite >>"${BOOTSTRAP_LOG}" 2>&1
  else
    log "no legacy state tree is present; migration skipped"
  fi
  touch "${MIGRATION_MARKER}"
  chmod 0600 "${MIGRATION_MARKER}"
fi

log "applying Hermes configuration"
"${GATEWAY_PRIVILEGE[@]}" \
  /usr/bin/env -i "${GATEWAY_ENV[@]}" \
  /opt/hermes-venv/bin/python -I /app/scripts/configure-hermes.py \
  >>"${BOOTSTRAP_LOG}" 2>&1

if ! start_media_evidence_broker; then
  log "media evidence broker failed to start"
  write_stack_state "child_start_failed" "media_evidence_broker" "${BROKER_PID:-}" "1" "" "exit_stack"
  exit 1
fi

if ! check_media_evidence_readiness; then
  log "media evidence readiness failed"
  write_stack_state "media_readiness_failed" "" "" "1" "" "exit_stack"
  exit 1
fi

if ! start_gateway; then
  write_stack_state "child_start_failed" "gateway" "${GATEWAY_PID:-}" "1" "" "exit_stack"
  exit 1
fi

touch "${HERMES_READY_FILE}"
chmod 0600 "${HERMES_READY_FILE}"
log "Hermes stack is ready"
write_stack_state "ready" "" "" "" "" "supervise"

supervise_stack
