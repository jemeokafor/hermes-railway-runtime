FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a

ARG HERMES_GIT_REF=2bd1977d8fad185c9b4be47884f7e87f1add0ce3
ARG MEDIA_WORKER_UID=23100
ARG MEDIA_WORKER_GID=23100
ARG MEDIA_ACQUISITION_UID=23101
ARG MEDIA_ACQUISITION_GID=23101
ARG WHISPER_MODEL_REVISION=3d3d5dee26484f91867d81cb899cfcf72b96be6c
ARG WHISPER_MODEL_SHA256=2a166925539a16005f14ff328359f9b9adb9dc4fb631bb3b227526862e93e2ef
ARG RAILWAY_GIT_COMMIT_SHA=unknown
ARG TARGETARCH=amd64
ARG UV_VERSION=0.12.5
ARG UV_AMD64_SHA256=68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2
ARG UV_ARM64_SHA256=9bf43b4d1a07665bf64d4c4e710930b382321a785e0eb10aac07f46471f86a31
ARG OLLAMA_VERSION=v0.32.15
ARG OLLAMA_AMD64_SHA256=50539c5fe9bf85887733355098dcdb266b433cb8c73fa180713417e9ed6e42bb
ARG OLLAMA_ARM64_SHA256=c898270b1690eab0f51aa9e9197686b7b4c6a7d88b83967763818f3127e477e9

ENV NODE_ENV=production
ENV PATH="/root/.local/bin:${PATH}"
ENV MEDIA_EVIDENCE_WHISPER_MODEL_PATH="/opt/media-models/base.en"
ENV SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
ENV REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
ENV CURL_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
ENV GIT_SSL_CAINFO="/etc/ssl/certs/ca-certificates.crt"
ENV NODE_EXTRA_CA_CERTS="/etc/ssl/certs/ca-certificates.crt"
ENV NPM_CONFIG_CAFILE="/etc/ssl/certs/ca-certificates.crt"
ENV UV_NATIVE_TLS=true
ENV UV_HTTP_TIMEOUT=300
ENV UV_HTTP_RETRIES=10

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clamav \
    clamav-freshclam \
    curl \
    espeak-ng \
    ffmpeg \
    file \
    fonts-dejavu-core \
    git \
    libffi-dev \
    libimage-exiftool-perl \
    libseccomp2 \
    poppler-utils \
    python3 \
    python3-dev \
    python3-venv \
    qpdf \
    ripgrep \
    tesseract-ocr \
    tesseract-ocr-eng \
    tini \
    util-linux \
    zstd \
  && rm -rf /var/lib/apt/lists/*

RUN freshclam --stdout \
  && test -n "$(find /var/lib/clamav -maxdepth 1 -type f \( -name 'daily.cvd' -o -name 'daily.cld' \) -size +0c -print -quit)"

RUN groupadd --system --gid "${MEDIA_WORKER_GID}" hermes-media \
  && useradd --system --uid "${MEDIA_WORKER_UID}" --gid hermes-media --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin hermes-media \
  && groupadd --system --gid "${MEDIA_ACQUISITION_GID}" hermes-acquire \
  && useradd --system --uid "${MEDIA_ACQUISITION_UID}" --gid hermes-acquire --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin hermes-acquire \
  && groupadd --system --gid 23102 hermes-gateway \
  && useradd --system --uid 23102 --gid hermes-gateway --no-create-home \
    --home-dir /data/.hermes-home --shell /usr/sbin/nologin hermes-gateway \
  && groupadd --system --gid 23103 hermes-evidence

RUN install -d -o root -g root -m 0755 /data

RUN case "${TARGETARCH}" in \
      amd64) UV_TARGET="x86_64-unknown-linux-gnu"; UV_SHA256="${UV_AMD64_SHA256}" ;; \
      arm64) UV_TARGET="aarch64-unknown-linux-gnu"; UV_SHA256="${UV_ARM64_SHA256}" ;; \
      *) echo "Unsupported uv architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
  && UV_ARCHIVE="uv-${UV_TARGET}.tar.gz" \
  && curl --fail --location --proto '=https' --tlsv1.2 \
    --output "/tmp/${UV_ARCHIVE}" \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${UV_ARCHIVE}" \
  && printf '%s  %s\n' "${UV_SHA256}" "/tmp/${UV_ARCHIVE}" | sha256sum --check --strict - \
  && mkdir /tmp/uv-release \
  && tar -xzf "/tmp/${UV_ARCHIVE}" -C /tmp/uv-release \
  && install -m 0755 "/tmp/uv-release/uv-${UV_TARGET}/uv" /usr/local/bin/uv \
  && install -m 0755 "/tmp/uv-release/uv-${UV_TARGET}/uvx" /usr/local/bin/uvx \
  && rm -rf "/tmp/${UV_ARCHIVE}" /tmp/uv-release \
  && uv --version

WORKDIR /opt
RUN git init hermes-agent \
  && cd hermes-agent \
  && git remote add origin https://github.com/NousResearch/hermes-agent.git \
  && git fetch --depth 1 origin "${HERMES_GIT_REF}" \
  && git checkout --detach FETCH_HEAD \
  && git rev-parse HEAD > /opt/hermes-agent.commit
COPY scripts/patch-hermes-telegram-retry.py /tmp/patch-hermes-telegram-retry.py
RUN python3 /tmp/patch-hermes-telegram-retry.py --root /opt/hermes-agent \
  && rm /tmp/patch-hermes-telegram-retry.py
RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/gateway/run.py')
text = path.read_text()
if (
    'class RedactingFormatter(logging.Formatter):' not in text
    and 'from agent.redact import RedactingFormatter' not in text
):
    marker = next(
        (line for line in text.splitlines(keepends=True) if line.startswith('from typing import ')),
        None,
    )
    if marker is None:
        raise SystemExit('Failed to locate import marker for RedactingFormatter patch')
    patch = marker + '''\n\nclass RedactingFormatter(logging.Formatter):\n    """Fallback redacting formatter for broken upstream builds."""\n\n    _SECRET_PATTERNS = (\n        re.compile(r"sk-[A-Za-z0-9_-]{10,}"),\n        re.compile(r"\\b\\d{5,}:[A-Za-z0-9_-]{20,}\\b"),\n        re.compile(r"Bearer\\s+[A-Za-z0-9._-]{20,}"),\n    )\n\n    def format(self, record):\n        rendered = super().format(record)\n        for pattern in self._SECRET_PATTERNS:\n            rendered = pattern.sub('[REDACTED]', rendered)\n        return rendered\n'''
    path.write_text(text.replace(marker, patch, 1))
PY

RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/run_agent.py')
text = path.read_text()
if (
    'Codex terminal SSE frame can omit response.output' not in text
    and 'from agent.codex_runtime import run_codex_stream' not in text
):
    marker = '''            except (_httpx.RemoteProtocolError, _httpx.ReadTimeout, _httpx.ConnectError, ConnectionError) as exc:\n'''
    if marker not in text:
        raise SystemExit('Failed to locate Codex stream exception marker')
    patch = '''            except TypeError as exc:\n                # Codex terminal SSE frame can omit response.output. The OpenAI\n                # SDK responses.stream helper parses that frame eagerly and raises\n                # TypeError before get_final_response(), even though earlier\n                # stream events contain the completed output item/text.\n                if "NoneType" not in str(exc) or "not iterable" not in str(exc):\n                    raise\n                if collected_output_items:\n                    return SimpleNamespace(\n                        status="completed",\n                        model=self.model,\n                        output=list(collected_output_items),\n                    )\n                if self._codex_streamed_text_parts and not has_tool_calls:\n                    assembled = "".join(self._codex_streamed_text_parts)\n                    return SimpleNamespace(\n                        status="completed",\n                        model=self.model,\n                        output_text=assembled,\n                        output=[SimpleNamespace(\n                            type="message",\n                            role="assistant",\n                            status="completed",\n                            content=[SimpleNamespace(type="output_text", text=assembled)],\n                        )],\n                    )\n                return self._run_codex_create_stream_fallback(api_kwargs, client=active_client)\n\n''' + marker
    path.write_text(text.replace(marker, patch, 1))
PY

RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/gateway/status.py')
text = path.read_text()
if 'Railway planned-stop marker source diagnostics' not in text:
    helper_marker = '_PLANNED_STOP_MARKER_TTL_S = 60\n\n\n'
    helper = '''_PLANNED_STOP_MARKER_TTL_S = 60


def _proc_cmdline_for_planned_stop_diag(pid: int | None) -> str | None:
    # Railway planned-stop marker source diagnostics: preserve who asked the
    # gateway to stop before the marker is consumed and unlinked.
    if pid is None or pid <= 0:
        return None
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if not data:
        return None
    return data.replace(b"\\x00", b" ").decode("utf-8", errors="replace").strip()[:500]


def _append_planned_stop_marker_diag(record: dict[str, Any], *, matched: bool, reason: str) -> None:
    try:
        marker = {
            "target_pid": record.get("target_pid"),
            "target_start_time": record.get("target_start_time"),
            "stopper_pid": record.get("stopper_pid"),
            "stopper_ppid": record.get("stopper_ppid"),
            "written_at": record.get("written_at"),
            "stopper_cmdline": record.get("stopper_cmdline"),
            "stopper_parent_cmdline": record.get("stopper_parent_cmdline"),
        }
        diag = {
            "observed_at": _utc_now_iso(),
            "matched": matched,
            "reason": reason,
            "consumer_pid": os.getpid(),
            "marker": marker,
        }
        logs_dir = get_hermes_home() / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        with (logs_dir / "planned-stop-markers.jsonl").open("a", encoding="utf-8") as fh:
            json.dump(diag, fh, sort_keys=True)
            fh.write("\\n")
    except Exception:
        pass


'''
    if helper_marker not in text:
        raise SystemExit('Failed to locate planned-stop constants marker')
    text = text.replace(helper_marker, helper, 1)

    stale_marker = '''    if _marker_is_stale(written_at, ttl_s):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return False
'''
    stale_patch = '''    if _marker_is_stale(written_at, ttl_s):
        if path.name == _PLANNED_STOP_MARKER_FILENAME:
            _append_planned_stop_marker_diag(record, matched=False, reason="stale")
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return False
'''
    if stale_marker not in text:
        raise SystemExit('Failed to locate planned-stop stale marker block')
    text = text.replace(stale_marker, stale_patch, 1)

    matches_marker = '''    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

    return matches
'''
    matches_patch = '''    if path.name == _PLANNED_STOP_MARKER_FILENAME:
        _append_planned_stop_marker_diag(
            record,
            matched=matches,
            reason="matched" if matches else "mismatch",
        )

    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

    return matches
'''
    if matches_marker not in text:
        raise SystemExit('Failed to locate planned-stop consume unlink block')
    text = text.replace(matches_marker, matches_patch, 1)

    record_marker = '''        record = {
            "target_pid": target_pid,
            "target_start_time": target_start_time,
            "stopper_pid": os.getpid(),
            "written_at": _utc_now_iso(),
        }
'''
    record_patch = '''        _stopper_pid = os.getpid()
        _stopper_ppid = os.getppid()
        record = {
            "target_pid": target_pid,
            "target_start_time": target_start_time,
            "stopper_pid": _stopper_pid,
            "stopper_ppid": _stopper_ppid,
            "stopper_cmdline": _proc_cmdline_for_planned_stop_diag(_stopper_pid),
            "stopper_parent_cmdline": _proc_cmdline_for_planned_stop_diag(_stopper_ppid),
            "written_at": _utc_now_iso(),
        }
'''
    if record_marker not in text:
        raise SystemExit('Failed to locate planned-stop record block')
    text = text.replace(record_marker, record_patch, 1)
    path.write_text(text)
PY

RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/agent/auxiliary_client.py')
text = path.read_text()
if (
    'Codex auxiliary avoids responses.stream parser for null terminal output' not in text
    and 'from agent.codex_runtime import _consume_codex_event_stream' not in text
):
    old = '''            with self._client.responses.stream(**resp_kwargs) as stream:
                for _event in stream:
                    _check_cancelled()
                    _etype = getattr(_event, "type", "")
                    if _etype == "response.output_item.done":
                        _done = getattr(_event, "item", None)
                        if _done is not None:
                            collected_output_items.append(_done)
                    elif "output_text.delta" in _etype:
                        _delta = getattr(_event, "delta", "")
                        if _delta:
                            collected_text_deltas.append(_delta)
                    elif "function_call" in _etype:
                        has_function_calls = True
                _check_cancelled()
                final = stream.get_final_response()
'''
    new = '''            # Codex auxiliary avoids responses.stream parser for null terminal output.
            # The OpenAI SDK helper eagerly parses response.completed and crashes
            # when chatgpt.com/backend-api/codex sends response.output = null.
            # responses.create(stream=True) exposes the same SSE events without
            # that parser state machine, so we can recover from collected events.
            _stream_kwargs = dict(resp_kwargs)
            _stream_kwargs["stream"] = True
            stream = self._client.responses.create(**_stream_kwargs)
            terminal_response = None
            try:
                for _event in stream:
                    _check_cancelled()
                    _etype = getattr(_event, "type", "")
                    if _etype == "response.output_item.done":
                        _done = getattr(_event, "item", None)
                        if _done is not None:
                            collected_output_items.append(_done)
                    elif "output_text.delta" in _etype:
                        _delta = getattr(_event, "delta", "")
                        if _delta:
                            collected_text_deltas.append(_delta)
                    elif "function_call" in _etype:
                        has_function_calls = True
                    elif _etype in {"response.completed", "response.incomplete", "response.failed"}:
                        terminal_response = getattr(_event, "response", None)
                _check_cancelled()
            finally:
                _close = getattr(stream, "close", None)
                if callable(_close):
                    try:
                        _close()
                    except Exception:
                        pass
            final = terminal_response or SimpleNamespace(output=[])
            if getattr(final, "output", None) is None:
                final.output = []
'''
    if old not in text:
        raise SystemExit('Failed to locate Codex auxiliary stream helper block')
    path.write_text(text.replace(old, new, 1))
PY

COPY media_evidence /opt/hermes-agent/media_evidence
COPY plugins/media-evidence /opt/hermes-agent/plugins/media-evidence

RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/pyproject.toml')
text = path.read_text(encoding='utf-8')
marker = '[tool.setuptools.packages.find]\ninclude = ['
replacement = '[tool.setuptools.packages.find]\ninclude = ["media_evidence", "media_evidence.*", '
if marker not in text:
    raise SystemExit('Failed to locate Hermes package discovery configuration')
path.write_text(text.replace(marker, replacement, 1), encoding='utf-8')
PY

WORKDIR /opt/hermes-agent
RUN uv venv /opt/hermes-venv --python 3.11 \
  && UV_NO_CACHE=1 UV_PROJECT_ENVIRONMENT=/opt/hermes-venv uv sync \
    --frozen \
    --no-dev \
    --extra all \
    --extra messaging \
    --extra voice \
    --python /opt/hermes-venv/bin/python \
  && ln -sf /opt/hermes-venv/bin/hermes /usr/local/bin/hermes \
  && /opt/hermes-venv/bin/python -I -c "from media_evidence.broker import main as broker_main; from media_evidence.broker_client import BrokerClient; from media_evidence.contracts import validate_manifest_schema; from media_evidence.worker import main" \
  && /opt/hermes-venv/bin/python -I -c "import faster_whisper, PIL, telegram" \
  && rm -rf /opt/hermes-agent/.git

RUN /opt/hermes-venv/bin/python -I - <<'PY'
from importlib.metadata import version

expected = {
    "faster-whisper": "1.2.1",
    "Pillow": "12.2.0",
    "python-telegram-bot": "22.6",
}
observed = {name: version(name) for name in expected}
if observed != expected:
    raise SystemExit(f"Locked runtime dependency mismatch: {observed!r}")
PY

RUN HF_HOME=/tmp/huggingface \
    WHISPER_MODEL_REVISION="${WHISPER_MODEL_REVISION}" \
    WHISPER_MODEL_SHA256="${WHISPER_MODEL_SHA256}" \
    /opt/hermes-venv/bin/python - <<'PY'
import hashlib
import json
import os
import shutil
from pathlib import Path

from huggingface_hub import snapshot_download

repository = "Systran/faster-whisper-base.en"
revision = os.environ["WHISPER_MODEL_REVISION"]
expected_model_sha256 = os.environ["WHISPER_MODEL_SHA256"]
target = Path(os.environ["MEDIA_EVIDENCE_WHISPER_MODEL_PATH"])
snapshot_download(
    repo_id=repository,
    revision=revision,
    local_dir=target,
    allow_patterns=["config.json", "model.bin", "tokenizer.json", "vocabulary.txt"],
)
model = target / "model.bin"
actual_model_sha256 = hashlib.sha256(model.read_bytes()).hexdigest()
if actual_model_sha256 != expected_model_sha256:
    raise SystemExit("Pinned Whisper model hash mismatch")
(target / "provenance.json").write_text(
    json.dumps(
        {
            "repository": repository,
            "revision": revision,
            "model_sha256": actual_model_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
shutil.rmtree(Path(os.environ["HF_HOME"]), ignore_errors=True)
PY

RUN chown -R root:root /opt/media-models \
  && find /opt/media-models -type d -exec chmod 0555 {} + \
  && find /opt/media-models -type f -exec chmod 0444 {} +

RUN chown -R root:root /opt/hermes-agent/media_evidence /opt/hermes-agent/plugins/media-evidence \
  && chmod -R a-w /opt/hermes-agent/media_evidence /opt/hermes-agent/plugins/media-evidence \
  && find /opt/hermes-agent/media_evidence /opt/hermes-agent/plugins/media-evidence \
    -type d -exec chmod 0555 {} + \
  && find /opt/hermes-agent/media_evidence /opt/hermes-agent/plugins/media-evidence \
    -type f -exec chmod 0444 {} +

RUN case "${TARGETARCH}" in \
      amd64) OLLAMA_ARCH="amd64"; OLLAMA_SHA256="${OLLAMA_AMD64_SHA256}" ;; \
      arm64) OLLAMA_ARCH="arm64"; OLLAMA_SHA256="${OLLAMA_ARM64_SHA256}" ;; \
      *) echo "Unsupported Ollama architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
  && OLLAMA_ARCHIVE="ollama-linux-${OLLAMA_ARCH}.tar.zst" \
  && curl --fail --location --proto '=https' --tlsv1.2 \
    --output "/tmp/${OLLAMA_ARCHIVE}" \
    "https://github.com/ollama/ollama/releases/download/${OLLAMA_VERSION}/${OLLAMA_ARCHIVE}" \
  && printf '%s  %s\n' "${OLLAMA_SHA256}" "/tmp/${OLLAMA_ARCHIVE}" | sha256sum --check --strict - \
  && zstd --decompress --quiet --stdout "/tmp/${OLLAMA_ARCHIVE}" | tar -xf - -C /usr/local \
  && rm "/tmp/${OLLAMA_ARCHIVE}" \
  && test -x /usr/local/bin/ollama \
  && ollama --version

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY scripts/configure-hermes.py \
  scripts/generate_media_sbom.py \
  scripts/hermes_smoke.py \
  scripts/media-evidence-readiness.py \
  scripts/ollama_probe.py \
  scripts/openai_codex_oauth.py \
  scripts/patch-hermes-telegram-retry.py \
  scripts/remote-hermes-bootstrap.sh \
  scripts/smoke.js \
  scripts/start-hermes-stack.sh \
  ./scripts/

RUN /opt/hermes-venv/bin/python -I -c "import runpy; runpy.run_path('/app/scripts/media-evidence-readiness.py', run_name='media_evidence_readiness_smoke')"

RUN case "${TARGETARCH}" in \
      amd64) UV_SHA256="${UV_AMD64_SHA256}"; OLLAMA_SHA256="${OLLAMA_AMD64_SHA256}" ;; \
      arm64) UV_SHA256="${UV_ARM64_SHA256}"; OLLAMA_SHA256="${OLLAMA_ARM64_SHA256}" ;; \
      *) exit 1 ;; \
    esac \
  && /opt/hermes-venv/bin/python /app/scripts/generate_media_sbom.py \
      --output /opt/hermes-runtime.cdx.json \
      --package-lock /app/package-lock.json \
      --application-version "${RAILWAY_GIT_COMMIT_SHA}" \
      --model-provenance /opt/media-models/base.en/provenance.json \
      --tool "uv|${UV_VERSION}|${UV_SHA256}|pkg:github/astral-sh/uv@${UV_VERSION}" \
      --tool "ollama|${OLLAMA_VERSION}|${OLLAMA_SHA256}|pkg:github/ollama/ollama@${OLLAMA_VERSION#v}" \
  && sha256sum /opt/hermes-runtime.cdx.json > /opt/hermes-runtime.cdx.sha256 \
  && printf '%s\n' "${RAILWAY_GIT_COMMIT_SHA}" > /opt/hermes-source.commit \
  && chmod 0444 /opt/hermes-runtime.cdx.json /opt/hermes-runtime.cdx.sha256 /opt/hermes-source.commit

LABEL org.opencontainers.image.revision="${RAILWAY_GIT_COMMIT_SHA}"

RUN chmod +x /app/scripts/start-hermes-stack.sh /app/scripts/media-evidence-readiness.py

EXPOSE 8080

ENTRYPOINT ["tini", "--"]
CMD ["node", "src/hermes-server.js"]
