FROM node:22-bookworm

ARG HERMES_GIT_REF=2bd1977d8fad185c9b4be47884f7e87f1add0ce3

ENV NODE_ENV=production
ENV PATH="/root/.local/bin:${PATH}"

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    ffmpeg \
    git \
    libffi-dev \
    python3 \
    python3-dev \
    python3-venv \
    ripgrep \
    tini \
    zstd \
  && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

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
if 'Codex terminal SSE frame can omit response.output' not in text:
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
if 'Codex auxiliary avoids responses.stream parser for null terminal output' not in text:
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

WORKDIR /opt/hermes-agent
RUN uv venv /opt/hermes-venv --python 3.11 \
  && VIRTUAL_ENV=/opt/hermes-venv uv pip install -e ".[all]" "python-telegram-bot[webhooks]==22.6" \
  && ln -sf /opt/hermes-venv/bin/hermes /usr/local/bin/hermes

RUN curl -fsSL https://ollama.com/install.sh | sh

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY src ./src
COPY scripts ./scripts

RUN chmod +x /app/scripts/start-hermes-stack.sh

EXPOSE 8080

ENTRYPOINT ["tini", "--"]
CMD ["node", "src/hermes-server.js"]
