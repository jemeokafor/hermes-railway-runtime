FROM node:22-bookworm

ARG HERMES_GIT_REF=a91a57fa5a13d516c38b07a141a9ce8a3daabeb0

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
