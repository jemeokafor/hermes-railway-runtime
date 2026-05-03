FROM node:22-bookworm

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
RUN git clone --depth 1 --branch main https://github.com/NousResearch/hermes-agent.git hermes-agent
RUN python3 - <<'PY'
from pathlib import Path

path = Path('/opt/hermes-agent/gateway/run.py')
text = path.read_text()
if 'class RedactingFormatter(logging.Formatter):' not in text:
    marker = next(
        (line for line in text.splitlines(keepends=True) if line.startswith('from typing import ')),
        None,
    )
    if marker is None:
        raise SystemExit('Failed to locate import marker for RedactingFormatter patch')
    patch = marker + '''\n\nclass RedactingFormatter(logging.Formatter):\n    """Fallback redacting formatter for broken upstream builds."""\n\n    _SECRET_PATTERNS = (\n        re.compile(r"sk-[A-Za-z0-9_-]{10,}"),\n        re.compile(r"\\b\\d{5,}:[A-Za-z0-9_-]{20,}\\b"),\n        re.compile(r"Bearer\\s+[A-Za-z0-9._-]{20,}"),\n    )\n\n    def format(self, record):\n        rendered = super().format(record)\n        for pattern in self._SECRET_PATTERNS:\n            rendered = pattern.sub('[REDACTED]', rendered)\n        return rendered\n'''
    path.write_text(text.replace(marker, patch, 1))
PY

WORKDIR /opt/hermes-agent
RUN uv venv /opt/hermes-venv --python 3.11 \
  && VIRTUAL_ENV=/opt/hermes-venv uv pip install -e ".[all]" \
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
