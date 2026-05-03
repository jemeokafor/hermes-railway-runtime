#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import uuid

sys.path.insert(0, "/opt/hermes-agent")

from run_agent import AIAgent  # noqa: E402


def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HERMES_SMOKE_MODEL", "gemma4:e4b")
    agent = AIAgent(
        base_url=os.environ.get("HERMES_SMOKE_BASE_URL", "http://127.0.0.1:11434/v1"),
        api_key=os.environ.get("HERMES_SMOKE_API_KEY", "ollama"),
        provider=os.environ.get("HERMES_SMOKE_PROVIDER", "custom"),
        model=model,
        max_iterations=2,
        quiet_mode=True,
        verbose_logging=False,
        session_id=f"smoke-{uuid.uuid4().hex[:8]}",
    )
    result = agent.run_conversation("Reply with OK only. Do not use tools.")
    print(json.dumps(result, indent=2, default=str))
    error = (result or {}).get("error")
    return 1 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
