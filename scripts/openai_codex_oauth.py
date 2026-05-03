#!/usr/bin/env python3
from __future__ import annotations

import sys

sys.path.insert(0, "/opt/hermes-agent")

from hermes_cli import auth  # noqa: E402


def main() -> int:
    provider = auth.PROVIDER_REGISTRY["openai-codex"]
    auth._login_openai_codex(None, provider)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
