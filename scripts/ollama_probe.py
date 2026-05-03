#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def request_json(url: str, payload: dict) -> tuple[int, str]:
    headers = {"Content-Type": "application/json"}
    bearer_token = payload.pop("__bearer_token", "")
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def build_tool_payload() -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": "noop",
                "description": "Return no-op status.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "description": "Arbitrary status string.",
                        }
                    },
                    "required": ["status"],
                },
            },
        }
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe local Ollama model endpoints")
    parser.add_argument("--model", required=True)
    parser.add_argument("--endpoint", choices=["api-chat", "v1-chat", "both"], default="both")
    parser.add_argument("--num-ctx", type=int, default=None)
    parser.add_argument("--include-tools", action="store_true")
    parser.add_argument("--reasoning-effort", default="")
    parser.add_argument("--bearer-env", default="")
    parser.add_argument("--prompt", default="Reply with OK only.")
    args = parser.parse_args()
    bearer_token = ""
    if args.bearer_env:
        import os
        bearer_token = os.environ.get(args.bearer_env, "")

    tests: list[tuple[str, str, dict]] = []

    if args.endpoint in {"api-chat", "both"}:
        native_payload = {
            "model": args.model,
            "messages": [{"role": "user", "content": args.prompt}],
            "stream": False,
        }
        if args.num_ctx is not None:
            native_payload["options"] = {"num_ctx": args.num_ctx}
        if args.include_tools:
            native_payload["tools"] = build_tool_payload()
        if bearer_token:
            native_payload["__bearer_token"] = bearer_token
        tests.append(("api-chat", "http://127.0.0.1:11434/api/chat", native_payload))

    if args.endpoint in {"v1-chat", "both"}:
        compat_payload = {
            "model": args.model,
            "messages": [{"role": "user", "content": args.prompt}],
            "stream": False,
        }
        if args.num_ctx is not None:
            compat_payload["options"] = {"num_ctx": args.num_ctx}
        if args.reasoning_effort:
            compat_payload["reasoning_effort"] = args.reasoning_effort
        if args.include_tools:
            compat_payload["tools"] = build_tool_payload()
        if bearer_token:
            compat_payload["__bearer_token"] = bearer_token
        tests.append(("v1-chat", "http://127.0.0.1:11434/v1/chat/completions", compat_payload))

    failed = False
    for label, url, payload in tests:
        status, body = request_json(url, payload)
        print(f"== {label} status={status} ==")
        print(body)
        if status >= 400:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
