#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path

import yaml

HERMES_HOME = Path(os.environ.get("HERMES_HOME", "/data/.hermes"))
CONFIG_PATH = HERMES_HOME / "config.yaml"
ENV_PATH = HERMES_HOME / ".env"
SKILL_PATH = HERMES_HOME / "skills" / "cortex-kb" / "SKILL.md"
OPENCLAW_CONFIG_PATH = Path("/data/.clawdbot/openclaw.json")
TELEGRAM_ALLOWLIST_PATH = Path("/data/.clawdbot/credentials/telegram-default-allowFrom.json")

CORTEX_URL = os.environ.get(
    "HERMES_BOOTSTRAP_CORTEX_URL",
    "https://cortex-mcp-production-d4ae.up.railway.app/mcp",
)
PRIMARY_PROVIDER = os.environ.get("HERMES_BOOTSTRAP_PRIMARY_PROVIDER", "custom").strip() or "custom"
PRIMARY_BASE_URL = os.environ.get("HERMES_BOOTSTRAP_PRIMARY_BASE_URL", "http://127.0.0.1:11434/v1").strip() or "http://127.0.0.1:11434/v1"
PRIMARY_MODEL = os.environ.get("HERMES_BOOTSTRAP_PRIMARY_MODEL", "glm-5.1:cloud").strip() or "glm-5.1:cloud"
PRIMARY_API_KEY_EXPR = os.environ.get("HERMES_BOOTSTRAP_PRIMARY_API_KEY_EXPR", "").strip()
PRIMARY_CONTEXT_LENGTH_RAW = os.environ.get("HERMES_BOOTSTRAP_PRIMARY_CONTEXT_LENGTH", "").strip()
PRIMARY_OLLAMA_NUM_CTX_RAW = os.environ.get("HERMES_BOOTSTRAP_OLLAMA_NUM_CTX", "").strip()
PRIMARY_REASONING_EFFORT = os.environ.get("HERMES_BOOTSTRAP_REASONING_EFFORT", "high").strip() or "high"
DEFAULT_TOPICS = [
    ("General", 0x6FB9F0, None),
    ("Research", 0x8EF0A0, None),
    ("Ops", 0xF6B26B, None),
    ("Knowledge Base", 0xD58CFF, "cortex-kb"),
]
CORTEX_TOOLS = [
    "chat_with_cortex",
    "search_exocortex",
    "get_dossier",
    "get_wiki_page",
    "ingest_url",
    "ingest_youtube",
    "ingest_file_base64",
    "add_note",
    "create_node",
    "create_edge",
    "log_decision",
    "request_promotion",
    "run_rac_assessment",
]


def is_local_base_url(url: str) -> bool:
    normalized = (url or "").lower()
    return normalized.startswith("http://127.0.0.1") or normalized.startswith("http://localhost")


def upsert_custom_provider(entries: list[dict], payload: dict) -> None:
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") == payload.get("name"):
            entry.update(payload)
            return
    entries.append(payload)


def load_yaml(path: Path) -> dict:
    if not path.exists() or not path.read_text().strip():
        return {}
    data = yaml.safe_load(path.read_text())
    return data if isinstance(data, dict) else {}


def save_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=False))


def load_env(path: Path) -> tuple[list[str], dict[str, str]]:
    lines: list[str] = []
    values: dict[str, str] = {}

    if path.exists():
      for raw_line in path.read_text().splitlines():
        lines.append(raw_line)
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key] = value

    return lines, values


def save_env(path: Path, lines: list[str], updates: dict[str, str]) -> None:
    existing_keys = set()
    rendered: list[str] = []

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            rendered.append(raw_line)
            continue

        key, _ = raw_line.split("=", 1)
        if key in updates:
            rendered.append(f"{key}={updates[key]}")
            existing_keys.add(key)
        else:
            rendered.append(raw_line)

    for key, value in updates.items():
        if key not in existing_keys:
            rendered.append(f"{key}={value}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rendered).strip() + "\n")


def load_openclaw_config() -> dict:
    if not OPENCLAW_CONFIG_PATH.exists():
        return {}
    return json.loads(OPENCLAW_CONFIG_PATH.read_text())


def extract_telegram_source() -> tuple[str | None, list[str]]:
    config = load_openclaw_config()
    token = (
        config.get("channels", {})
        .get("telegram", {})
        .get("botToken")
    )

    allow_from: list[str] = []
    if TELEGRAM_ALLOWLIST_PATH.exists():
        data = json.loads(TELEGRAM_ALLOWLIST_PATH.read_text())
        raw_users = data.get("allowFrom", [])
        if isinstance(raw_users, list):
            allow_from = [str(item) for item in raw_users if str(item).strip()]

    return token, allow_from


def ensure_cortex_skill() -> None:
    SKILL_PATH.parent.mkdir(parents=True, exist_ok=True)
    SKILL_PATH.write_text(
        """---
name: cortex-kb
description: Use Cortex as the primary knowledge graph, wiki, and governance loop.
---

# Cortex Knowledge Base

Use Cortex whenever persistent knowledge would help.

Default Cortex chat settings:
- chat mode: `cortex_plus_model`
- model: `deepseek-ai/deepseek-r1`
- use `web_cortex_model` only when web-assisted grounding is needed

Operational rules:
- Search before guessing: use `search_exocortex`, `get_dossier`, and `get_wiki_page` to inspect existing knowledge.
- Ingest durable inputs: use `ingest_url`, `ingest_youtube`, or `ingest_file_base64` when the user shares material worth preserving.
- Persist distilled insights: use `add_note` for concise learnings and `log_decision` for durable reasoning or commitments.
- Extend the graph deliberately: use `create_node` and `create_edge` when new entities or relationships need to exist.
- Escalate or governance-route work with `request_promotion` and `run_rac_assessment` when relevant.

When working in the Knowledge Base topic, prefer Cortex-first workflows and push back any information that is likely to matter later.
"""
    )


def merge_dm_topics(existing_topics: list[dict]) -> list[dict]:
    existing_by_name = {
        str(topic.get("name")): topic
        for topic in existing_topics
        if isinstance(topic, dict) and topic.get("name")
    }

    merged: list[dict] = []
    for name, icon_color, skill in DEFAULT_TOPICS:
        topic = dict(existing_by_name.get(name, {}))
        topic["name"] = name
        topic.setdefault("icon_color", icon_color)
        if skill:
            topic["skill"] = skill
        elif "skill" in topic and not topic["skill"]:
            topic.pop("skill", None)
        merged.append(topic)

    return merged


def ensure_dm_topics(config: dict, user_id: str | None) -> None:
    if not user_id:
        return

    platforms = config.setdefault("platforms", {})
    telegram = platforms.setdefault("telegram", {})
    extra = telegram.setdefault("extra", {})
    dm_topics = extra.setdefault("dm_topics", [])

    target_entry = None
    for entry in dm_topics:
        if str(entry.get("chat_id")) == str(user_id):
            target_entry = entry
            break

    if target_entry is None:
        target_entry = {"chat_id": int(user_id), "topics": []}
        dm_topics.append(target_entry)

    target_entry["chat_id"] = int(user_id)
    target_entry["topics"] = merge_dm_topics(target_entry.get("topics", []))


def main() -> None:
    config = load_yaml(CONFIG_PATH)
    env_lines, env_values = load_env(ENV_PATH)
    telegram_token, allowed_users = extract_telegram_source()
    topic_user_id = None
    if allowed_users:
        topic_user_id = allowed_users[0]
    else:
        migrated_users = str(env_values.get("TELEGRAM_ALLOWED_USERS", "")).split(",")
        topic_user_id = next((item.strip() for item in migrated_users if item.strip()), "")
        topic_user_id = topic_user_id or os.environ.get("HERMES_BOOTSTRAP_TELEGRAM_USER", "").strip()

    updates: dict[str, str] = {}
    if telegram_token and not env_values.get("TELEGRAM_BOT_TOKEN"):
        updates["TELEGRAM_BOT_TOKEN"] = telegram_token
    if allowed_users:
        updates["TELEGRAM_ALLOWED_USERS"] = ",".join(allowed_users)
    if topic_user_id:
        updates.setdefault("TELEGRAM_HOME_CHANNEL", topic_user_id)

    if updates:
        save_env(ENV_PATH, env_lines, updates)

    model = config.setdefault("model", {})
    model["provider"] = PRIMARY_PROVIDER
    model["base_url"] = PRIMARY_BASE_URL
    model["default"] = PRIMARY_MODEL
    if PRIMARY_API_KEY_EXPR:
        model["api_key"] = PRIMARY_API_KEY_EXPR
    else:
        model.pop("api_key", None)
    if PRIMARY_CONTEXT_LENGTH_RAW:
        model["context_length"] = int(PRIMARY_CONTEXT_LENGTH_RAW)
    else:
        model.pop("context_length", None)
    if PRIMARY_OLLAMA_NUM_CTX_RAW and is_local_base_url(PRIMARY_BASE_URL):
        model["ollama_num_ctx"] = int(PRIMARY_OLLAMA_NUM_CTX_RAW)
    else:
        model.pop("ollama_num_ctx", None)

    agent = config.setdefault("agent", {})
    agent["reasoning_effort"] = PRIMARY_REASONING_EFFORT

    delegation = config.setdefault("delegation", {})
    delegation["base_url"] = "http://127.0.0.1:11434/v1"
    delegation["model"] = "gemma4:e4b"

    terminal = config.setdefault("terminal", {})
    terminal["backend"] = "local"
    terminal["cwd"] = "/data/workspace"
    terminal.setdefault("timeout", 180)

    mcp_servers = config.setdefault("mcp_servers", {})
    mcp_servers["cortex"] = {
        "url": CORTEX_URL,
        "headers": {
            "Authorization": "Bearer ${CORTEX_MCP_BEARER_TOKEN}",
        },
        "enabled": True,
        "timeout": 120,
        "connect_timeout": 60,
        "tools": {
            "include": CORTEX_TOOLS,
            "resources": True,
            "prompts": True,
        },
    }

    custom_providers = config.setdefault("custom_providers", [])
    if isinstance(custom_providers, list):
        upsert_custom_provider(
            custom_providers,
            {
                "name": "nvidia",
                "base_url": "https://integrate.api.nvidia.com/v1",
                "api_key": "${NVIDIA_API_KEY}",
                "api_mode": "chat_completions",
            },
        )

    ensure_dm_topics(config, topic_user_id)
    ensure_cortex_skill()
    save_yaml(CONFIG_PATH, config)

    print(f"configured {CONFIG_PATH}")


if __name__ == "__main__":
    main()
