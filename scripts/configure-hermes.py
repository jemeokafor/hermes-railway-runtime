#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

import yaml

HERMES_HOME = Path(os.environ.get("HERMES_HOME", "/data/.hermes"))
CONFIG_PATH = HERMES_HOME / "config.yaml"
ENV_PATH = HERMES_HOME / ".env"
SKILL_PATH = HERMES_HOME / "skills" / "cortex-kb" / "SKILL.md"
LEGACY_SOURCE_PATH = Path(os.environ.get("HERMES_LEGACY_SOURCE", "/data/.clawdbot"))
LEGACY_CONFIG_PATH = LEGACY_SOURCE_PATH / "openclaw.json"
LEGACY_TELEGRAM_ALLOWLIST_PATH = LEGACY_SOURCE_PATH / "credentials/telegram-default-allowFrom.json"
STAGED_LEGACY_SOURCE_PATH = Path("/data/.hermes-home/.legacy-clawdbot")
GATEWAY_UID = 23102
GATEWAY_GID = 23102
EVIDENCE_GID = 23103
MAX_OWNERSHIP_ENTRIES = 100_000
APPROVED_GATEWAY_TREES = (
    Path("/data/.hermes"),
    Path("/data/.hermes-home"),
    Path("/data/workspace"),
)
GATEWAY_RUNTIME_DIRECTORIES = (
    Path("/data/.hermes/logs"),
    Path("/data/.hermes/cache"),
    Path("/data/.hermes-home/.cache"),
    Path("/data/.hermes-home/.config"),
    Path("/data/.hermes-home/.local"),
    Path("/data/.hermes-home/.local/share"),
    Path("/data/.hermes-home/.local/state"),
    Path("/data/.hermes-home/tmp"),
)
ROOT_PRIVATE_DIRECTORIES = (
    Path("/data/.hermes-supervisor"),
    Path("/data/.hermes-supervisor/logs"),
    Path("/run/hermes-supervisor"),
)

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
DELEGATION_MODEL = os.environ.get("HERMES_DELEGATION_OLLAMA_MODEL", "gemma4:e4b").strip() or "gemma4:e4b"
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
    validate_control_file(path)
    if not path.exists() or not path.read_text().strip():
        return {}
    data = yaml.safe_load(path.read_text())
    return data if isinstance(data, dict) else {}


def save_yaml(path: Path, data: dict) -> None:
    secure_write_text(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=False))


def validate_control_file(path: Path, mode: int = 0o600) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"Unsafe Hermes control file: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"Unsafe Hermes control file: {path}")
        if metadata.st_uid != os.geteuid():
            raise RuntimeError(f"Hermes control file is not owned by its effective user: {path}")
        if stat.S_IMODE(metadata.st_mode) != mode:
            os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _validate_ownership_entry(path: Path, metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError(f"Unsafe ownership tree entry (symlink): {path}")
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise RuntimeError(f"Unsafe ownership tree entry (multiply linked file): {path}")
        return
    if stat.S_ISDIR(metadata.st_mode):
        return
    raise RuntimeError(f"Unsafe ownership tree entry (special file): {path}")


def collect_safe_ownership_tree(
    root: Path,
    *,
    max_entries: int = MAX_OWNERSHIP_ENTRIES,
) -> list[tuple[Path, tuple[int, int, int]]]:
    """Collect one offline tree without following or accepting unsafe entries."""
    if max_entries < 1:
        raise ValueError("max_entries must be positive")

    pending = [Path(root)]
    collected: list[tuple[Path, tuple[int, int, int]]] = []
    while pending:
        path = pending.pop()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"Unable to inspect ownership tree entry: {path}") from exc
        _validate_ownership_entry(path, metadata)
        collected.append(
            (path, (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)))
        )
        if len(collected) > max_entries:
            raise RuntimeError(f"Ownership tree exceeds {max_entries} entries: {root}")
        if stat.S_ISDIR(metadata.st_mode):
            try:
                with os.scandir(path) as entries:
                    children = []
                    for entry in entries:
                        if len(collected) + len(pending) + len(children) >= max_entries:
                            raise RuntimeError(
                                f"Ownership tree exceeds {max_entries} entries: {root}"
                            )
                        children.append(Path(entry.path))
            except OSError as exc:
                raise RuntimeError(f"Unable to enumerate ownership tree: {path}") from exc
            pending.extend(reversed(sorted(children, key=lambda child: child.name)))
    return collected


def change_tree_ownership(
    roots: tuple[Path, ...] | list[Path],
    *,
    uid: int,
    gid: int,
    max_entries: int = MAX_OWNERSHIP_ENTRIES,
) -> None:
    """Validate every tree before changing any ownership, then recheck each inode."""
    collected: list[tuple[Path, tuple[int, int, int]]] = []
    remaining = max_entries
    for root in roots:
        if remaining < 1:
            raise RuntimeError(f"Ownership trees exceed {max_entries} entries")
        tree = collect_safe_ownership_tree(root, max_entries=remaining)
        collected.extend(tree)
        remaining -= len(tree)
        if remaining < 0:
            raise RuntimeError(f"Ownership trees exceed {max_entries} entries")

    for path, identity in reversed(collected):
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if identity[2] == stat.S_IFDIR:
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise RuntimeError(f"Ownership tree changed during preparation: {path}") from exc
        try:
            metadata = os.fstat(descriptor)
            _validate_ownership_entry(path, metadata)
            observed = (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))
            if observed != identity:
                raise RuntimeError(f"Ownership tree changed during preparation: {path}")
            os.fchown(descriptor, uid, gid)
        finally:
            os.close(descriptor)


def stage_legacy_tree(
    source: Path,
    destination: Path,
    *,
    max_entries: int = MAX_OWNERSHIP_ENTRIES,
    max_bytes: int = 2 * 1024 * 1024 * 1024,
) -> None:
    """Copy a validated legacy tree into a gateway-owned staging directory."""
    try:
        source.lstat()
    except FileNotFoundError:
        return
    source_entries = collect_safe_ownership_tree(source, max_entries=max_entries)
    if source_entries[0][1][2] != stat.S_IFDIR:
        raise RuntimeError("Legacy migration source is not a directory")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        destination_entries = collect_safe_ownership_tree(destination, max_entries=max_entries)
        if destination_entries[0][1][2] != stat.S_IFDIR:
            raise RuntimeError("Legacy migration staging path is not a directory")
        return

    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    copied_bytes = 0
    try:
        directories = [
            path
            for path, identity in source_entries
            if identity[2] == stat.S_IFDIR and path != source
        ]
        for path in sorted(directories, key=lambda item: len(item.parts)):
            target = temporary / path.relative_to(source)
            target.mkdir(mode=0o700)

        for path, identity in source_entries:
            if identity[2] != stat.S_IFREG:
                continue
            target = temporary / path.relative_to(source)
            source_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                metadata = os.fstat(source_fd)
                observed = (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))
                if observed != identity or metadata.st_nlink != 1:
                    raise RuntimeError(f"Legacy migration tree changed during staging: {path}")
                target_fd = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        copied_bytes += len(chunk)
                        if copied_bytes > max_bytes:
                            raise RuntimeError("Legacy migration tree exceeds its byte budget")
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_fd, view)
                            if written <= 0:
                                raise RuntimeError("Legacy migration staging write failed")
                            view = view[written:]
                    os.fsync(target_fd)
                finally:
                    os.close(target_fd)
            finally:
                os.close(source_fd)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _ensure_directory(
    path: Path,
    *,
    mode: int,
    required_uid: int | None = None,
    required_gid: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=mode)
        metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError(f"Unsafe runtime directory: {path}")
    if required_uid is not None and metadata.st_uid != required_uid:
        raise RuntimeError(f"Runtime directory has an unsafe owner: {path}")
    if required_gid is not None and metadata.st_gid != required_gid:
        os.chown(path, -1, required_gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def prepare_runtime_layout() -> None:
    """Perform the one bounded root-to-gateway ownership transition at startup."""
    if os.geteuid() != 0:
        raise RuntimeError("Runtime ownership preparation requires root")

    data = Path("/data")
    try:
        data_metadata = data.lstat()
    except OSError as exc:
        raise RuntimeError("Persistent data root is unavailable") from exc
    if not stat.S_ISDIR(data_metadata.st_mode) or stat.S_ISLNK(data_metadata.st_mode):
        raise RuntimeError("Persistent data root is unsafe")
    os.chown(data, 0, 0, follow_symlinks=False)
    os.chmod(data, 0o755, follow_symlinks=False)

    for path in APPROVED_GATEWAY_TREES:
        _ensure_directory(path, mode=0o700)
    for path in GATEWAY_RUNTIME_DIRECTORIES:
        _ensure_directory(path, mode=0o700)
    stage_legacy_tree(Path("/data/.clawdbot"), STAGED_LEGACY_SOURCE_PATH)

    for path in ROOT_PRIVATE_DIRECTORIES:
        _ensure_directory(path, mode=0o700, required_uid=0)
    for root in (Path("/data/.hermes-supervisor"), Path("/run/hermes-supervisor")):
        for path, _identity in collect_safe_ownership_tree(root):
            if path.lstat().st_uid != 0:
                raise RuntimeError(f"Root supervisor tree has an unsafe owner: {path}")

    _ensure_directory(
        Path("/run/hermes-media"),
        mode=0o750,
        required_uid=0,
        required_gid=GATEWAY_GID,
    )
    _ensure_directory(Path("/run/hermes-media/tmp"), mode=0o700, required_uid=0)
    _ensure_directory(Path("/data/.ollama"), mode=0o700, required_uid=0)
    _ensure_directory(Path("/data/.ollama/models"), mode=0o700, required_uid=0)
    _ensure_directory(
        Path("/data/media-evidence"),
        mode=0o710,
        required_uid=0,
        required_gid=EVIDENCE_GID,
    )

    change_tree_ownership(
        list(APPROVED_GATEWAY_TREES),
        uid=GATEWAY_UID,
        gid=GATEWAY_GID,
    )
    for path in (*APPROVED_GATEWAY_TREES, *GATEWAY_RUNTIME_DIRECTORIES):
        os.chmod(path, 0o700, follow_symlinks=False)


def secure_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    validate_control_file(path, mode)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def load_env(path: Path) -> tuple[list[str], dict[str, str]]:
    lines: list[str] = []
    values: dict[str, str] = {}

    validate_control_file(path)
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

    secure_write_text(path, "\n".join(rendered).strip() + "\n")


def load_legacy_config() -> dict:
    validate_control_file(LEGACY_CONFIG_PATH)
    if not LEGACY_CONFIG_PATH.exists():
        return {}
    return json.loads(LEGACY_CONFIG_PATH.read_text())


def extract_telegram_source() -> tuple[str | None, list[str]]:
    config = load_legacy_config()
    token = (
        config.get("channels", {})
        .get("telegram", {})
        .get("botToken")
    )

    allow_from: list[str] = []
    validate_control_file(LEGACY_TELEGRAM_ALLOWLIST_PATH)
    if LEGACY_TELEGRAM_ALLOWLIST_PATH.exists():
        data = json.loads(LEGACY_TELEGRAM_ALLOWLIST_PATH.read_text())
        raw_users = data.get("allowFrom", [])
        if isinstance(raw_users, list):
            allow_from = [str(item) for item in raw_users if str(item).strip()]

    return token, allow_from


def ensure_cortex_skill() -> None:
    secure_write_text(
        SKILL_PATH,
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


def configure() -> None:
    os.umask(0o077)
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
    delegation["model"] = DELEGATION_MODEL

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare-runtime-layout", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if args.prepare_runtime_layout:
        prepare_runtime_layout()
        print("prepared root supervisor and gateway runtime layout")
        return
    configure()


if __name__ == "__main__":
    main()
