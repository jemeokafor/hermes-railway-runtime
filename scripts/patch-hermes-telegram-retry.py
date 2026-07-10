#!/usr/bin/env python3
"""Apply the Telegram RetryAfter delivery fix to a pinned Hermes source tree.

The patch is intentionally idempotent and fails closed when upstream source no
longer matches the expected v0.17.0 shape. That forces a reviewed refresh
instead of silently building an unpatched runtime.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(path: Path, *, sentinel: str, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if sentinel in text:
        return False
    if text.count(old) != 1:
        raise SystemExit(
            f"Failed to apply Telegram RetryAfter patch to {path}: "
            f"expected one source marker, found {text.count(old)}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def patch_hermes(root: Path) -> list[Path]:
    base_path = root / "gateway/platforms/base.py"
    telegram_path = root / "gateway/platforms/telegram.py"
    changed: list[Path] = []

    if replace_once(
        base_path,
        sentinel="retry_after_seconds: Optional[float] = None",
        old="""    retryable: bool = False  # True for transient connection errors — base will retry automatically
    # When the adapter had to split an oversized payload across multiple
""",
        new="""    retryable: bool = False  # True for transient connection errors — base will retry automatically
    # Minimum delay mandated by the remote platform before another attempt.
    # This must override shorter local backoff (for example Telegram RetryAfter).
    retry_after_seconds: Optional[float] = None
    # When the adapter had to split an oversized payload across multiple
""",
    ):
        changed.append(base_path)

    if replace_once(
        base_path,
        sentinel="server_delay = max(0.0, result.retry_after_seconds or 0.0)",
        old="""            # Retry with exponential backoff for transient errors
            for attempt in range(1, max_retries + 1):
                delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
""",
        new="""            # Retry with exponential backoff for transient errors. A remote
            # Retry-After value is a mandatory floor, not a hint: retrying
            # before it expires only burns attempts inside the same embargo.
            for attempt in range(1, max_retries + 1):
                backoff_delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                server_delay = max(0.0, result.retry_after_seconds or 0.0)
                delay = max(backoff_delay, server_delay)
""",
    ):
        if base_path not in changed:
            changed.append(base_path)

    if replace_once(
        telegram_path,
        sentinel="retry_after_seconds=retry_after_seconds",
        old="""            logger.warning(
                "[%s] sendRichMessage transient failure (no legacy resend): %s",
                self.name, exc,
            )
            return SendResult(
                success=False,
                error=str(exc),
                retryable=(is_connect_timeout or not is_timeout),
            )
""",
        new="""            logger.warning(
                "[%s] sendRichMessage transient failure (no legacy resend): %s",
                self.name, exc,
            )
            retry_after = getattr(exc, "retry_after", None)
            try:
                retry_after_seconds = float(
                    retry_after.total_seconds()
                    if hasattr(retry_after, "total_seconds")
                    else retry_after
                ) if retry_after is not None else None
            except (TypeError, ValueError, OverflowError):
                retry_after_seconds = None
            return SendResult(
                success=False,
                error=str(exc),
                retryable=(is_connect_timeout or not is_timeout),
                retry_after_seconds=retry_after_seconds,
            )
""",
    ):
        changed.append(telegram_path)

    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/opt/hermes-agent"))
    args = parser.parse_args()

    changed = patch_hermes(args.root)
    if changed:
        for path in changed:
            print(f"patched {path}")
    else:
        print("Telegram RetryAfter patch already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
