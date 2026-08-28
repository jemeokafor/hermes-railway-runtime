from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .sandbox import disable_process_inspection, restrict_filesystem


_READ_ONLY_PATHS = (
    Path("/usr"),
    Path("/lib"),
    Path("/lib64"),
    Path("/opt/hermes-venv"),
    Path("/etc/hosts"),
    Path("/etc/host.conf"),
    Path("/etc/gai.conf"),
    Path("/etc/nsswitch.conf"),
    Path("/etc/resolv.conf"),
    Path("/etc/services"),
    Path("/etc/ssl"),
    Path("/dev/urandom"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--write", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not os.path.isabs(command[0]):
        return 125
    write_paths = [Path(value) for value in args.write]
    try:
        disable_process_inspection()
        restrict_filesystem(
            read_only=[path for path in _READ_ONLY_PATHS if path.exists()],
            read_write=[Path("/dev/null"), *write_paths],
            required=True,
        )
        os.execve(command[0], command, dict(os.environ))
    except BaseException:
        return 125
    return 125


if __name__ == "__main__":
    sys.exit(main())
