from __future__ import annotations

import importlib.util
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "configure-hermes.py"
SPEC = importlib.util.spec_from_file_location("configure_hermes", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load configure-hermes.py")
configure_hermes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(configure_hermes)


class ConfigureHermesTests(unittest.TestCase):
    def test_existing_control_file_permissions_are_hardened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text("SECRET=value\n", encoding="utf-8")
            path.chmod(0o644)
            configure_hermes.validate_control_file(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_control_file_symlinks_and_hardlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("SECRET=value\n", encoding="utf-8")
            symlink = root / "symlink"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "Unsafe Hermes control file"):
                configure_hermes.validate_control_file(symlink)
            hardlink = root / "hardlink"
            os.link(target, hardlink)
            with self.assertRaisesRegex(RuntimeError, "Unsafe Hermes control file"):
                configure_hermes.validate_control_file(hardlink)

    def test_control_file_must_belong_to_effective_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text("model: {}\n", encoding="utf-8")
            with mock.patch.object(configure_hermes.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaisesRegex(RuntimeError, "effective user"):
                    configure_hermes.validate_control_file(path)

    def test_unsafe_gateway_ownership_migration_trees_are_rejected(self) -> None:
        constructors = {
            "symlink": lambda path, target: path.symlink_to(target),
            "fifo": lambda path, _target: os.mkfifo(path),
            "socket": self._make_unix_socket,
            "hardlink": lambda path, target: os.link(target, path),
        }
        for name, constructor in constructors.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "gateway-tree"
                root.mkdir()
                target = root / "target"
                target.write_text("state\n", encoding="utf-8")
                unsafe = root / name
                resource = constructor(unsafe, target)
                try:
                    with self.assertRaisesRegex(RuntimeError, "Unsafe ownership tree entry"):
                        configure_hermes.collect_safe_ownership_tree(root)
                finally:
                    if resource is not None:
                        resource.close()

    def test_ownership_migration_validates_all_trees_before_chown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            safe = base / "safe"
            unsafe = base / "unsafe"
            safe.mkdir()
            unsafe.mkdir()
            (safe / "state").write_text("safe\n", encoding="utf-8")
            (unsafe / "link").symlink_to(safe / "state")
            with (
                mock.patch.object(configure_hermes.os, "chown") as chown,
                mock.patch.object(configure_hermes.os, "fchown") as fchown,
            ):
                with self.assertRaisesRegex(RuntimeError, "Unsafe ownership tree entry"):
                    configure_hermes.change_tree_ownership(
                        [safe, unsafe],
                        uid=configure_hermes.GATEWAY_UID,
                        gid=configure_hermes.GATEWAY_GID,
                    )
                chown.assert_not_called()
                fchown.assert_not_called()

    def test_device_entries_are_rejected(self) -> None:
        metadata = mock.Mock(st_mode=stat.S_IFCHR | 0o600, st_nlink=1)
        with self.assertRaisesRegex(RuntimeError, "special file"):
            configure_hermes._validate_ownership_entry(Path("/unsafe/device"), metadata)

    def test_ownership_migration_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "gateway-tree"
            root.mkdir()
            (root / "state").write_text("state\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exceeds 1 entries"):
                configure_hermes.collect_safe_ownership_tree(root, max_entries=1)

    def test_legacy_staging_rejects_unsafe_source_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "legacy"
            destination = base / "gateway" / "legacy"
            source.mkdir()
            destination.parent.mkdir()
            (source / "unsafe").symlink_to(base / "outside")
            with self.assertRaisesRegex(RuntimeError, "Unsafe ownership tree entry"):
                configure_hermes.stage_legacy_tree(source, destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.iterdir()), [])

    def test_legacy_staging_copies_only_validated_regular_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "legacy"
            destination = base / "gateway" / "legacy"
            (source / "credentials").mkdir(parents=True)
            destination.parent.mkdir()
            (source / "openclaw.json").write_text('{"version": 1}\n', encoding="utf-8")
            (source / "credentials" / "allow.json").write_text("{}\n", encoding="utf-8")

            configure_hermes.stage_legacy_tree(source, destination)

            self.assertEqual(
                (destination / "openclaw.json").read_text(encoding="utf-8"),
                '{"version": 1}\n',
            )
            self.assertEqual(
                stat.S_IMODE((destination / "openclaw.json").stat().st_mode),
                0o600,
            )

    @staticmethod
    def _make_unix_socket(path: Path, _target: Path) -> socket.socket:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(path))
        return listener


if __name__ == "__main__":
    unittest.main()
