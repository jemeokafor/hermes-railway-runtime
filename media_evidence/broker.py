from __future__ import annotations

import argparse
import errno
import grp
import logging
import math
import os
import pwd
import re
import signal
import socket
import stat
import struct
import threading
from pathlib import Path
from typing import Any, Callable

from .broker_protocol import (
    ALLOWED_OPERATIONS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    NULL_REQUEST_ID,
    PROTOCOL_ID,
    BrokerProtocolError,
    encode_response,
    make_error_response,
    make_success_response,
    receive_request,
    reject_buffered_trailing_data,
)
from .broker_public import public_pipeline_result
from .contracts import MediaEvidenceError
from .pipeline import MediaEvidencePipeline


DEFAULT_BROKER_SOCKET = "/run/hermes-media/broker.sock"
DEFAULT_GATEWAY_USER = "hermes-gateway"
DEFAULT_GATEWAY_GROUP = "hermes-gateway"
DEFAULT_WORKER_USER = "hermes-media"
DEFAULT_ACQUISITION_USER = "hermes-acquire"
MAX_ACTIVE_HANDLERS = 8
SOCKET_PARENT_MODE = 0o750
SOCKET_MODE = 0o660

_PEER_CREDENTIALS = struct.Struct("3i")
_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


PeerCredentialsReader = Callable[[socket.socket], tuple[int, int, int]]


class BrokerServer:
    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        pipeline: Any | None = None,
        pipeline_factory: Callable[[], Any] | None = None,
        gateway_uid: int | None = None,
        gateway_gid: int | None = None,
        gateway_user: str | None = None,
        gateway_group: str | None = None,
        require_root: bool = True,
        socket_owner_uid: int | None = None,
        set_ownership: bool | None = None,
        euid_getter: Callable[[], int] = os.geteuid,
        peer_credentials_reader: PeerCredentialsReader | None = None,
        max_handlers: int = MAX_ACTIVE_HANDLERS,
        request_timeout: float = 30.0,
        logger: logging.Logger | None = None,
    ):
        effective_uid = euid_getter()
        if require_root and effective_uid != 0:
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker requires a root service identity",
            )

        configured_path = socket_path or os.getenv(
            "MEDIA_EVIDENCE_BROKER_SOCKET",
            DEFAULT_BROKER_SOCKET,
        )
        self.socket_path = Path(configured_path)
        if (
            not self.socket_path.is_absolute()
            or self.socket_path.parent == Path(self.socket_path.anchor)
            or "\x00" in os.fspath(self.socket_path)
            or len(os.fsencode(self.socket_path)) > 107
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker socket path is invalid",
            )

        if gateway_uid is None:
            user_name = gateway_user or os.getenv(
                "MEDIA_EVIDENCE_GATEWAY_USER",
                DEFAULT_GATEWAY_USER,
            )
            try:
                gateway_uid = pwd.getpwnam(user_name).pw_uid
            except KeyError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The configured Hermes gateway user is unavailable",
                ) from exc
        if gateway_gid is None:
            group_name = gateway_group or os.getenv(
                "MEDIA_EVIDENCE_GATEWAY_GROUP",
                DEFAULT_GATEWAY_GROUP,
            )
            try:
                gateway_gid = grp.getgrnam(group_name).gr_gid
            except KeyError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The configured Hermes gateway group is unavailable",
                ) from exc
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (gateway_uid, gateway_gid)
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The configured Hermes gateway identity is invalid",
            )
        if require_root and (gateway_uid == 0 or gateway_gid == 0):
            raise MediaEvidenceError(
                "configuration_error",
                "The Hermes gateway identity must be non-root",
            )
        self.gateway_uid = gateway_uid
        self.gateway_gid = gateway_gid

        if socket_owner_uid is None:
            socket_owner_uid = 0 if require_root else effective_uid
        if (
            not isinstance(socket_owner_uid, int)
            or isinstance(socket_owner_uid, bool)
            or socket_owner_uid < 0
            or (require_root and socket_owner_uid != 0)
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker socket owner is invalid",
            )
        self.socket_owner_uid = socket_owner_uid
        self.require_root = require_root
        self._euid_getter = euid_getter
        self.set_ownership = require_root if set_ownership is None else set_ownership

        if (
            not isinstance(max_handlers, int)
            or isinstance(max_handlers, bool)
            or not 1 <= max_handlers <= MAX_ACTIVE_HANDLERS
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker handler limit is invalid",
            )
        if (
            isinstance(request_timeout, bool)
            or not isinstance(request_timeout, (int, float))
            or not math.isfinite(float(request_timeout))
            or float(request_timeout) <= 0
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker request timeout is invalid",
            )
        self.max_handlers = max_handlers
        self.request_timeout = float(request_timeout)

        if pipeline is not None and pipeline_factory is not None:
            raise MediaEvidenceError(
                "configuration_error",
                "Configure one media evidence pipeline source",
            )
        if pipeline is None:
            pipeline = (pipeline_factory or self._pipeline_from_environment)()
        self.pipeline = pipeline

        self._peer_credentials_reader = peer_credentials_reader or self._read_peer_credentials
        self._logger = logger or logging.getLogger("media_evidence.broker")
        self._handler_slots = threading.BoundedSemaphore(max_handlers)
        self._state_lock = threading.Lock()
        self._handlers_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._bound_identity: tuple[int, int] | None = None
        self._handlers: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._started = False

    @classmethod
    def from_environment(cls, **overrides: Any) -> BrokerServer:
        return cls(**overrides)

    @property
    def active_handlers(self) -> int:
        with self._handlers_lock:
            return len(self._handlers)

    @staticmethod
    def _pipeline_from_environment() -> MediaEvidencePipeline:
        configured_roots = os.getenv(
            "MEDIA_EVIDENCE_INPUT_ROOTS",
            "/data/workspace:/data/.hermes/cache",
        )
        return MediaEvidencePipeline(
            root=Path(os.getenv("MEDIA_EVIDENCE_ROOT", "/data/media-evidence")),
            allowed_roots=[Path(value) for value in configured_roots.split(os.pathsep) if value],
            require_worker_identity=True,
            worker_user=os.getenv("MEDIA_EVIDENCE_WORKER_USER", DEFAULT_WORKER_USER),
            acquisition_user=os.getenv(
                "MEDIA_EVIDENCE_ACQUISITION_USER",
                DEFAULT_ACQUISITION_USER,
            ),
            gateway_user=os.getenv("MEDIA_EVIDENCE_GATEWAY_USER", DEFAULT_GATEWAY_USER),
        )

    def start(self) -> None:
        if self.require_root and self._euid_getter() != 0:
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker requires a root service identity",
            )
        with self._state_lock:
            if self._started:
                return
            if self._stop_event.is_set():
                raise MediaEvidenceError(
                    "configuration_error",
                    "The media evidence broker cannot be restarted",
                )
            self._ensure_socket_parent()
            self._remove_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.set_inheritable(False)
                listener.bind(os.fspath(self.socket_path))
                metadata = self.socket_path.lstat()
                self._bound_identity = (metadata.st_dev, metadata.st_ino)
                if self.set_ownership:
                    os.chown(
                        self.socket_path,
                        self.socket_owner_uid,
                        self.gateway_gid,
                        follow_symlinks=False,
                    )
                os.chmod(self.socket_path, SOCKET_MODE)
                self._verify_bound_socket()
                listener.listen(self.max_handlers)
                listener.settimeout(0.25)
            except BaseException:
                listener.close()
                self._cleanup_socket()
                raise
            self._listener = listener
            self._started = True
        self._logger.info("media evidence broker started")

    def serve_forever(self, *, install_signal_handlers: bool = True) -> None:
        self.start()
        previous_handlers: dict[signal.Signals, Any] = {}
        if install_signal_handlers and threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self._handle_signal)
        try:
            while not self._stop_event.is_set():
                listener = self._listener
                if listener is None:
                    break
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    self._logger.error("media evidence broker accept failed")
                    continue
                self._accept_connection(connection)
        finally:
            self.shutdown()
            self._wait_for_handlers()
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)

    def shutdown(self) -> None:
        self._stop_event.set()
        with self._state_lock:
            listener = self._listener
            self._listener = None
        if listener is not None:
            listener.close()
        with self._handlers_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self._cleanup_socket()

    close = shutdown

    def _handle_signal(self, _signum: int, _frame: Any) -> None:
        self.shutdown()

    def _wait_for_handlers(self) -> None:
        with self._handlers_lock:
            handlers = list(self._handlers)
        for handler in handlers:
            handler.join(timeout=1.0)

    def _accept_connection(self, connection: socket.socket) -> None:
        try:
            connection.set_inheritable(False)
            peer_pid, peer_uid, peer_gid = self._peer_credentials_reader(connection)
        except Exception:
            self._logger.warning("media evidence broker rejected unavailable peer credentials")
            connection.close()
            return
        credentials = (peer_pid, peer_uid, peer_gid)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in credentials):
            self._logger.warning("media evidence broker rejected malformed peer credentials")
            connection.close()
            return
        if peer_pid <= 0 or peer_uid != self.gateway_uid or peer_gid != self.gateway_gid:
            self._logger.warning(
                "media evidence broker rejected peer pid=%d uid=%d gid=%d",
                peer_pid,
                peer_uid,
                peer_gid,
            )
            connection.close()
            return
        if self._stop_event.is_set() or not self._handler_slots.acquire(blocking=False):
            self._logger.warning("media evidence broker rejected connection at handler capacity")
            connection.close()
            return

        try:
            connection.settimeout(self.request_timeout)
        except Exception:
            self._handler_slots.release()
            connection.close()
            self._logger.error("media evidence broker failed to configure a handler")
            return
        handler = threading.Thread(
            target=self._run_handler,
            args=(connection,),
            name="media-evidence-broker-handler",
            daemon=True,
        )
        with self._handlers_lock:
            self._handlers.add(handler)
            self._connections.add(connection)
        try:
            handler.start()
        except Exception:
            with self._handlers_lock:
                self._handlers.discard(handler)
                self._connections.discard(connection)
            self._handler_slots.release()
            connection.close()
            self._logger.error("media evidence broker failed to start a handler")

    def _run_handler(self, connection: socket.socket) -> None:
        try:
            self._handle_connection(connection)
        finally:
            connection.close()
            with self._handlers_lock:
                self._connections.discard(connection)
                self._handlers.discard(threading.current_thread())
            self._handler_slots.release()

    def _handle_connection(self, connection: socket.socket) -> None:
        request_id = NULL_REQUEST_ID
        operation = "unparsed"
        error_code: str | None = None
        try:
            request = receive_request(connection)
            request_id = request["request_id"]
            operation = request["operation"]
            reject_buffered_trailing_data(connection)
            result = self._dispatch(operation, request["arguments"])
            response = make_success_response(request_id, result)
        except BrokerProtocolError as exc:
            request_id = exc.request_id or request_id
            if exc.code == "frame_too_large":
                error_code = "request_too_large"
                message = "The media evidence broker request exceeds its byte limit"
            else:
                error_code = exc.code if _SAFE_ERROR_CODE.fullmatch(exc.code) else "invalid_request"
                message = exc.message
            response = make_error_response(request_id, error_code, message)
        except MediaEvidenceError as exc:
            error_code, message = self._sanitize_media_error(exc)
            response = make_error_response(request_id, error_code, message)
        except Exception:
            error_code = "internal_error"
            response = make_error_response(
                request_id,
                error_code,
                "The media evidence operation failed",
            )

        try:
            encoded = encode_response(response)
        except BrokerProtocolError as exc:
            error_code = "response_too_large" if exc.code == "frame_too_large" else "internal_error"
            message = (
                "The media evidence broker response exceeds its byte limit"
                if error_code == "response_too_large"
                else "The media evidence response could not be returned"
            )
            encoded = encode_response(
                make_error_response(
                    request_id,
                    error_code,
                    message,
                )
            )
        try:
            connection.sendall(encoded)
        except OSError:
            self._logger.warning(
                "media evidence broker response delivery failed request_id=%s operation=%s",
                request_id,
                operation,
            )
            return
        if error_code is None:
            self._logger.info(
                "media evidence broker request completed request_id=%s operation=%s",
                request_id,
                operation,
            )
        else:
            self._logger.warning(
                "media evidence broker request failed request_id=%s operation=%s error=%s",
                request_id,
                operation,
                error_code,
            )

    def _dispatch(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if operation == "health":
            return {
                "ok": True,
                "status": "ready",
                "protocol": PROTOCOL_ID,
                "operations": sorted(ALLOWED_OPERATIONS),
                "limits": {
                    "request_bytes": MAX_REQUEST_BYTES,
                    "response_bytes": MAX_RESPONSE_BYTES,
                    "active_handlers": self.max_handlers,
                },
            }
        if operation == "capabilities":
            return public_pipeline_result(operation, self.pipeline.capabilities())
        if operation == "analyze":
            return public_pipeline_result(
                operation,
                self.pipeline.analyze(
                    source_path=arguments.get("source_path"),
                    source_url=arguments.get("source_url"),
                    allow_network_acquisition=arguments.get("allow_network_acquisition", False),
                    rights_basis=arguments.get("rights_basis"),
                    privacy=arguments.get("privacy"),
                    purpose=arguments.get("purpose"),
                    options=arguments.get("options"),
                ),
            )
        if operation == "status":
            return public_pipeline_result(operation, self.pipeline.status(arguments["job_id"]))
        if operation == "validate_claims":
            return public_pipeline_result(
                operation,
                self.pipeline.validate_claims(
                    job_id=arguments["job_id"],
                    claims=arguments["claims"],
                ),
            )
        raise BrokerProtocolError(
            "unsupported_operation",
            "The broker operation is unsupported",
        )

    @staticmethod
    def _sanitize_media_error(exc: MediaEvidenceError) -> tuple[str, str]:
        code = exc.code if isinstance(exc.code, str) and _SAFE_ERROR_CODE.fullmatch(exc.code) else "internal_error"
        message = exc.message
        if (
            not isinstance(message, str)
            or not 1 <= len(message) <= 512
            or any(ord(character) < 32 or ord(character) == 127 for character in message)
        ):
            message = "The media evidence operation failed"
        return code, message

    def _ensure_socket_parent(self) -> None:
        parent = self.socket_path.parent
        try:
            ancestor = parent.parent.lstat()
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "The broker socket parent is unavailable",
            ) from exc
        if (
            parent.parent.is_symlink()
            or not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid != self.socket_owner_uid
            or stat.S_IMODE(ancestor.st_mode) & 0o022
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The broker socket parent is unsafe",
            )

        created = False
        try:
            os.mkdir(parent, SOCKET_PARENT_MODE)
            created = True
        except FileExistsError:
            pass
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(parent, flags)
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "The broker socket parent is unsafe",
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if created:
                if self.set_ownership:
                    os.fchown(descriptor, self.socket_owner_uid, self.gateway_gid)
                os.fchmod(descriptor, SOCKET_PARENT_MODE)
                metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != self.socket_owner_uid
                or metadata.st_gid != self.gateway_gid
                or stat.S_IMODE(metadata.st_mode) != SOCKET_PARENT_MODE
            ):
                raise MediaEvidenceError(
                    "configuration_error",
                    "The broker socket parent ownership or permissions are unsafe",
                )
        finally:
            os.close(descriptor)

    def _remove_stale_socket(self) -> None:
        try:
            original = self.socket_path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "The broker socket path is unavailable",
            ) from exc
        if (
            self.socket_path.is_symlink()
            or not stat.S_ISSOCK(original.st_mode)
            or original.st_nlink != 1
            or original.st_uid != self.socket_owner_uid
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The existing broker socket path is unsafe",
            )

        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.2)
            probe.connect(os.fspath(self.socket_path))
        except FileNotFoundError:
            return
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The existing broker socket cannot be safely classified",
                ) from exc
        else:
            raise MediaEvidenceError(
                "configuration_error",
                "A media evidence broker is already listening",
            )
        finally:
            probe.close()

        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(current.st_mode)
            or current.st_uid != self.socket_owner_uid
            or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The existing broker socket changed during stale-socket validation",
            )
        self.socket_path.unlink()

    def _verify_bound_socket(self) -> None:
        metadata = self.socket_path.lstat()
        if (
            self.socket_path.is_symlink()
            or not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != self.socket_owner_uid
            or metadata.st_gid != self.gateway_gid
            or stat.S_IMODE(metadata.st_mode) != SOCKET_MODE
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The broker socket ownership or permissions are unsafe",
            )

    def _cleanup_socket(self) -> None:
        identity = self._bound_identity
        if identity is None:
            return
        try:
            metadata = self.socket_path.lstat()
        except FileNotFoundError:
            self._bound_identity = None
            return
        except OSError:
            return
        if (
            stat.S_ISSOCK(metadata.st_mode)
            and metadata.st_uid == self.socket_owner_uid
            and (metadata.st_dev, metadata.st_ino) == identity
        ):
            try:
                self.socket_path.unlink()
            except OSError:
                return
            self._bound_identity = None

    @staticmethod
    def _read_peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise OSError("peer credentials are unavailable")
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            _PEER_CREDENTIALS.size,
        )
        return _PEER_CREDENTIALS.unpack(credentials)


MediaEvidenceBroker = BrokerServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the privileged media evidence broker")
    parser.add_argument(
        "--socket",
        default=os.getenv("MEDIA_EVIDENCE_BROKER_SOCKET", DEFAULT_BROKER_SOCKET),
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    server: BrokerServer | None = None
    try:
        server = BrokerServer(socket_path=arguments.socket)
        server.serve_forever(install_signal_handlers=True)
        return 0
    except KeyboardInterrupt:
        if server is not None:
            server.shutdown()
        return 0
    except Exception:
        logging.getLogger("media_evidence.broker").error(
            "media evidence broker terminated during secure startup or service"
        )
        if server is not None:
            server.shutdown()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
