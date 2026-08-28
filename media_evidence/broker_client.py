from __future__ import annotations

import grp
import math
import os
import secrets
import socket
import stat
import struct
from pathlib import Path
from typing import Any, Callable

from .broker_protocol import encode_request, make_request, receive_response
from .contracts import MediaEvidenceError


DEFAULT_BROKER_SOCKET = "/run/hermes-media/broker.sock"
DEFAULT_GATEWAY_GROUP = "hermes-gateway"
DEFAULT_TIMEOUT_SECONDS = 1900.0

_PEER_CREDENTIALS = struct.Struct("3i")


class BrokerClientError(MediaEvidenceError):
    """A local broker transport failure with an explicit delivery phase."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        phase: str,
        request_id: str,
        operation: str,
    ):
        super().__init__(
            code,
            message,
            details={
                "phase": phase,
                "request_id": request_id,
                "operation": operation,
            },
        )
        self.phase = phase
        self.request_id = request_id
        self.operation = operation


class BrokerUnavailableError(BrokerClientError):
    pass


class BrokerOutcomeUnknownError(BrokerClientError):
    pass


class BrokerRemoteError(MediaEvidenceError):
    """A correlated error response returned by the privileged broker."""


SocketValidator = Callable[[Path], object]
Connector = Callable[[Path, float], socket.socket]
PeerCredentialsReader = Callable[[socket.socket], tuple[int, int, int]]


class BrokerClient:
    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        timeout: float | None = None,
        gateway_group: str | None = None,
        gateway_gid: int | None = None,
        expected_socket_uid: int = 0,
        request_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
        socket_validator: SocketValidator | None = None,
        connector: Connector | None = None,
        peer_credentials_reader: PeerCredentialsReader | None = None,
    ):
        configured_path = socket_path or os.getenv(
            "MEDIA_EVIDENCE_BROKER_SOCKET",
            DEFAULT_BROKER_SOCKET,
        )
        self.socket_path = Path(configured_path)
        if not self.socket_path.is_absolute() or "\x00" in os.fspath(self.socket_path):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker socket path is invalid",
            )
        if len(os.fsencode(self.socket_path)) > 107:
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker socket path is too long",
            )

        if timeout is None:
            raw_timeout = os.getenv(
                "MEDIA_EVIDENCE_BROKER_TIMEOUT_SECONDS",
                str(DEFAULT_TIMEOUT_SECONDS),
            )
            try:
                timeout = float(raw_timeout)
            except ValueError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The media evidence broker timeout is invalid",
                ) from exc
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or float(timeout) <= 0
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker timeout is invalid",
            )
        self.timeout = float(timeout)

        if not isinstance(expected_socket_uid, int) or isinstance(expected_socket_uid, bool) or expected_socket_uid < 0:
            raise MediaEvidenceError(
                "configuration_error",
                "The media evidence broker owner is invalid",
            )
        self.expected_socket_uid = expected_socket_uid
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
        if not isinstance(gateway_gid, int) or isinstance(gateway_gid, bool) or gateway_gid < 0:
            raise MediaEvidenceError(
                "configuration_error",
                "The configured Hermes gateway group is invalid",
            )
        self.gateway_gid = gateway_gid
        self._request_id_factory = request_id_factory
        self._socket_validator = socket_validator or self._validate_socket_path
        self._connector = connector or self._connect_unix_socket
        self._peer_credentials_reader = peer_credentials_reader or self._read_peer_credentials

    def health(self) -> dict[str, Any]:
        return self.request("health", {})

    def capabilities(self) -> dict[str, Any]:
        return self.request("capabilities", {})

    def analyze(
        self,
        *,
        source_path: str | None = None,
        source_url: str | None = None,
        allow_network_acquisition: bool = False,
        rights_basis: str,
        privacy: str,
        purpose: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "allow_network_acquisition": allow_network_acquisition,
            "rights_basis": rights_basis,
            "privacy": privacy,
            "purpose": purpose,
        }
        if source_path is not None:
            arguments["source_path"] = source_path
        if source_url is not None:
            arguments["source_url"] = source_url
        if options is not None:
            arguments["options"] = options
        return self.request("analyze", arguments)

    def status(self, job_id: str) -> dict[str, Any]:
        return self.request("status", {"job_id": job_id})

    def validate_claims(
        self,
        *,
        job_id: str,
        claims: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return self.request("validate_claims", {"job_id": job_id, "claims": claims})

    def request(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        request_id = self._request_id_factory()
        request = make_request(request_id, operation, arguments)
        frame = encode_request(request)

        connection: socket.socket | None = None
        sent_bytes = 0
        try:
            before_identity = self._socket_validator(self.socket_path)
            connection = self._connector(self.socket_path, self.timeout)
            connection.settimeout(self.timeout)
            connection.set_inheritable(False)
            peer_pid, peer_uid, _peer_gid = self._peer_credentials_reader(connection)
            if peer_pid <= 0 or peer_uid != self.expected_socket_uid:
                raise OSError("unexpected broker peer identity")
            after_identity = self._socket_validator(self.socket_path)
            if after_identity != before_identity:
                raise OSError("broker socket identity changed")
        except Exception as exc:
            if connection is not None:
                connection.close()
            raise BrokerUnavailableError(
                "broker_unavailable",
                "The media evidence broker is unavailable before request delivery",
                phase="before_send",
                request_id=request_id,
                operation=operation,
            ) from exc

        try:
            while sent_bytes < len(frame):
                try:
                    written = connection.send(frame[sent_bytes:])
                except InterruptedError:
                    continue
                if written <= 0:
                    raise OSError("broker connection accepted no request bytes")
                sent_bytes += written
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            response = receive_response(connection, expected_request_id=request_id)
        except Exception as exc:
            if sent_bytes:
                raise BrokerOutcomeUnknownError(
                    "outcome_unknown",
                    "The media evidence broker outcome is unknown after request delivery",
                    phase="after_send",
                    request_id=request_id,
                    operation=operation,
                ) from exc
            raise BrokerUnavailableError(
                "broker_unavailable",
                "The media evidence broker is unavailable before request delivery",
                phase="before_send",
                request_id=request_id,
                operation=operation,
            ) from exc
        finally:
            connection.close()

        if response["ok"] is False:
            error = response["error"]
            raise BrokerRemoteError(error["code"], error["message"])
        return response["result"]

    def _validate_socket_path(self, path: Path) -> tuple[int, int, int, int, int]:
        parent = path.parent
        try:
            parent_metadata = parent.lstat()
            socket_metadata = path.lstat()
        except OSError as exc:
            raise OSError("broker socket is unavailable") from exc
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != self.expected_socket_uid
            or parent_metadata.st_gid != self.gateway_gid
            or stat.S_IMODE(parent_metadata.st_mode) != 0o750
        ):
            raise OSError("broker socket parent is unsafe")
        if (
            path.is_symlink()
            or not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_nlink != 1
            or socket_metadata.st_uid != self.expected_socket_uid
            or socket_metadata.st_gid != self.gateway_gid
            or stat.S_IMODE(socket_metadata.st_mode) != 0o660
        ):
            raise OSError("broker socket is unsafe")
        return (
            socket_metadata.st_dev,
            socket_metadata.st_ino,
            socket_metadata.st_uid,
            socket_metadata.st_gid,
            stat.S_IMODE(socket_metadata.st_mode),
        )

    @staticmethod
    def _connect_unix_socket(path: Path, timeout: float) -> socket.socket:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(timeout)
            connection.set_inheritable(False)
            connection.connect(os.fspath(path))
            return connection
        except BaseException:
            connection.close()
            raise

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


MediaEvidenceBrokerClient = BrokerClient
