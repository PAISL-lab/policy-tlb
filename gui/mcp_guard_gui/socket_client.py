# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QLocalSocket


class MessageRouter(QObject):
    message_received = Signal(dict)
    event_received = Signal(dict)
    metrics_received = Signal(dict)
    reload_result_received = Signal(dict)
    error_received = Signal(str)

    def route_message(self, payload: dict[str, Any]) -> None:
        self.message_received.emit(payload)
        message_type = payload.get("type", "event")
        if message_type == "event" or (
            message_type is None and "hook" in payload and "action" in payload
        ):
            self.event_received.emit(payload)
        elif message_type == "metrics_snapshot":
            self.metrics_received.emit(payload)
        elif message_type == "reload_result":
            self.reload_result_received.emit(payload)


class SocketClient(MessageRouter):
    connection_state_changed = Signal(str)

    def __init__(self, socket_path: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.socket_path = socket_path
        self._socket = QLocalSocket(self)
        self._buffer = bytearray()
        self._backoff_ms = 250
        self._stopping = False
        self._reconnect = QTimer(self)
        self._reconnect.setSingleShot(True)

        self._socket.connected.connect(self._on_connected)
        self._socket.disconnected.connect(self._on_disconnected)
        self._socket.readyRead.connect(self._on_ready_read)
        self._socket.errorOccurred.connect(self._on_error)
        self._reconnect.timeout.connect(self.connect_to_loader)

    def start(self) -> None:
        self._stopping = False
        self.connect_to_loader()

    def stop(self) -> None:
        self._stopping = True
        self._reconnect.stop()
        self._socket.abort()
        self.connection_state_changed.emit("disconnected")

    def connect_to_loader(self) -> None:
        if self._socket.state() != QLocalSocket.LocalSocketState.UnconnectedState:
            return
        self.connection_state_changed.emit("connecting")
        self._socket.connectToServer(self.socket_path)

    def _schedule_reconnect(self) -> None:
        if self._stopping:
            return
        self._reconnect.start(self._backoff_ms)
        self._backoff_ms = min(self._backoff_ms * 2, 5000)

    def _on_connected(self) -> None:
        self._backoff_ms = 250
        self.connection_state_changed.emit("connected")
        self.error_received.emit("")

    def _on_disconnected(self) -> None:
        self.connection_state_changed.emit("disconnected")
        self._schedule_reconnect()

    def _on_error(self, *_args: object) -> None:
        self.error_received.emit(self._socket.errorString())
        self.connection_state_changed.emit("error")
        if self._socket.state() == QLocalSocket.LocalSocketState.UnconnectedState:
            self._schedule_reconnect()

    def _on_ready_read(self) -> None:
        self._buffer.extend(bytes(self._socket.readAll()))
        while b"\n" in self._buffer:
            line, _, rest = self._buffer.partition(b"\n")
            self._buffer = bytearray(rest)
            self._emit_line(line)

    def _emit_line(self, line: bytes) -> None:
        if not line.strip():
            return
        try:
            payload = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.error_received.emit(f"malformed JSON: {exc}")
            return
        if isinstance(payload, dict):
            self.route_message(payload)
        else:
            self.error_received.emit("malformed JSON: top-level value is not an object")


class ReplayClient(MessageRouter):
    connection_state_changed = Signal(str)

    def __init__(
        self,
        replay_path: Path,
        parent: QObject | None = None,
        interval_ms: int = 100,
    ) -> None:
        super().__init__(parent)
        self.replay_path = replay_path
        self._lines: list[str] = []
        self._index = 0
        self._timer = QTimer(self)
        self._timer.setInterval(max(interval_ms, 1))
        self._timer.timeout.connect(self._emit_next)

    def start(self) -> None:
        try:
            self._lines = self.replay_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.error_received.emit(str(exc))
            self.connection_state_changed.emit("error")
            return
        self.connection_state_changed.emit("replaying")
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self.connection_state_changed.emit("disconnected")

    def _emit_next(self) -> None:
        if not self._lines:
            return
        line = self._lines[self._index % len(self._lines)].strip()
        self._index += 1
        if not line:
            return
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            self.error_received.emit(f"malformed replay JSON: {exc}")
            return
        if isinstance(payload, dict):
            self.route_message(payload)
        else:
            self.error_received.emit("malformed replay JSON: top-level value is not an object")


DemoClient = ReplayClient
