# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QLocalSocket


class SocketClient(QObject):
    message_received = Signal(dict)
    state_changed = Signal(str)
    error_changed = Signal(str)

    def __init__(self, socket_path: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.socket_path = socket_path
        self._socket = QLocalSocket(self)
        self._buffer = bytearray()
        self._backoff_ms = 500
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
        self.state_changed.emit("disconnected")

    def connect_to_loader(self) -> None:
        if self._socket.state() != QLocalSocket.LocalSocketState.UnconnectedState:
            return
        self.state_changed.emit("connecting")
        self._socket.connectToServer(self.socket_path)

    def _schedule_reconnect(self) -> None:
        if self._stopping:
            return
        self._reconnect.start(self._backoff_ms)
        self._backoff_ms = min(self._backoff_ms * 2, 5000)

    def _on_connected(self) -> None:
        self._backoff_ms = 500
        self.state_changed.emit("connected")
        self.error_changed.emit("")

    def _on_disconnected(self) -> None:
        self.state_changed.emit("disconnected")
        self._schedule_reconnect()

    def _on_error(self, *_args: object) -> None:
        self.error_changed.emit(self._socket.errorString())
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
            self.error_changed.emit(f"malformed JSON: {exc}")
            return
        if isinstance(payload, dict):
            self.message_received.emit(payload)


class DemoClient(QObject):
    message_received = Signal(dict)
    state_changed = Signal(str)
    error_changed = Signal(str)

    def __init__(self, demo_path: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.demo_path = demo_path
        self._lines: list[str] = []
        self._index = 0
        self._timer = QTimer(self)
        self._timer.setInterval(600)
        self._timer.timeout.connect(self._emit_next)

    def start(self) -> None:
        try:
            self._lines = self.demo_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.error_changed.emit(str(exc))
            self.state_changed.emit("error")
            return
        self.state_changed.emit("connected")
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self.state_changed.emit("disconnected")

    def _emit_next(self) -> None:
        if not self._lines:
            return
        line = self._lines[self._index % len(self._lines)]
        self._index += 1
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            self.error_changed.emit(f"malformed demo JSON: {exc}")
            return
        if isinstance(payload, dict):
            self.message_received.emit(payload)
