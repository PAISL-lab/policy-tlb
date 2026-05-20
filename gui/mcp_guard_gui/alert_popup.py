# SPDX-License-Identifier: Apache-2.0
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from .models import EventRecord


class AlertPopup(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.parent_window = parent
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setObjectName("alertPopup")
        self._title = QLabel()
        self._title.setObjectName("alertTitle")
        self._body = QLabel()
        self._body.setObjectName("alertBody")
        self._body.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)
        layout.addWidget(self._title)
        layout.addWidget(self._body)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_event(self, event: EventRecord, offset: int = 0, extra_count: int = 0) -> None:
        suffix = f" (+{extra_count})" if extra_count else ""
        self._title.setText(f"MCP Guard blocked an operation{suffix}")
        self._body.setText(
            "Denied by the active MCP Guard policy.\n"
            f"{event.hook} {event.target}\n"
            f"rule={event.rule} profile={event.profile_id} agent={event.agent_id} "
            f"duration={event.duration_us:.3f} us"
        )
        self.resize(380, 136)
        if self.parent_window and self.parent_window.isVisible():
            parent_rect = self.parent_window.frameGeometry()
            self.move(parent_rect.right() - 380, parent_rect.top() + 72 + offset)
        else:
            screen = QGuiApplication.primaryScreen()
            if screen:
                rect = screen.availableGeometry()
                self.move(rect.right() - self.width() - 18, rect.top() + 72 + offset)
        self.show()
        self.raise_()
        self._timer.start(5000)


class AlertManager:
    def __init__(self, parent: QWidget) -> None:
        self.parent = parent
        self.enabled = True
        self._popups = [AlertPopup(parent) for _ in range(3)]
        self._next_index = 0
        self._suppressed = 0

    def show_event(self, event: EventRecord) -> None:
        if not self.enabled:
            return
        visible = [popup for popup in self._popups if popup.isVisible()]
        if len(visible) >= len(self._popups):
            self._suppressed += 1
            visible[-1].show_event(event, offset=(len(visible) - 1) * 142, extra_count=self._suppressed)
            return
        self._suppressed = 0
        popup = self._popups[self._next_index]
        self._next_index = (self._next_index + 1) % len(self._popups)
        popup.show_event(event, offset=len(visible) * 142)
