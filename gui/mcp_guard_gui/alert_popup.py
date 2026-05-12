from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from .models import GuardEvent


class AlertPopup(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._title = QLabel()
        self._body = QLabel()
        self._body.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._title)
        layout.addWidget(self._body)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_event(self, event: GuardEvent) -> None:
        self._title.setText(f"{event.action.upper()} {event.hook} {event.layer}")
        target = event.raw.get("path") or f"port {event.raw.get('port', '-')}"
        self._body.setText(
            f"{target}\nrule={event.raw.get('rule', '-') or '-'} "
            f"duration={event.duration_us:.3f}us"
        )
        if self.parentWidget():
            parent_rect = self.parentWidget().geometry()
            self.move(parent_rect.right() - 360, parent_rect.top() + 72)
        self.resize(340, 110)
        self.show()
        self._timer.start(4500)
