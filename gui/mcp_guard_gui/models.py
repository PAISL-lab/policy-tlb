from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt


LAYER_BASELINE_US = {
    "L1": 0.018,
    "L2": 0.023,
    "L3": 0.989,
}


@dataclass
class GuardEvent:
    raw: dict[str, Any]

    @property
    def action(self) -> str:
        return str(self.raw.get("action", "-"))

    @property
    def hook(self) -> str:
        return str(self.raw.get("hook", "-"))

    @property
    def layer(self) -> str:
        return str(self.raw.get("layer", "-"))

    @property
    def duration_ns(self) -> int:
        try:
            return int(self.raw.get("duration_ns", 0))
        except (TypeError, ValueError):
            return 0

    @property
    def duration_us(self) -> float:
        if "duration_us" in self.raw:
            try:
                return float(self.raw["duration_us"])
            except (TypeError, ValueError):
                pass
        return self.duration_ns / 1000.0

    @property
    def model_us(self) -> float:
        if "model_us" in self.raw:
            try:
                return float(self.raw["model_us"])
            except (TypeError, ValueError):
                pass
        return LAYER_BASELINE_US.get(self.layer, 0.0)

    @property
    def delta_us(self) -> float:
        if "delta_us" in self.raw:
            try:
                return float(self.raw["delta_us"])
            except (TypeError, ValueError):
                pass
        return self.duration_us - self.model_us


class EventStore:
    def __init__(self, max_events: int = 5000) -> None:
        self.max_events = max_events
        self.events: list[GuardEvent] = []
        self.count_by_action: dict[str, int] = {}
        self.count_by_layer: dict[str, int] = {}

    def add(self, payload: dict[str, Any]) -> GuardEvent:
        event = GuardEvent(payload)
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        self.count_by_action[event.action] = self.count_by_action.get(event.action, 0) + 1
        self.count_by_layer[event.layer] = self.count_by_layer.get(event.layer, 0) + 1
        return event


class EventTableModel(QAbstractTableModel):
    COLUMNS = [
        ("Action", "action"),
        ("Hook", "hook"),
        ("Layer", "layer"),
        ("Duration us", "duration_us"),
        ("PID", "pid"),
        ("Path", "path"),
        ("Rule", "rule"),
        ("Error", "error"),
    ]

    def __init__(self, store: EventStore) -> None:
        super().__init__()
        self.store = store

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.store.events)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        event = self.store.events[index.row()]
        _, field = self.COLUMNS[index.column()]
        if field == "duration_us":
            return f"{event.duration_us:.3f}"
        return str(event.raw.get(field, "-") or "-")

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section][0]
        return section + 1

    def add_payload(self, payload: dict[str, Any]) -> GuardEvent:
        row = len(self.store.events)
        self.beginInsertRows(QModelIndex(), row, row)
        event = self.store.add(payload)
        self.endInsertRows()
        return event
