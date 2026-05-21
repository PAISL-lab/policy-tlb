# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont


LAYER_BASELINE_US = {
    "L1": 0.018,
    "L2": 0.023,
    "L3": 0.989,
}


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _text_value(value: Any, default: str = "-") -> str:
    if value is None or value == "":
        return default
    return str(value)


@dataclass(frozen=True)
class EventRecord:
    raw: dict[str, Any]
    timestamp_ns: int = 0
    pid: int = 0
    tgid: int = 0
    uid: int = 0
    comm: str = "-"
    hook: str = "-"
    action: str = "-"
    layer: str = "-"
    duration_ns: int = 0
    duration_us: float = 0.0
    model_us: float = 0.0
    delta_us: float = 0.0
    rule_id: int = 0
    profile_id: int = 0
    agent_id: int = 0
    error: int = 0
    path: str = "-"
    rule: str = "-"
    port: int = 0
    resource_id: int = 0
    epoch: int = 0

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EventRecord:
        raw = dict(payload)
        timestamp_ns = _int_value(raw.get("timestamp_ns", raw.get("ts_ns", 0)))
        duration_ns = _int_value(raw.get("duration_ns", 0))
        duration_us = _float_value(raw.get("duration_us"), duration_ns / 1000.0)
        layer = _text_value(raw.get("layer"))
        model_us = _float_value(raw.get("model_us"), LAYER_BASELINE_US.get(layer, 0.0))
        delta_us = _float_value(raw.get("delta_us"), duration_us - model_us)
        return cls(
            raw=raw,
            timestamp_ns=timestamp_ns,
            pid=_int_value(raw.get("pid", 0)),
            tgid=_int_value(raw.get("tgid", 0)),
            uid=_int_value(raw.get("uid", 0)),
            comm=_text_value(raw.get("comm")),
            hook=_text_value(raw.get("hook")),
            action=_text_value(raw.get("action")),
            layer=layer,
            duration_ns=duration_ns,
            duration_us=duration_us,
            model_us=model_us,
            delta_us=delta_us,
            rule_id=_int_value(raw.get("rule_id", 0)),
            profile_id=_int_value(raw.get("profile_id", 0)),
            agent_id=_int_value(raw.get("agent_id", 0)),
            error=_int_value(raw.get("error", 0)),
            path=_text_value(raw.get("path")),
            rule=_text_value(raw.get("rule")),
            port=_int_value(raw.get("port", 0)),
            resource_id=_int_value(raw.get("resource_id", 0)),
            epoch=_int_value(raw.get("epoch", 0)),
        )

    @property
    def target(self) -> str:
        if self.path != "-":
            return self.path
        if self.hook == "socket_connect" or self.port:
            return f"dst=:{self.port}"
        return "-"

    @property
    def local_time(self) -> str:
        if not self.timestamp_ns:
            return "-"
        return datetime.fromtimestamp(self.timestamp_ns / 1_000_000_000).strftime("%H:%M:%S")


GuardEvent = EventRecord


@dataclass
class MetricsSnapshot:
    raw: dict[str, Any] = field(default_factory=dict)
    total: int = 0
    l1_ratio: float = 0.0
    l2_ratio: float = 0.0
    l3_ratio: float = 0.0
    entries: list[dict[str, Any]] = field(default_factory=list)
    received_at: datetime | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> MetricsSnapshot:
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            entries = []
        total = _int_value(payload.get("total", 0))
        layer_counts = Counter()
        for entry in entries:
            if isinstance(entry, dict):
                layer_counts[_text_value(entry.get("layer"))] += _int_value(entry.get("count", 0))
        if not total:
            total = sum(layer_counts.values())
        if total:
            l1_ratio = _float_value(payload.get("l1_ratio"), layer_counts["L1"] / total)
            l2_ratio = _float_value(payload.get("l2_ratio"), layer_counts["L2"] / total)
            l3_ratio = _float_value(payload.get("l3_ratio"), layer_counts["L3"] / total)
        else:
            l1_ratio = l2_ratio = l3_ratio = 0.0
        return cls(dict(payload), total, l1_ratio, l2_ratio, l3_ratio, entries, datetime.now())


@dataclass
class RuntimeStatus:
    connection_state: str = "disconnected"
    socket_path: str = "/tmp/mcp-guard.sock"
    last_error: str = ""
    reload_success: bool = False
    reload_rule_count: int = 0
    reload_generation: int = 0
    reload_epoch: int = 0
    reload_error: str = ""
    last_reload_raw: dict[str, Any] = field(default_factory=dict)

    def apply_reload_result(self, payload: dict[str, Any]) -> None:
        self.last_reload_raw = dict(payload)
        self.reload_success = bool(payload.get("success", False))
        self.reload_rule_count = _int_value(payload.get("rule_count", 0))
        self.reload_generation = _int_value(payload.get("generation", 0))
        self.reload_epoch = _int_value(payload.get("epoch", 0))
        self.reload_error = _text_value(payload.get("error"), "")


class EventStore:
    def __init__(self, max_events: int = 5000) -> None:
        self.max_events = max_events
        self.events: list[EventRecord] = []
        self.count_by_action: Counter[str] = Counter()
        self.count_by_hook: Counter[str] = Counter()
        self.count_by_layer: Counter[str] = Counter()
        self.count_by_profile: Counter[int] = Counter()
        self.count_by_agent: Counter[int] = Counter()
        self.current_epoch = 0
        self.latest_high_risk: EventRecord | None = None

    def add(self, payload: dict[str, Any]) -> EventRecord:
        event = EventRecord.from_payload(payload)
        self.events.append(event)
        self._increment(event)
        if event.action in {"deny", "audit"}:
            self.latest_high_risk = event
        if event.epoch:
            self.current_epoch = max(self.current_epoch, event.epoch)
        while len(self.events) > self.max_events:
            removed = self.events.pop(0)
            self._decrement(removed)
        return event

    def _increment(self, event: EventRecord) -> None:
        self.count_by_action[event.action] += 1
        self.count_by_hook[event.hook] += 1
        self.count_by_layer[event.layer] += 1
        self.count_by_profile[event.profile_id] += 1
        self.count_by_agent[event.agent_id] += 1

    def _decrement(self, event: EventRecord) -> None:
        for counter, key in (
            (self.count_by_action, event.action),
            (self.count_by_hook, event.hook),
            (self.count_by_layer, event.layer),
            (self.count_by_profile, event.profile_id),
            (self.count_by_agent, event.agent_id),
        ):
            counter[key] -= 1
            if counter[key] <= 0:
                del counter[key]

    @property
    def average_latency_us(self) -> float:
        if not self.events:
            return 0.0
        return sum(event.duration_us for event in self.events) / len(self.events)


class EventTableModel(QAbstractTableModel):
    COLUMNS = [
        ("Time", "local_time"),
        ("Action", "action"),
        ("Hook", "hook"),
        ("Layer", "layer"),
        ("Duration", "duration_us"),
        ("PID", "pid"),
        ("Profile", "profile_id"),
        ("Agent", "agent_id"),
        ("Target", "target"),
        ("Rule", "rule"),
    ]

    def __init__(self, store: EventStore) -> None:
        super().__init__()
        self.store = store
        self.action_filter = "all"
        self.hook_filter = "all"
        self.layer_filter = "all"
        self.profile_filter = "all"
        self.agent_filter = "all"
        self.text_filter = ""
        self._rows: list[int] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        event = self.event_at(index.row())
        if role == Qt.ItemDataRole.FontRole and index.column() in (1, 2, 8):
            font = QFont()
            font.setBold(event.action in {"deny", "audit"})
            return font
        if role == Qt.ItemDataRole.ForegroundRole:
            if event.action == "deny":
                return QColor("#b42318")
            if event.action == "audit":
                return QColor("#92400e")
            if event.action == "allow":
                return QColor("#067647")
        if role == Qt.ItemDataRole.BackgroundRole:
            if event.action == "deny":
                return QColor("#fff1f2")
            if event.action == "audit":
                return QColor("#fffbeb")
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        _, field_name = self.COLUMNS[index.column()]
        value = getattr(event, field_name)
        if field_name == "duration_us":
            return f"{event.duration_us:.3f} us"
        return str(value)

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

    def event_at(self, row: int) -> EventRecord:
        return self.store.events[self._rows[row]]

    def add_payload(self, payload: dict[str, Any]) -> EventRecord:
        event = self.store.add(payload)
        self.refresh()
        return event

    def set_filters(
        self,
        *,
        action: str | None = None,
        hook: str | None = None,
        layer: str | None = None,
        profile: str | None = None,
        agent: str | None = None,
        text: str | None = None,
    ) -> None:
        if action is not None:
            self.action_filter = action
        if hook is not None:
            self.hook_filter = hook
        if layer is not None:
            self.layer_filter = layer
        if profile is not None:
            self.profile_filter = profile
        if agent is not None:
            self.agent_filter = agent
        if text is not None:
            self.text_filter = text.strip().lower()
        self.refresh()

    def refresh(self) -> None:
        self.beginResetModel()
        self._rows = [
            index for index, event in enumerate(self.store.events) if self._matches(event)
        ]
        self.endResetModel()

    def _matches(self, event: EventRecord) -> bool:
        if self.action_filter != "all" and event.action != self.action_filter:
            return False
        if self.hook_filter != "all" and event.hook != self.hook_filter:
            return False
        if self.layer_filter != "all" and event.layer != self.layer_filter:
            return False
        if self.profile_filter != "all" and str(event.profile_id) != self.profile_filter:
            return False
        if self.agent_filter != "all" and str(event.agent_id) != self.agent_filter:
            return False
        if self.text_filter:
            haystack = " ".join(
                [event.path, event.rule, event.comm, event.hook, event.action, event.target]
            ).lower()
            if self.text_filter not in haystack:
                return False
        return True
