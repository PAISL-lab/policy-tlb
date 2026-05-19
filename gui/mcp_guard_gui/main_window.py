# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .alert_popup import AlertManager
from .models import EventRecord, EventStore, EventTableModel, MetricsSnapshot, RuntimeStatus
from .socket_client import ReplayClient, SocketClient


class MainWindow(QMainWindow):
    def __init__(
        self,
        socket_path: str,
        replay_path: Path | None = None,
        max_events: int = 5000,
        popups_enabled: bool = True,
    ) -> None:
        super().__init__()
        self.setWindowTitle("MCP Guard")
        self.socket_path = socket_path
        self.store = EventStore(max_events=max_events)
        self.model = EventTableModel(self.store)
        self.runtime = RuntimeStatus(socket_path=socket_path)
        self.metrics = MetricsSnapshot()
        self.alerts = AlertManager(self)
        self.alerts.enabled = popups_enabled

        self.connection_dashboard_label = QLabel("disconnected")
        self.connection_runtime_label = QLabel("disconnected")
        self.connection_status_label = QLabel("disconnected")
        self.socket_label = QLabel(socket_path)
        self.total_label = QLabel("0")
        self.deny_label = QLabel("0")
        self.audit_label = QLabel("0")
        self.epoch_label = QLabel("0")
        self.avg_latency_label = QLabel("0.000 us")
        self.layer_label = QLabel("L1 0 / L2 0 / L3 0")
        self.latest_label = QLabel("-")
        self.latest_label.setWordWrap(True)
        self.metrics_summary_label = QLabel("No metrics snapshot")
        self.reload_label = QLabel("No reload result")
        self.error_label = QLabel("")
        self.popup_toggle = QCheckBox("Deny popups")
        self.popup_toggle.setChecked(popups_enabled)
        self.popup_toggle.toggled.connect(self._toggle_popups)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlainText("Select an event to inspect raw JSON and timing details.")
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.metrics_table = QTableWidget(0, 5)
        self.metrics_table.setHorizontalHeaderLabels(["Hook", "Layer", "Action", "Count", "Avg us"])
        self.metrics_table.horizontalHeader().setStretchLastSection(True)

        self._build_ui()
        self._create_client(replay_path)

    def closeEvent(self, event: Any) -> None:
        self.client.stop()
        super().closeEvent(event)

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._dashboard_tab(), "Dashboard")
        tabs.addTab(self._events_tab(), "Events")
        tabs.addTab(self._metrics_tab(), "Metrics")
        tabs.addTab(self._runtime_tab(), "Runtime")
        self.setCentralWidget(tabs)

        status = QStatusBar()
        status.addWidget(QLabel("socket:"))
        status.addWidget(self.socket_label)
        status.addPermanentWidget(self.connection_status_label)
        self.setStatusBar(status)

    def _create_client(self, replay_path: Path | None) -> None:
        if replay_path:
            self.client = ReplayClient(replay_path, self)
        else:
            self.client = SocketClient(self.socket_path, self)
        self.client.event_received.connect(self._add_event)
        self.client.metrics_received.connect(self._metrics_received)
        self.client.reload_result_received.connect(self._reload_result_received)
        self.client.connection_state_changed.connect(self._state_changed)
        self.client.error_received.connect(self._error_received)
        self.client.start()

    def _dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(self._summary_panel())
        layout.addWidget(self._layer_panel())
        latest = QGroupBox("Latest high-risk event")
        latest_layout = QVBoxLayout(latest)
        latest_layout.addWidget(self.latest_label)
        layout.addWidget(latest)
        layout.addStretch(1)
        return tab

    def _summary_panel(self) -> QWidget:
        box = QGroupBox("Runtime summary")
        grid = QGridLayout(box)
        labels = [
            ("Connection", self.connection_dashboard_label),
            ("Events", self.total_label),
            ("Deny", self.deny_label),
            ("Audit", self.audit_label),
            ("Epoch", self.epoch_label),
            ("Avg latency", self.avg_latency_label),
        ]
        for index, (title, widget) in enumerate(labels):
            grid.addWidget(QLabel(title), index // 3 * 2, index % 3)
            grid.addWidget(widget, index // 3 * 2 + 1, index % 3)
        return box

    def _layer_panel(self) -> QWidget:
        box = QGroupBox("Layer distribution")
        layout = QVBoxLayout(box)
        layout.addWidget(self.layer_label)
        return box

    def _events_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(self._filter_bar())
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setSizes([860, 420])
        layout.addWidget(splitter)
        return tab

    def _filter_bar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.action_filter = self._combo(["all", "allow", "deny", "audit"])
        self.hook_filter = self._combo(
            ["all", "exec", "file_open", "file_read", "file_write", "socket_connect"]
        )
        self.layer_filter = self._combo(["all", "L1", "L2", "L3"])
        self.profile_filter = QLineEdit()
        self.profile_filter.setPlaceholderText("profile")
        self.agent_filter = QLineEdit()
        self.agent_filter.setPlaceholderText("agent")
        self.search_filter = QLineEdit()
        self.search_filter.setPlaceholderText("search")
        for widget in (
            self.action_filter,
            self.hook_filter,
            self.layer_filter,
            self.profile_filter,
            self.agent_filter,
            self.search_filter,
        ):
            layout.addWidget(widget)
        self.action_filter.currentTextChanged.connect(self._apply_filters)
        self.hook_filter.currentTextChanged.connect(self._apply_filters)
        self.layer_filter.currentTextChanged.connect(self._apply_filters)
        self.profile_filter.textChanged.connect(self._apply_filters)
        self.agent_filter.textChanged.connect(self._apply_filters)
        self.search_filter.textChanged.connect(self._apply_filters)
        return bar

    def _combo(self, values: list[str]) -> QComboBox:
        combo = QComboBox()
        combo.addItems(values)
        return combo

    def _metrics_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(self.metrics_summary_label)
        layout.addWidget(self.metrics_table)
        return tab

    def _runtime_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        form_box = QGroupBox("Runtime")
        form = QFormLayout(form_box)
        form.addRow("Socket", QLabel(self.socket_path))
        form.addRow("Connection", self.connection_runtime_label)
        form.addRow("Last error", self.error_label)
        form.addRow("Last reload", self.reload_label)
        form.addRow("Alerts", self.popup_toggle)
        layout.addWidget(form_box)
        layout.addStretch(1)
        return tab

    def _add_event(self, payload: dict[str, Any]) -> None:
        event = self.model.add_payload(payload)
        self._update_dashboard()
        if event.action == "deny":
            self.alerts.show_event(event)

    def _metrics_received(self, payload: dict[str, Any]) -> None:
        self.metrics = MetricsSnapshot.from_payload(payload)
        self._update_metrics_view()

    def _reload_result_received(self, payload: dict[str, Any]) -> None:
        self.runtime.apply_reload_result(payload)
        state = "success" if self.runtime.reload_success else "failed"
        self.reload_label.setText(
            f"{state} rules={self.runtime.reload_rule_count} "
            f"generation={self.runtime.reload_generation} epoch={self.runtime.reload_epoch}"
        )
        if self.runtime.reload_epoch:
            self.epoch_label.setText(str(self.runtime.reload_epoch))

    def _state_changed(self, state: str) -> None:
        self.runtime.connection_state = state
        self.connection_dashboard_label.setText(state)
        self.connection_runtime_label.setText(state)
        self.connection_status_label.setText(state)

    def _error_received(self, error: str) -> None:
        self.runtime.last_error = error
        self.error_label.setText(error or "")
        if error:
            self.statusBar().showMessage(error, 5000)

    def _toggle_popups(self, enabled: bool) -> None:
        self.alerts.enabled = enabled

    def _apply_filters(self) -> None:
        profile = self.profile_filter.text().strip() or "all"
        agent = self.agent_filter.text().strip() or "all"
        self.model.set_filters(
            action=self.action_filter.currentText(),
            hook=self.hook_filter.currentText(),
            layer=self.layer_filter.currentText(),
            profile=profile,
            agent=agent,
            text=self.search_filter.text(),
        )

    def _update_dashboard(self) -> None:
        self.total_label.setText(str(len(self.store.events)))
        self.deny_label.setText(str(self.store.count_by_action.get("deny", 0)))
        self.audit_label.setText(str(self.store.count_by_action.get("audit", 0)))
        self.epoch_label.setText(str(self.store.current_epoch))
        self.avg_latency_label.setText(f"{self.store.average_latency_us:.3f} us")
        total = max(len(self.store.events), 1)
        layer_text = "  ".join(
            f"{layer}: {self.store.count_by_layer.get(layer, 0)} "
            f"({self.store.count_by_layer.get(layer, 0) / total:.0%})"
            for layer in ("L1", "L2", "L3")
        )
        self.layer_label.setText(layer_text)
        if self.store.latest_high_risk:
            event = self.store.latest_high_risk
            self.latest_label.setText(
                f"{event.action.upper()} {event.hook} {event.target} "
                f"rule={event.rule} profile={event.profile_id} agent={event.agent_id}"
            )
        self._update_metrics_view(event_derived=True)

    def _update_metrics_view(self, event_derived: bool = False) -> None:
        if self.metrics.received_at and not event_derived:
            self.metrics_summary_label.setText(
                "Snapshot {time} total={total} L1={l1:.0%} L2={l2:.0%} L3={l3:.0%}".format(
                    time=self.metrics.received_at.strftime("%H:%M:%S"),
                    total=self.metrics.total,
                    l1=self.metrics.l1_ratio,
                    l2=self.metrics.l2_ratio,
                    l3=self.metrics.l3_ratio,
                )
            )
            entries = self.metrics.entries
        else:
            total = max(len(self.store.events), 1)
            self.metrics_summary_label.setText(
                "Event-derived total={total} L1={l1:.0%} L2={l2:.0%} L3={l3:.0%}".format(
                    total=len(self.store.events),
                    l1=self.store.count_by_layer.get("L1", 0) / total,
                    l2=self.store.count_by_layer.get("L2", 0) / total,
                    l3=self.store.count_by_layer.get("L3", 0) / total,
                )
            )
            entries = []
        self.metrics_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            avg_us = entry.get("avg_us", entry.get("avg_duration_us", "-"))
            values = [
                entry.get("hook", "-"),
                entry.get("layer", "-"),
                entry.get("action", "-"),
                entry.get("count", 0),
                avg_us,
            ]
            for col, value in enumerate(values):
                self.metrics_table.setItem(row, col, QTableWidgetItem(str(value)))

    def _selection_changed(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        event = self.model.event_at(indexes[0].row())
        self._show_detail(event)

    def _show_detail(self, event: EventRecord) -> None:
        pretty = json.dumps(event.raw, indent=2, ensure_ascii=False)
        self.detail.setPlainText(
            f"{pretty}\n\n"
            f"duration_us={event.duration_us:.3f}\n"
            f"model_us={event.model_us:.3f}\n"
            f"delta_us={event.delta_us:.3f}\n"
            f"profile_id={event.profile_id}\n"
            f"agent_id={event.agent_id}\n"
            f"resource_id={event.resource_id}"
        )
