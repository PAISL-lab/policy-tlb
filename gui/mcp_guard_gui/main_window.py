# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QSplitter,
    QStatusBar,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .alert_popup import AlertPopup
from .models import EventStore, EventTableModel, GuardEvent
from .socket_client import DemoClient, SocketClient


class MainWindow(QMainWindow):
    def __init__(self, socket_path: str, demo_path: Path | None = None) -> None:
        super().__init__()
        self.setWindowTitle("MCP Guard")
        self.socket_path = socket_path
        self.store = EventStore()
        self.model = EventTableModel(self.store)
        self.alert = AlertPopup(self)

        self.connection_label = QLabel("disconnected")
        self.status_connection_label = QLabel("disconnected")
        self.total_label = QLabel("events: 0")
        self.deny_label = QLabel("deny: 0")
        self.layer_label = QLabel("L1: 0  L2: 0  L3: 0")
        self.metrics_layer_label = QLabel("L1: 0  L2: 0  L3: 0")
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.dashboard_table = QTableView()
        self.dashboard_table.setModel(self.model)
        self.dashboard_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.dashboard_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.dashboard_table.horizontalHeader().setStretchLastSection(True)

        self._build_ui()

        if demo_path:
            self.client = DemoClient(demo_path, self)
        else:
            self.client = SocketClient(socket_path, self)
        self.client.message_received.connect(self._message_received)
        self.client.state_changed.connect(self._state_changed)
        self.client.error_changed.connect(self._error_changed)
        self.client.start()

    def closeEvent(self, event: Any) -> None:
        self.client.stop()
        super().closeEvent(event)

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._dashboard_tab(), "Dashboard")
        tabs.addTab(self._events_tab(), "Events")
        tabs.addTab(self._metrics_tab(), "Metrics")
        tabs.addTab(self._policy_tab(), "Policy")
        self.setCentralWidget(tabs)

        status = QStatusBar()
        status.addWidget(QLabel(f"socket: {self.socket_path}"))
        status.addPermanentWidget(self.status_connection_label)
        self.setStatusBar(status)

    def _summary_row(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.addWidget(self.connection_label)
        layout.addWidget(self.total_label)
        layout.addWidget(self.deny_label)
        layout.addWidget(self.layer_label)
        layout.addStretch(1)
        return row

    def _dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(self._summary_row())
        layout.addWidget(QLabel("Recent Events"))
        layout.addWidget(self.dashboard_table)
        return tab

    def _events_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setSizes([850, 430])
        layout.addWidget(splitter)
        return tab

    def _metrics_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Metrics snapshot support is prepared."))
        layout.addWidget(self.metrics_layer_label)
        layout.addStretch(1)
        return tab

    def _policy_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Policy status will be populated from loader reload_result messages."))
        layout.addStretch(1)
        return tab

    def _message_received(self, payload: dict[str, Any]) -> None:
        message_type = payload.get("type", "event")
        if message_type == "event":
            self._add_event(payload)
        elif "hook" in payload and "action" in payload:
            self._add_event(payload)
        elif message_type == "metrics_snapshot":
            self.statusBar().showMessage("metrics snapshot received", 3000)
        elif message_type == "reload_result":
            self.statusBar().showMessage("policy reload result received", 3000)

    def _add_event(self, payload: dict[str, Any]) -> None:
        event = self.model.add_payload(payload)
        self._update_counters()
        if event.action == "deny":
            self.alert.show_event(event)

    def _update_counters(self) -> None:
        self.total_label.setText(f"events: {len(self.store.events)}")
        self.deny_label.setText(f"deny: {self.store.count_by_action.get('deny', 0)}")
        layer_text = "L1: {l1}  L2: {l2}  L3: {l3}".format(
            l1=self.store.count_by_layer.get("L1", 0),
            l2=self.store.count_by_layer.get("L2", 0),
            l3=self.store.count_by_layer.get("L3", 0),
        )
        self.layer_label.setText(layer_text)
        self.metrics_layer_label.setText(layer_text)

    def _selection_changed(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        event = self.store.events[indexes[0].row()]
        pretty = json.dumps(event.raw, indent=2, ensure_ascii=False)
        self.detail.setPlainText(
            f"{pretty}\n\n"
            f"duration_us={event.duration_us:.3f}\n"
            f"model_us={event.model_us:.3f}\n"
            f"delta_us={event.delta_us:.3f}"
        )

    def _state_changed(self, state: str) -> None:
        self.connection_label.setText(state)
        self.status_connection_label.setText(state)

    def _error_changed(self, error: str) -> None:
        if error:
            self.statusBar().showMessage(error, 5000)
