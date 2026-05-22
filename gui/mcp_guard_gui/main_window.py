# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGraphicsDropShadowEffect,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QStyle,
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
        self.setMinimumSize(1120, 720)
        self.socket_path = socket_path
        self.store = EventStore(max_events=max_events)
        self.model = EventTableModel(self.store)
        self.runtime = RuntimeStatus(socket_path=socket_path)
        self.metrics = MetricsSnapshot()
        self.alerts = AlertManager(self)
        self.alerts.enabled = popups_enabled
        self.selected_event: EventRecord | None = None
        self._queued_events: list[dict[str, Any]] = []

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
        self.layer_bars: dict[str, QProgressBar] = {}
        self.latest_label = QLabel("-")
        self.latest_label.setWordWrap(True)
        self.latest_action_label = QLabel("No high-risk event")
        self.latest_action_label.setObjectName("riskAction")
        self.latest_target_label = QLabel("-")
        self.latest_target_label.setObjectName("riskTarget")
        self.latest_meta_label = QLabel("Waiting for deny or audit events")
        self.latest_meta_label.setObjectName("riskMeta")
        self.latest_meta_label.setWordWrap(True)
        self.posture_label = QLabel("Monitoring")
        self.posture_label.setObjectName("posturePill")
        self.metrics_summary_label = QLabel("No metrics snapshot")
        self.metrics_summary_label.setObjectName("metricsSummary")
        self.reload_label = QLabel("No reload result")
        self.error_label = QLabel("")
        self.filter_count_label = QLabel("0 shown")
        self.filter_count_label.setObjectName("filterCount")
        self.filter_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.queue_label = QLabel("Live")
        self.queue_label.setObjectName("queueState")
        self.queue_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_heading = QLabel("Event details")
        self.detail_heading.setObjectName("detailHeading")
        self.detail_summary = QLabel("Select an event to inspect raw JSON and timing details.")
        self.detail_summary.setObjectName("detailSummary")
        self.detail_summary.setWordWrap(True)
        for label in (
            self.total_label,
            self.deny_label,
            self.audit_label,
            self.epoch_label,
            self.avg_latency_label,
        ):
            label.setObjectName("statValue")
        self.deny_label.setObjectName("denyValue")
        self.connection_dashboard_label.setObjectName("statePill")
        self.connection_runtime_label.setObjectName("statePill")
        self.connection_status_label.setObjectName("statePill")
        for label in (
            self.connection_dashboard_label,
            self.connection_runtime_label,
            self.connection_status_label,
        ):
            self._set_state_label(label, "disconnected")
        self.popup_toggle = QCheckBox("Deny popups")
        self.runtime_popup_toggle = QCheckBox("Deny popups")
        for toggle in (self.popup_toggle, self.runtime_popup_toggle):
            toggle.setChecked(popups_enabled)
            toggle.toggled.connect(self._toggle_popups)
        self.pause_toggle = QCheckBox("Pause stream")
        self.pause_toggle.setToolTip("Hold incoming events without adding them to the table.")
        self.pause_toggle.toggled.connect(self._toggle_pause)
        self.follow_toggle = QCheckBox("Follow latest")
        self.follow_toggle.setToolTip("Keep event tables scrolled to the newest visible row.")
        self.follow_toggle.setChecked(True)

        self.clear_filters_button = self._toolbar_button(
            "Reset",
            QStyle.StandardPixmap.SP_BrowserReload,
            "Clear all event filters.",
        )
        self.clear_filters_button.clicked.connect(self._clear_filters)
        self.latest_button = self._toolbar_button(
            "Newest",
            QStyle.StandardPixmap.SP_ArrowDown,
            "Select the newest visible event.",
        )
        self.latest_button.clicked.connect(self._select_latest_event)
        self.copy_detail_button = self._toolbar_button(
            "Copy JSON",
            QStyle.StandardPixmap.SP_DialogSaveButton,
            "Copy the selected event JSON to the clipboard.",
        )
        self.copy_detail_button.setEnabled(False)
        self.copy_detail_button.clicked.connect(self._copy_detail_json)

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
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((86, 78, 132, 62, 96, 70, 76, 70, 320, 160)):
            self.table.setColumnWidth(column, width)

        self.dashboard_table = QTableView()
        self.dashboard_table.setModel(self.model)
        self.dashboard_table.setAlternatingRowColors(True)
        self.dashboard_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.dashboard_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.dashboard_table.verticalHeader().setVisible(False)
        self.dashboard_table.verticalHeader().setDefaultSectionSize(28)
        self.dashboard_table.horizontalHeader().setStretchLastSection(True)
        self.dashboard_table.setColumnWidth(0, 86)
        self.dashboard_table.setColumnWidth(1, 78)
        self.dashboard_table.setColumnWidth(2, 132)
        self.dashboard_table.setColumnWidth(8, 420)
        for column in (4, 5, 6, 7):
            self.dashboard_table.setColumnHidden(column, True)

        self.metrics_table = QTableWidget(0, 5)
        self.metrics_table.setHorizontalHeaderLabels(["Hook", "Layer", "Action", "Count", "Avg us"])
        self.metrics_table.horizontalHeader().setStretchLastSection(True)
        self.metrics_table.verticalHeader().setVisible(False)

        self._build_ui()
        self._create_client(replay_path)

    def closeEvent(self, event: Any) -> None:
        self.client.stop()
        super().closeEvent(event)

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.setObjectName("mainTabs")
        tabs.setDocumentMode(True)
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
        tab.setObjectName("page")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)
        layout.addWidget(self._dashboard_header())
        layout.addWidget(self._summary_panel())
        lower = QHBoxLayout()
        lower.setSpacing(14)
        lower.addWidget(self._layer_panel(), 1)
        lower.addWidget(self._latest_panel(), 2)
        layout.addLayout(lower)
        layout.addWidget(self._recent_panel(), 1)
        return tab

    def _dashboard_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("dashboardHeader")
        self._add_shadow(header, y_offset=12, blur_radius=28, color=QColor(15, 23, 42, 48))
        layout = QHBoxLayout(header)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(16)
        accent = QFrame()
        accent.setObjectName("headerAccent")
        accent.setFixedSize(4, 54)
        title_col = QVBoxLayout()
        title_col.setSpacing(4)
        title = QLabel("MCP Guard Runtime")
        title.setObjectName("dashboardTitle")
        subtitle = QLabel(f"Local enforcement telemetry  |  {self.socket_path}")
        subtitle.setObjectName("dashboardSubtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        layout.addWidget(accent)
        layout.addLayout(title_col)
        layout.addStretch(1)
        layout.addWidget(self.posture_label)
        layout.addWidget(self.popup_toggle)
        return header

    def _summary_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("cardBand")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(2, 2, 2, 10)
        layout.setSpacing(12)
        cards = [
            ("Connection", self.connection_dashboard_label, "Live loader state", "statCard"),
            ("Events", self.total_label, "Recent buffered events", "statCard"),
            ("Denied", self.deny_label, "Policy blocks", "statCardDanger"),
            ("Audit", self.audit_label, "Observed warnings", "statCardWarn"),
            ("Epoch", self.epoch_label, "Latest policy epoch", "statCard"),
            ("Avg latency", self.avg_latency_label, "Event mean", "statCard"),
        ]
        for title, widget, caption, object_name in cards:
            layout.addWidget(self._stat_card(title, widget, caption, object_name))
        return panel

    def _stat_card(self, title: str, value: QLabel, caption: str, object_name: str) -> QWidget:
        card = QFrame()
        card.setObjectName(object_name)
        card.setMinimumHeight(96)
        self._add_shadow(card)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setObjectName("statTitle")
        caption_label = QLabel(caption)
        caption_label.setObjectName("statCaption")
        card_layout.addWidget(title_label)
        card_layout.addWidget(value)
        card_layout.addWidget(caption_label)
        return card

    def _layer_panel(self) -> QWidget:
        box = QGroupBox("Layer distribution")
        box.setObjectName("surfaceGroup")
        self._add_shadow(box)
        layout = QVBoxLayout(box)
        layout.setContentsMargins(14, 20, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(self.layer_label)
        for layer in ("L1", "L2", "L3"):
            row = QHBoxLayout()
            row.setSpacing(10)
            label = QLabel(layer)
            label.setObjectName("filterLabel")
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(True)
            bar.setFormat("0%")
            bar.setObjectName(f"layerBar{layer}")
            row.addWidget(label)
            row.addWidget(bar, 1)
            layout.addLayout(row)
            self.layer_bars[layer] = bar
        return box

    def _latest_panel(self) -> QWidget:
        latest = QGroupBox("Latest high-risk event")
        latest.setObjectName("surfaceGroup")
        self._add_shadow(latest)
        latest_layout = QVBoxLayout(latest)
        latest_layout.setContentsMargins(16, 22, 16, 16)
        latest_layout.setSpacing(8)
        latest_layout.addWidget(self.latest_action_label)
        latest_layout.addWidget(self.latest_target_label)
        latest_layout.addWidget(self.latest_meta_label)
        latest_layout.addStretch(1)
        return latest

    def _recent_panel(self) -> QWidget:
        recent = QGroupBox("Recent events")
        recent.setObjectName("surfaceGroup")
        self._add_shadow(recent)
        layout = QVBoxLayout(recent)
        layout.setContentsMargins(14, 22, 14, 14)
        layout.setSpacing(10)
        hint = QLabel("Newest security decisions")
        hint.setObjectName("sectionHint")
        layout.addWidget(hint)
        layout.addWidget(self.dashboard_table)
        return recent

    def _events_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("page")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(self._filter_bar())
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self._detail_panel())
        splitter.setSizes([930, 350])
        layout.addWidget(splitter)
        return tab

    def _detail_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailPanel")
        self._add_shadow(panel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        heading_row = QHBoxLayout()
        heading_row.addWidget(self.detail_heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self.copy_detail_button)
        layout.addLayout(heading_row)
        layout.addWidget(self.detail_summary)
        layout.addWidget(self.detail, 1)
        return panel

    def _filter_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("filterBar")
        self._add_shadow(bar)
        bar.setFixedHeight(96)
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(8)
        filter_row = QHBoxLayout()
        filter_row.setSpacing(9)
        action_row = QHBoxLayout()
        action_row.setSpacing(9)
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
        for label_text, widget in (
            ("Action", self.action_filter),
            ("Hook", self.hook_filter),
            ("Layer", self.layer_filter),
            ("Profile", self.profile_filter),
            ("Agent", self.agent_filter),
            ("Search", self.search_filter),
        ):
            label = QLabel(label_text)
            label.setObjectName("filterLabel")
            filter_row.addWidget(label)
            filter_row.addWidget(widget)
        filter_row.addStretch(1)
        action_row.addWidget(self.pause_toggle)
        action_row.addWidget(self.follow_toggle)
        action_row.addWidget(self.clear_filters_button)
        action_row.addWidget(self.latest_button)
        action_row.addStretch(1)
        action_row.addWidget(self.queue_label)
        action_row.addWidget(self.filter_count_label)
        for widget in (
            self.action_filter,
            self.hook_filter,
            self.layer_filter,
            self.profile_filter,
            self.agent_filter,
            self.search_filter,
        ):
            widget.setMinimumWidth(86)
            widget.setMaximumHeight(30)
        layout.addLayout(filter_row)
        layout.addLayout(action_row)
        self.action_filter.currentTextChanged.connect(self._apply_filters)
        self.hook_filter.currentTextChanged.connect(self._apply_filters)
        self.layer_filter.currentTextChanged.connect(self._apply_filters)
        self.profile_filter.textChanged.connect(self._apply_filters)
        self.agent_filter.textChanged.connect(self._apply_filters)
        self.search_filter.textChanged.connect(self._apply_filters)
        return bar

    def _toolbar_button(
        self,
        text: str,
        icon: QStyle.StandardPixmap,
        tooltip: str,
    ) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("toolbarButton")
        button.setIcon(self.style().standardIcon(icon))
        button.setToolTip(tooltip)
        button.setMaximumHeight(30)
        return button

    def _combo(self, values: list[str]) -> QComboBox:
        combo = QComboBox()
        combo.addItems(values)
        return combo

    def _metrics_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("page")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)
        summary = QFrame()
        summary.setObjectName("metricsPanel")
        self._add_shadow(summary)
        summary_layout = QVBoxLayout(summary)
        summary_layout.setContentsMargins(16, 14, 16, 14)
        metrics_title = QLabel("Metrics")
        metrics_title.setObjectName("panelTitle")
        summary_layout.addWidget(metrics_title)
        summary_layout.addWidget(self.metrics_summary_label)
        layout.addWidget(summary)
        layout.addWidget(self.metrics_table)
        return tab

    def _runtime_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("page")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        form_box = QGroupBox("Runtime")
        form_box.setObjectName("surfaceGroup")
        self._add_shadow(form_box)
        form = QFormLayout(form_box)
        form.setContentsMargins(16, 24, 16, 16)
        form.setSpacing(12)
        form.addRow("Socket", QLabel(self.socket_path))
        form.addRow("Connection", self.connection_runtime_label)
        form.addRow("Last error", self.error_label)
        form.addRow("Last reload", self.reload_label)
        form.addRow("Alerts", self.runtime_popup_toggle)
        layout.addWidget(form_box)
        layout.addStretch(1)
        return tab

    def _add_shadow(
        self,
        widget: QWidget,
        *,
        y_offset: int = 8,
        blur_radius: int = 20,
        color: QColor = QColor(15, 23, 42, 28),
    ) -> None:
        shadow = QGraphicsDropShadowEffect(widget)
        shadow.setBlurRadius(blur_radius)
        shadow.setOffset(0, y_offset)
        shadow.setColor(color)
        widget.setGraphicsEffect(shadow)

    def _add_event(self, payload: dict[str, Any]) -> None:
        if self.pause_toggle.isChecked():
            self._queued_events.append(dict(payload))
            if len(self._queued_events) > self.store.max_events:
                self._queued_events.pop(0)
            self._update_queue_label()
            return
        self._ingest_event(payload)

    def _ingest_event(self, payload: dict[str, Any]) -> EventRecord:
        event = self.model.add_payload(payload)
        self._update_dashboard()
        self._update_filter_count()
        if self.follow_toggle.isChecked():
            self._scroll_to_latest()
        if event.action == "deny":
            self.alerts.show_event(event)
        return event

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
        self._set_state_label(self.connection_dashboard_label, state)
        self._set_state_label(self.connection_runtime_label, state)
        self._set_state_label(self.connection_status_label, state)

    def _set_state_label(self, label: QLabel, state: str) -> None:
        label.setText(state)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    def _error_received(self, error: str) -> None:
        self.runtime.last_error = error
        self.error_label.setText(error or "")
        if error:
            self.statusBar().showMessage(error, 5000)

    def _toggle_popups(self, enabled: bool) -> None:
        self.alerts.enabled = enabled
        for toggle in (self.popup_toggle, self.runtime_popup_toggle):
            if toggle.isChecked() != enabled:
                toggle.blockSignals(True)
                toggle.setChecked(enabled)
                toggle.blockSignals(False)

    def _toggle_pause(self, paused: bool) -> None:
        if paused:
            self._update_queue_label()
            self.statusBar().showMessage("Event stream paused", 2500)
            return
        queued = list(self._queued_events)
        self._queued_events.clear()
        for payload in queued:
            self._ingest_event(payload)
        self._update_queue_label()
        if queued:
            self.statusBar().showMessage(f"Added {len(queued)} queued events", 3000)

    def _update_queue_label(self) -> None:
        queued = len(self._queued_events)
        if self.pause_toggle.isChecked():
            self.queue_label.setText(f"Paused / {queued} queued")
            self.queue_label.setProperty("state", "paused")
        else:
            self.queue_label.setText("Live")
            self.queue_label.setProperty("state", "live")
        self.queue_label.style().unpolish(self.queue_label)
        self.queue_label.style().polish(self.queue_label)

    def _clear_filters(self) -> None:
        widgets = [
            self.action_filter,
            self.hook_filter,
            self.layer_filter,
            self.profile_filter,
            self.agent_filter,
            self.search_filter,
        ]
        for widget in widgets:
            widget.blockSignals(True)
        self.action_filter.setCurrentText("all")
        self.hook_filter.setCurrentText("all")
        self.layer_filter.setCurrentText("all")
        self.profile_filter.clear()
        self.agent_filter.clear()
        self.search_filter.clear()
        for widget in widgets:
            widget.blockSignals(False)
        self._apply_filters()
        self._scroll_to_latest()
        self.statusBar().showMessage("Filters reset", 2000)

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
        self._update_filter_count()
        if self.follow_toggle.isChecked():
            self._scroll_to_latest()

    def _update_filter_count(self) -> None:
        self.filter_count_label.setText(
            f"{self.model.rowCount()} shown / {len(self.store.events)} total"
        )

    def _select_latest_event(self) -> None:
        if self.model.rowCount() == 0:
            self.statusBar().showMessage("No visible events", 2000)
            return
        row = self.model.rowCount() - 1
        self.table.selectRow(row)
        self.table.scrollTo(self.model.index(row, 0), QAbstractItemView.ScrollHint.PositionAtCenter)
        self.dashboard_table.selectRow(row)
        self.dashboard_table.scrollTo(
            self.model.index(row, 0),
            QAbstractItemView.ScrollHint.PositionAtCenter,
        )
        self.statusBar().showMessage("Newest visible event selected", 2000)

    def _scroll_to_latest(self) -> None:
        if self.model.rowCount() == 0:
            return
        self.table.scrollToBottom()
        self.dashboard_table.scrollToBottom()

    def _update_dashboard(self) -> None:
        self.total_label.setText(str(len(self.store.events)))
        self.deny_label.setText(str(self.store.count_by_action.get("deny", 0)))
        self.audit_label.setText(str(self.store.count_by_action.get("audit", 0)))
        self.epoch_label.setText(str(self.store.current_epoch))
        self.avg_latency_label.setText(f"{self.store.average_latency_us:.3f} us")
        deny_count = self.store.count_by_action.get("deny", 0)
        if deny_count:
            self.posture_label.setText(f"{deny_count} blocked")
            self.posture_label.setProperty("posture", "active")
        else:
            self.posture_label.setText("Monitoring")
            self.posture_label.setProperty("posture", "quiet")
        self.posture_label.style().unpolish(self.posture_label)
        self.posture_label.style().polish(self.posture_label)
        total = max(len(self.store.events), 1)
        layer_text = "  ".join(
            f"{layer}: {self.store.count_by_layer.get(layer, 0)} "
            f"({self.store.count_by_layer.get(layer, 0) / total:.0%})"
            for layer in ("L1", "L2", "L3")
        )
        self.layer_label.setText(layer_text)
        for layer, bar in self.layer_bars.items():
            count = self.store.count_by_layer.get(layer, 0)
            ratio = int(count / total * 100)
            bar.setValue(ratio)
            bar.setFormat(f"{count} events / {ratio}%")
        if self.store.latest_high_risk:
            event = self.store.latest_high_risk
            self.latest_action_label.setText(f"{event.action.upper()} / {event.hook}")
            self.latest_target_label.setText(event.target)
            self.latest_meta_label.setText(
                f"rule={event.rule}  profile={event.profile_id}  "
                f"agent={event.agent_id}  duration={event.duration_us:.3f} us"
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
        self.selected_event = event
        self.copy_detail_button.setEnabled(True)
        pretty = json.dumps(event.raw, indent=2, ensure_ascii=False)
        self.detail_heading.setText(f"{event.action.upper()} / {event.hook}")
        self.detail_summary.setText(
            f"{event.target} | rule={event.rule} | "
            f"profile={event.profile_id} agent={event.agent_id}"
        )
        self.detail.setPlainText(
            f"{pretty}\n\n"
            f"duration_us={event.duration_us:.3f}\n"
            f"model_us={event.model_us:.3f}\n"
            f"delta_us={event.delta_us:.3f}\n"
            f"profile_id={event.profile_id}\n"
            f"agent_id={event.agent_id}\n"
            f"resource_id={event.resource_id}"
        )

    def _copy_detail_json(self) -> None:
        if not self.selected_event:
            self.statusBar().showMessage("Select an event first", 2000)
            return
        QApplication.clipboard().setText(
            json.dumps(self.selected_event.raw, indent=2, ensure_ascii=False)
        )
        self.statusBar().showMessage("Event JSON copied", 2000)
