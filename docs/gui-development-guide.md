# GUI Development Guide

This guide is for the developer owning the desktop GUI. The GUI should consume loader events from `/tmp/mcp-guard.sock`, render security alerts, and provide a clear runtime view of MCP Guard behavior.

## Technology Choice

Use **Python 3 + PySide6 (Qt for Python)** for the GUI.

Why PySide6:

- The repository already has a Qt stylesheet at `gui/resources/style.qss`.
- Unix socket JSON-line clients are straightforward in Python.
- Qt Widgets provide strong table, filtering, splitter, tab, and dialog support.
- PySide6 is fast enough for the current event volume and keeps iteration fast.
- The GUI can be developed without root privileges by replaying sample JSON lines.

GTK is a valid Linux-native option, but it cannot reuse `style.qss` and is less convenient for this dashboard's table/chart-heavy workflow. Use PySide6 unless the project explicitly pivots to a GNOME/libadwaita app.

## Goal

Build a PySide6 desktop GUI that can run independently of loader development as long as the socket event contract remains stable.

The GUI tree is Python-only. Application code lives under `gui/mcp_guard_gui/`, while `gui/resources/` stores Qt assets and `gui/samples/` stores replayable demo events.

Recommended structure:

```text
gui/
  run_gui.py
  requirements.txt
  mcp_guard_gui/
    __init__.py
    app.py
    socket_client.py
    models.py
    main_window.py
    alert_popup.py
    resources.py
  resources/
    style.qss
    icon.png
  samples/
    events.ndjson
```

Future UI growth can split `main_window.py` into `views/dashboard.py`,
`views/events.py`, `views/metrics.py`, and `views/policy.py` once the window
logic becomes too large.

## Runtime Contract

The GUI connects to a Unix domain socket:

```text
/tmp/mcp-guard.sock
```

The loader sends one newline-delimited JSON object per event. Current event example:

```json
{
  "ts_ns": 123,
  "pid": 15263,
  "uid": 0,
  "hook": "exec",
  "action": "deny",
  "layer": "L3",
  "duration_ns": 3887,
  "rule_id": 1,
  "error": 13,
  "path": "/usr/bin/true",
  "rule": "test-true",
  "port": 0
}
```

Current required fields for v1 display:

- `ts_ns`
- `pid`
- `uid`
- `hook`
- `action`
- `layer`
- `duration_ns`
- `rule_id`
- `error`
- `path`
- `rule`
- `port`

Fields expected soon from the loader:

- `type`: `event`, `metrics_snapshot`, `reload_result`, or `health`
- `tgid`
- `comm`
- `epoch`
- `resource_id`
- `duration_us`
- `model_us`
- `delta_us`
- metrics payloads for hook/layer/action counters and histogram buckets

Compatibility rule: unknown fields must be ignored, and missing optional fields render as `-`.

## UI Requirements

The first screen must be the operational dashboard, not a landing page.

Primary layout:

- Top status bar: connection state, socket path, event count, deny count, current epoch.
- Left navigation tabs: Dashboard, Events, Metrics, Policy.
- Main dashboard: L1/L2/L3 hit counts, deny count, latest high-risk event, average latency.
- Events table: time, action, hook, layer, duration, pid, path/destination, rule.
- Details panel: selected event JSON, timing comparison, decision reason, process metadata.
- Bottom status area: last socket error and last reload result.

Use restrained operational styling. This is a security dashboard, so prioritize readability, density, and fast scanning over decorative visuals.

## PySide6 Components

### `SocketClient`

Responsibilities:

- Connect to `/tmp/mcp-guard.sock`.
- Read newline-delimited JSON.
- Reconnect with exponential backoff when the loader is not running.
- Emit parsed Python dictionaries to the UI.
- Expose connection states: `disconnected`, `connecting`, `connected`, `error`.

Implementation notes:

- Use `QLocalSocket` from PySide6.
- Buffer partial reads until newline.
- Parse with Python `json.loads`.
- Never block the UI thread.
- Treat malformed JSON as a recoverable error and keep reading.

### `EventStore`

Responsibilities:

- Keep an in-memory bounded list of recent events.
- Maintain counters by action, hook, and layer.
- Maintain current filters and filtered row indexes.
- Provide data to `QAbstractTableModel`.

Recommended normalized fields:

- `timestamp_ns`
- `pid`
- `tgid`
- `uid`
- `comm`
- `hook`
- `action`
- `layer`
- `duration_ns`
- `duration_us`
- `model_us`
- `delta_us`
- `rule_id`
- `error`
- `path`
- `rule`
- `port`
- `resource_id`
- `epoch`

### `MainWindow`

Responsibilities:

- Own the main dashboard layout.
- Connect `SocketClient` signals to models/views.
- Provide action/hook/layer/search filters.
- Show counters, connection state, and selected event details.
- Load `gui/resources/style.qss` at startup.

### `MetricsView`

Responsibilities:

- Show L1/L2/L3 counts and hit ratios.
- Show latency averages and histogram buckets when metrics snapshots are available.
- Fall back to event-derived counters when metrics snapshots are not available yet.

Initial implementation can use `QTableWidget`/`QTableView` and simple bars. Add `pyqtgraph` later only if charting becomes important.

### `AlertPopup`

Responsibilities:

- Show transient alerts for `action=deny`.
- Include action, hook, path/destination, rule, and duration.
- Avoid stealing focus.
- Auto-dismiss after a short timeout.

Do not show popups for every allow/audit event by default.

## Timing Display

Show timing in both raw and comparable forms:

- `duration_ns`
- `duration_us = duration_ns / 1000` if missing from loader
- model baseline:
  - L1: `0.018us`
  - L2: `0.023us`
  - L3: `0.989us`
- delta:
  - `duration_us - model_us`

Color guidance:

- Green: below or near model baseline.
- Yellow: within 5x model baseline.
- Red: above 5x model baseline.

Keep color as a secondary signal; the table text must remain readable.

## Development Tasks

1. Maintain PySide6 packaging.
   - Keep `gui/requirements.txt` as the minimal dependency list.
   - Keep `gui/run_gui.py` as the executable entrypoint.
   - Keep application modules under `gui/mcp_guard_gui/`.
   - Keep `style.qss` and `icon.png` under `gui/resources/`.

2. Extend `SocketClient`.
   - Connect/reconnect to `/tmp/mcp-guard.sock`.
   - Parse newline-delimited JSON.
   - Emit `event_received`, `metrics_received`, `reload_result_received`, and `connection_state_changed` signals.
   - Make socket path configurable.

3. Extend models.
   - Add `EventStore`.
   - Add `EventTableModel` using `QAbstractTableModel`.
   - Add filtering by action, hook, layer, and text search.
   - Keep a bounded event history to avoid unbounded memory growth.

4. Extend `MainWindow`.
   - Build Dashboard, Events, Metrics, and Policy tabs.
   - Wire socket signals into the store and views.
   - Add details panel for selected rows.
   - Add counters for deny/audit/allow and L1/L2/L3.

5. Extend `AlertPopup`.
   - Trigger on deny events.
   - Auto-dismiss without focus stealing.
   - Add a settings toggle to disable popups.

6. Add offline/demo mode.
   - Provide `gui/samples/events.ndjson`.
   - Add `--demo gui/samples/events.ndjson` option.
   - Let GUI work continue without root, BPF, or loader access.

7. Route metrics messages.
   - Display shutdown-summary-derived event counters initially.
   - Route loader `metrics_snapshot` messages to `MetricsView`.
   - Ignore unknown message types safely.

## Test Plan

Manual live-loader test:

```bash
sudo ./mcp-guard policies
python3 gui/run_gui.py
sudo cat /etc/shadow
```

Expected GUI behavior:

- Connection state becomes connected.
- Deny event appears in the table.
- Alert popup appears for the deny event.
- Details panel shows `layer`, `duration_ns`, `rule`, and `path`.

Manual L2/metrics observation:

```bash
sudo ./mcp-guard policies
python3 gui/run_gui.py
# run network/file activity in another terminal
```

Expected behavior:

- Events update live when deny/audit records arrive.
- L1/L2/L3 counters update from event-derived data.
- Loader `metrics_snapshot` messages update the Metrics tab without requiring GUI restart.

Manual no-loader test:

- Start GUI while `/tmp/mcp-guard.sock` does not exist.
- GUI shows disconnected state.
- Start loader later.
- GUI reconnects without restart.

Demo mode test:

```bash
python3 gui/run_gui.py --demo gui/samples/events.ndjson
```

Expected behavior:

- GUI displays sample events without requiring root.
- Filters, details panel, counters, and popup logic work.

Malformed input test:

- Feed a bad JSON line in demo mode or through a test socket.
- GUI records an error state but keeps running.

## Coordination With Loader Developer

The GUI depends on the loader's JSON field names. Coordinate through `docs/loader-development-guide.md`.

Compatibility rules:

- Unknown fields are ignored.
- Missing optional fields render as `-`.
- Missing required fields should not crash the GUI; mark the event as malformed.
- New loader fields should be added to the details panel before being promoted into table columns.
- When loader adds message types such as `metrics_snapshot`, `reload_result`, or `health`, the GUI should route by `type` and keep event rendering separate.
