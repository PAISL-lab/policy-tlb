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
  "profile_id": 42,
  "agent_id": 7,
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
- `profile_id`
- `agent_id`
- `error`
- `path`
- `rule`
- `port`

Additional message and timing fields sent by the loader:

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

## Phase 7 Implementation Scope

The GUI phase should turn the current skeleton into a usable operator
dashboard. It is not just a visual shell: it must consume live loader messages,
preserve recent event state, expose metrics, and keep working when the loader is
temporarily unavailable.

Core work:

- Make the PySide6 app launch cleanly from `gui/run_gui.py`.
- Stabilize `SocketClient` for `/tmp/mcp-guard.sock`.
- Parse `event`, `metrics_snapshot`, and `reload_result` messages.
- Render deny/audit/allow events in an Events table.
- Show L1/L2/L3 hit counts, hit ratios, and latency summaries.
- Show `profile_id` and `agent_id` for MCP agent attribution.
- Show transient deny alerts without stealing focus.
- Add reconnect handling and visible connection state.
- Add sample replay mode so GUI development works without root or BPF.
- Update `gui/README.md` with setup, live mode, and replay mode instructions.

Implementation order:

1. Finish socket ingestion.
   - Use `QLocalSocket`.
   - Buffer partial reads until newline.
   - Route by `type`.
   - Keep malformed JSON recoverable.

2. Finish data models.
   - Normalize missing fields.
   - Store bounded recent events.
   - Maintain counters by action, hook, layer, profile, and agent.
   - Expose an `EventTableModel`.

3. Finish the dashboard.
   - Top connection/status strip.
   - Summary counters.
   - L1/L2/L3 ratio cards or compact panels.
   - Latest deny/audit event panel.

4. Finish Events view.
   - Sortable table.
   - Filters for action, hook, layer, profile/agent, and text search.
   - Detail panel with raw JSON and timing comparison.

5. Finish Metrics view.
   - Consume loader `metrics_snapshot` JSON.
   - Display total counts, layer ratios, average/min/max latency, and histogram
     buckets.
   - Fall back to event-derived counters when no snapshot has arrived.

6. Finish Policy/Runtime view.
   - Show last reload result.
   - Show active epoch/generation when present.
   - Show current socket path and reconnect state.

7. Finish alerts.
   - Show popup only for `action=deny` by default.
   - Include hook, path/destination, rule, profile/agent, and duration.
   - Add a UI toggle to disable popups.

8. Finish replay and documentation.
   - Keep `gui/samples/events.ndjson` representative.
   - Add replay mode to `run_gui.py` or a small helper module.
   - Document live and replay workflows.

Out of scope for this phase:

- Editing kernel policy files from the GUI.
- Running privileged loader commands from the GUI.
- Remote monitoring over TCP.
- Long-term event persistence or database storage.

## Development Specification

This section is the implementation contract for Phase 7. A developer should be
able to implement the GUI directly from this section without needing to infer
module responsibilities from the rest of the repository.

### Command Line Interface

`gui/run_gui.py` must support these modes:

```bash
python gui/run_gui.py
python gui/run_gui.py --socket /tmp/mcp-guard.sock
python gui/run_gui.py --replay gui/samples/events.ndjson
python gui/run_gui.py --no-popups
```

Arguments:

| Argument | Required | Default | Behavior |
|---|---:|---|---|
| `--socket PATH` | no | `/tmp/mcp-guard.sock` | Unix socket path for live loader events |
| `--replay PATH` | no | none | Read newline-delimited sample JSON instead of connecting to the socket |
| `--no-popups` | no | false | Start with deny popups disabled |
| `--max-events N` | no | `5000` | Maximum in-memory event history |

Rules:

- `--replay` and live socket mode are mutually exclusive.
- The GUI must not require `sudo`.
- CLI parsing belongs in `gui/run_gui.py` or `gui/mcp_guard_gui/app.py`.

### Module Contract

Required modules and responsibilities:

| Module | Required Classes/Functions | Responsibility |
|---|---|---|
| `app.py` | `main(argv=None)`, `create_app()` | Parse CLI, create `QApplication`, load style, create `MainWindow` |
| `socket_client.py` | `SocketClient`, `ReplayClient` | Live socket ingestion and sample replay ingestion |
| `models.py` | `EventRecord`, `EventStore`, `EventTableModel`, `MetricsSnapshot`, `RuntimeStatus` | Normalize messages, hold state, expose table model |
| `main_window.py` | `MainWindow` | Build dashboard/events/metrics/runtime UI and wire signals |
| `alert_popup.py` | `AlertPopup`, optional `AlertManager` | Non-blocking deny notifications |
| `resources.py` | `load_stylesheet()`, `resource_path()` | Resolve `style.qss`, icons, and sample paths |

Do not reintroduce C++/Qt source files under `gui/src/`. The GUI implementation
is Python/PySide6 only.

### Signal Contract

`SocketClient` and `ReplayClient` must emit Qt signals with these meanings:

| Signal | Payload | Meaning |
|---|---|---|
| `message_received` | `dict` | Any parsed JSON object before routing |
| `event_received` | `dict` | A security event, usually `type=event` or missing `type` |
| `metrics_received` | `dict` | A `type=metrics_snapshot` message |
| `reload_result_received` | `dict` | A `type=reload_result` message |
| `connection_state_changed` | `str` | `disconnected`, `connecting`, `connected`, `replaying`, or `error` |
| `error_received` | `str` | Recoverable socket, replay, or JSON parse error |

Routing rules:

- Missing `type` means `event` for backward compatibility.
- Unknown `type` emits `message_received` and is ignored by event table logic.
- Malformed JSON emits `error_received` and does not stop ingestion.

### Event Schema

Normalize incoming events to `EventRecord` with these fields:

| Field | Type | Default | Display |
|---|---|---|---|
| `timestamp_ns` | int | `ts_ns` or `0` | Details, optional hidden sort key |
| `pid` | int | `0` | Table |
| `tgid` | int | `0` | Details |
| `uid` | int | `0` | Details |
| `comm` | str | `"-"` | Table/details |
| `hook` | str | `"-"` | Table/filter |
| `action` | str | `"-"` | Table/filter |
| `layer` | str | `"-"` | Table/filter |
| `duration_ns` | int | `0` | Table/details |
| `duration_us` | float | `duration_ns / 1000` | Table/details |
| `model_us` | float | by layer | Details |
| `delta_us` | float | `duration_us - model_us` | Details |
| `rule_id` | int | `0` | Details |
| `profile_id` | int | `0` | Table/details |
| `agent_id` | int | `0` | Table/details |
| `error` | int | `0` | Details |
| `path` | str | `"-"` | Table/details |
| `rule` | str | `"-"` | Table/details |
| `port` | int | `0` | Table/details when nonzero |
| `resource_id` | int | `0` | Details |
| `epoch` | int | `0` | Status/details |
| `raw` | dict | original message | Details JSON |

Model baseline by layer:

| Layer | `model_us` |
|---|---:|
| `L1` | `0.018` |
| `L2` | `0.023` |
| `L3` | `0.989` |
| unknown | `0.0` |

### Metrics Schema

The GUI must accept both current and future metrics JSON. Minimum required
behavior:

- If a message has `type=metrics_snapshot`, do not add it as an event row.
- Extract total count and L1/L2/L3 ratios when fields are present.
- If detailed hook/layer/action entries are present, render them in Metrics view.
- If no metrics snapshot has arrived, derive counts from `EventStore`.

Recommended normalized metrics fields:

| Field | Type | Default |
|---|---|---|
| `total` | int | `0` |
| `l1_ratio` | float | derived or `0.0` |
| `l2_ratio` | float | derived or `0.0` |
| `l3_ratio` | float | derived or `0.0` |
| `entries` | list[dict] | `[]` |
| `received_at` | datetime | now |

### Reload Result Schema

Normalize `type=reload_result` messages into `RuntimeStatus`.

Fields:

| Field | Type | Default |
|---|---|---|
| `success` | bool | false |
| `rule_count` | int | `0` |
| `generation` | int | `0` |
| `epoch` | int | `0` |
| `error` | str | `""` |

UI behavior:

- Show successful reloads in neutral/positive status color.
- Show failed reloads in warning status color.
- Do not clear the event table on reload.

### Event Store Rules

`EventStore` is the single source of truth for event-derived UI state.

Required behavior:

- Keep at most `max_events` records.
- Drop oldest records when capacity is exceeded.
- Maintain counters by:
  - action
  - hook
  - layer
  - profile_id
  - agent_id
- Maintain latest deny event.
- Maintain current epoch as the max nonzero epoch observed.
- Provide filtering without mutating the raw event list.

Filters:

| Filter | Values |
|---|---|
| action | `all`, `allow`, `deny`, `audit` |
| hook | `all`, `exec`, `file_open`, `file_read`, `file_write`, `socket_connect` |
| layer | `all`, `L1`, `L2`, `L3` |
| profile/agent | `all` or exact numeric id |
| text | substring match against `path`, `rule`, `comm`, `hook`, `action` |

### Event Table Columns

Required columns, in order:

| Column | Source |
|---|---|
| Time | `timestamp_ns`, formatted as local time when possible |
| Action | `action` |
| Hook | `hook` |
| Layer | `layer` |
| Duration | `duration_us` with 3 decimals |
| PID | `pid` |
| Profile | `profile_id` |
| Agent | `agent_id` |
| Target | `path` or `dst=:port` for network events |
| Rule | `rule` |

Rows:

- `deny` rows should be visually prominent but readable.
- `audit` rows should be distinct from `allow`.
- Never rely on color alone; keep text labels visible.

### Window Layout Specification

The first viewport must be the operational dashboard.

Recommended widget hierarchy:

```text
QMainWindow
  central QWidget
    QVBoxLayout
      Status strip
      QSplitter horizontal
        Navigation QListWidget or QTabWidget
        Main QStackedWidget
          Dashboard page
          Events page
          Metrics page
          Runtime page
      Bottom status line
```

Dashboard page:

- Summary row: connection, total events, deny count, current epoch/generation.
- Layer panel: L1/L2/L3 counts and ratios.
- Latency panel: average duration by layer, latest event duration.
- Latest deny/audit panel.

Events page:

- Filter toolbar.
- `QTableView` backed by `EventTableModel`.
- Details panel with raw JSON and timing comparison.

Metrics page:

- Snapshot timestamp.
- Layer ratio bars.
- Metrics table for hook/layer/action rows when available.
- Histogram bucket display when available.

Runtime page:

- Socket path.
- Connection state.
- Last socket error.
- Last reload result.
- Popup enabled/disabled setting.

### Alert Specification

Alert popup behavior:

- Trigger only for `action=deny` unless the user enables audit alerts later.
- Include: action, hook, target, rule, profile_id, agent_id, duration_us.
- Do not steal focus.
- Auto-dismiss after 5 seconds.
- Queue at most 3 visible popups; collapse additional alerts into a counter.
- Provide a UI toggle to disable future popups for the current session.

### Replay Specification

Replay mode is required for non-root GUI development.

Input format:

- One JSON object per line.
- Blank lines are ignored.
- Invalid lines emit `error_received` and replay continues.

Timing:

- Initial implementation may replay lines at 100 ms intervals.
- A future `--replay-speed` may be added, but is not required in Phase 7.

Replay mode state:

- `connection_state_changed` emits `replaying`.
- Replay messages go through the same normalization path as live socket messages.

### Error Handling

Required error handling:

- Missing socket path: show disconnected, retry.
- Socket disconnect: show disconnected, retry with backoff.
- JSON decode error: show last error, continue.
- Missing required event fields: create a malformed event record and show `-`
  for unavailable values.
- UI exceptions in message handling must not kill socket ingestion; catch and
  surface them through status/error display where practical.

Reconnect backoff:

- Start at 250 ms.
- Double up to a maximum of 5 seconds.
- Reset to 250 ms after a successful connection.

### Nonfunctional Requirements

- UI must remain responsive while ingesting events.
- No blocking socket reads on the UI thread.
- Memory must be bounded by `max_events`.
- Unknown JSON fields must be preserved in details via `raw`.
- The app must work on a normal user account.
- Styling must remain readable with `gui/resources/style.qss`.

### Implementation Checklist

- [ ] CLI supports live and replay mode.
- [ ] `SocketClient` handles reconnect and JSON lines.
- [ ] `ReplayClient` reads `events.ndjson`.
- [ ] `EventRecord` normalization handles missing fields.
- [ ] `EventStore` keeps bounded history and counters.
- [ ] `EventTableModel` exposes required columns.
- [ ] Dashboard shows counters, ratios, latest high-risk event.
- [ ] Events page supports filters and details panel.
- [ ] Metrics page handles `metrics_snapshot`.
- [ ] Runtime page shows socket/reload/error state.
- [ ] Deny popup works and can be disabled.
- [ ] `gui/README.md` documents setup, live mode, replay mode, troubleshooting.
- [ ] Manual test plan passes.

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
- `profile_id`
- `agent_id`
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

6. Add sample replay.
   - Read `gui/samples/events.ndjson`.
   - Feed messages through the same model path as live socket events.
   - Make replay mode usable without `sudo` or a running loader.

7. Update GUI documentation.
   - Document virtualenv setup.
   - Document live mode with `sudo ./mcp-guard policies`.
   - Document replay mode.
   - Include screenshots only after the UI is stable.

## Acceptance Criteria

- `python gui/run_gui.py` launches the GUI without root privileges.
- When the loader is not running, the GUI shows `disconnected` and keeps trying
  to reconnect without freezing.
- When `sudo ./mcp-guard policies` is running, the GUI receives live events from
  `/tmp/mcp-guard.sock`.
- Deny events appear in the Events table and trigger one popup by default.
- Metrics snapshots update the dashboard without blocking event ingestion.
- Reload results are visible in the runtime/status area.
- Missing optional JSON fields render as `-`; unknown fields do not crash the
  app.
- The app can replay `gui/samples/events.ndjson` without a running loader.
- `profile_id` and `agent_id` are visible in table or detail views.
- `gui/README.md` explains setup, live run, replay run, and troubleshooting.

## Manual Test Plan

Live mode:

```bash
sudo ./mcp-guard policies --metrics-interval 1s
python gui/run_gui.py
```

Trigger representative events:

```bash
/usr/bin/true
cat /tmp/some-protected-file
nc -vz 127.0.0.1 4444
```

Replay mode:

```bash
python gui/run_gui.py --replay gui/samples/events.ndjson
```

Check:

- Connection indicator changes correctly.
- Events table updates without UI stalls.
- Dashboard counters match incoming messages.
- Deny popup appears and auto-dismisses.
- Metrics and reload messages do not appear as normal event rows unless the UI
  intentionally has a system-message view.

## Coordination With Loader Developer

The GUI depends on the loader's JSON field names. Coordinate through `docs/loader-development-guide.md`.

Compatibility rules:

- Unknown fields are ignored.
- Missing optional fields render as `-`.
- Missing required fields should not crash the GUI; mark the event as malformed.
- New loader fields should be added to the details panel before being promoted into table columns.
- When loader adds message types such as `metrics_snapshot`, `reload_result`, or `health`, the GUI should route by `type` and keep event rendering separate.
