# GUI Development Guide

This guide is for the developer owning the desktop GUI. The GUI should consume loader events from `/tmp/mcp-guard.sock`, render security alerts, and provide a clear runtime view of MCP Guard behavior.

## Goal

Build a Qt GUI that can run independently of loader development as long as the socket event contract remains stable.

Current GUI directory is an empty skeleton:

- `gui/src/main.cpp`
- `gui/src/MainWindow.*`
- `gui/src/SocketClient.*`
- `gui/src/AlertPopup.*`
- `gui/resources/style.qss`
- `gui/resources/icon.png`

## External Contract

The GUI connects to a Unix domain socket:

```text
/tmp/mcp-guard.sock
```

The loader sends one JSON object per line. Example:

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

Required fields for v1 display:

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

The GUI must ignore unknown fields.

## UI Requirements

The first screen should be the operational dashboard, not a landing page.

Primary layout:

- Top status bar: connection state, event count, deny count, current filter.
- Main event table: time, action, hook, layer, duration, pid, path/destination, rule.
- Right details panel: selected event JSON fields, timing comparison, suggested response.
- Bottom status area: socket path and last error.

Use restrained operational styling. This is a security dashboard, so prioritize readability and scanning over decoration.

## Components

### `SocketClient`

Responsibilities:

- Connect to `/tmp/mcp-guard.sock`.
- Read newline-delimited JSON.
- Reconnect with backoff when the loader is not running.
- Emit parsed event objects to the UI.
- Expose connection states: disconnected, connecting, connected, error.

Implementation notes:

- Use `QLocalSocket`.
- Buffer partial reads until newline.
- Parse with `QJsonDocument`.
- Never block the UI thread.
- Treat malformed JSON as a recoverable error and keep reading.

### `MainWindow`

Responsibilities:

- Own the dashboard layout.
- Maintain an in-memory event model.
- Provide filtering by action, hook, layer, and text search.
- Show event counters and latest status.

Recommended model fields:

- `timestampNs`
- `pid`
- `uid`
- `hook`
- `action`
- `layer`
- `durationNs`
- `ruleId`
- `error`
- `path`
- `rule`
- `port`

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
- `duration_us = duration_ns / 1000`
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

Keep the color as a secondary signal; the table text must remain readable.

## Development Tasks

1. Fill `gui/CMakeLists.txt`.
   - Use Qt Widgets.
   - Build a `mcp-guard-gui` executable.
   - Include `gui/resources/style.qss` and `gui/resources/icon.png`.

2. Implement `SocketClient`.
   - Add connection, reconnect, read buffer, JSON parse, and event signal.
   - Make socket path configurable, defaulting to `/tmp/mcp-guard.sock`.

3. Implement `MainWindow`.
   - Build the dashboard layout.
   - Add event table and details panel.
   - Wire `SocketClient` signals to the event model.
   - Add filters and counters.

4. Implement `AlertPopup`.
   - Trigger on deny events.
   - Show compact event information.
   - Auto-dismiss without focus stealing.

5. Add offline/demo mode.
   - Provide a local sample JSON event stream for UI development when the loader is not running.
   - This lets GUI work continue without root or BPF access.

## Test Plan

Manual test with live loader:

```bash
sudo ./mcp-guard policies
./gui/build/mcp-guard-gui
curl https://example.com
```

Expected GUI behavior:

- Connection state becomes connected.
- Deny event appears in the table.
- Alert popup appears.
- Details panel shows `layer`, `duration_ns`, and rule.

Manual test without loader:

- Start GUI while `/tmp/mcp-guard.sock` does not exist.
- GUI shows disconnected state.
- Start loader later.
- GUI reconnects without restart.

Malformed input test:

- Send a bad JSON line through a test socket.
- GUI records an error state but keeps running.

## Coordination With Loader Developer

The GUI depends on the loader's JSON field names. Coordinate through `docs/loader-development-guide.md`.

Compatibility rules:

- Unknown fields are ignored.
- Missing optional fields render as `-`.
- Missing required fields should not crash the GUI; mark the event as malformed.
- New loader fields should be added to the details panel before being promoted into table columns.

