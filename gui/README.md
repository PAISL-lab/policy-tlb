<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MCP Guard GUI

PySide6 desktop GUI for MCP Guard.

## Layout

```text
gui/
  run_gui.py              executable entrypoint
  requirements.txt        Python dependencies
  mcp_guard_gui/          application package
  resources/              stylesheet assets
  samples/                replayable demo event streams
```

## Setup

```bash
cd gui
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Replay Mode

Run without the loader or root privileges:

```bash
python3 run_gui.py --replay samples/events.ndjson
```

Useful options:

```bash
python3 run_gui.py --replay samples/events.ndjson --no-popups
python3 run_gui.py --replay samples/events.ndjson --replay-interval-ms 10
python3 run_gui.py --max-events 1000
python3 run_gui.py --socket /tmp/mcp-guard.sock
python3 run_gui.py --background
python3 run_gui.py --quit-on-close
```

## Live Loader Mode

Start the loader:

```bash
sudo ./mcp-guard policies
```

On a desktop session, the loader automatically starts the GUI when using the
default `policies` directory. Auto-launched GUI instances open the main window
by default. Closing the window hides it and keeps deny popups active in the
background. To start the GUI manually instead:

```bash
sudo ./mcp-guard policies --no-gui
cd gui
python3 run_gui.py
```

The GUI connects to `/tmp/mcp-guard.sock` by default.
Closing the main window hides it and keeps the notification listener running by
default, so deny popups can still appear. Use the tray menu's `Quit GUI` action
or start with `--quit-on-close` when you want closing the window to stop the GUI
process.

Force GUI startup with a non-default policy directory:

```bash
sudo ./mcp-guard /path/to/policies --gui
```

## Troubleshooting

- If live mode shows `disconnected`, start `mcp-guard` first and confirm
  `/tmp/mcp-guard.sock` exists.
- If auto-launch fails, check `/tmp/mcp-guard-gui.log`.
- Use `python3 run_gui.py --background` to keep only tray/background alerts
  without opening the main window.
- If deny events print in the loader but no popup appears, confirm a
  `gui/run_gui.py` process is still running and check `/tmp/mcp-guard-gui.log`.
- The GUI does not need `sudo`; only the loader needs privileges.
- Use replay mode for UI work when BPF or the loader is not running.

## License Boundary

The GUI is licensed under AGPL-3.0-or-later and is designed to run as a
separate program from the GPL-licensed core enforcement engine. It communicates
with the core through the Unix domain socket newline-delimited JSON event
protocol and should not directly link against or copy GPL core implementation
code.
