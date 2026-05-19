# MCP Guard GUI

PySide6 desktop GUI for MCP Guard.

## Layout

```text
gui/
  run_gui.py              executable entrypoint
  requirements.txt        Python dependencies
  mcp_guard_gui/          application package
  resources/              style and icon assets
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
python3 run_gui.py --max-events 1000
python3 run_gui.py --socket /tmp/mcp-guard.sock
```

## Live Loader Mode

Start the loader in another terminal:

```bash
sudo ./mcp-guard policies
```

Then run:

```bash
cd gui
python3 run_gui.py
```

The GUI connects to `/tmp/mcp-guard.sock` by default.

## Troubleshooting

- If live mode shows `disconnected`, start `mcp-guard` first and confirm
  `/tmp/mcp-guard.sock` exists.
- The GUI does not need `sudo`; only the loader needs privileges.
- Use replay mode for UI work when BPF or the loader is not running.
