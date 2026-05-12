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

## Demo Mode

Run without the loader or root privileges:

```bash
python3 run_gui.py --demo samples/events.ndjson
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
