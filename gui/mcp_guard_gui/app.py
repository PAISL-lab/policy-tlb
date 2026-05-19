# SPDX-License-Identifier: Apache-2.0
import argparse
import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .resources import load_stylesheet, resource_path


def create_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv[:1])
    app.setApplicationName("MCP Guard")
    app.setStyleSheet(load_stylesheet())

    icon = resource_path("icon.png")
    if icon.exists():
        app.setWindowIcon(QIcon(str(icon)))
    return app


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP Guard desktop GUI")
    parser.add_argument(
        "--socket",
        default="/tmp/mcp-guard.sock",
        help="Unix socket path exposed by the mcp-guard loader",
    )
    parser.add_argument(
        "--replay",
        type=Path,
        help="Replay newline-delimited sample JSON events instead of connecting to the loader",
    )
    parser.add_argument(
        "--demo",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-popups",
        action="store_true",
        help="Start with deny popup notifications disabled",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=5000,
        help="Maximum number of events to keep in memory",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    app = create_app()

    replay_path = args.replay or args.demo
    window = MainWindow(
        socket_path=args.socket,
        replay_path=replay_path,
        max_events=max(args.max_events, 1),
        popups_enabled=not args.no_popups,
    )
    window.resize(1280, 760)
    window.show()
    return app.exec()
