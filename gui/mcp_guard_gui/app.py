import argparse
import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .resources import load_stylesheet, resource_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP Guard desktop GUI")
    parser.add_argument(
        "--socket",
        default="/tmp/mcp-guard.sock",
        help="Unix socket path exposed by the mcp-guard loader",
    )
    parser.add_argument(
        "--demo",
        type=Path,
        help="Replay newline-delimited sample JSON events instead of connecting to the loader",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    app = QApplication(sys.argv[:1])
    app.setApplicationName("MCP Guard")
    app.setStyleSheet(load_stylesheet())

    icon = resource_path("icon.png")
    if icon.exists():
        app.setWindowIcon(QIcon(str(icon)))

    window = MainWindow(socket_path=args.socket, demo_path=args.demo)
    window.resize(1280, 760)
    window.show()
    return app.exec()
