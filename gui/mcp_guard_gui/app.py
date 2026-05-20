# SPDX-License-Identifier: Apache-2.0
import argparse
import sys
from pathlib import Path

from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

from .main_window import MainWindow
from .resources import load_stylesheet, resource_path


def create_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv[:1])
    app.setApplicationName("MCP Guard")
    app.setStyleSheet(load_stylesheet())

    icon = resource_path("icon.png")
    if icon.exists() and icon.stat().st_size > 0:
        app.setWindowIcon(QIcon(str(icon)))
    else:
        app.setWindowIcon(app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
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
        "--replay-interval-ms",
        type=int,
        default=100,
        help="Milliseconds between replayed events",
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
        "--background",
        action="store_true",
        help="Run without showing the main window; deny popups remain enabled",
    )
    parser.add_argument(
        "--tray",
        action="store_true",
        help="Run in the system tray and keep listening after the window is hidden",
    )
    parser.add_argument(
        "--quit-on-close",
        action="store_true",
        help="Exit the GUI when the main window is closed instead of hiding it",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=5000,
        help="Maximum number of events to keep in memory",
    )
    return parser.parse_args(argv)


def create_tray_icon(app: QApplication, window: MainWindow) -> QSystemTrayIcon | None:
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return None

    icon_path = resource_path("icon.png")
    icon = (
        QIcon(str(icon_path))
        if icon_path.exists() and icon_path.stat().st_size > 0
        else app.windowIcon()
    )
    tray = QSystemTrayIcon(icon, app)
    tray.setToolTip("MCP Guard")

    menu = QMenu()
    show_action = QAction("Show MCP Guard", menu)
    hide_action = QAction("Hide Window", menu)
    quit_action = QAction("Quit GUI", menu)
    show_action.triggered.connect(window.showNormal)
    show_action.triggered.connect(window.raise_)
    show_action.triggered.connect(window.activateWindow)
    hide_action.triggered.connect(window.hide)
    quit_action.triggered.connect(window.quit_application)
    quit_action.triggered.connect(app.quit)
    menu.addAction(show_action)
    menu.addAction(hide_action)
    menu.addSeparator()
    menu.addAction(quit_action)
    tray.setContextMenu(menu)
    tray.activated.connect(
        lambda reason: window.showNormal()
        if reason == QSystemTrayIcon.ActivationReason.Trigger
        else None
    )
    tray.show()
    return tray


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    app = create_app()
    background = args.background or args.tray
    keep_alive = not args.quit_on_close
    app.setQuitOnLastWindowClosed(False if keep_alive else not background)

    replay_path = args.replay or args.demo
    window = MainWindow(
        socket_path=args.socket,
        replay_path=replay_path,
        max_events=max(args.max_events, 1),
        popups_enabled=not args.no_popups,
        close_to_tray=keep_alive,
        replay_interval_ms=max(args.replay_interval_ms, 1),
    )
    window.resize(1280, 760)
    tray = create_tray_icon(app, window) if background else None
    if not background:
        window.show()
    elif not tray:
        print("MCP Guard GUI running in background mode without system tray support.")
    return app.exec()
