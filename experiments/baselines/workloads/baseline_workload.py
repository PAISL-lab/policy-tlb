#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse
import errno
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def run_server(host: str, port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(256)
    srv.settimeout(0.1)
    try:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    conn.recv(16)
                    conn.sendall(b"ok")
                except OSError:
                    pass
    finally:
        srv.close()


def socket_event(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, port))
        sock.sendall(b"x")
        sock.recv(16)
        return "allow"
    except OSError as exc:
        if exc.errno == errno.EACCES:
            return "deny"
        return "fail"
    finally:
        sock.close()


def exec_event(command: str) -> str:
    proc = subprocess.run([command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return "allow" if proc.returncode == 0 else "deny"


def warm_file_event(fp, idx: int) -> str:
    try:
        if idx % 2:
            fp.seek(0)
            fp.read(32)
        else:
            fp.seek(0, os.SEEK_END)
            fp.write(b"x")
            fp.flush()
        return "allow"
    except OSError as exc:
        return "deny" if exc.errno == errno.EACCES else "fail"


def cold_file_event(base: Path, idx: int) -> str:
    path = base / f"cold_{idx}.dat"
    try:
        path.write_bytes(b"baseline\n")
        with path.open("r+b") as fp:
            fp.read(8)
            fp.write(b"x")
        path.unlink(missing_ok=True)
        return "allow"
    except OSError as exc:
        return "deny" if exc.errno == errno.EACCES else "fail"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--workload", choices=("warm", "cold", "mixed"), default="warm")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=45555)
    parser.add_argument("--command", default="/usr/bin/true")
    parser.add_argument("--socket-every", type=int, default=16)
    parser.add_argument("--exec-every", type=int, default=512)
    args = parser.parse_args()

    counts = {"allow": 0, "deny": 0, "fail": 0, "file": 0, "socket": 0, "exec": 0}
    stop = threading.Event()
    server = threading.Thread(target=run_server, args=(args.host, args.port, stop), daemon=True)
    server.start()
    time.sleep(0.15)

    try:
        with tempfile.TemporaryDirectory(prefix="mcpguard-baseline-") as tmp:
            base = Path(tmp)
            warm_path = base / "warm_agent_state.dat"
            warm_path.write_bytes(b"agent-state\n" * 16)

            with warm_path.open("r+b", buffering=0) as fp:
                for idx in range(args.events):
                    if args.workload == "cold":
                        result = cold_file_event(base, idx)
                        counts["file"] += 1
                    elif args.workload == "mixed" and args.exec_every > 0 and idx % args.exec_every == 0:
                        result = exec_event(args.command)
                        counts["exec"] += 1
                    elif args.workload == "mixed" and args.socket_every > 0 and idx % args.socket_every == 0:
                        result = socket_event(args.host, args.port)
                        counts["socket"] += 1
                    elif args.workload == "warm" and args.socket_every > 0 and idx % args.socket_every == 0:
                        result = socket_event(args.host, args.port)
                        counts["socket"] += 1
                    else:
                        result = warm_file_event(fp, idx)
                        counts["file"] += 1
                    counts[result] += 1
    finally:
        stop.set()
        server.join(timeout=1.0)

    print(f"workload={args.workload}")
    print(f"events={args.events}")
    print(f"file_events={counts['file']}")
    print(f"socket_events={counts['socket']}")
    print(f"exec_events={counts['exec']}")
    print(f"allow_count={counts['allow']}")
    print(f"deny_count={counts['deny']}")
    print(f"fail_count={counts['fail']}")
    return 0 if counts["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
