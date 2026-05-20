#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import errno
import os
import socket
import subprocess
import tempfile
from pathlib import Path


def try_exec(command: str) -> str:
    proc = subprocess.run([command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return "allow" if proc.returncode == 0 else "deny"


def try_socket(port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        sock.connect(("127.0.0.1", port))
        return "allow"
    except OSError as exc:
        return "deny" if exc.errno == errno.EACCES else "fail"
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--mode", choices=("normal", "suspicious"), default="normal")
    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument("--command", default="/usr/bin/true")
    args = parser.parse_args()

    counts = {"allow": 0, "deny": 0, "fail": 0}
    with tempfile.TemporaryDirectory(prefix="mcpguard-exp-mixed-") as tmp:
        base = Path(tmp)
        work = base / "agent.txt"
        work.write_text("agent state\n", encoding="utf-8")

        for idx in range(args.events):
            step = idx % (4 if args.mode == "suspicious" else 3)
            if step == 0:
                try:
                    with work.open("rb") as fp:
                        fp.read(16)
                    counts["allow"] += 1
                except OSError as exc:
                    counts["deny" if exc.errno == errno.EACCES else "fail"] += 1
            elif step == 1:
                try:
                    with work.open("ab") as fp:
                        fp.write(b"x")
                    counts["allow"] += 1
                except OSError as exc:
                    counts["deny" if exc.errno == errno.EACCES else "fail"] += 1
            elif step == 2:
                counts[try_socket(args.port)] += 1
            else:
                counts[try_exec(args.command)] += 1

    for key in ("allow", "deny", "fail"):
        print(f"{key}_count={counts[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
