#!/usr/bin/env python3
import argparse
import errno
import socket
import threading
import time


def run_server(host: str, port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument("--expect", choices=("allow", "deny", "either"), default="allow")
    parser.add_argument("--start-server", action="store_true")
    args = parser.parse_args()

    stop = threading.Event()
    thread = None
    if args.start_server:
        thread = threading.Thread(target=run_server, args=(args.host, args.port, stop), daemon=True)
        thread.start()
        time.sleep(0.2)

    allowed = 0
    denied = 0
    failed = 0
    for _ in range(args.events):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            sock.connect((args.host, args.port))
            allowed += 1
            try:
                sock.sendall(b"x")
                sock.recv(16)
            except OSError:
                pass
        except OSError as exc:
            if exc.errno == errno.EACCES:
                denied += 1
            else:
                failed += 1
        finally:
            sock.close()

    stop.set()
    if thread:
        thread.join(timeout=1.0)

    print(f"allow_count={allowed}")
    print(f"deny_count={denied}")
    print(f"other_failure_count={failed}")

    if args.expect == "allow" and (denied or failed):
        return 1
    if args.expect == "deny" and denied == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
