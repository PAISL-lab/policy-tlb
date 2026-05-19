#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

cd "$(dirname "$0")/.."
make -s mcp-guard

tmpdir="$(mktemp -d)"
guard_pid=""

cleanup() {
  if [[ -n "${guard_pid}" ]] && kill -0 "${guard_pid}" 2>/dev/null; then
    kill -INT "${guard_pid}" 2>/dev/null || true
    wait "${guard_pid}" 2>/dev/null || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

command -v python3 >/dev/null

cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_paths.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_network.json" <<'JSON'
{"rules":[]}
JSON

./mcp-guard "${tmpdir}" --metrics-interval 1 > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

python3 - <<'PY'
import json
import os
import socket
import sys
import time

deadline = time.time() + 6
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

while True:
    try:
        sock.connect("/tmp/mcp-guard.sock")
        break
    except OSError:
        if time.time() > deadline:
            print("failed to connect to event socket", file=sys.stderr)
            sys.exit(1)
        time.sleep(0.1)

sock.settimeout(0.5)
buffer = b""
while time.time() < deadline:
    for _ in range(20):
        with open("/dev/null", "rb") as fp:
            fp.read(1)
    try:
        chunk = sock.recv(4096)
    except socket.timeout:
        continue
    if not chunk:
        continue
    buffer += chunk
    while b"\n" in buffer:
        line, buffer = buffer.split(b"\n", 1)
        if not line:
            continue
        payload = json.loads(line.decode())
        if payload.get("type") != "metrics_snapshot":
            continue
        if payload.get("total_count", 0) <= 0:
            print("metrics snapshot had no samples", file=sys.stderr)
            sys.exit(1)
        if "ratios" not in payload or "layers" not in payload:
            print("metrics snapshot missing aggregate fields", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

print("timed out waiting for metrics_snapshot", file=sys.stderr)
sys.exit(1)
PY

sleep 1
kill -INT "${guard_pid}" 2>/dev/null || true
wait "${guard_pid}" 2>/dev/null || true
guard_pid=""

grep -q "metrics snapshot:" "${tmpdir}/guard.log"
grep -q "metrics ratios:" "${tmpdir}/guard.log"
grep "metrics ratios:" "${tmpdir}/guard.log" | tail -n 5
echo "metrics snapshot test passed"
