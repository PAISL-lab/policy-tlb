#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

cd "$(dirname "$0")/.."
make -s mcp-guard

tmpdir="$(mktemp -d)"
secret="${tmpdir}/secret.txt"
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

printf 'classified\n' > "${secret}"
cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_paths.json" <<JSON
{"rules":[{"name":"l1-secret","value":"${secret}","action":"deny"}]}
JSON
cat > "${tmpdir}/dangerous_network.json" <<'JSON'
{"rules":[{"name":"l1-port-4444","value":"0.0.0.0/0","port":4444,"action":"deny"}]}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

SECRET_PATH="${secret}" python3 - <<'PY'
import errno
import os
import socket
import sys

secret = os.environ["SECRET_PATH"]

def expect_eacces(fn, label):
    try:
        fn()
    except OSError as exc:
        if exc.errno == errno.EACCES:
            return
        print(f"{label}: expected EACCES, got errno={exc.errno}", file=sys.stderr)
        sys.exit(1)
    print(f"{label}: expected EACCES, operation succeeded", file=sys.stderr)
    sys.exit(1)

for idx in range(2):
    expect_eacces(lambda: open(secret, "rb").read(), f"file open #{idx + 1}")

for idx in range(2):
    def connect_once():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            sock.connect(("127.0.0.1", 4444))
    expect_eacces(connect_once, f"socket connect #{idx + 1}")
PY

sleep 1

grep -q "rule=l1-secret" "${tmpdir}/guard.log"
grep -q "rule=l1-port-4444" "${tmpdir}/guard.log"
grep -q "layer=L3" "${tmpdir}/guard.log"
grep -q "layer=L1" "${tmpdir}/guard.log"

echo "L1 cache events:"
grep "layer=L1" "${tmpdir}/guard.log" | tail -n 10
echo "L3 miss events:"
grep "layer=L3" "${tmpdir}/guard.log" | tail -n 10
echo "L1 cache test passed"
