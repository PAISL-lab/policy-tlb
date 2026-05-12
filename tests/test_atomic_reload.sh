#!/usr/bin/env bash
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

write_common_policy() {
  local dir="$1"

  cat > "${dir}/dangerous_paths.json" <<'JSON'
{"rules":[]}
JSON
  cat > "${dir}/dangerous_network.json" <<'JSON'
{"rules":[]}
JSON
}

write_common_policy "${tmpdir}"
cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[{"name":"atomic-true","value":"/usr/bin/true","action":"deny"}]}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

set +e
/usr/bin/true
status=$?
set -e
if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected /usr/bin/true to be denied by initial policy"
  exit 1
fi

cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false,"flags":["bad_reload_flag"]}
JSON

python3 - "${guard_pid}" "${tmpdir}/reload_state" <<'PY'
import json
import os
import signal
import socket
import sys
import time

pid = int(sys.argv[1])
state_path = sys.argv[2]
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
os.kill(pid, signal.SIGHUP)
buffer = b""
while time.time() < deadline:
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
        if payload.get("type") != "reload_result":
            continue
        if payload.get("success") is not False:
            print("expected reload_result success=false", file=sys.stderr)
            sys.exit(1)
        with open(state_path, "w", encoding="utf-8") as fp:
            fp.write(f"{payload.get('epoch')} {payload.get('active_generation')}\n")
        sys.exit(0)

print("timed out waiting for failed reload_result", file=sys.stderr)
sys.exit(1)
PY

read -r failed_epoch failed_generation < "${tmpdir}/reload_state"
sleep 1
set +e
/usr/bin/true
status=$?
set -e
if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected old deny policy to remain active after failed reload"
  exit 1
fi

cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[]}
JSON

python3 - "${guard_pid}" "${failed_epoch}" "${failed_generation}" <<'PY'
import json
import os
import signal
import socket
import sys
import time

pid = int(sys.argv[1])
failed_epoch = int(sys.argv[2])
failed_generation = int(sys.argv[3])
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
os.kill(pid, signal.SIGHUP)
buffer = b""
while time.time() < deadline:
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
        if payload.get("type") != "reload_result":
            continue
        if payload.get("success") is not True:
            print(f"expected successful reload_result, got {payload}", file=sys.stderr)
            sys.exit(1)
        if payload.get("epoch", 0) <= failed_epoch:
            print(f"expected epoch to increase from {failed_epoch}, got {payload.get('epoch')}", file=sys.stderr)
            sys.exit(1)
        if payload.get("active_generation", 0) <= failed_generation:
            print(
                f"expected generation to increase from {failed_generation}, got {payload.get('active_generation')}",
                file=sys.stderr,
            )
            sys.exit(1)
        sys.exit(0)

print("timed out waiting for successful reload_result", file=sys.stderr)
sys.exit(1)
PY

/usr/bin/true

grep -q "failed to load policies" "${tmpdir}/guard.log"
echo "atomic reload rollback test passed"
