#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

cd "$(dirname "$0")/.."
source experiments/scripts/common.sh
make -s mcp-guard

tmpdir="$(mktemp -d /tmp/mcpguard-exp-reload-XXXXXX)"
guard_pid=""

cleanup() {
  mcp_exp_stop_guard_for_policy "${tmpdir}" "${guard_pid}"
  mcp_exp_remove_tmpdir "${tmpdir}"
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
guard_pid="$(mcp_exp_guard_pids_for_policy "${tmpdir}" | head -1 || true)"

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

python3 - "${guard_pid}" <<'PY'
import json
import os
import signal
import socket
import sys
import time

pid = int(sys.argv[1])
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
        if not isinstance(payload.get("epoch"), int):
            print("failed reload_result missing epoch", file=sys.stderr)
            sys.exit(1)
        if not isinstance(payload.get("active_generation"), int):
            print("failed reload_result missing active_generation", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

print("timed out waiting for failed reload_result", file=sys.stderr)
sys.exit(1)
PY

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

kill -HUP "${guard_pid}"

allowed=0
for _ in $(seq 1 30); do
  set +e
  /usr/bin/true >/dev/null 2>&1
  status=$?
  set -e
  if [[ ${status} -eq 0 ]]; then
    allowed=1
    break
  fi
  sleep 0.2
done

if [[ ${allowed} -ne 1 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected /usr/bin/true to be allowed after successful reload"
  exit 1
fi

grep -q "failed to load policies" "${tmpdir}/guard.log"
grep -Eq "generation=[0-9]+ epoch=[0-9]+" "${tmpdir}/guard.log"
echo "atomic reload rollback test passed"
