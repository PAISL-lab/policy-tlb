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

cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[{"name":"scoped-true","value":"/usr/bin/true","action":"deny"}]}
JSON
cat > "${tmpdir}/dangerous_paths.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_network.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/mcp_agent_profile.json" <<'JSON'
{
  "profile": "python-agent",
  "profile_id": 42,
  "agent_id": 7,
  "mode": "scoped",
  "comms": ["python3"]
}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

/usr/bin/true

set +e
python3 - <<'PY'
import errno
import subprocess
import sys

try:
    subprocess.run(["/usr/bin/true"], check=True)
except PermissionError:
    sys.exit(0)
except OSError as exc:
    sys.exit(0 if exc.errno == errno.EACCES else 1)
except subprocess.CalledProcessError as exc:
    sys.exit(0 if exc.returncode == 126 else 1)
else:
    sys.exit(1)
PY
status=$?
set -e

if [[ ${status} -ne 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected python3-scoped /usr/bin/true exec to be denied"
  exit 1
fi

sleep 1
grep -q "profile id=42 agent=7 mode=scoped scopes=1 name=python-agent" "${tmpdir}/guard.log"
grep -q "profile=42 agent=7 hook=exec" "${tmpdir}/guard.log"
grep -q "rule=scoped-true" "${tmpdir}/guard.log"
grep "rule=scoped-true" "${tmpdir}/guard.log" | tail -n 5
echo "agent scope test passed"
