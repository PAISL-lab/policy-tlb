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

cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[{"name":"test-true","value":"/usr/bin/true","action":"deny"}]}
JSON
cat > "${tmpdir}/dangerous_paths.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_network.json" <<'JSON'
{"rules":[]}
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

sleep 1
if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected /usr/bin/true to be denied"
  exit 1
fi

grep -q "hook=exec" "${tmpdir}/guard.log"
grep "hook=exec" "${tmpdir}/guard.log" | tail -n 5
echo "execve deny test passed"
