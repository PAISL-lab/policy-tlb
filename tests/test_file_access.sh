#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
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

printf 'classified\n' > "${secret}"
cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
cat > "${tmpdir}/dangerous_commands.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_network.json" <<'JSON'
{"rules":[]}
JSON
cat > "${tmpdir}/dangerous_paths.json" <<JSON
{"rules":[{"name":"test-secret","value":"${secret}","action":"deny"}]}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

set +e
/bin/cat "${secret}" >/dev/null 2>&1
status=$?
set -e

sleep 1
if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected protected file read to be denied"
  exit 1
fi

grep -Eq "hook=file_(open|read)" "${tmpdir}/guard.log"
grep -E "hook=file_(open|read)" "${tmpdir}/guard.log" | tail -n 5
echo "file access deny test passed"
