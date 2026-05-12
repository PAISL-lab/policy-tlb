#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

cd "$(dirname "$0")/.."
make -s mcp-guard

tmpdir="$(mktemp -d)"
protected_dir="${tmpdir}/protected"
allowed_file="${protected_dir}/allowed.txt"
denied_file="${protected_dir}/blocked/secret.txt"
guard_pid=""

cleanup() {
  if [[ -n "${guard_pid}" ]] && kill -0 "${guard_pid}" 2>/dev/null; then
    kill -INT "${guard_pid}" 2>/dev/null || true
    wait "${guard_pid}" 2>/dev/null || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

mkdir -p "${protected_dir}/blocked"
printf 'allowed\n' > "${allowed_file}"
printf 'classified\n' > "${denied_file}"

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
{"rules":[
  {"name":"protected-dir","value":"${protected_dir}","action":"deny"},
  {"name":"allowed-exception","value":"${allowed_file}","action":"allow"}
]}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

/bin/cat "${allowed_file}" >/dev/null

set +e
/bin/cat "${denied_file}" >/dev/null 2>&1
status=$?
set -e

sleep 1

if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/guard.log"
  echo "expected LPM prefix protected file read to be denied"
  exit 1
fi

grep -q "rule=protected-dir" "${tmpdir}/guard.log"
if grep -q "rule=allowed-exception" "${tmpdir}/guard.log"; then
  cat "${tmpdir}/guard.log"
  echo "allowed longest-prefix exception should not emit a deny event"
  exit 1
fi

grep "rule=protected-dir" "${tmpdir}/guard.log" | tail -n 5
echo "path LPM trie test passed"
