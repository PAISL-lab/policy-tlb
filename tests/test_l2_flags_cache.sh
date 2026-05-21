#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
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

write_empty_policy() {
  local dir="$1"

  cat > "${dir}/dangerous_commands.json" <<'JSON'
{"rules":[]}
JSON
  cat > "${dir}/dangerous_paths.json" <<'JSON'
{"rules":[]}
JSON
  cat > "${dir}/dangerous_network.json" <<'JSON'
{"rules":[]}
JSON
}

write_empty_policy "${tmpdir}"
cat > "${tmpdir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON

./mcp-guard "${tmpdir}" > "${tmpdir}/guard.log" 2>&1 &
guard_pid=$!
sleep 1

if ! kill -0 "${guard_pid}" 2>/dev/null; then
  cat "${tmpdir}/guard.log"
  exit 1
fi

for _ in 1 2 3; do
  /bin/cat /dev/null >/dev/null
done

kill -INT "${guard_pid}" 2>/dev/null || true
wait "${guard_pid}" 2>/dev/null || true
guard_pid=""

grep -q "policy flags: .*skip_l2_safe=0" "${tmpdir}/guard.log"
grep -q "hook=file_open layer=L2 action=allow" "${tmpdir}/guard.log"

bad_dir="${tmpdir}/bad"
mkdir -p "${bad_dir}"
write_empty_policy "${bad_dir}"
cat > "${bad_dir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false,"flags":["unknown_l2_flag"]}
JSON

set +e
./mcp-guard "${bad_dir}" > "${tmpdir}/bad.log" 2>&1
status=$?
set -e

if [[ ${status} -eq 0 ]]; then
  cat "${tmpdir}/bad.log"
  echo "expected unknown flag policy load to fail"
  exit 1
fi

grep -q "unknown policy flag: unknown_l2_flag" "${tmpdir}/bad.log"

grep "hook=file_open layer=L2 action=allow" "${tmpdir}/guard.log" | tail -n 5
echo "L2 flag/cache test passed"
