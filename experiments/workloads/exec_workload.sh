#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

events="${1:-10000}"
command_path="${2:-/usr/bin/true}"
expect="${3:-allow}"

allow_count=0
deny_count=0

for _ in $(seq 1 "${events}"); do
  set +e
  "${command_path}" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    allow_count=$((allow_count + 1))
  else
    deny_count=$((deny_count + 1))
  fi
done

echo "allow_count=${allow_count}"
echo "deny_count=${deny_count}"

case "${expect}" in
  allow)
    [[ "${deny_count}" -eq 0 ]] || exit 1
    ;;
  deny)
    [[ "${deny_count}" -gt 0 ]] || exit 1
    ;;
  either)
    ;;
  *)
    echo "expect must be allow, deny, or either" >&2
    exit 2
    ;;
esac
