#!/usr/bin/env bash
set -euo pipefail

snapshot="${1:-}"
if [[ -z "${snapshot}" ]]; then
  echo "usage: $0 <result-dir-or-original-governor-file>" >&2
  exit 2
fi

if [[ -d "${snapshot}" ]]; then
  snapshot="${snapshot}/env/original_governor.txt"
fi

if [[ ! -r "${snapshot}" ]]; then
  echo "WARN: governor snapshot not found: ${snapshot}" >&2
  exit 0
fi

while IFS='=' read -r path value; do
  [[ -n "${path}" && -n "${value}" ]] || continue
  if [[ -w "${path}" ]]; then
    echo "${value}" >"${path}" 2>/dev/null || echo "WARN: failed to restore ${path}" >&2
  fi
done <"${snapshot}"
