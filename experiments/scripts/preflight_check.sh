#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

source experiments/config/experiment.env

status=0
warn() {
  echo "WARN: $*" >&2
}

check_cmd() {
  local name="$1"
  if command -v "${name}" >/dev/null 2>&1; then
    echo "OK: ${name} found"
  else
    echo "FAIL: ${name} not found" >&2
    status=1
  fi
}

if [[ ${EUID} -eq 0 ]]; then
  echo "OK: running as root"
else
  echo "FAIL: preflight must run as root for BPF load checks" >&2
  status=1
fi

if [[ -x ./mcp-guard ]]; then
  echo "OK: mcp-guard binary exists"
else
  warn "mcp-guard binary missing; make will build it"
fi

if make -q mcp-guard >/dev/null 2>&1; then
  echo "OK: build is up to date"
else
  echo "INFO: running make mcp-guard"
  make mcp-guard || status=1
fi

check_cmd bpftool
check_cmd clang
check_cmd "${EXPERIMENT_TASKSET}"
check_cmd python3

if [[ -r /proc/sys/net/core/bpf_jit_enable ]]; then
  jit="$(cat /proc/sys/net/core/bpf_jit_enable || echo N/A)"
  echo "BPF JIT: ${jit}"
  if [[ "${jit}" == "0" ]]; then
    warn "BPF JIT is disabled. To enable manually: sudo sysctl -w net.core.bpf_jit_enable=1"
  fi
else
  warn "cannot read /proc/sys/net/core/bpf_jit_enable"
fi

echo "CPU governor:"
if compgen -G "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >/dev/null; then
  cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c
else
  echo "N/A"
fi

mkdir -p "${EXPERIMENT_RESULT_BASE}"
if [[ -w "${EXPERIMENT_RESULT_BASE}" ]]; then
  echo "OK: ${EXPERIMENT_RESULT_BASE} writable"
else
  echo "FAIL: ${EXPERIMENT_RESULT_BASE} not writable" >&2
  status=1
fi

exit "${status}"
