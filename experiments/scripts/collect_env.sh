#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
result_dir="${1:-}"
policy_dir="${2:-${MCP_GUARD_POLICY_DIR:-policies}}"

if [[ -z "${result_dir}" ]]; then
  echo "usage: $0 <result-dir> [policy-dir]" >&2
  exit 2
fi

mkdir -p "${result_dir}/env"
cd "${repo_root}"

write_cmd() {
  local outfile="$1"
  shift
  {
    echo "\$ $*"
    "$@"
  } >"${outfile}" 2>&1 || {
    {
      echo "\$ $*"
      echo "N/A"
    } >"${outfile}"
  }
}

{
  echo "timestamp=$(date -Iseconds 2>/dev/null || echo N/A)"
  echo "hostname=$(hostname 2>/dev/null || echo N/A)"
  echo "pwd=${repo_root}"
} >"${result_dir}/env/system.txt"

write_cmd "${result_dir}/env/lscpu.txt" lscpu
write_cmd "${result_dir}/env/memory.txt" free -h
write_cmd "${result_dir}/env/kernel.txt" uname -a

{
  echo "clang:"
  clang --version 2>/dev/null || echo "N/A"
  echo
  echo "gcc:"
  gcc --version 2>/dev/null || echo "N/A"
} >"${result_dir}/env/compiler.txt"

{
  echo "bpftool:"
  bpftool version 2>/dev/null || echo "N/A"
  echo
  echo "bpf_jit_enable:"
  cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "N/A"
  echo
  echo "lsm:"
  cat /sys/kernel/security/lsm 2>/dev/null || echo "N/A"
} >"${result_dir}/env/bpf.txt"

{
  git rev-parse HEAD 2>/dev/null || echo "N/A"
  echo
  git status --short 2>/dev/null || echo "N/A"
} >"${result_dir}/env/git.txt"

{
  for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [[ -r "${governor}" ]]; then
      printf "%s=" "${governor}"
      cat "${governor}"
    fi
  done
} >"${result_dir}/env/cpu_governor.txt" 2>/dev/null || echo "N/A" >"${result_dir}/env/cpu_governor.txt"

write_cmd "${result_dir}/env/loadavg.txt" cat /proc/loadavg

{
  found=0
  for thermal in /sys/class/thermal/thermal_zone*/temp; do
    if [[ -r "${thermal}" ]]; then
      found=1
      printf "%s=" "${thermal}"
      cat "${thermal}"
    fi
  done
  [[ "${found}" -eq 1 ]] || echo "N/A"
} >"${result_dir}/env/thermal.txt" 2>/dev/null || echo "N/A" >"${result_dir}/env/thermal.txt"

{
  if compgen -G "${policy_dir}/*.json" >/dev/null; then
    sha256sum "${policy_dir}"/*.json
  else
    echo "N/A"
  fi
} >"${result_dir}/env/policy_hash.txt" 2>&1 || echo "N/A" >"${result_dir}/env/policy_hash.txt"
