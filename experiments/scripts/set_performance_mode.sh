#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
source experiments/config/experiment.env

result_dir="${1:-${EXPERIMENT_RESULT_BASE}/manual_cpu_mode}"
mkdir -p "${result_dir}/env"

original="${result_dir}/env/original_governor.txt"
: >"${original}"

for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  if [[ -r "${governor}" ]]; then
    printf "%s=" "${governor}" >>"${original}"
    cat "${governor}" >>"${original}"
  fi
done

for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  if [[ -w "${governor}" ]]; then
    echo performance >"${governor}" 2>/dev/null || echo "WARN: failed to set ${governor}" >&2
  elif [[ -e "${governor}" ]]; then
    echo "WARN: ${governor} is not writable; continuing" >&2
  fi
done

echo "EXPERIMENT_CPU_CORE=${EXPERIMENT_CPU_CORE}"
echo "Use: taskset -c ${EXPERIMENT_CPU_CORE} <command>"
