#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
source experiments/config/experiment.env
source experiments/scripts/common.sh

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
result_dir="${EXPERIMENT_RESULT_DIR:-${EXPERIMENT_RESULT_BASE}/${timestamp}_reload}"
mkdir -p "${result_dir}"/{env,raw,parsed,tables,logs}
trap 'mcp_exp_restore_result_owner "${result_dir}"' EXIT
experiments/scripts/collect_env.sh "${result_dir}" "${MCP_GUARD_POLICY_DIR}"
experiments/scripts/clean_experiment_state.sh >/dev/null 2>&1 || true
make mcp-guard

run_one() {
  local run_id="$1"
  local run_dir="${result_dir}/raw/$(printf "run_%03d" "${run_id}")"
  local start_ns end_ns rc
  local start_sec elapsed_sec
  start_sec="$(date +%s)"
  echo "[reload] start run=${run_id}" >&2
  mkdir -p "${run_dir}"
  start_ns="$(date +%s%N)"
  rc=0
  tests/test_atomic_reload.sh >"${run_dir}/workload.log" 2>&1 || rc=$?
  end_ns="$(date +%s%N)"
  cp "${run_dir}/workload.log" "${run_dir}/guard.log"
  {
    echo "benchmark=reload"
    echo "run_id=${run_id}"
    echo "reload_success_count=$([[ ${rc} -eq 0 ]] && echo 1 || echo 0)"
    echo "rollback_success_count=$([[ ${rc} -eq 0 ]] && echo 1 || echo 0)"
    echo "elapsed_ns=$((end_ns - start_ns))"
    echo "exit_status=${rc}"
  } >"${run_dir}/elapsed.txt"
  echo "${rc}" >"${run_dir}/exit_status.txt"
  grep "hook=.*layer=.*count=" "${run_dir}/guard.log" >"${run_dir}/metrics.txt" || true
  python3 experiments/tools/parse_metrics.py "${run_dir}/guard.log" --run-id "${run_id}" --json-out "${run_dir}/metrics.json" --csv-out "${run_dir}/metrics.csv"
  elapsed_sec=$(($(date +%s) - start_sec))
  echo "[reload] done run=${run_id} elapsed=${elapsed_sec}s status=${rc}" >&2
  return "${rc}"
}

echo "[reload] result_dir=${result_dir}" >&2
echo "[reload] repeats=${EXPERIMENT_REPEATS}" >&2
for run_id in $(seq 1 "${EXPERIMENT_REPEATS}"); do
  run_one "${run_id}"
done

python3 experiments/tools/analyze_results.py "${result_dir}"
echo "${result_dir}"
