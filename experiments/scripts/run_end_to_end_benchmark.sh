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
result_dir="${EXPERIMENT_RESULT_DIR:-${EXPERIMENT_RESULT_BASE}/${timestamp}_e2e}"
mkdir -p "${result_dir}"/{env,raw,parsed,tables,logs}
trap 'mcp_exp_restore_result_owner "${result_dir}"' EXIT
experiments/scripts/collect_env.sh "${result_dir}" "${MCP_GUARD_POLICY_DIR}"
make mcp-guard

run_cmd() {
  if command -v "${EXPERIMENT_TASKSET}" >/dev/null 2>&1; then
    "${EXPERIMENT_TASKSET}" -c "${EXPERIMENT_CPU_CORE}" "$@"
  else
    "$@"
  fi
}

make_empty_policy() {
  local dir="$1"
  mkdir -p "${dir}"
  printf '{"default_action":"allow","enforce":true,"audit_allowed":false}\n' >"${dir}/default_policy.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_commands.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_paths.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_network.json"
}

run_workload_group() {
  local tmpdir="$1"
  experiments/workloads/file_io_workload.sh read 100000 "${tmpdir}/io" 10 warm
  experiments/workloads/file_io_workload.sh write 100000 "${tmpdir}/io" 10 warm
  experiments/workloads/file_io_workload.sh open 10000 "${tmpdir}/io" 10 warm
  python3 experiments/workloads/socket_workload.py --events 1000 --port "${EXPERIMENT_SOCKET_PORT}" --expect either
  python3 experiments/workloads/mixed_agent_workload.py --events 10000 --mode normal --port "${EXPERIMENT_SOCKET_PORT}"
}

run_one() {
  local run_id="$1"
  local mode="$2"
  local run_dir="${result_dir}/raw/$(printf "run_%03d" "${run_id}")"
  local tmpdir policy_dir guard_pid start_ns end_ns rc
  tmpdir="$(mktemp -d "${EXPERIMENT_TMP_BASE}/mcpguard-exp-e2e-XXXXXX")"
  policy_dir="${tmpdir}/policies"
  mkdir -p "${run_dir}"
  make_empty_policy "${policy_dir}"
  cleanup() {
    if [[ -n "${guard_pid:-}" ]] && kill -0 "${guard_pid}" 2>/dev/null; then
      kill -INT "${guard_pid}" 2>/dev/null || true
      wait "${guard_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
  }
  trap cleanup RETURN

  guard_pid=""
  if [[ "${mode}" == "guard_on" ]]; then
    run_cmd ./mcp-guard "${policy_dir}" >"${run_dir}/guard.log" 2>&1 &
    guard_pid=$!
    sleep 1
  else
    : >"${run_dir}/guard.log"
  fi

  rc=0
  start_ns="$(date +%s%N)"
  if [[ -x "${EXPERIMENT_TIME}" ]]; then
    run_cmd "${EXPERIMENT_TIME}" -v experiments/workloads/file_io_workload.sh mixed "${EXPERIMENT_EVENTS_PER_RUN}" "${tmpdir}/io" 10 warm >"${run_dir}/workload.log" 2>"${run_dir}/time.log" || rc=$?
  else
    run_cmd experiments/workloads/file_io_workload.sh mixed "${EXPERIMENT_EVENTS_PER_RUN}" "${tmpdir}/io" 10 warm >"${run_dir}/workload.log" 2>&1 || rc=$?
  fi
  end_ns="$(date +%s%N)"

  if [[ -n "${guard_pid}" ]]; then
    kill -INT "${guard_pid}" 2>/dev/null || true
    wait "${guard_pid}" 2>/dev/null || true
    guard_pid=""
  fi

  elapsed_ns=$((end_ns - start_ns))
  {
    echo "benchmark=end_to_end"
    echo "run_id=${run_id}"
    echo "mode=${mode}"
    echo "events=${EXPERIMENT_EVENTS_PER_RUN}"
    echo "elapsed_ns=${elapsed_ns}"
    awk -F': ' '/User time|System time|Maximum resident|Voluntary context|Involuntary context|Elapsed/ {gsub(/^[ \t]+/, "", $1); gsub(/ /, "_", $1); print tolower($1)"="$2}' "${run_dir}/time.log" 2>/dev/null || true
    awk -v e="${EXPERIMENT_EVENTS_PER_RUN}" -v ns="${elapsed_ns}" 'BEGIN { if (ns > 0) printf "throughput_events_per_sec=%.6f\n", e/(ns/1000000000.0); }'
    echo "exit_status=${rc}"
  } >"${run_dir}/elapsed.txt"
  echo "${rc}" >"${run_dir}/exit_status.txt"
  grep "hook=.*layer=.*count=" "${run_dir}/guard.log" >"${run_dir}/metrics.txt" || true
  python3 experiments/tools/parse_metrics.py "${run_dir}/guard.log" --run-id "${run_id}" --json-out "${run_dir}/metrics.json" --csv-out "${run_dir}/metrics.csv"
  return "${rc}"
}

run_id=1
for repeat in $(seq 1 "${EXPERIMENT_REPEATS}"); do
  run_one "${run_id}" guard_off
  run_id=$((run_id + 1))
  run_one "${run_id}" guard_on
  run_id=$((run_id + 1))
done

python3 experiments/tools/analyze_results.py "${result_dir}"
echo "${result_dir}"
