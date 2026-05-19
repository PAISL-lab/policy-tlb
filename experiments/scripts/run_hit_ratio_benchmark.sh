#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
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
result_dir="${EXPERIMENT_RESULT_DIR:-${EXPERIMENT_RESULT_BASE}/${timestamp}_hit_ratio}"
mkdir -p "${result_dir}"/{env,raw,parsed,tables,logs}
trap 'cleanup_active_guard; mcp_exp_restore_result_owner "${result_dir}"' EXIT
experiments/scripts/collect_env.sh "${result_dir}" "${MCP_GUARD_POLICY_DIR}"
make mcp-guard
active_guard_pid=""
active_guard_policy_dir=""

cleanup_active_guard() {
  mcp_exp_stop_guard_for_policy "${active_guard_policy_dir:-}" "${active_guard_pid:-}"
}
abort_experiment() {
  echo "[hit-ratio] interrupted; cleaning up" >&2
  cleanup_active_guard
  exit 130
}
trap abort_experiment INT TERM

start_guard() {
  local policy_dir="$1"
  local log_path="$2"

  if command -v "${EXPERIMENT_TASKSET}" >/dev/null 2>&1; then
    "${EXPERIMENT_TASKSET}" -c "${EXPERIMENT_CPU_CORE}" ./mcp-guard "${policy_dir}" >"${log_path}" 2>&1 &
  else
    ./mcp-guard "${policy_dir}" >"${log_path}" 2>&1 &
  fi
  guard_pid=$!
  active_guard_pid="${guard_pid}"
  active_guard_policy_dir="${policy_dir}"
}

stop_guard() {
  local pid="${1:-}"
  mcp_exp_stop_guard_for_policy "${active_guard_policy_dir:-}" "${pid}"
}

make_empty_policy() {
  local dir="$1"
  mkdir -p "${dir}"
  printf '{"default_action":"allow","enforce":true,"audit_allowed":false}\n' >"${dir}/default_policy.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_commands.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_paths.json"
  printf '{"rules":[]}\n' >"${dir}/dangerous_network.json"
  cat >"${dir}/mcp_agent_profile.json" <<'JSON'
{"profile":"experiment-python-workload","profile_id":100,"agent_id":1,"mode":"scoped","comms":["python3"]}
JSON
}

timeout_cmd() {
  if command -v timeout >/dev/null 2>&1; then
    timeout --kill-after=5s "${EXPERIMENT_RUN_TIMEOUT_SEC}" "$@"
  else
    "$@"
  fi
}

run_one() {
  local run_id="$1"
  local files="$2"
  local run_dir="${result_dir}/raw/$(printf "run_%03d" "${run_id}")"
  local tmpdir policy_dir guard_pid start_ns end_ns rc
  local start_sec elapsed_sec
  start_sec="$(date +%s)"
  echo "[hit-ratio] start run=${run_id} files=${files} events=${EXPERIMENT_EVENTS_PER_RUN}" >&2
  tmpdir="$(mktemp -d "${EXPERIMENT_TMP_BASE}/mcpguard-exp-hit-XXXXXX")"
  policy_dir="${tmpdir}/policies"
  mkdir -p "${run_dir}"
  : >"${run_dir}/phase.log"
  make_empty_policy "${policy_dir}"
  cleanup() {
    if [[ -n "${guard_pid:-}" ]] && kill -0 "${guard_pid}" 2>/dev/null; then
      kill -INT "${guard_pid}" 2>/dev/null || true
      wait "${guard_pid}" 2>/dev/null || true
    fi
    mcp_exp_remove_tmpdir "${tmpdir}"
  }
  trap cleanup RETURN

  start_guard "${policy_dir}" "${run_dir}/guard.log"
  sleep 1
  guard_pid="$(mcp_exp_guard_pids_for_policy "${policy_dir}" | head -1 || true)"
  active_guard_pid="${guard_pid}"
  if [[ -z "${guard_pid}" ]] || ! kill -0 "${guard_pid}" 2>/dev/null; then
    cp "${run_dir}/guard.log" "${run_dir}/error.log"
    echo "guard_start_failed" >"${run_dir}/exit_status.txt"
    return 1
  fi
  start_ns="$(date +%s%N)"
  rc=0
  echo "phase=workload_start ts=$(date -Iseconds)" >>"${run_dir}/phase.log"
  {
    timeout_cmd experiments/workloads/file_io_workload.sh all "${EXPERIMENT_EVENTS_PER_RUN}" "${tmpdir}/io" "${files}" warm
  } >"${run_dir}/workload.log" 2>&1 || rc=$?
  end_ns="$(date +%s%N)"
  echo "phase=workload_done ts=$(date -Iseconds) status=${rc}" >>"${run_dir}/phase.log"
  echo "phase=guard_stop_start ts=$(date -Iseconds)" >>"${run_dir}/phase.log"
  stop_guard "${guard_pid}"
  guard_pid=""
  active_guard_pid=""
  active_guard_policy_dir=""
  echo "phase=guard_stop_done ts=$(date -Iseconds)" >>"${run_dir}/phase.log"
  {
    echo "benchmark=hit_ratio"
    echo "run_id=${run_id}"
    echo "files=${files}"
    echo "events_per_run=${EXPERIMENT_EVENTS_PER_RUN}"
    echo "elapsed_ns=$((end_ns - start_ns))"
    echo "exit_status=${rc}"
  } >"${run_dir}/elapsed.txt"
  echo "${rc}" >"${run_dir}/exit_status.txt"
  grep "hook=.*layer=.*count=" "${run_dir}/guard.log" >"${run_dir}/metrics.txt" || true
  python3 experiments/tools/parse_metrics.py "${run_dir}/guard.log" --run-id "${run_id}" --json-out "${run_dir}/metrics.json" --csv-out "${run_dir}/metrics.csv"
  elapsed_sec=$(($(date +%s) - start_sec))
  echo "[hit-ratio] done run=${run_id} files=${files} elapsed=${elapsed_sec}s status=${rc}" >&2
  return "${rc}"
}

run_id=1
for repeat in $(seq 1 "${EXPERIMENT_REPEATS}"); do
  for files in 1 10 100; do
    run_one "${run_id}" "${files}"
    run_id=$((run_id + 1))
  done
done

python3 experiments/tools/analyze_results.py "${result_dir}"
echo "${result_dir}"
