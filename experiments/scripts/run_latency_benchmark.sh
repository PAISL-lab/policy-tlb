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
result_dir="${EXPERIMENT_RESULT_DIR:-${EXPERIMENT_RESULT_BASE}/${timestamp}_latency}"
mkdir -p "${result_dir}"/{env,raw,parsed,tables,logs}
trap 'mcp_exp_restore_result_owner "${result_dir}"' EXIT

experiments/scripts/collect_env.sh "${result_dir}" "${MCP_GUARD_POLICY_DIR}"
make clean && make

run_cmd() {
  if command -v "${EXPERIMENT_TASKSET}" >/dev/null 2>&1; then
    "${EXPERIMENT_TASKSET}" -c "${EXPERIMENT_CPU_CORE}" "$@"
  else
    "$@"
  fi
}

make_policy_dir() {
  local dir="$1"
  local secret="$2"
  mkdir -p "${dir}"
  cat >"${dir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
  cat >"${dir}/dangerous_commands.json" <<'JSON'
{"rules":[{"name":"bench-true","value":"/usr/bin/true","action":"deny"}]}
JSON
  cat >"${dir}/dangerous_paths.json" <<JSON
{"rules":[{"name":"bench-secret","value":"${secret}","action":"deny"}]}
JSON
  cat >"${dir}/dangerous_network.json" <<JSON
{"rules":[{"name":"bench-port","value":"0.0.0.0/0","port":${EXPERIMENT_SOCKET_PORT},"action":"deny"}]}
JSON
}

run_one() {
  local run_id="$1"
  local run_name
  run_name="$(printf "run_%03d" "${run_id}")"
  local run_dir="${result_dir}/raw/${run_name}"
  local tmpdir policy_dir guard_pid start_ns end_ns rc
  local start_sec elapsed_sec
  start_sec="$(date +%s)"
  echo "[latency] start run=${run_id} events=${EXPERIMENT_EVENTS_PER_RUN}" >&2
  tmpdir="$(mktemp -d "${EXPERIMENT_TMP_BASE}/mcpguard-exp-latency-XXXXXX")"
  policy_dir="${tmpdir}/policies"
  mkdir -p "${run_dir}"
  printf 'classified\n' >"${tmpdir}/secret.txt"
  make_policy_dir "${policy_dir}" "${tmpdir}/secret.txt"

  cleanup() {
    mcp_exp_stop_guard_for_policy "${policy_dir:-}" "${guard_pid:-}"
    mcp_exp_remove_tmpdir "${tmpdir}"
  }
  trap cleanup RETURN

  run_cmd ./mcp-guard "${policy_dir}" >"${run_dir}/guard.log" 2>&1 &
  guard_pid=$!
  sleep 1
  guard_pid="$(mcp_exp_guard_pids_for_policy "${policy_dir}" | head -1 || true)"
  if ! kill -0 "${guard_pid}" 2>/dev/null; then
    cp "${run_dir}/guard.log" "${run_dir}/error.log"
    echo "guard_start_failed" >"${run_dir}/exit_status.txt"
    return 1
  fi

  start_ns="$(date +%s%N)"
  rc=0
  {
    experiments/workloads/file_io_workload.sh read "${EXPERIMENT_EVENTS_PER_RUN}" "${tmpdir}/io" 1 warm
    experiments/workloads/file_io_workload.sh write "${EXPERIMENT_EVENTS_PER_RUN}" "${tmpdir}/io" 1 warm
    set +e
    experiments/workloads/exec_workload.sh 100 /usr/bin/true deny
    socket_rc=$?
    python3 experiments/workloads/socket_workload.py --events 100 --port "${EXPERIMENT_SOCKET_PORT}" --expect deny
    sock_rc=$?
    set -e
    [[ "${socket_rc}" -eq 0 && "${sock_rc}" -eq 0 ]]
  } >"${run_dir}/workload.log" 2>&1 || rc=$?
  end_ns="$(date +%s%N)"

  mcp_exp_stop_guard_for_policy "${policy_dir}" "${guard_pid}"
  guard_pid=""

  {
    echo "benchmark=latency"
    echo "run_id=${run_id}"
    echo "events_per_run=${EXPERIMENT_EVENTS_PER_RUN}"
    echo "elapsed_ns=$((end_ns - start_ns))"
    echo "exit_status=${rc}"
  } >"${run_dir}/elapsed.txt"
  echo "${rc}" >"${run_dir}/exit_status.txt"
  grep "hook=.*layer=.*count=" "${run_dir}/guard.log" >"${run_dir}/metrics.txt" || true
  python3 experiments/tools/parse_metrics.py "${run_dir}/guard.log" --run-id "${run_id}" --json-out "${run_dir}/metrics.json" --csv-out "${run_dir}/metrics.csv"
  elapsed_sec=$(($(date +%s) - start_sec))
  echo "[latency] done run=${run_id} elapsed=${elapsed_sec}s status=${rc}" >&2
  return "${rc}"
}

original_events_per_run="${EXPERIMENT_EVENTS_PER_RUN}"
echo "[latency] result_dir=${result_dir}" >&2
echo "[latency] warmup_runs=${EXPERIMENT_WARMUP_RUNS} repeats=${EXPERIMENT_REPEATS} events=${original_events_per_run}" >&2
for warm in $(seq 1 "${EXPERIMENT_WARMUP_RUNS}"); do
  echo "[latency] warmup start run=${warm}" >&2
  EXPERIMENT_EVENTS_PER_RUN=100 run_one "${warm}" >/dev/null 2>&1 || true
  rm -rf "${result_dir}/raw/$(printf "run_%03d" "${warm}")"
  echo "[latency] warmup done run=${warm}" >&2
done
EXPERIMENT_EVENTS_PER_RUN="${original_events_per_run}"

for run_id in $(seq 1 "${EXPERIMENT_REPEATS}"); do
  run_one "${run_id}"
done

python3 experiments/tools/analyze_results.py "${result_dir}"
echo "${result_dir}"
