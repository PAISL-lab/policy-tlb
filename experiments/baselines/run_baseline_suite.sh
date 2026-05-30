#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/experiments/scripts/common.sh"

if [[ -f "${REPO_ROOT}/experiments/config/experiment.env" ]]; then
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/experiments/config/experiment.env"
fi

REPEATS="${BASELINE_REPEATS:-${EXPERIMENT_REPEATS:-30}}"
EVENTS="${BASELINE_EVENTS_PER_RUN:-${EXPERIMENT_EVENTS_PER_RUN:-100000}}"
CPU_CORE="${BASELINE_CPU_CORE:-${EXPERIMENT_CPU_CORE:-2}}"
WORKLOADS="${BASELINE_WORKLOADS:-warm}"
RESULT_BASE="${BASELINE_RESULT_BASE:-${EXPERIMENT_RESULT_BASE:-experiments/results}}"
POLICY_DIR="${BASELINE_MCPGUARD_POLICY_DIR:-${MCP_GUARD_POLICY_DIR:-policies}}"
SOCKET_PORT="${BASELINE_SOCKET_PORT:-45555}"
COMMAND="${BASELINE_COMMAND:-/usr/bin/true}"
FOLLOWUP_SWEEP="${BASELINE_FOLLOWUP_SWEEP:-}"
FOLLOWUP_PER_OPEN="${BASELINE_FOLLOWUP_PER_OPEN:-${EVENTS}}"
BASELINE_BUILD_DIR="${BASELINE_BUILD_DIR:-${REPO_ROOT}/experiments/baselines/build/workloads}"
CC="${CC:-cc}"
TASKSET_BIN="$(command -v taskset || true)"
TIME_BIN="${TIME_BIN:-/usr/bin/time}"

RESULT_DIR="${REPO_ROOT}/${RESULT_BASE}/$(date +%Y%m%d_%H%M%S)_baseline_independent"
NAIVE_LOADER=""
PTRACE_MONITOR=""
C_FILE_WORKLOAD=""
ACTIVE_GUARD_PID=""

cleanup() {
  if [[ -n "${ACTIVE_GUARD_PID}" ]]; then
    mcp_exp_stop_process "${ACTIVE_GUARD_PID}" || true
    ACTIVE_GUARD_PID=""
  fi
  mcp_exp_restore_result_owner "${RESULT_DIR}" || true
}
trap cleanup EXIT INT TERM

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "baseline suite must run as root for BPF LSM modes" >&2
    exit 1
  fi
}

task_prefix() {
  if [[ -n "${TASKSET_BIN}" && -n "${CPU_CORE}" ]]; then
    printf '%s\n' "${TASKSET_BIN}" "-c" "${CPU_CORE}"
  fi
}

run_with_time() {
  local run_dir="$1"
  shift
  local -a prefix=()

  mapfile -t prefix < <(task_prefix)
  set +e
  "${TIME_BIN}" -v -o "${run_dir}/elapsed.txt" \
    "${prefix[@]}" "$@" >"${run_dir}/workload.log" 2>"${run_dir}/error.log"
  local status=$?
  set -e
  echo "${status}" > "${run_dir}/exit_status.txt"
  return "${status}"
}

build_c_file_workload() {
  local out="${BASELINE_BUILD_DIR}/baseline_file_io_workload"

  mkdir -p "${BASELINE_BUILD_DIR}"
  "${CC}" -g -O2 -Wall -Wextra \
    "${SCRIPT_DIR}/workloads/baseline_file_io_workload.c" \
    -o "${out}"
  printf '%s\n' "${out}"
}

wait_for_log() {
  local file="$1"
  local pattern="$2"
  for _ in $(seq 1 50); do
    if grep -q "${pattern}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_naive_guard() {
  local run_dir="$1"
  local -a prefix=()

  mapfile -t prefix < <(task_prefix)
  NAIVE_EBPF_DENY_PORT=4444 \
  "${prefix[@]}" "${NAIVE_LOADER}" >"${run_dir}/guard.log" 2>"${run_dir}/guard.error.log" &
  ACTIVE_GUARD_PID=$!
  wait_for_log "${run_dir}/guard.log" "naive-ebpf-lsm running" || {
    echo "naive eBPF LSM did not become ready" >&2
    return 1
  }
}

start_mcpguard() {
  local run_dir="$1"
  local -a prefix=()

  mapfile -t prefix < <(task_prefix)
  "${prefix[@]}" "${REPO_ROOT}/mcp-guard" "${REPO_ROOT}/${POLICY_DIR}" --no-gui \
    >"${run_dir}/guard.log" 2>"${run_dir}/guard.error.log" &
  ACTIVE_GUARD_PID=$!
  wait_for_log "${run_dir}/guard.log" "mcp-guard running" || {
    echo "MCPGuard did not become ready" >&2
    return 1
  }
}

stop_active_guard() {
  if [[ -n "${ACTIVE_GUARD_PID}" ]]; then
    mcp_exp_stop_process "${ACTIVE_GUARD_PID}" || true
    ACTIVE_GUARD_PID=""
  fi
}

parse_guard_metrics() {
  local run_dir="$1"
  local run_id="$2"

  if [[ -s "${run_dir}/guard.log" ]]; then
    python3 "${REPO_ROOT}/experiments/tools/parse_metrics.py" \
      "${run_dir}/guard.log" \
      --run-id "${run_id}" \
      --json-out "${run_dir}/metrics.json" \
      --csv-out "${run_dir}/metrics.csv" || true
    cp "${run_dir}/guard.log" "${run_dir}/metrics.txt"
  else
    printf '{"run_id": %s, "metrics": []}\n' "${run_id}" > "${run_dir}/metrics.json"
    printf 'run_id,hook,layer,action,count,avg_ns,min_ns,max_ns,bucket_0,bucket_1,bucket_2,bucket_3,bucket_4,bucket_5,bucket_6,bucket_7\n' > "${run_dir}/metrics.csv"
    : > "${run_dir}/metrics.txt"
  fi
}

run_workload() {
  local run_dir="$1"
  local workload="$2"
  local followup="$3"

  case "${workload}" in
    file_warm)
      run_with_time "${run_dir}" "${C_FILE_WORKLOAD}" \
        --events "${EVENTS}" --workload warm --followup-per-open "${followup}" || true
      ;;
    file_cold)
      run_with_time "${run_dir}" "${C_FILE_WORKLOAD}" \
        --events "${EVENTS}" --workload cold --followup-per-open "${followup}" || true
      ;;
    *)
      run_with_time "${run_dir}" python3 "${SCRIPT_DIR}/workloads/baseline_workload.py" \
        --events "${EVENTS}" --workload "${workload}" --port "${SOCKET_PORT}" --command "${COMMAND}" || true
      ;;
  esac
}

run_mode() {
  local mode="$1"
  local workload="$2"
  local run_id="$3"
  local followup="$4"
  local run_name
  local run_dir
  local workload_dir

  run_name="$(printf 'run_%03d' "${run_id}")"
  workload_dir="${workload}"
  if [[ "${workload}" == file_* ]]; then
    workload_dir="${workload}_f${followup}"
  fi
  run_dir="${RESULT_DIR}/${mode}/${workload_dir}/${run_name}"
  mkdir -p "${run_dir}"
  echo "mode=${mode} workload=${workload} run=${run_id} events=${EVENTS} followup_per_open=${followup}" > "${run_dir}/phase.log"
  : > "${run_dir}/guard.log"

  case "${mode}" in
    no_guard)
      run_workload "${run_dir}" "${workload}" "${followup}"
      ;;
    naive_ebpf_lsm)
      start_naive_guard "${run_dir}"
      run_workload "${run_dir}" "${workload}" "${followup}"
      stop_active_guard
      ;;
    mcpguard)
      start_mcpguard "${run_dir}"
      run_workload "${run_dir}" "${workload}" "${followup}"
      stop_active_guard
      ;;
    ptrace_monitor)
      case "${workload}" in
        file_warm)
          run_with_time "${run_dir}" "${PTRACE_MONITOR}" -- "${C_FILE_WORKLOAD}" \
            --events "${EVENTS}" --workload warm --followup-per-open "${followup}" || true
          ;;
        file_cold)
          run_with_time "${run_dir}" "${PTRACE_MONITOR}" -- "${C_FILE_WORKLOAD}" \
            --events "${EVENTS}" --workload cold --followup-per-open "${followup}" || true
          ;;
        *)
          run_with_time "${run_dir}" "${PTRACE_MONITOR}" -- python3 "${SCRIPT_DIR}/workloads/baseline_workload.py" \
            --events "${EVENTS}" --workload "${workload}" --port "${SOCKET_PORT}" --command "${COMMAND}" || true
          ;;
      esac
      ;;
    *)
      echo "unknown mode: ${mode}" >&2
      return 1
      ;;
  esac

  parse_guard_metrics "${run_dir}" "${run_id}"
}

followup_values_for_workload() {
  local workload="$1"

  if [[ "${workload}" == file_* ]]; then
    if [[ -n "${FOLLOWUP_SWEEP}" ]]; then
      tr ',' '\n' <<< "${FOLLOWUP_SWEEP}"
    else
      printf '%s\n' "${FOLLOWUP_PER_OPEN}"
    fi
  else
    printf '0\n'
  fi
}

main() {
  need_root
  if pgrep -x mcp-guard >/dev/null 2>&1; then
    echo "mcp-guard is already running; stop it before baseline experiments" >&2
    exit 1
  fi

  mkdir -p "${RESULT_DIR}/env" "${RESULT_DIR}/tables"
  "${REPO_ROOT}/experiments/scripts/collect_env.sh" "${RESULT_DIR}" "${REPO_ROOT}/${POLICY_DIR}" >/dev/null 2>&1 || true

  echo "[baseline] building independent baselines"
  NAIVE_LOADER="$("${SCRIPT_DIR}/naive_ebpf_lsm/build.sh")"
  PTRACE_MONITOR="$("${SCRIPT_DIR}/ptrace_monitor/build.sh")"
  C_FILE_WORKLOAD="$(build_c_file_workload)"
  (cd "${REPO_ROOT}" && make mcp-guard)

  echo "[baseline] result_dir=${RESULT_DIR}"
  echo "[baseline] repeats=${REPEATS} events=${EVENTS} workloads=${WORKLOADS}"
  if [[ -n "${FOLLOWUP_SWEEP}" ]]; then
    echo "[baseline] followup_sweep=${FOLLOWUP_SWEEP}"
  fi

  IFS=',' read -r -a workload_list <<< "${WORKLOADS}"
  for workload in "${workload_list[@]}"; do
    mapfile -t followup_list < <(followup_values_for_workload "${workload}")
    for followup in "${followup_list[@]}"; do
      for run_id in $(seq 1 "${REPEATS}"); do
        for mode in no_guard naive_ebpf_lsm mcpguard ptrace_monitor; do
          echo "[baseline] mode=${mode} workload=${workload} followup=${followup} run=${run_id}/${REPEATS}"
          run_mode "${mode}" "${workload}" "${run_id}" "${followup}"
        done
      done
    done
  done

  python3 "${SCRIPT_DIR}/tools/analyze_baselines.py" "${RESULT_DIR}"
  echo "${RESULT_DIR}"
}

main "$@"
