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
result_dir="${EXPERIMENT_RESULT_DIR:-${EXPERIMENT_RESULT_BASE}/${timestamp}_lpm}"
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

run_one() {
  local run_id="$1"
  local depth="$2"
  local run_dir="${result_dir}/raw/$(printf "run_%03d" "${run_id}")"
  local tmpdir policy_dir protected path guard_pid start_ns end_ns rc
  tmpdir="$(mktemp -d "${EXPERIMENT_TMP_BASE}/mcpguard-exp-lpm-XXXXXX")"
  policy_dir="${tmpdir}/policies"
  mkdir -p "${run_dir}" "${policy_dir}"
  protected="${tmpdir}/protected"
  path="${protected}"
  for idx in $(seq 1 "${depth}"); do
    path="${path}/d${idx}"
  done
  mkdir -p "${path}/blocked" "${path}/allowed"
  printf 'secret\n' >"${path}/blocked/secret.txt"
  printf 'public\n' >"${path}/allowed/public.txt"
  cat >"${policy_dir}/default_policy.json" <<'JSON'
{"default_action":"allow","enforce":true,"audit_allowed":false}
JSON
  printf '{"rules":[]}\n' >"${policy_dir}/dangerous_commands.json"
  cat >"${policy_dir}/dangerous_paths.json" <<JSON
{"rules":[{"name":"protected-dir","value":"${path}/blocked/","action":"deny"}]}
JSON
  printf '{"rules":[]}\n' >"${policy_dir}/dangerous_network.json"

  cleanup() {
    if [[ -n "${guard_pid:-}" ]] && kill -0 "${guard_pid}" 2>/dev/null; then
      kill -INT "${guard_pid}" 2>/dev/null || true
      wait "${guard_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
  }
  trap cleanup RETURN

  run_cmd ./mcp-guard "${policy_dir}" >"${run_dir}/guard.log" 2>&1 &
  guard_pid=$!
  sleep 1
  start_ns="$(date +%s%N)"
  rc=0
  python3 - "${path}/blocked/secret.txt" "${path}/allowed/public.txt" "${EXPERIMENT_EVENTS_PER_RUN}" >"${run_dir}/workload.log" 2>&1 <<'PY' || rc=$?
import errno
import sys
blocked, allowed, events = sys.argv[1], sys.argv[2], int(sys.argv[3])
deny = allow = 0
for idx in range(events):
    target = blocked if idx % 2 == 0 else allowed
    try:
        open(target, "rb").read(1)
        allow += 1
    except OSError as exc:
        if exc.errno == errno.EACCES:
            deny += 1
        else:
            raise
print(f"allow_count={allow}")
print(f"deny_count={deny}")
PY
  end_ns="$(date +%s%N)"
  kill -INT "${guard_pid}" 2>/dev/null || true
  wait "${guard_pid}" 2>/dev/null || true
  guard_pid=""
  {
    echo "benchmark=lpm_trie"
    echo "run_id=${run_id}"
    echo "path_depth=${depth}"
    echo "events_per_run=${EXPERIMENT_EVENTS_PER_RUN}"
    echo "elapsed_ns=$((end_ns - start_ns))"
    echo "exit_status=${rc}"
  } >"${run_dir}/elapsed.txt"
  echo "${rc}" >"${run_dir}/exit_status.txt"
  grep "hook=.*layer=.*count=" "${run_dir}/guard.log" >"${run_dir}/metrics.txt" || true
  python3 experiments/tools/parse_metrics.py "${run_dir}/guard.log" --run-id "${run_id}" --json-out "${run_dir}/metrics.json" --csv-out "${run_dir}/metrics.csv"
}

run_id=1
for repeat in $(seq 1 "${EXPERIMENT_REPEATS}"); do
  for depth in 1 3 5 10; do
    run_one "${run_id}" "${depth}"
    run_id=$((run_id + 1))
  done
done

python3 experiments/tools/analyze_results.py "${result_dir}"
echo "${result_dir}"
