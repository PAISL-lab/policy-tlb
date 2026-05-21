#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
source experiments/config/experiment.env

run_step() {
  local name="$1"
  shift
  local start_sec elapsed_sec

  experiments/scripts/clean_experiment_state.sh >/dev/null 2>&1 || true
  start_sec="$(date +%s)"
  echo "[experiment-all] start ${name} ts=$(date -Iseconds)" >&2
  "$@"
  elapsed_sec=$(($(date +%s) - start_sec))
  echo "[experiment-all] done ${name} elapsed=${elapsed_sec}s ts=$(date -Iseconds)" >&2
}

echo "[experiment-all] config repeats=${EXPERIMENT_REPEATS} events=${EXPERIMENT_EVENTS_PER_RUN}" >&2

experiments/scripts/preflight_check.sh
experiments/scripts/clean_experiment_state.sh >/dev/null 2>&1 || true
run_step latency experiments/scripts/run_latency_benchmark.sh
run_step hit-ratio experiments/scripts/run_hit_ratio_benchmark.sh
run_step lpm-trie experiments/scripts/run_lpm_trie_benchmark.sh
run_step reload experiments/scripts/run_reload_benchmark.sh
run_step end-to-end experiments/scripts/run_end_to_end_benchmark.sh
