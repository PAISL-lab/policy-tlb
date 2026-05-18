#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

experiments/scripts/preflight_check.sh
experiments/scripts/run_latency_benchmark.sh
experiments/scripts/run_hit_ratio_benchmark.sh
experiments/scripts/run_lpm_trie_benchmark.sh
experiments/scripts/run_reload_benchmark.sh
experiments/scripts/run_end_to_end_benchmark.sh
