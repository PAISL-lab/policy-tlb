# MCPGuard Experiments

This directory contains the controlled benchmark and experiment harness used to
measure MCPGuard performance for paper-oriented evaluation.

The harness separates two measurement domains:

- BPF hook internal policy-path latency, collected from `mcp-guard` metrics
  summary lines.
- End-to-end workload overhead, collected with `/usr/bin/time -v` around user
  workloads with guard off and guard on.

The default configuration is in `experiments/config/experiment.env`.

## Quick Start

```bash
sudo make experiment-preflight
sudo make experiment-all
```

Individual experiments:

```bash
sudo experiments/scripts/run_latency_benchmark.sh
sudo experiments/scripts/run_hit_ratio_benchmark.sh
sudo experiments/scripts/run_lpm_trie_benchmark.sh
sudo experiments/scripts/run_reload_benchmark.sh
sudo experiments/scripts/run_end_to_end_benchmark.sh
```

Analyze an existing result directory:

```bash
python3 experiments/tools/analyze_results.py experiments/results/<run-dir>
cat experiments/results/<run-dir>/report.md
```

## Result Layout

Each experiment creates:

```text
experiments/results/YYYYMMDD_HHMMSS/
├── env/
├── raw/
├── parsed/
├── tables/
├── logs/
└── report.md
```

Each measured run creates:

```text
raw/run_001/
├── guard.log
├── workload.log
├── metrics.txt
├── metrics.json
├── metrics.csv
├── elapsed.txt
└── exit_status.txt
```

## Important Interpretation Rule

The latency in the metrics tables is the policy decision time measured inside
the eBPF hook path. It is not the full system call latency and not the full
application response time. Use the end-to-end benchmark for workload-level
overhead.
