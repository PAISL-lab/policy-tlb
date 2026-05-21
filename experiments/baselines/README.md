<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Independent Baseline Experiments

This directory contains baseline experiments that are intentionally isolated
from the main MCPGuard implementation. The files here do not modify the
production BPF programs, loader, policy parser, or Makefile targets.

The comparison modes are:

| Mode | Purpose | Enforcement semantics |
|---|---|---|
| `no_guard` | End-to-end workload baseline without MCPGuard | No security enforcement |
| `naive_ebpf_lsm` | Cacheless eBPF LSM baseline | BPF LSM hooks run a simple policy check on every event |
| `mcpguard` | Proposed system | Existing MCPGuard binary and policy directory |
| `ptrace_monitor` | Traditional user-space syscall tracing baseline | Monitoring/interposition baseline, not equivalent to BPF LSM |

The naive eBPF LSM baseline is a separate BPF object and separate loader. It
uses the same hook class as MCPGuard but does not use MCPGuard's L1 cache, L2
fast path, resource-id follow-up cache, tail-call pipeline, or epoch reuse.

## Run

Build and run the suite:

```bash
sudo experiments/baselines/run_baseline_suite.sh
```

Do not compile `naive_guard_loader.c` or `naive_guard.bpf.c` directly from an
editor command. The naive eBPF baseline needs the generated libbpf skeleton and
the repository include paths. Use:

```bash
experiments/baselines/naive_ebpf_lsm/build.sh
```

Small smoke run:

```bash
sudo env BASELINE_REPEATS=1 BASELINE_EVENTS_PER_RUN=1000 \
  experiments/baselines/run_baseline_suite.sh
```

Optional workload mix:

```bash
sudo env BASELINE_WORKLOADS=warm,cold,mixed \
  experiments/baselines/run_baseline_suite.sh
```

Results are written under:

```text
experiments/results/<timestamp>_baseline_independent/
```

The generated tables include:

- `tables/baseline_e2e.csv`
- `tables/baseline_hook_latency.csv`
- `tables/baseline_syscall_monitor.csv`
- `tables/baseline_summary.csv`
- `report.md`

## Interpretation Notes

The `naive_ebpf_lsm` mode is the primary technical baseline for MCPGuard because
it uses BPF LSM hooks and kernel-side enforcement but removes the cache and
pipeline optimizations.

The `ptrace_monitor` mode is included as a secondary traditional syscall
monitoring baseline. It is useful for overhead comparison, but it should not be
described as semantically equivalent to BPF LSM enforcement.
