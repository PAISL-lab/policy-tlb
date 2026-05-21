# Variable Control

## Controlled Or Recorded Variables

1. Same hardware
2. Same OS
3. Same kernel version
4. Same clang/gcc/libbpf/bpftool version
5. Same git commit hash
6. Same build flags
7. Same policy file
8. Same workload event count
9. Same CPU governor where possible
10. Same CPU core pinning where possible
11. Same root privilege
12. Same temp directory base
13. Same loopback network target
14. Same daemon log level
15. Same warm-up count
16. Same measurement method
17. Minimized background load
18. AC power connection recorded when detectable by the user
19. Temperature and throttling hints recorded when exposed by sysfs
20. BPF JIT activation recorded

## Variables Not Fully Controlled

- Linux scheduler decisions
- Hardware interrupts
- CPU cache and TLB state
- Thermal throttling
- Background daemons
- Filesystem cache state
- Dynamic turbo frequencies

## Why They Are Not Fully Controlled

MCPGuard is evaluated on a normal desktop Linux system rather than a fully
isolated real-time benchmarking rig. Some system behavior is intentionally left
intact because the project targets real Linux MCP agent deployments.

## Mitigation

- Use at least 30 independent repetitions.
- Use fixed workload sizes.
- Pin guard and workloads to a configured CPU core with `taskset` when present.
- Attempt to use the performance CPU governor.
- Record load average, governor, kernel, compiler, BPF JIT, and policy hashes.
- Keep per-event raw logging disabled in default experiments.

On a general-purpose desktop Linux system, scheduler behavior, interrupts, cache
state, temperature, and background work cannot be fully eliminated. This study
therefore controls variables where practical by using the same CPU governor,
core pinning, workload, policy, and repeated measurements.

## Paper Caveat

The latency reported by this experiment is measured inside the eBPF hook policy
decision path. It does not represent full system-call latency or the complete
response time of a user application.

When reporting percentiles from the default metrics, state that p50/p95/p99 are
histogram-bucket approximations unless a dedicated debug-mode raw event trace is
used. Debug raw tracing should not be used for headline performance numbers
because it perturbs the hot path.
