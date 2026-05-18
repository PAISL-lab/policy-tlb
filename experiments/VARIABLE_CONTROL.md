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

일반 데스크톱 Linux 환경에서는 스케줄러, 인터럽트, 캐시 상태, 온도, 백그라운드 작업을 완전히 제거할 수 없으므로, 본 연구는 CPU governor, core pinning, 동일 workload, 동일 policy, 반복 측정을 통해 가능한 범위에서 변수를 통제하였다.

## Paper Caveat

본 실험의 latency는 eBPF hook 내부의 정책 판단 경로에서 측정된 값이며, 전체 시스템 콜 수행 시간 또는 사용자 애플리케이션의 전체 응답 시간을 의미하지 않는다.

When reporting percentiles from the default metrics, state that p50/p95/p99 are
histogram-bucket approximations unless a dedicated debug-mode raw event trace is
used. Debug raw tracing should not be used for headline performance numbers
because it perturbs the hot path.
