# Experiment Design

## Purpose

The purpose of this experiment suite is to evaluate MCPGuard under controlled
and repeatable conditions, with enough repetitions and event volume to support
paper-quality performance claims.

## Research Questions

1. How much faster is the L1 Fast Path than the L3 Slow Path?
2. How high is the L1 hit ratio for repeated `file_read` and `file_write` I/O?
3. How much overhead does LPM Trie path policy matching add in L3?
4. Do policy reload, epoch invalidation, and atomic rollback preserve policy
   consistency?
5. What is the end-to-end workload overhead of guard off versus guard on?
6. Are the results repeatable over at least 30 independent runs?

## Independent Variables

- Processing path: L1 Fast Path, L2 Semi-Fast Path, L3 Slow Path
- Hook type: `exec`, `file_open`, `file_read`, `file_write`, `socket_connect`
- Policy type: exact command rule, exact file rule, LPM Trie path prefix rule,
  socket port rule, reload/epoch policy
- Execution mode: guard off, guard on, cold cache, warm cache

## Dependent Variables

- `duration_ns`, `duration_us`
- Average, minimum, maximum latency
- Approximate p50, p95, p99 latency from histogram buckets
- L1/L2/L3 ratio
- Total event count
- End-to-end elapsed time
- Throughput in events/sec
- Deny and allow counts

## Controlled Variables

The harness records or fixes hardware, OS, kernel version, compiler versions,
libbpf/bpftool version, git commit, build flags, policy files, workload event
counts, CPU governor, CPU core pinning, root privilege, temp directory base,
loopback network target, daemon log mode, warm-up count, measurement method,
background load, AC power hints, thermal hints, and BPF JIT status.

## Experiment And Control Groups

- Hook-internal latency: compare L1/L2/L3 rows from the same `mcp-guard`
  metrics summary.
- End-to-end overhead: compare identical workloads with guard off and guard on.
- Reload consistency: compare behavior before reload, after reload, and after a
  deliberately invalid reload attempt.

## Repetition Count

Default measurement repetitions are 30 independent runs. Default warm-up runs
are 3. Each measured run should generate at least 10,000 events per hook or
workload dimension where practical.

## Measurement Method

MCPGuard prints metrics summary lines on shutdown. The experiment harness
captures those lines in `guard.log`, extracts them into JSON/CSV, and aggregates
them with Python tools. End-to-end elapsed time is collected separately with
`/usr/bin/time -v`.

본 실험의 latency는 eBPF hook 내부의 정책 판단 경로에서 측정된 값이며, 전체 시스템 콜 수행 시간 또는 사용자 애플리케이션의 전체 응답 시간을 의미하지 않는다.

## Result Interpretation

The L1/L2/L3 metrics are useful for policy-path comparison. They must not be
mixed with end-to-end workload elapsed time. Histogram percentiles are marked as
approximate because the production metrics keep buckets rather than per-event
samples.

## Limitations

General-purpose Linux cannot remove all scheduler, interrupt, cache, thermal,
and background workload effects. This harness fixes controllable variables and
records uncontrolled variables to make interpretation explicit.
