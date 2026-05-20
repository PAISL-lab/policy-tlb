# Experimental Evaluation

We evaluate MCPGuard using a controlled benchmark harness that separates
eBPF-hook internal policy decision latency from end-to-end workload overhead.
Each measurement is repeated at least 30 times, with fixed workload sizes,
fixed policy inputs, recorded kernel/compiler versions, and CPU pinning where
available.

The reported hook latency values are measured inside the eBPF LSM policy path
and do not represent full syscall latency. End-to-end overhead is reported
separately by comparing guard-off and guard-on workloads.
