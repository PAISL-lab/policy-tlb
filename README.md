# MCP eBPF Guard

Ultra-low overhead runtime security framework for MCP agents using eBPF.

## Overview

MCP eBPF Guard detects and controls dangerous behavior from local MCP agents, including unauthorized command execution, sensitive file access, and suspicious network connections.

## Architecture

- eBPF LSM hooks
- 3-tier TLB-hit modeled pipeline
- Lock-free epoch invalidation
- Ring buffer event delivery
- User-space event streaming over stdout and `/tmp/mcp-guard.sock`

## Features

- Detect dangerous command execution
- Monitor sensitive file access
- Block suspicious IPv4 socket connections
- Send real-time user-space alerts
- Cache policy decisions using L1 fast path
- Invalidate cache with global epoch

## Build

```bash
make
```

The build generates `bpf/vmlinux.h` from the running kernel BTF when needed,
compiles `bpf/mcp_guard.bpf.c`, generates a libbpf skeleton, and links the
`mcp-guard` loader.

## Run

`bpf` must appear in the active LSM chain:

```bash
cat /sys/kernel/security/lsm
```

Run the guard as root:

```bash
sudo ./mcp-guard policies
```

Send `SIGHUP` to reload JSON policies and bump the global epoch:

```bash
sudo kill -HUP $(pidof mcp-guard)
```

## Tests

```bash
make test
```

The tests start the guard with temporary policies and verify exec, file,
socket, and policy reload denial paths. They require root because BPF LSM
program loading is privileged.
