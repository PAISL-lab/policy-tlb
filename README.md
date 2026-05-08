# MCP eBPF Guard

MCP eBPF Guard is a runtime security framework for local Model Context Protocol
(MCP) agents. It uses BPF LSM hooks and a TLB-hit-modeled 3-tier decision
pipeline to detect and block dangerous agent behavior with low overhead.

This repository is an implementation-oriented PoC based on the paper idea:

> Ultra-Low Overhead MCP Agent Behavioral Control Framework using
> TLB-Hit Modeled 3-Tier eBPF Pipeline

## Why This Exists

MCP gives LLM agents a standard way to access local tools, files, databases, and
network resources. That power also creates a sharp runtime security problem:
a prompt-injected or hijacked agent can attempt unauthorized command execution,
sensitive file access, or outbound network connections.

Traditional monitoring approaches have tradeoffs:

- `ptrace` and audit-style tracing can add heavy user/kernel context switching.
- Kernel modules can enforce strongly, but increase kernel integrity and crash
  risk.
- Naive eBPF monitors are safer, but repeated deep string checks on every event
  can still be expensive.

MCP eBPF Guard uses eBPF LSM for kernel-level enforcement without loading a
custom kernel module. The design moves expensive checks out of the hot path by
hoisting policy decisions to the resource allocation point and caching later
decisions by process, hook, and resource id.

## Paper Model

The paper maps the hardware TLB hit idea onto security policy checking.

Instead of fully validating every syscall, the framework separates checks into
three tiers:

| Tier | Purpose | Expected Cost Model |
|---|---|---:|
| L1 Fast Path | Epoch-valid cache lookup by process, hook, and resource | `0.018us` |
| L2 Semi-Fast Path | Cheap resource class checks, such as safe non-regular files | cumulative `0.023us` |
| L3 Slow Path | Deep policy evaluation, path/command/socket rule matching, event emit | cumulative `0.989us` |

The main optimization is resource-level hoisting:

1. Evaluate a resource once at allocation/open/connect/exec time.
2. Store the decision in an L1 cache with the current global epoch.
3. Reuse the decision for later read/write or repeated hook activity.
4. Invalidate all cached decisions in O(1) by incrementing a global epoch.

This mirrors TLB behavior: most events should become fast cache hits, while only
first-time or policy-changing events pay the slow-path cost.

## Current Implementation

The current PoC implements:

- BPF LSM hooks for:
  - `bprm_check_security`
  - `file_open`
  - `file_permission`
  - `socket_connect`
- L1 decision cache using a BPF LRU per-CPU hash map.
- Global epoch invalidation using a BPF array map.
- Policy rule map and config map.
- Ring buffer event delivery to user space.
- User-space loader using libbpf skeletons.
- Unix socket event publishing at `/tmp/mcp-guard.sock`.
- Deny tests for exec, file access, socket connect, and policy reload.
- Timing instrumentation with `layer`, `duration_ns`, `duration_us`,
  `model_us`, and `delta_us`.

## Repository Layout

```text
bpf/
  mcp_guard.bpf.c          BPF LSM hook entrypoints
  l1_fast_path.bpf.c       L1 cache lookup/store and resource id helpers
  l2_semi_fast_path.bpf.c  Cheap resource class checks
  l3_slow_path.bpf.c       Policy matching and ring buffer event emission
  maps.bpf.h               BPF map definitions
  vmlinux.h                CO-RE kernel type header

include/
  common.h                 Shared constants and enums
  cache_key.h              L1 cache key/value ABI
  policy.h                 Policy config/rule ABI
  event.h                  Ring buffer event ABI

loader/
  main.c                   Loader lifecycle, signals, stdout events
  bpf_loader.c             libbpf skeleton load/attach wrapper
  policy_loader.c          JSON policy loader and epoch bump
  ringbuf_reader.c         BPF ring buffer polling
  unix_socket_server.c     GUI-facing Unix socket publisher

policies/
  default_policy.json
  dangerous_commands.json
  dangerous_paths.json
  dangerous_network.json
  mcp_agent_profile.json

tests/
  test_execve.sh
  test_file_access.sh
  test_socket_connect.sh
  test_policy_update.sh

docs/
  loader-development-guide*.md
  gui-development-guide*.md
```

## Architecture

```text
             MCP agent / local process
                       |
                       v
              Linux syscall path
                       |
                       v
                BPF LSM hooks
                       |
       +---------------+----------------+
       |                                |
       v                                |
  L1 Fast Path                          |
  cache lookup                          |
       | hit                            |
       v                                |
  allow / deny                          |
                                        |
       miss                             |
       v                                |
  L2 Semi-Fast Path                     |
  cheap safe-resource checks            |
       | hit                            |
       v                                |
  allow + cache                         |
                                        |
       miss                             |
       v                                |
  L3 Slow Path                          |
  policy map scan, path/socket/exec     |
  matching, cache update, event emit    |
                       |
                       v
             BPF ring buffer events
                       |
                       v
                user-space loader
                       |
          stdout + /tmp/mcp-guard.sock
                       |
                       v
                     GUI
```

## Decision Pipeline

### L1 Fast Path

L1 uses `struct mcp_cache_key`:

- `tgid`
- `pid`
- `hook_id`
- `resource_id`

The cached value stores:

- decision epoch
- action: allow, deny, audit
- flags
- rule id
- reason

If the cache entry exists and its epoch equals the global epoch, the hook returns
immediately based on the cached action.

### L2 Semi-Fast Path

L2 avoids expensive string/path logic for obviously safe resources. For example,
non-regular files and selected directory read cases can be allowed without
policy string matching.

### L3 Slow Path

L3 performs deeper checks:

- command prefix checks for exec
- path/resource matching for file access
- IPv4/port matching for socket connect
- ring buffer event emission for deny/audit decisions
- cache population for follow-up events

For file policies, the PoC uses both path strings and an inode-based
`resource_id`. This makes repeated read/write enforcement less dependent on path
string availability in every hook.

## Epoch Invalidation

Policy reload does not scan and delete every cache entry. Instead:

1. User space validates and writes policy maps.
2. User space increments `global_epoch`.
3. L1 cache entries with an old epoch become invalid automatically.

This makes global invalidation O(1), which is the core lock-free epoch idea from
the paper.

## Policy Format

Default policy:

```json
{
  "default_action": "allow",
  "enforce": true,
  "audit_allowed": false
}
```

Command policy:

```json
{
  "rules": [
    {
      "name": "curl",
      "value": "/usr/bin/curl",
      "action": "deny"
    }
  ]
}
```

Path policy:

```json
{
  "rules": [
    {
      "name": "shadow-file",
      "value": "/etc/shadow",
      "action": "deny"
    }
  ]
}
```

Network policy:

```json
{
  "rules": [
    {
      "name": "reverse-shell-port-4444",
      "value": "0.0.0.0/0",
      "port": 4444,
      "action": "deny"
    }
  ]
}
```

## Requirements

Runtime requirements:

- Linux with eBPF and BPF LSM enabled
- `bpf` present in the active LSM chain
- `clang`
- `bpftool`
- `libbpf`
- root privileges to load BPF LSM programs

Check BPF LSM:

```bash
cat /sys/kernel/security/lsm
```

Expected output should include `bpf`, for example:

```text
lockdown,capability,landlock,yama,apparmor,bpf,ima,evm
```

If `CONFIG_BPF_LSM=y` exists but `bpf` is missing from the active LSM chain, add
it to the kernel boot parameter, update GRUB, and reboot:

```text
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

## Build

```bash
make
```

The build:

1. Uses `bpf/vmlinux.h` for CO-RE type information.
2. Compiles `bpf/mcp_guard.bpf.c` for the BPF target.
3. Generates `build/mcp_guard.skel.h` with `bpftool`.
4. Links the `mcp-guard` user-space loader.

Clean build outputs:

```bash
make clean
```

## Run

Start the guard:

```bash
sudo ./mcp-guard policies
```

Expected startup:

```text
loaded 7 policy rules, epoch=1
event socket listening at /tmp/mcp-guard.sock
mcp-guard running; send SIGHUP to reload policy, Ctrl-C to stop
```

Reload policies:

```bash
sudo kill -HUP $(pidof mcp-guard)
```

Stop:

```bash
sudo kill -INT $(pidof mcp-guard)
```

Read GUI-facing events:

```bash
nc -U /tmp/mcp-guard.sock
```

## Tests

Run all tests:

```bash
sudo make test
```

Run individually:

```bash
sudo ./tests/test_execve.sh
sudo ./tests/test_file_access.sh
sudo ./tests/test_socket_connect.sh
sudo ./tests/test_policy_update.sh
```

The tests verify:

- dangerous command execution denial
- protected file access denial
- suspicious IPv4 socket connect denial
- policy reload and epoch invalidation

Sample output:

```text
[deny] pid=15263 uid=0 hook=exec layer=L3 duration_ns=3887 duration_us=3.887 model_us=0.989 delta_us=2.898 rule=1 error=13 path=/usr/bin/true rule=test-true
```

## Timing Interpretation

The PoC emits timing data for deny/audit events.

Fields:

- `layer`: layer where the decision was made
- `duration_ns`: hook entry to event emission
- `duration_us`: `duration_ns / 1000`
- `model_us`: paper-derived cumulative cost baseline
- `delta_us`: measured value minus model baseline

Current baselines:

| Layer | Baseline |
|---|---:|
| L1 | `0.018us` |
| L2 | `0.023us` |
| L3 | `0.989us` |

The measured PoC value includes more than pure policy lookup. It includes helper
calls, map lookups, event preparation, and ring buffer submission. L3 events are
therefore expected to be higher than the idealized paper model. To evaluate the
paper's main claim, measure repeated access after the first L3 miss and compare
L1 hit behavior against the L3 slow path.

## Current Limitations

- The policy parser is intentionally minimal and should be hardened before
  production use.
- GUI files are still skeletons; development guides are available under `docs/`.
- Event timing is emitted for deny/audit events, not every allow event.
- File resource matching currently uses inode-oriented resource ids in the PoC.
- L3 policy matching scans a fixed-size array map, which is simple but not the
  final optimized data structure.

## Developer Guides

Loader work:

- `docs/loader-development-guide.md`
- `docs/loader-development-guide-ko.md`

GUI work:

- `docs/gui-development-guide.md`
- `docs/gui-development-guide-ko.md`

These documents define the loader/GUI split, socket event contract, development
tasks, and acceptance criteria so separate developers can work in parallel.

## Safety Note

This is an experimental security PoC. It attaches BPF LSM programs and can deny
real process, file, and socket operations. Test it in a development environment
before using it on a primary workstation.

