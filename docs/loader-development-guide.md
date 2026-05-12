# Loader Development Guide

This guide is for the developer owning the user-space loader. The loader is the root process that loads BPF programs, writes policy maps, reads kernel ring buffer events, and publishes GUI-facing events.

## Goal

Turn the current PoC loader into a stable daemon with predictable policy loading, event delivery, reload behavior, and observability.

Current entrypoint:

```bash
sudo ./mcp-guard policies
```

The loader must keep these contracts stable for the GUI developer:

- Unix socket path: `/tmp/mcp-guard.sock`
- Event format: one JSON object per line
- Policy reload: `SIGHUP`
- Shutdown: `SIGINT` or `SIGTERM`
- Default policy directory: `policies`

## Current Flow

1. `loader/main.c` raises `RLIMIT_MEMLOCK`.
2. `loader/bpf_loader.c` opens and loads `build/mcp_guard.skel.h`.
3. `loader/bpf_loader.c` disables auto-attach for internal L2/L3 programs and
   writes their fds into hook-specific tail-call `PROG_ARRAY` maps.
4. `loader/policy_loader.c` reads JSON policy files and writes BPF maps.
5. Policy load increments `global_epoch`.
6. `loader/ringbuf_reader.c` polls the BPF ring buffer.
7. `loader/main.c` prints events to stdout.
8. `loader/unix_socket_server.c` publishes the same events to `/tmp/mcp-guard.sock`.

## Public Interfaces To Preserve

### Event JSON

The socket server currently sends newline-delimited JSON:

```json
{
  "ts_ns": 123,
  "pid": 15263,
  "uid": 0,
  "hook": "exec",
  "action": "deny",
  "layer": "L3",
  "duration_ns": 3887,
  "rule_id": 1,
  "error": 13,
  "path": "/usr/bin/true",
  "rule": "test-true",
  "port": 0
}
```

Do not remove or rename these fields without updating the GUI guide and GUI client. Additive fields are allowed.

### Policy Files

Policy directory inputs:

- `default_policy.json`
- `dangerous_commands.json`
- `dangerous_paths.json`
- `dangerous_network.json`

Current schema is intentionally small:

```json
{"default_action":"allow","enforce":true,"audit_allowed":false}
```

```json
{"rules":[{"name":"test","value":"/path/or/command","action":"deny"}]}
```

```json
{"rules":[{"name":"blocked-port","value":"0.0.0.0/0","port":4444,"action":"deny"}]}
```

## Remaining Loader Roadmap

The loader is already able to load BPF programs, populate tail-call maps, write
basic policies, read events, reload on `SIGHUP`, and publish GUI-facing JSON.
The remaining work is about stronger policy data structures, safer reloads,
agent scoping, observability, and benchmark/report support.

| Framework Phase | Loader Responsibility | Main Files |
|---|---|---|
| 2. LPM_TRIE path policy | Convert path prefix rules into trie keys and load the trie map | `policy_loader.c`, `bpf_loader.c` |
| 3. L2 flag/cache strengthening | Parse rule/cache flags and expose cache behavior settings | `policy_loader.c`, `main.c` |
| 4. metrics/histogram map | Read metrics maps, aggregate snapshots, publish summaries | `bpf_loader.c`, `main.c`, `unix_socket_server.c` |
| 5. atomic policy reload | Build/validate inactive policy state and flip active generation last | `policy_loader.c`, `main.c` |
| 6. MCP agent scoping | Parse agent profiles and bind policy scopes to pid/tgid/cgroup/comm | `policy_loader.c`, `main.c` |
| 7. GUI | Stabilize socket schema and add health/reload/metrics messages | `unix_socket_server.c`, `main.c` |
| 8. benchmark/report | Add benchmark mode and write CSV/JSON reports | `main.c`, new `report_writer.c` |

## Detailed Loader Backlog

### 1. LPM_TRIE Path Policy Loader

Current path policy rules are loaded into the fixed-size `policy_rules` array.
For the next implementation stage, path prefix matching should move to an
LPM trie map so L3 avoids scanning every path rule.

Tasks:

- Add a path policy trie map id to `loader/bpf_loader.h`.
- Expose the trie map fd through `mcp_bpf_map_fd`.
- Define a user-space key builder matching the BPF trie key layout.
- Normalize path policy values before loading:
  - reject empty paths
  - require absolute paths
  - collapse trailing slashes except `/`
  - reject values longer than `MCP_GUARD_PATH_LEN`
- Convert each prefix to a trie key and update the BPF map.
- Keep existing array rules for command and network policies.
- Decide the transition mode:
  - compatibility mode: keep path rules in both array and trie
  - optimized mode: path prefixes only in trie, metadata in an auxiliary map

Acceptance:

- `dangerous_paths.json` can deny a file under a configured path prefix.
- More than one path prefix can coexist without ordering bugs.
- Policy reload removes deleted path prefixes.
- Bad path policy reload does not clear the active policy.

### 2. L2 Flag And Cache Configuration

L2 currently makes a few hard-coded cheap decisions. The loader should make
these behaviors configurable without forcing BPF code changes for every test.

Tasks:

- Extend policy JSON with optional flags, for example:
  - `cache_followups`
  - `audit_allowed`
  - `skip_dir_read`
  - `deny_on_tailcall_fail`
- Validate flags per rule type.
- Store global cache behavior in `policy_config`.
- Store per-rule flags in `mcp_policy_rule.flags`.
- Print loaded flag summaries at startup in verbose mode.

Acceptance:

- Existing policy files still load unchanged.
- Unknown flags are rejected with a useful error.
- Tests can assert that follow-up read/write cache behavior is enabled.

### 3. Metrics And Histogram Reader

BPF currently emits per-event timing through the ring buffer. The next step is
to add map-based counters and histograms so the loader can report hit ratio and
latency distribution without relying only on deny events.

Tasks:

- Add map ids for metrics/histogram maps.
- Read metrics periodically in the main loop.
- Aggregate by hook, layer, action, and reason.
- Compute L1/L2/L3 hit ratios.
- Publish a JSON message with `"type":"metrics_snapshot"`.
- Print a final summary on shutdown.

Acceptance:

- Running `sudo ./mcp-guard policies --metrics-interval 1s` prints periodic
  metrics.
- GUI clients can distinguish event messages from metrics messages.
- Metrics do not block ring buffer polling.

### 4. Atomic Policy Reload

The current reload path validates some inputs, clears the rule array, loads new
entries, then increments `global_epoch`. This is good enough for a PoC but not
for a robust live daemon.

Tasks:

- Parse every policy file into memory first.
- Validate the complete policy set before touching BPF maps.
- Add an active generation field to policy config when the BPF side supports it.
- Load new data into inactive generation maps or shadow slots.
- Flip the active generation last.
- Increment `global_epoch` only after the full policy state is visible.
- On failure, leave the existing policy and epoch unchanged.

Acceptance:

- Corrupting one policy file and sending `SIGHUP` keeps the previous policy
  active.
- Reload result is published as JSON:
  - `"type":"reload_result"`
  - `success`
  - `rule_count`
  - `epoch`
  - `error`

### 5. MCP Agent Scoping

The framework needs to distinguish a normal local process from a specific MCP
agent profile. The loader owns profile parsing and scope map population.

Tasks:

- Parse `policies/mcp_agent_profile.json`.
- Assign stable `agent_id` and `profile_id` values.
- Bind profiles to one or more selectors:
  - `pid`
  - `tgid`
  - `comm`
  - future: `cgroup_id`
- Load scope entries into BPF maps.
- Add agent/profile fields to event JSON once the BPF event ABI exposes them.

Acceptance:

- A policy can apply only to a selected MCP agent process.
- Non-agent processes can use a default profile.
- GUI events include enough fields to show which profile made the decision.

### 6. GUI Socket Contract

The loader socket should become a stable event and control channel for the GUI.

Tasks:

- Add `"type":"event"` to existing event JSON.
- Correctly escape JSON strings.
- Add additive fields:
  - `comm`
  - `tgid`
  - `epoch`
  - `resource_id`
  - `duration_us`
  - `model_us`
  - `delta_us`
- Add message types:
  - `metrics_snapshot`
  - `reload_result`
  - `health`
- Keep newline-delimited JSON.

Acceptance:

- Existing GUI clients that ignore unknown fields keep working.
- A disconnected or slow GUI client never blocks enforcement/event polling.

### 7. Benchmark And Report Mode

The loader should support reproducible measurements for the paper-style report.

Tasks:

- Add CLI options:
  - `--benchmark`
  - `--duration`
  - `--report`
  - `--warmup`
- Capture policy version, kernel version, BPF LSM status, and git commit.
- Export JSON and CSV reports.
- Include:
  - event counts by hook/layer
  - L1/L2/L3 hit ratio
  - average and percentile latency
  - model baseline and measured delta

Acceptance:

- One command can produce a report under `reports/`.
- Report output is deterministic enough to compare before/after changes.

## Implementation Tasks

1. Harden policy parsing in `loader/policy_loader.c`.
   - Replace the current minimal string scanner with a real JSON parser or a small validated parser.
   - Reject malformed files with filename and field-level error messages.
   - Validate `action` as `allow`, `deny`, or `audit`.
   - Validate required fields per rule type.
   - Keep `MCP_GUARD_MAX_RULES` overflow as a hard error.

2. Improve daemon lifecycle in `loader/main.c`.
   - Add CLI flags: `--policy-dir`, `--socket`, `--foreground`, `--verbose`.
   - Keep positional `policies` path working for compatibility.
   - Print a clear startup summary: loaded rules, epoch, socket path, attached hooks.
   - On `SIGHUP`, reload policies atomically: if reload fails, keep the previous policy active.

3. Make policy map updates atomic enough for live reload.
   - Build new rule array in memory first.
   - Write disabled/empty entries only after validation succeeds.
   - Update config and rules.
   - Increment epoch last.

4. Improve event transport in `loader/unix_socket_server.c`.
   - Keep newline-delimited JSON.
   - Escape JSON strings correctly for `path` and `rule`.
   - Add `comm`, `tgid`, `epoch`, `resource_id`, `duration_us`, `model_us`, and `delta_us`.
   - Handle slow/disconnected clients without blocking ring buffer polling.

5. Add runtime metrics.
   - Count events by `hook`, `action`, and `layer`.
   - Track `min/avg/p95/p99` for `duration_ns`.
   - Print summary on shutdown.
   - Optional: expose metrics JSON over the same socket with a distinct message type.

## Acceptance Criteria

The loader developer is done when these pass:

```bash
make clean && make
sudo make test
```

Manual checks:

```bash
sudo ./mcp-guard policies
sudo kill -HUP $(pidof mcp-guard)
nc -U /tmp/mcp-guard.sock
```

Expected behavior:

- Bad policy reload does not clear the active policy.
- GUI socket clients receive JSON lines without breaking stdout logging.
- LSM attach failures print the failing program name and libbpf error.
- `sudo make test` prints event lines with `layer` and `duration_ns`.

## Coordination With GUI Developer

The GUI developer depends on the socket JSON contract. If the loader changes fields, update `docs/gui-development-guide.md` in the same commit.

Preferred event compatibility rule:

- Never remove existing fields.
- New fields are optional for the GUI.
- Unknown fields must be ignored by the GUI.
