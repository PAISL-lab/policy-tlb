# Loader Development Guide

This guide is for the developer owning the user-space loader. The loader is the root process that loads BPF programs, writes policy maps, reads kernel ring buffer events, and publishes GUI-facing events.

## Goal

Maintain the loader as a stable daemon with predictable policy loading, event delivery, reload behavior, agent scoping, and observability.

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
  "profile_id": 1,
  "agent_id": 1,
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
- `mcp_agent_profile.json`

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

```json
{"profile":"python-agent","profile_id":42,"agent_id":7,"mode":"scoped","comms":["python3"]}
```

## Remaining Loader Roadmap

The loader is already able to load BPF programs, populate tail-call maps, write
basic policies, load generation-aware path/command/network/resource indexes,
load MCP agent scope maps, read events, reload on `SIGHUP`, print metrics on
shutdown, and publish GUI-facing JSON. The remaining work is mainly GUI
integration and benchmark/report support.

| Framework Phase | Loader Responsibility | Main Files |
|---|---|---|
| 2. LPM_TRIE/hash indexed policy | Complete: path/command/network policies use generation-aware indexed maps, with resource hash entries for follow-up file access | `policy_loader.c`, `bpf_loader.c`, `l3_slow_path.bpf.c` |
| 3. L2 flag/cache strengthening | Complete: separated config/rule flags, startup summary, unknown flag rejection, and runtime L2 test | `policy_loader.c`, `main.c` |
| 4. metrics/histogram map | Complete: shutdown summary, periodic snapshots, layer ratios, and GUI metrics JSON | `bpf_loader.c`, `main.c`, `unix_socket_server.c` |
| 5. atomic policy reload | Complete: inactive-generation staging, active generation flip, old generation cleanup, snapshot/rollback, and reload_result JSON | `policy_loader.c`, `main.c` |
| 6. MCP agent scoping | Complete for comm/pid/tgid selectors: profile parsing, scope maps, BPF prefiltering, event attribution, and runtime test | `policy_loader.c`, `main.c`, `l3_slow_path.bpf.c` |
| 7. GUI | Stabilize socket schema and add health/reload/metrics messages | `unix_socket_server.c`, `main.c` |
| 8. benchmark/report | Add benchmark mode and write CSV/JSON reports | `main.c`, new `report_writer.c` |

## Detailed Loader Backlog

### 1. LPM_TRIE Path Policy Loader

Path, command, network, and resource-id policies are now loaded into indexed
BPF maps. The L3 slow path consults generation-aware maps before falling back to
the default action.

Implemented:

- Path policy trie map id in `loader/bpf_loader.h`.
- Command policy trie map id.
- Network policy trie map id.
- Resource policy hash map id.
- Trie map fd exposure through `mcp_bpf_map_fd`.
- User-space trie key/value construction.
- Path prefixes loaded from `dangerous_paths.json`.
- Command prefixes loaded from `dangerous_commands.json`.
- IPv4/CIDR plus port rules loaded from `dangerous_network.json`.
- Resource-id hash entries for follow-up file read/write checks.
- Path policy normalization:
  - reject empty paths
  - require absolute paths
  - collapse trailing slashes except `/`
  - reject values longer than `MCP_GUARD_RULE_VALUE_LEN`
- Inactive-generation writes before active generation flip.
- Old-generation cleanup after successful reload.
- Runtime coverage through `tests/test_path_lpm_trie.sh`.

Remaining:

- Keep `policy_rules` as compatibility metadata or remove it after all tooling
  reads the indexed maps directly.

Acceptance:

- `dangerous_paths.json` can deny a file under a configured path prefix.
- More than one path prefix can coexist without ordering bugs.
- Policy reload removes deleted path prefixes.
- Bad path policy reload does not clear the active policy.
- Longest-prefix allow exceptions can override broader deny prefixes.

### 2. L2 Flag And Cache Configuration

L2 now reads `policy_config.flags`, and the loader parses initial config/rule
flags from JSON. This keeps cheap-path behavior tunable without recompiling BPF.

Implemented:

- `skip_dir_read`
- `cache_file_followups`
- `deny_tailcall_fail`
- `skip_l2_safe`
- Global flags in `policy_config.flags`.
- Per-rule flags in `mcp_policy_rule.flags`.
- `flags: [...]` arrays with unknown flag rejection.
- Startup flag summary after policy load.
- `tests/test_l2_flags_cache.sh` coverage for L2 file-open allow and bad flag rejection.

Remaining:

- Add deeper follow-up cache tests that inspect L1 read/write reuse after file-open decisions.
- Decide whether rule-level `skip_l2_safe` should remain metadata only or drive a future per-resource L2 bypass map.

Acceptance:

- Existing policy files still load unchanged.
- Unknown flags are rejected with a useful error.
- Tests can assert that follow-up read/write cache behavior is enabled.
- Tests can assert that safe file-open operations hit L2.

### 3. Metrics And Histogram Reader

BPF now records per-CPU counters and coarse latency histograms by hook, layer,
and action. The loader prints a final metrics summary on shutdown and can emit
periodic metrics snapshots while running.

Implemented:

- Metrics map id in `loader/bpf_loader.h`.
- Per-CPU metrics reads in the loader.
- Count, total, min, max, and 8 histogram buckets.
- Shutdown summary.
- `--metrics-interval` CLI option.
- Periodic `metrics snapshot` stdout output.
- Explicit L1/L2/L3 layer ratios.
- GUI-facing JSON messages with `"type":"metrics_snapshot"`.
- `tests/test_metrics_snapshot.sh` coverage.

Remaining:

- Aggregate by reason.
- Add per-hook histogram JSON details to the GUI snapshot if the GUI needs
  full bucket rendering instead of aggregate ratios.

Acceptance:

- Running `sudo ./mcp-guard policies --metrics-interval 1s` prints periodic
  metrics.
- GUI clients can distinguish event messages from metrics messages.
- Metrics do not block ring buffer polling.
- Tests can receive a `metrics_snapshot` message over `/tmp/mcp-guard.sock`.

### 4. Atomic Policy Reload

The reload path parses policy files into memory first, snapshots the active BPF
maps, writes the new policy state, and increments `global_epoch` last. If a map
write fails before the epoch flip, the loader restores the previous policy maps.

Implemented:

- Parse every policy file into memory first.
- Build the complete policy state before touching BPF maps.
- Validate the complete policy set before map writes.
- Stage path/command/network/resource index entries under the next inactive
  generation.
- Snapshot active policy rules, config, indexed maps, and scope maps.
- Delete staged generation entries if a reload write fails before epoch bump.
- Track `active_generation` in policy config.
- Increment `global_epoch` only after policy maps/config are updated.
- Clean up the previous generation's indexed entries after a successful flip.
- Publish `"type":"reload_result"` JSON over the GUI socket.
- `tests/test_atomic_reload.sh` coverage.

Remaining:

- Scope maps still use snapshot/rollback because scope selectors are keyed by
  process identity rather than generation. Add generation to scope keys if
  profile reloads become high-frequency.

Acceptance:

- Corrupting one policy file and sending `SIGHUP` keeps the previous policy
  active.
- Failed reload keeps the previous epoch.
- Reload result is published as JSON:
  - `"type":"reload_result"`
  - `success`
  - `rule_count`
  - `epoch`
  - `error`

### 5. MCP Agent Scoping

The framework needs to distinguish a normal local process from a specific MCP
agent profile. The loader owns profile parsing and scope map population.

Implemented:

- `policies/mcp_agent_profile.json` parsing.
- Stable `agent_id`, `profile_id`, and `profile` name storage in
  `policy_config`.
- `system-wide` mode for host-wide enforcement.
- `scoped` mode for agent-only enforcement.
- Scope selectors:
  - `comm` / `comms`
  - `pid` / `pids`
  - `tgid` / `tgids`
- Dedicated BPF scope maps for `comm`, `pid`, and `tgid`.
- BPF prefiltering before L1/L2/L3 policy work.
- Profile/agent consistency checks on scope map hits.
- `profile_id` and `agent_id` in ring-buffer events and GUI JSON.
- Snapshot/rollback of scope maps during atomic reload.
- Runtime coverage through `tests/test_agent_scope.sh`.

Remaining:

- Add `cgroup_id` selectors when the daemon owns a stable cgroup placement
  contract for MCP agents.
- Support multiple simultaneously active profiles if the product requires more
  than one scoped policy set at a time.

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
./configure
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
