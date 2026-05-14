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

The remaining loader work is Phase 7 support for the GUI control/event channel
and Phase 8 benchmark/report mode. Earlier policy indexing, L2 flags, metrics
maps, generation-aware reload, and agent scoping are already implemented and
should be treated as stable contracts unless a test-driven bug fix requires a
change.

## Development Specification

This section defines the remaining loader implementation contract. A loader
developer should be able to implement the remaining work directly from this
section.

### Remaining Scope

| Area | Status | Required Next Work |
|---|---|---|
| GUI event socket | partially implemented | Complete event JSON fields, JSON escaping, health messages, slow-client handling |
| Metrics transport | partially implemented | Ensure stable `metrics_snapshot` schema with detailed entries |
| Reload transport | partially implemented | Keep `reload_result` schema stable and document all fields |
| Benchmark/report | not implemented | Add CLI mode, workload timing capture, JSON/CSV report writer |
| Policy parser hardening | partial | Improve validation/errors without changing policy file compatibility |

Out of scope for the remaining loader phase:

- Adding new BPF hooks.
- Changing the 3-tier BPF pipeline.
- Replacing the GUI with a web service.
- Running GUI processes from the loader.

### Command Line Interface

The final loader CLI must support:

```bash
sudo ./mcp-guard [POLICY_DIR]
sudo ./mcp-guard --policy-dir policies
sudo ./mcp-guard policies --metrics-interval 1s
sudo ./mcp-guard policies --socket /tmp/mcp-guard.sock
sudo ./mcp-guard policies --benchmark --duration 30s --warmup 5s --report reports/run.json
sudo ./mcp-guard policies --benchmark --duration 30s --report reports/run.csv
```

Arguments:

| Argument | Required | Default | Behavior |
|---|---:|---|---|
| positional `POLICY_DIR` | no | `policies` | Backward-compatible policy directory |
| `--policy-dir PATH` | no | positional or `policies` | Explicit policy directory |
| `--socket PATH` | no | `/tmp/mcp-guard.sock` | Unix socket path for GUI JSON messages |
| `--metrics-interval DURATION` | no | disabled | Emit periodic metrics snapshots |
| `--benchmark` | no | false | Enable benchmark/report collection mode |
| `--duration DURATION` | only with benchmark | `30s` | Benchmark measurement window |
| `--warmup DURATION` | no | `0s` | Warmup window excluded from report |
| `--report PATH` | with benchmark | generated under `reports/` | Report output path |
| `--report-format json|csv` | no | inferred from extension | Explicit report format |
| `--foreground` | no | true for now | Reserved for daemonization compatibility |
| `--verbose` | no | false | Print extra loader diagnostics |

Duration grammar:

- Accept integer seconds: `30`.
- Accept suffixes: `ms`, `s`, `m`.
- Reject zero or negative durations where a positive value is required.

Compatibility rules:

- Existing `sudo ./mcp-guard policies` behavior must keep working.
- Unknown options must print usage and exit nonzero.
- Invalid benchmark/report combinations must fail before BPF attach.

### Module Contract

| File | Responsibility |
|---|---|
| `loader/main.c` | CLI parsing, lifecycle, signal handling, benchmark loop coordination |
| `loader/bpf_loader.c` | libbpf open/load/attach, tail-call setup, map fd exposure |
| `loader/policy_loader.c` | Policy parse/validate/load/reload into BPF maps |
| `loader/ringbuf_reader.c` | BPF ring buffer polling and callback dispatch |
| `loader/unix_socket_server.c` | Nonblocking GUI socket broadcast |
| `loader/report_writer.c` | New file for benchmark JSON/CSV output |
| `loader/report_writer.h` | New report writer API |

Do not put report serialization into `main.c`; keep it in `report_writer.c` so
the runtime daemon path remains readable.

### GUI Socket Message Contract

All GUI messages are newline-delimited JSON objects. Every message must include
`type`.

#### `type=event`

Required fields:

| Field | Type | Source |
|---|---|---|
| `type` | string | literal `event` |
| `ts_ns` | integer | `mcp_event.ts_ns` |
| `pid` | integer | `mcp_event.pid` |
| `tgid` | integer | `mcp_event.tgid` |
| `uid` | integer | `mcp_event.uid` |
| `comm` | string | `mcp_event.comm` |
| `hook` | string | decoded hook |
| `action` | string | decoded action |
| `layer` | string | decoded layer |
| `duration_ns` | integer | `mcp_event.duration_ns` |
| `duration_us` | number | `duration_ns / 1000.0` |
| `model_us` | number | model baseline by layer |
| `delta_us` | number | `duration_us - model_us` |
| `rule_id` | integer | `mcp_event.rule_id` |
| `profile_id` | integer | `mcp_event.profile_id` |
| `agent_id` | integer | `mcp_event.agent_id` |
| `error` | integer | errno value |
| `path` | string | path or `""` |
| `rule` | string | matched rule or `""` |
| `port` | integer | destination port or `0` |
| `ipv4_addr` | string | dotted IPv4 or `""` |
| `resource_id` | integer | `mcp_event.resource_id` |
| `epoch` | integer | `mcp_event.epoch` |

Rules:

- Escape JSON strings correctly for `path`, `rule`, and `comm`.
- Keep numeric values numeric, not quoted.
- `ipv4_addr` should be dotted decimal for GUI display.
- Do not block ring buffer polling if no GUI client is connected.

#### `type=metrics_snapshot`

Minimum schema:

```json
{
  "type": "metrics_snapshot",
  "ts_ns": 123,
  "total": 100,
  "l1_ratio": 0.70,
  "l2_ratio": 0.05,
  "l3_ratio": 0.25,
  "entries": []
}
```

Detailed `entries[]` item:

| Field | Type |
|---|---|
| `hook` | string |
| `layer` | string |
| `action` | string |
| `count` | integer |
| `avg_ns` | integer |
| `min_ns` | integer |
| `max_ns` | integer |
| `buckets` | array of 8 integers |

Rules:

- Emit snapshots only when `--metrics-interval` is set.
- Snapshot generation must not block event polling.
- Empty metrics are valid and should emit `total=0`.

#### `type=reload_result`

Schema:

```json
{
  "type": "reload_result",
  "success": true,
  "rule_count": 7,
  "generation": 2,
  "epoch": 2,
  "error": ""
}
```

Rules:

- Emit after every initial load and `SIGHUP` reload attempt once the socket
  server is available.
- On failure, keep previous active policy and include a useful `error` string.

#### `type=health`

Schema:

```json
{
  "type": "health",
  "status": "running",
  "policy_dir": "policies",
  "generation": 2,
  "epoch": 2,
  "rule_count": 7,
  "socket_path": "/tmp/mcp-guard.sock"
}
```

Rules:

- Emit once after startup.
- Emit after successful reload.
- Optional future heartbeat is allowed but not required.

### JSON Escaping Specification

`loader/unix_socket_server.c` must provide a small JSON string escaping helper.

Required escaping:

- `"` as `\"`
- `\` as `\\`
- newline as `\n`
- carriage return as `\r`
- tab as `\t`
- control bytes below `0x20` as `\u00XX`

The helper must truncate safely if the output buffer is too small and must never
write past the buffer.

### Slow Client Handling

The Unix socket server must keep enforcement/event polling independent from GUI
clients.

Rules:

- Each client fd must be nonblocking.
- If a write returns `EAGAIN` or `EWOULDBLOCK`, drop that message for that
  client or disconnect the client.
- If a write returns `EPIPE`, `ECONNRESET`, or another permanent error, remove
  the client.
- Do not buffer unbounded data per client.
- Enforce `MCP_GUARD_MAX_CLIENTS`.

### Benchmark Mode Specification

Benchmark mode observes runtime metrics for a fixed window and writes a report.
It does not need to generate workload by itself in this phase; workload can be
created by tests or a separate shell while the loader records metrics.

Benchmark lifecycle:

1. Parse and validate CLI.
2. Load and attach BPF programs.
3. Load policy.
4. Start GUI socket unless disabled in a future option.
5. Run warmup window, ignoring warmup metrics in the final report.
6. Reset or mark the metrics baseline.
7. Run measurement window.
8. Read metrics, policy metadata, kernel metadata, and git metadata.
9. Write report.
10. Print report path and summary.
11. Exit cleanly.

Report metadata:

| Field | Source |
|---|---|
| `timestamp` | wall-clock time |
| `duration_ms` | CLI |
| `warmup_ms` | CLI |
| `policy_dir` | CLI |
| `rule_count` | policy load result |
| `generation` | policy load result |
| `epoch` | policy load result |
| `kernel_release` | `uname` |
| `bpf_lsm_enabled` | `/sys/kernel/security/lsm` contains `bpf` |
| `git_commit` | `git rev-parse HEAD` when available |
| `loader_version` | optional static string |

Report metrics:

- total count
- count by hook/layer/action
- L1/L2/L3 ratios
- average latency by hook/layer/action
- min/max latency
- histogram buckets
- model baseline by layer
- measured delta from model baseline

JSON report shape:

```json
{
  "metadata": {},
  "summary": {
    "total": 0,
    "l1_ratio": 0.0,
    "l2_ratio": 0.0,
    "l3_ratio": 0.0
  },
  "metrics": []
}
```

CSV report columns:

```text
hook,layer,action,count,avg_ns,min_ns,max_ns,bucket0,bucket1,bucket2,bucket3,bucket4,bucket5,bucket6,bucket7,model_us,delta_us
```

### Report Writer API

Add `loader/report_writer.h`:

```c
struct mcp_report_metadata {
	const char *policy_dir;
	const char *report_path;
	unsigned int duration_ms;
	unsigned int warmup_ms;
	unsigned int rule_count;
	unsigned int generation;
	unsigned long long epoch;
};

int mcp_write_json_report(const char *path,
			  const struct mcp_report_metadata *metadata,
			  const struct mcp_metric_snapshot *snapshot);
int mcp_write_csv_report(const char *path,
			 const struct mcp_report_metadata *metadata,
			 const struct mcp_metric_snapshot *snapshot);
```

The exact internal snapshot type may be adjusted to match existing metrics
reader code, but report writing must remain behind this API boundary.

### Policy Parser Hardening

Remaining parser work should improve diagnostics without breaking current JSON
files.

Required behavior:

- Report filename and field name on validation errors.
- Reject unknown `action` values instead of silently treating them as `allow`.
- Reject invalid ports above `65535`.
- Reject invalid CIDR prefixes.
- Reject scoped agent profiles with no selectors.
- Keep `MCP_GUARD_MAX_RULES` overflow as a hard error.

### Loader Implementation Checklist

- [ ] Event JSON includes `type`, `comm`, `tgid`, `epoch`, `resource_id`,
  `duration_us`, `model_us`, `delta_us`, and `ipv4_addr`.
- [ ] JSON strings are escaped correctly.
- [ ] Unix socket clients are nonblocking and cannot stall ring buffer polling.
- [ ] `metrics_snapshot` schema includes detailed entries.
- [ ] `reload_result` schema is stable for success and failure.
- [ ] Startup and reload publish `health` messages.
- [ ] CLI supports `--policy-dir`, `--socket`, `--benchmark`, `--duration`,
  `--warmup`, `--report`, `--report-format`, and keeps positional policy dir.
- [ ] Benchmark mode writes JSON reports.
- [ ] Benchmark mode writes CSV reports.
- [ ] Reports include metadata needed for paper comparisons.
- [ ] Parser diagnostics identify file and invalid field.
- [ ] `sudo make test` passes.
- [ ] New loader tests cover socket JSON fields, JSON escaping, and report
  generation.

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
