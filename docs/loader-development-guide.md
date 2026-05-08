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
2. `loader/bpf_loader.c` opens, loads, and attaches `build/mcp_guard.skel.h`.
3. `loader/policy_loader.c` reads JSON policy files and writes BPF maps.
4. Policy load increments `global_epoch`.
5. `loader/ringbuf_reader.c` polls the BPF ring buffer.
6. `loader/main.c` prints events to stdout.
7. `loader/unix_socket_server.c` publishes the same events to `/tmp/mcp-guard.sock`.

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

