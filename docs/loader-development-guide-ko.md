# 로더 개발 가이드

이 문서는 user-space loader 담당 개발자를 위한 가이드입니다. 로더는 root 권한으로 실행되며 BPF 프로그램 로드, 정책 맵 갱신, 커널 ring buffer 이벤트 수신, GUI용 이벤트 전송을 담당합니다.

## 목표

로더를 안정적인 데몬으로 유지하는 것이 목표입니다. 특히 정책 로딩, 이벤트 전달, 정책 reload, agent scoping, 관측 가능성을 예측 가능한 형태로 만들어야 합니다.

현재 실행 방식:

```bash
sudo ./mcp-guard policies
```

GUI 개발자와 공유해야 하는 계약은 다음과 같습니다.

- Unix socket 경로: `/tmp/mcp-guard.sock`
- 이벤트 형식: 한 줄에 JSON 객체 하나
- 정책 reload: `SIGHUP`
- 종료: `SIGINT` 또는 `SIGTERM`
- 기본 정책 디렉토리: `policies`

## 현재 흐름

1. `loader/main.c`가 `RLIMIT_MEMLOCK`을 올립니다.
2. `loader/bpf_loader.c`가 `build/mcp_guard.skel.h`를 열고 BPF 프로그램을 load합니다.
3. `loader/bpf_loader.c`가 내부 L2/L3 프로그램의 auto-attach를 끄고 hook별 tail-call `PROG_ARRAY` map에 program fd를 씁니다.
4. `loader/policy_loader.c`가 JSON 정책 파일을 읽고 BPF map에 씁니다.
5. 정책 load가 끝나면 `global_epoch`를 증가시킵니다.
6. `loader/ringbuf_reader.c`가 BPF ring buffer를 poll합니다.
7. `loader/main.c`가 이벤트를 stdout에 출력합니다.
8. `loader/unix_socket_server.c`가 같은 이벤트를 `/tmp/mcp-guard.sock`으로 GUI에 전달합니다.

## 유지해야 할 공개 인터페이스

### 이벤트 JSON

socket server는 newline-delimited JSON을 보냅니다.

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

GUI 가이드와 GUI client를 함께 수정하지 않는 한 기존 필드를 삭제하거나 이름을 바꾸면 안 됩니다. 필드 추가는 허용됩니다.

### 정책 파일

정책 디렉토리에서 읽는 파일:

- `default_policy.json`
- `dangerous_commands.json`
- `dangerous_paths.json`
- `dangerous_network.json`
- `mcp_agent_profile.json`

현재 스키마는 의도적으로 작게 유지되어 있습니다.

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

## 남은 로더 개발 범위

현재 로더는 BPF 프로그램 load/attach, tail-call map 구성, 기본 정책 map 적재, generation-aware path/command/network/resource index 적재, MCP agent scope map 적재, `SIGHUP` reload, ring buffer 이벤트 수신, 종료 시 metrics summary 출력, GUI용 JSON 전송까지 수행합니다. 남은 작업은 주로 GUI 통합과 benchmark/report 기능입니다.

| 프레임워크 단계 | 로더 책임 | 주요 파일 |
|---|---|---|
| 2. LPM_TRIE/hash indexed policy | 완료: path/command/network 정책은 generation-aware index map 사용, file follow-up은 resource hash 사용 | `policy_loader.c`, `bpf_loader.c`, `l3_slow_path.bpf.c` |
| 3. L2 flag/cache 강화 | 완료: config/rule flag 분리, startup summary, 알 수 없는 flag 거부, L2 runtime test 포함 | `policy_loader.c`, `main.c` |
| 4. metrics/histogram map | 완료: 종료 summary, 주기적 snapshot, layer ratio, GUI metrics JSON 포함 | `bpf_loader.c`, `main.c`, `unix_socket_server.c` |
| 5. atomic policy reload | 완료: inactive-generation staging, active generation flip, old generation cleanup, snapshot/rollback, reload_result JSON 포함 | `policy_loader.c`, `main.c` |
| 6. MCP agent scoping | comm/pid/tgid selector 기준 완료: profile parsing, scope map, BPF prefilter, event attribution, runtime test 포함 | `policy_loader.c`, `main.c`, `l3_slow_path.bpf.c` |
| 7. GUI | socket schema 안정화, health/reload/metrics 메시지 추가 | `unix_socket_server.c`, `main.c` |
| 8. benchmark/report | benchmark mode와 CSV/JSON report 생성 | `main.c`, 새 `report_writer.c` |

## 상세 로더 백로그

### 1. LPM_TRIE Path Policy Loader

path, command, network, resource-id 정책은 이제 indexed BPF map에 적재됩니다. L3 slow path는 기본 action으로 떨어지기 전에 generation-aware map을 조회합니다.

구현됨:

- `loader/bpf_loader.h`의 path policy trie map id.
- command policy trie map id.
- network policy trie map id.
- resource policy hash map id.
- `mcp_bpf_map_fd`의 trie map fd 노출.
- user-space trie key/value 구성.
- `dangerous_paths.json`의 path prefix 적재.
- `dangerous_commands.json`의 command prefix 적재.
- `dangerous_network.json`의 IPv4/CIDR + port rule 적재.
- follow-up file read/write를 위한 resource-id hash entry.
- path policy 정규화:
  - 빈 path 거부
  - 절대 경로만 허용
  - `/`를 제외한 trailing slash 제거
  - `MCP_GUARD_RULE_VALUE_LEN`보다 긴 값 거부
- active generation flip 전 inactive generation에 먼저 write.
- 성공한 reload 후 old-generation cleanup.
- `tests/test_path_lpm_trie.sh` runtime test 추가.

남음:

- 모든 tooling이 indexed map을 직접 읽게 되면 `policy_rules`를 compatibility metadata로 유지할지 제거할지 결정합니다.

완료 기준:

- `dangerous_paths.json`의 prefix 하위 파일 접근을 차단할 수 있어야 합니다.
- path prefix 여러 개가 순서 버그 없이 공존해야 합니다.
- policy reload 시 삭제된 path prefix가 제거되어야 합니다.
- 잘못된 path 정책 reload가 기존 active policy를 지우면 안 됩니다.
- 더 구체적인 longest-prefix allow 예외가 더 넓은 deny prefix를 덮어쓸 수 있어야 합니다.

### 2. L2 Flag And Cache Configuration

L2는 이제 `policy_config.flags`를 읽고, loader는 JSON에서 초기 config/rule flag를 파싱합니다. 따라서 BPF를 다시 컴파일하지 않고 일부 cheap-path 동작을 조정할 수 있습니다.

구현됨:

- `skip_dir_read`
- `cache_file_followups`
- `deny_tailcall_fail`
- `skip_l2_safe`
- global flag의 `policy_config.flags` 저장.
- per-rule flag의 `mcp_policy_rule.flags` 저장.
- `flags: [...]` 배열과 알 수 없는 flag 거부.
- policy load 이후 startup flag summary 출력.
- `tests/test_l2_flags_cache.sh`에서 L2 file-open allow와 잘못된 flag 거부 검증.

남음:

- file-open 결정 이후 read/write L1 재사용을 직접 확인하는 follow-up cache test를 더 강화합니다.
- rule-level `skip_l2_safe`를 metadata로 유지할지, 향후 per-resource L2 bypass map으로 연결할지 결정합니다.

완료 기준:

- 기존 정책 파일은 수정 없이 계속 load되어야 합니다.
- 알 수 없는 flag는 명확한 오류와 함께 거부되어야 합니다.
- test에서 후속 read/write cache 동작이 켜졌는지 검증할 수 있어야 합니다.
- test에서 safe file-open 동작이 L2에 걸렸는지 검증할 수 있어야 합니다.

### 3. Metrics And Histogram Reader

BPF는 이제 hook, layer, action별 per-CPU counter와 coarse latency histogram을 기록합니다. loader는 종료 시 최종 metrics summary를 출력하고, 실행 중 주기적 metrics snapshot도 발행할 수 있습니다.

구현됨:

- `loader/bpf_loader.h`의 metrics map id.
- loader의 per-CPU metrics read.
- count, total, min, max, 8개 histogram bucket.
- 종료 시 summary 출력.
- `--metrics-interval` CLI option.
- 주기적 `metrics snapshot` stdout 출력.
- L1/L2/L3 layer ratio 계산.
- `"type":"metrics_snapshot"` GUI용 JSON message.
- `tests/test_metrics_snapshot.sh` test 추가.

남음:

- reason별 집계를 추가합니다.
- GUI가 전체 bucket rendering을 필요로 하면 per-hook histogram JSON detail을 추가합니다.

완료 기준:

- `sudo ./mcp-guard policies --metrics-interval 1s`가 주기적으로 metrics를 출력해야 합니다.
- GUI client가 event 메시지와 metrics 메시지를 구분할 수 있어야 합니다.
- metrics 수집이 ring buffer polling을 막으면 안 됩니다.
- `/tmp/mcp-guard.sock`에서 `metrics_snapshot` message를 받을 수 있어야 합니다.

### 4. Atomic Policy Reload

현재 reload는 정책 파일을 먼저 memory로 parse하고, active BPF map을 snapshot한 뒤, 새 정책 상태를 쓰고 `global_epoch`를 마지막에 증가시킵니다. epoch flip 전에 map write가 실패하면 loader는 이전 policy map을 복원합니다.

구현됨:

- 모든 정책 파일을 먼저 memory로 parse합니다.
- BPF map을 건드리기 전에 전체 정책 상태를 구성합니다.
- BPF map write 전에 전체 policy set을 검증합니다.
- path/command/network/resource index entry를 다음 inactive generation에 stage합니다.
- active policy rules, config, indexed map, scope map을 snapshot합니다.
- epoch bump 전에 reload write가 실패하면 staged generation entry를 삭제합니다.
- policy config의 `active_generation`을 갱신합니다.
- policy map/config 갱신 뒤 마지막에 `global_epoch`를 증가시킵니다.
- 성공한 flip 뒤 이전 generation의 indexed entry를 정리합니다.
- GUI socket으로 `"type":"reload_result"` JSON을 발행합니다.
- `tests/test_atomic_reload.sh` test를 추가했습니다.

남음:

- scope map은 process identity를 key로 쓰기 때문에 아직 snapshot/rollback 방식입니다. profile reload가 잦아지면 scope key에도 generation을 넣습니다.

완료 기준:

- 정책 파일 하나를 깨뜨린 뒤 `SIGHUP`을 보내도 기존 정책이 계속 active여야 합니다.
- 실패한 reload는 기존 epoch를 유지해야 합니다.
- reload 결과가 JSON으로 발행되어야 합니다.
  - `"type":"reload_result"`
  - `success`
  - `rule_count`
  - `epoch`
  - `error`

### 5. MCP Agent Scoping

프레임워크는 일반 로컬 프로세스와 특정 MCP agent profile을 구분해야 합니다. profile parsing과 scope map 적재는 loader 책임입니다.

구현됨:

- `policies/mcp_agent_profile.json` parsing.
- `policy_config`에 안정적인 `agent_id`, `profile_id`, `profile` 이름 저장.
- host-wide enforcement를 위한 `system-wide` mode.
- agent-only enforcement를 위한 `scoped` mode.
- scope selector:
  - `comm` / `comms`
  - `pid` / `pids`
  - `tgid` / `tgids`
- `comm`, `pid`, `tgid`별 전용 BPF scope map.
- L1/L2/L3 정책 처리 전에 BPF prefilter 적용.
- scope map hit 시 active profile/agent와 일치하는지 검증.
- ring-buffer event와 GUI JSON에 `profile_id`, `agent_id` 포함.
- atomic reload 중 scope map snapshot/rollback.
- `tests/test_agent_scope.sh` runtime test.

남음:

- MCP agent의 cgroup 배치 계약이 안정화되면 `cgroup_id` selector 추가.
- 동시에 여러 profile을 활성화해야 하는 제품 요구가 생기면 multi-profile policy set 지원.

완료 기준:

- 특정 MCP agent process에만 적용되는 정책을 만들 수 있어야 합니다.
- agent가 아닌 process는 default profile을 사용할 수 있어야 합니다.
- GUI event만 보고 어떤 profile이 결정을 내렸는지 알 수 있어야 합니다.

### 6. GUI Socket Contract

loader socket은 GUI를 위한 안정적인 event/control channel이 되어야 합니다.

작업:

- 기존 event JSON에 `"type":"event"`를 추가합니다.
- JSON 문자열 escaping을 올바르게 처리합니다.
- 필드를 additive하게 추가합니다.
  - `comm`
  - `tgid`
  - `epoch`
  - `resource_id`
  - `duration_us`
  - `model_us`
  - `delta_us`
- 메시지 type을 추가합니다.
  - `metrics_snapshot`
  - `reload_result`
  - `health`
- newline-delimited JSON 형식은 유지합니다.

완료 기준:

- 알 수 없는 필드를 무시하는 기존 GUI client가 계속 동작해야 합니다.
- GUI client가 느리거나 끊겨도 enforcement/event polling을 막으면 안 됩니다.

### 7. Benchmark And Report Mode

논문 스타일의 성능 비교를 위해 loader가 재현 가능한 측정 mode를 제공해야 합니다.

작업:

- CLI option을 추가합니다.
  - `--benchmark`
  - `--duration`
  - `--report`
  - `--warmup`
- policy version, kernel version, BPF LSM 상태, git commit을 기록합니다.
- JSON/CSV report를 export합니다.
- report에 다음을 포함합니다.
  - hook/layer별 event count
  - L1/L2/L3 hit ratio
  - 평균 및 percentile latency
  - model baseline과 measured delta

완료 기준:

- 하나의 명령으로 `reports/` 아래에 report를 생성할 수 있어야 합니다.
- report 결과로 변경 전/후 성능을 비교할 수 있어야 합니다.

## 개발 작업

남은 loader 작업은 GUI control/event channel을 위한 7단계 지원과
benchmark/report mode를 위한 8단계 구현입니다. policy indexing, L2 flag,
metrics map, generation-aware reload, agent scoping은 이미 구현된 계약으로
취급하고, test-driven bug fix가 아닌 이상 구조를 흔들지 않습니다.

## 개발 명세

이 섹션은 남은 loader 구현 계약입니다. loader 담당 개발자는 이 섹션만
보고 남은 기능을 구현할 수 있어야 합니다.

### 남은 범위

| 영역 | 상태 | 다음 필수 작업 |
|---|---|---|
| GUI event socket | 일부 구현 | event JSON field 완성, JSON escaping, health message, slow-client handling |
| Metrics transport | 일부 구현 | 상세 entry를 포함한 안정적인 `metrics_snapshot` schema |
| Reload transport | 일부 구현 | `reload_result` schema 고정 및 모든 field 문서화 |
| Benchmark/report | 미구현 | CLI mode, workload timing capture, JSON/CSV report writer |
| Policy parser hardening | 일부 구현 | 정책 파일 호환성을 유지하면서 validation/error 개선 |

남은 loader 단계에서 제외할 것:

- 새 BPF hook 추가.
- 3-tier BPF pipeline 변경.
- GUI를 web service로 교체.
- loader에서 GUI process 실행.

### Command Line Interface

최종 loader CLI는 다음 모드를 지원해야 합니다.

```bash
sudo ./mcp-guard [POLICY_DIR]
sudo ./mcp-guard --policy-dir policies
sudo ./mcp-guard policies --metrics-interval 1s
sudo ./mcp-guard policies --socket /tmp/mcp-guard.sock
sudo ./mcp-guard policies --benchmark --duration 30s --warmup 5s --report reports/run.json
sudo ./mcp-guard policies --benchmark --duration 30s --report reports/run.csv
```

인자:

| 인자 | 필수 | 기본값 | 동작 |
|---|---:|---|---|
| positional `POLICY_DIR` | 아니오 | `policies` | 기존 호환 policy directory |
| `--policy-dir PATH` | 아니오 | positional 또는 `policies` | 명시적 policy directory |
| `--socket PATH` | 아니오 | `/tmp/mcp-guard.sock` | GUI JSON message용 Unix socket path |
| `--metrics-interval DURATION` | 아니오 | disabled | 주기적 metrics snapshot 발행 |
| `--benchmark` | 아니오 | false | benchmark/report collection mode |
| `--duration DURATION` | benchmark 시 | `30s` | benchmark measurement window |
| `--warmup DURATION` | 아니오 | `0s` | report에서 제외할 warmup window |
| `--report PATH` | benchmark 시 | `reports/` 아래 자동 생성 | report output path |
| `--report-format json|csv` | 아니오 | 확장자로 추론 | 명시적 report format |
| `--foreground` | 아니오 | 현재 true | daemonization 호환 reserved option |
| `--verbose` | 아니오 | false | loader diagnostic 추가 출력 |

Duration grammar:

- 정수 초를 허용합니다: `30`.
- suffix를 허용합니다: `ms`, `s`, `m`.
- 양수가 필요한 곳에서 0 또는 음수 duration은 거부합니다.

호환성 규칙:

- 기존 `sudo ./mcp-guard policies` 동작은 유지해야 합니다.
- 알 수 없는 option은 usage를 출력하고 nonzero로 종료합니다.
- 잘못된 benchmark/report 조합은 BPF attach 전에 실패해야 합니다.

### Module Contract

| 파일 | 책임 |
|---|---|
| `loader/main.c` | CLI parsing, lifecycle, signal handling, benchmark loop coordination |
| `loader/bpf_loader.c` | libbpf open/load/attach, tail-call setup, map fd exposure |
| `loader/policy_loader.c` | policy parse/validate/load/reload into BPF maps |
| `loader/ringbuf_reader.c` | BPF ring buffer polling and callback dispatch |
| `loader/unix_socket_server.c` | nonblocking GUI socket broadcast |
| `loader/report_writer.c` | 새 benchmark JSON/CSV output |
| `loader/report_writer.h` | 새 report writer API |

Report serialization은 `main.c`에 넣지 않습니다. runtime daemon path를 읽기
쉽게 유지하기 위해 `report_writer.c` 뒤에 API boundary를 둡니다.

### GUI Socket Message Contract

GUI message는 모두 newline-delimited JSON object입니다. 모든 message는
`type` field를 포함해야 합니다.

#### `type=event`

필수 field:

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
| `model_us` | number | layer별 model baseline |
| `delta_us` | number | `duration_us - model_us` |
| `rule_id` | integer | `mcp_event.rule_id` |
| `profile_id` | integer | `mcp_event.profile_id` |
| `agent_id` | integer | `mcp_event.agent_id` |
| `error` | integer | errno value |
| `path` | string | path 또는 `""` |
| `rule` | string | matched rule 또는 `""` |
| `port` | integer | destination port 또는 `0` |
| `ipv4_addr` | string | dotted IPv4 또는 `""` |
| `resource_id` | integer | `mcp_event.resource_id` |
| `epoch` | integer | `mcp_event.epoch` |

규칙:

- `path`, `rule`, `comm`은 JSON string escaping을 올바르게 적용합니다.
- 숫자 값은 문자열이 아니라 숫자로 둡니다.
- `ipv4_addr`는 GUI 표시를 위해 dotted decimal로 둡니다.
- GUI client가 없어도 ring buffer polling을 막으면 안 됩니다.

#### `type=metrics_snapshot`

최소 schema:

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

상세 `entries[]` item:

| Field | Type |
|---|---|
| `hook` | string |
| `layer` | string |
| `action` | string |
| `count` | integer |
| `avg_ns` | integer |
| `min_ns` | integer |
| `max_ns` | integer |
| `buckets` | 8개 integer array |

규칙:

- `--metrics-interval`이 설정된 경우에만 snapshot을 발행합니다.
- snapshot 생성이 event polling을 막으면 안 됩니다.
- 빈 metrics도 valid하며 `total=0`으로 발행할 수 있습니다.

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

규칙:

- socket server가 준비된 뒤 initial load와 모든 `SIGHUP` reload attempt 후
  발행합니다.
- 실패 시 기존 active policy를 유지하고 유용한 `error` string을 포함합니다.

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

규칙:

- startup 이후 한 번 발행합니다.
- 성공한 reload 후 발행합니다.
- 향후 heartbeat를 추가할 수 있지만 1차 필수는 아닙니다.

### JSON Escaping Specification

`loader/unix_socket_server.c`는 작은 JSON string escaping helper를 제공해야
합니다.

필수 escaping:

- `"` -> `\"`
- `\` -> `\\`
- newline -> `\n`
- carriage return -> `\r`
- tab -> `\t`
- `0x20` 미만 control byte -> `\u00XX`

helper는 output buffer가 작을 때 안전하게 truncate해야 하며 buffer 밖에
쓰면 안 됩니다.

### Slow Client Handling

Unix socket server는 GUI client와 enforcement/event polling을 분리해야 합니다.

규칙:

- 각 client fd는 nonblocking이어야 합니다.
- write가 `EAGAIN` 또는 `EWOULDBLOCK`을 반환하면 해당 client에 대해 message를
  drop하거나 client를 disconnect합니다.
- write가 `EPIPE`, `ECONNRESET` 또는 영구 오류를 반환하면 client를 제거합니다.
- client별 unbounded buffer를 만들지 않습니다.
- `MCP_GUARD_MAX_CLIENTS`를 강제합니다.

### Benchmark Mode Specification

Benchmark mode는 고정된 window 동안 runtime metrics를 관찰하고 report를
생성합니다. 이 단계에서 loader가 workload를 직접 생성할 필요는 없습니다.
workload는 test나 별도 shell에서 만들고, loader는 측정/보고를 담당합니다.

Benchmark lifecycle:

1. CLI를 parse/validate합니다.
2. BPF program을 load/attach합니다.
3. policy를 load합니다.
4. 향후 option이 생기기 전까지 GUI socket도 시작합니다.
5. warmup window를 실행하고 final report에서는 제외합니다.
6. metrics baseline을 reset하거나 mark합니다.
7. measurement window를 실행합니다.
8. metrics, policy metadata, kernel metadata, git metadata를 읽습니다.
9. report를 씁니다.
10. report path와 summary를 출력합니다.
11. clean exit합니다.

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
| `bpf_lsm_enabled` | `/sys/kernel/security/lsm`에 `bpf` 포함 여부 |
| `git_commit` | 가능하면 `git rev-parse HEAD` |
| `loader_version` | optional static string |

Report metrics:

- total count
- hook/layer/action별 count
- L1/L2/L3 ratio
- hook/layer/action별 average latency
- min/max latency
- histogram bucket
- layer별 model baseline
- model baseline 대비 measured delta

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

`loader/report_writer.h`를 추가합니다.

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

내부 snapshot type은 기존 metrics reader 코드에 맞춰 조정할 수 있지만, report
writing은 이 API boundary 뒤에 있어야 합니다.

### Policy Parser Hardening

남은 parser 작업은 기존 JSON 파일 호환성을 깨지 않으면서 진단 품질을 높이는
방향으로 진행합니다.

필수 동작:

- validation error에 filename과 field name을 포함합니다.
- 알 수 없는 `action` 값을 조용히 `allow`로 처리하지 말고 거부합니다.
- `65535`를 초과하는 port를 거부합니다.
- invalid CIDR prefix를 거부합니다.
- selector가 없는 scoped agent profile을 거부합니다.
- `MCP_GUARD_MAX_RULES` 초과는 hard error로 유지합니다.

### Loader Implementation Checklist

- [ ] Event JSON에 `type`, `comm`, `tgid`, `epoch`, `resource_id`,
  `duration_us`, `model_us`, `delta_us`, `ipv4_addr`가 포함됩니다.
- [ ] JSON string escaping이 올바릅니다.
- [ ] Unix socket client가 nonblocking이며 ring buffer polling을 막지 않습니다.
- [ ] `metrics_snapshot` schema가 상세 entry를 포함합니다.
- [ ] `reload_result` schema가 success/failure 양쪽에서 안정적입니다.
- [ ] startup/reload가 `health` message를 발행합니다.
- [ ] CLI가 `--policy-dir`, `--socket`, `--benchmark`, `--duration`,
  `--warmup`, `--report`, `--report-format`을 지원하고 positional policy dir도 유지합니다.
- [ ] Benchmark mode가 JSON report를 생성합니다.
- [ ] Benchmark mode가 CSV report를 생성합니다.
- [ ] Report에 논문식 비교에 필요한 metadata가 포함됩니다.
- [ ] Parser diagnostic이 파일명과 잘못된 field를 식별합니다.
- [ ] `sudo make test`가 통과합니다.
- [ ] socket JSON field, JSON escaping, report generation을 검증하는 loader test가 추가됩니다.

## 완료 기준

로더 담당 개발자는 아래 명령이 통과하면 1차 완료로 봅니다.

```bash
./configure
make clean && make
sudo make test
```

수동 확인:

```bash
sudo ./mcp-guard policies
sudo kill -HUP $(pidof mcp-guard)
nc -U /tmp/mcp-guard.sock
```

기대 동작:

- 잘못된 정책 reload가 기존 정책을 지우지 않습니다.
- GUI socket client가 stdout logging과 별개로 JSON line을 받습니다.
- LSM attach 실패 시 실패한 program 이름과 libbpf error가 출력됩니다.
- `sudo make test` 출력에 `layer`와 `duration_ns`가 포함됩니다.

## GUI 개발자와의 협업 규칙

GUI 개발자는 socket JSON 계약에 의존합니다. loader가 필드를 변경하면 같은 commit에서 `docs/gui-development-guide-ko.md`도 수정해야 합니다.

권장 호환성 규칙:

- 기존 필드는 제거하지 않습니다.
- 새 필드는 GUI 입장에서 optional입니다.
- GUI는 알 수 없는 필드를 무시해야 합니다.
