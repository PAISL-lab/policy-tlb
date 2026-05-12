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

현재 로더는 BPF 프로그램 load/attach, tail-call map 구성, 기본 정책 map 적재, path prefix의 LPM trie 적재, MCP agent scope map 적재, `SIGHUP` reload, ring buffer 이벤트 수신, 종료 시 metrics summary 출력, GUI용 JSON 전송까지 수행합니다. 남은 작업은 주로 GUI 통합과 benchmark/report 기능입니다.

| 프레임워크 단계 | 로더 책임 | 주요 파일 |
|---|---|---|
| 2. LPM_TRIE path policy | 완료: path prefix 정규화, LPM trie 적재, runtime test 포함 | `policy_loader.c`, `bpf_loader.c` |
| 3. L2 flag/cache 강화 | 완료: config/rule flag 분리, startup summary, 알 수 없는 flag 거부, L2 runtime test 포함 | `policy_loader.c`, `main.c` |
| 4. metrics/histogram map | 완료: 종료 summary, 주기적 snapshot, layer ratio, GUI metrics JSON 포함 | `bpf_loader.c`, `main.c`, `unix_socket_server.c` |
| 5. atomic policy reload | 완료: validation, map snapshot/rollback, generation bump, reload_result JSON 포함 | `policy_loader.c`, `main.c` |
| 6. MCP agent scoping | comm/pid/tgid selector 기준 완료: profile parsing, scope map, BPF prefilter, event attribution, runtime test 포함 | `policy_loader.c`, `main.c`, `l3_slow_path.bpf.c` |
| 7. GUI | socket schema 안정화, health/reload/metrics 메시지 추가 | `unix_socket_server.c`, `main.c` |
| 8. benchmark/report | benchmark mode와 CSV/JSON report 생성 | `main.c`, 새 `report_writer.c` |

## 상세 로더 백로그

### 1. LPM_TRIE Path Policy Loader

path 정책은 이제 `path_policy_trie`에 적재되고, file-open L3 slow path는 기본 action으로 떨어지기 전에 trie를 조회합니다. command/network rule은 아직 고정 크기 `policy_rules` array를 사용합니다.

구현됨:

- `loader/bpf_loader.h`의 path policy trie map id.
- `mcp_bpf_map_fd`의 trie map fd 노출.
- user-space trie key/value 구성.
- `dangerous_paths.json`의 path prefix 적재.
- path policy 정규화:
  - 빈 path 거부
  - 절대 경로만 허용
  - `/`를 제외한 trailing slash 제거
  - `MCP_GUARD_RULE_VALUE_LEN`보다 긴 값 거부
- 성공한 reload 중 trie cleanup.
- `tests/test_path_lpm_trie.sh` runtime test 추가.

남음:

- path rule을 `policy_rules`에서 완전히 분리할 경우 최종 metadata layout을 정합니다.

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
- active policy rules, config, path trie entry를 snapshot합니다.
- epoch bump 전에 reload write가 실패하면 active map을 rollback합니다.
- policy config의 `active_generation`을 갱신합니다.
- policy map/config 갱신 뒤 마지막에 `global_epoch`를 증가시킵니다.
- GUI socket으로 `"type":"reload_result"` JSON을 발행합니다.
- `tests/test_atomic_reload.sh` test를 추가했습니다.

남음:

- 진짜 inactive-generation map swap은 BPF map 이중화 또는 BPF lookup의 generation-aware 구조가 필요합니다. 현재 구현은 기존 map을 snapshot/rollback하는 방식입니다.

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

1. `loader/policy_loader.c`의 정책 parsing을 강화합니다.
   - 현재의 최소 문자열 scanner를 실제 JSON parser 또는 검증 가능한 작은 parser로 교체합니다.
   - 잘못된 파일은 파일명과 필드 단위 오류를 포함해 거부합니다.
   - `action`은 `allow`, `deny`, `audit`만 허용합니다.
   - rule type별 필수 필드를 검증합니다.
   - `MCP_GUARD_MAX_RULES` 초과는 hard error로 처리합니다.

2. `loader/main.c`의 데몬 lifecycle을 개선합니다.
   - CLI flag를 추가합니다: `--policy-dir`, `--socket`, `--foreground`, `--verbose`.
   - 기존 positional `policies` 인자는 호환성을 위해 계속 지원합니다.
   - startup summary를 명확히 출력합니다: rule 수, epoch, socket path, attach된 hook.
   - `SIGHUP` reload는 atomic하게 처리합니다. reload 실패 시 기존 정책을 유지해야 합니다.

3. live reload를 위해 policy map update를 안전하게 만듭니다.
   - 새 rule 배열을 먼저 memory에서 구성합니다.
   - validation이 성공한 뒤에만 기존 map entry를 비웁니다.
   - config와 rules를 갱신합니다.
   - epoch는 가장 마지막에 증가시킵니다.

4. `loader/unix_socket_server.c`의 event transport를 개선합니다.
   - newline-delimited JSON 형식은 유지합니다.
   - `path`, `rule` 문자열을 올바르게 JSON escape합니다.
   - `comm`, `tgid`, `epoch`, `resource_id`, `duration_us`, `model_us`, `delta_us` 필드를 추가합니다.
   - 느리거나 끊긴 client가 ring buffer polling을 막지 않게 합니다.

5. runtime metrics를 추가합니다.
   - `hook`, `action`, `layer`별 이벤트 수를 셉니다.
   - `duration_ns`의 `min/avg/p95/p99`를 추적합니다.
   - 종료 시 summary를 출력합니다.
   - 선택 사항: 같은 socket에 별도 message type으로 metrics JSON을 노출합니다.

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
