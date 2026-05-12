# 로더 개발 가이드

이 문서는 user-space loader 담당 개발자를 위한 가이드입니다. 로더는 root 권한으로 실행되며 BPF 프로그램 로드, 정책 맵 갱신, 커널 ring buffer 이벤트 수신, GUI용 이벤트 전송을 담당합니다.

## 목표

현재 PoC 로더를 안정적인 데몬으로 발전시키는 것이 목표입니다. 특히 정책 로딩, 이벤트 전달, 정책 reload, 관측 가능성을 예측 가능한 형태로 만들어야 합니다.

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

## 남은 로더 개발 범위

현재 로더는 BPF 프로그램 load/attach, tail-call map 구성, 기본 정책 map 적재, `SIGHUP` reload, ring buffer 이벤트 수신, GUI용 JSON 전송까지 수행합니다. 남은 작업은 정책 자료구조 고도화, 안전한 reload, MCP agent scope, 관측성, benchmark/report 기능입니다.

| 프레임워크 단계 | 로더 책임 | 주요 파일 |
|---|---|---|
| 2. LPM_TRIE path policy | path prefix rule을 trie key로 변환해 BPF trie map에 적재 | `policy_loader.c`, `bpf_loader.c` |
| 3. L2 flag/cache 강화 | rule/cache flag를 파싱하고 cache 동작 설정을 전달 | `policy_loader.c`, `main.c` |
| 4. metrics/histogram map | metrics map을 읽고 snapshot/summary를 생성 | `bpf_loader.c`, `main.c`, `unix_socket_server.c` |
| 5. atomic policy reload | inactive 정책 상태를 검증/적재한 뒤 active generation을 마지막에 교체 | `policy_loader.c`, `main.c` |
| 6. MCP agent scoping | agent profile을 파싱하고 pid/tgid/cgroup/comm 기준 scope map 적재 | `policy_loader.c`, `main.c` |
| 7. GUI | socket schema 안정화, health/reload/metrics 메시지 추가 | `unix_socket_server.c`, `main.c` |
| 8. benchmark/report | benchmark mode와 CSV/JSON report 생성 | `main.c`, 새 `report_writer.c` |

## 상세 로더 백로그

### 1. LPM_TRIE Path Policy Loader

현재 path 정책은 고정 크기 `policy_rules` array에 들어갑니다. 다음 단계에서는 path prefix matching을 LPM trie map으로 옮겨 L3가 모든 path rule을 선형 scan하지 않도록 해야 합니다.

작업:

- `loader/bpf_loader.h`에 path policy trie map id를 추가합니다.
- `mcp_bpf_map_fd`에서 trie map fd를 노출합니다.
- BPF trie key layout과 일치하는 user-space key builder를 정의합니다.
- path 정책 값을 적재 전에 정규화합니다.
  - 빈 path 거부
  - 절대 경로만 허용
  - `/`를 제외한 trailing slash 제거
  - `MCP_GUARD_PATH_LEN`보다 긴 값 거부
- 각 prefix를 trie key로 변환해 BPF map에 update합니다.
- command/network 정책은 기존 array rule을 유지합니다.
- 전환 방식을 결정합니다.
  - 호환 모드: path rule을 array와 trie에 모두 적재
  - 최적화 모드: path prefix는 trie에만 적재하고 metadata는 보조 map 사용

완료 기준:

- `dangerous_paths.json`의 prefix 하위 파일 접근을 차단할 수 있어야 합니다.
- path prefix 여러 개가 순서 버그 없이 공존해야 합니다.
- policy reload 시 삭제된 path prefix가 제거되어야 합니다.
- 잘못된 path 정책 reload가 기존 active policy를 지우면 안 됩니다.

### 2. L2 Flag And Cache Configuration

L2는 현재 몇 가지 cheap decision을 hard-coded로 처리합니다. 앞으로는 BPF 코드를 매번 바꾸지 않고 정책/설정으로 동작을 조정할 수 있어야 합니다.

작업:

- 정책 JSON에 optional flag를 추가합니다.
  - `cache_followups`
  - `audit_allowed`
  - `skip_dir_read`
  - `deny_on_tailcall_fail`
- rule type별 허용 flag를 검증합니다.
- global cache 동작은 `policy_config`에 저장합니다.
- per-rule flag는 `mcp_policy_rule.flags`에 저장합니다.
- verbose mode에서 적재된 flag summary를 출력합니다.

완료 기준:

- 기존 정책 파일은 수정 없이 계속 load되어야 합니다.
- 알 수 없는 flag는 명확한 오류와 함께 거부되어야 합니다.
- test에서 후속 read/write cache 동작이 켜졌는지 검증할 수 있어야 합니다.

### 3. Metrics And Histogram Reader

현재 BPF는 ring buffer event에 timing 정보를 담아 보냅니다. 다음 단계에서는 deny event에만 의존하지 않고 hit ratio와 latency distribution을 볼 수 있도록 map 기반 counter/histogram을 읽어야 합니다.

작업:

- metrics/histogram map id를 추가합니다.
- main loop에서 metrics를 주기적으로 읽습니다.
- hook, layer, action, reason별로 집계합니다.
- L1/L2/L3 hit ratio를 계산합니다.
- `"type":"metrics_snapshot"` JSON 메시지를 발행합니다.
- 종료 시 최종 summary를 출력합니다.

완료 기준:

- `sudo ./mcp-guard policies --metrics-interval 1s`가 주기적으로 metrics를 출력해야 합니다.
- GUI client가 event 메시지와 metrics 메시지를 구분할 수 있어야 합니다.
- metrics 수집이 ring buffer polling을 막으면 안 됩니다.

### 4. Atomic Policy Reload

현재 reload는 일부 입력을 검증한 뒤 rule array를 비우고 새 entry를 적재한 다음 `global_epoch`를 증가시킵니다. PoC에는 충분하지만 live daemon으로는 더 안전한 구조가 필요합니다.

작업:

- 모든 정책 파일을 먼저 memory로 parse합니다.
- BPF map을 건드리기 전에 전체 정책 set을 검증합니다.
- BPF 쪽 지원이 준비되면 policy config에 active generation 필드를 추가합니다.
- 새 정책을 inactive generation map 또는 shadow slot에 적재합니다.
- active generation 교체는 가장 마지막에 수행합니다.
- 전체 정책 상태가 보인 뒤에만 `global_epoch`를 증가시킵니다.
- 실패하면 기존 policy와 epoch를 그대로 유지합니다.

완료 기준:

- 정책 파일 하나를 깨뜨린 뒤 `SIGHUP`을 보내도 기존 정책이 계속 active여야 합니다.
- reload 결과가 JSON으로 발행되어야 합니다.
  - `"type":"reload_result"`
  - `success`
  - `rule_count`
  - `epoch`
  - `error`

### 5. MCP Agent Scoping

프레임워크는 일반 로컬 프로세스와 특정 MCP agent profile을 구분해야 합니다. profile parsing과 scope map 적재는 loader 책임입니다.

작업:

- `policies/mcp_agent_profile.json`을 parse합니다.
- 안정적인 `agent_id`, `profile_id`를 할당합니다.
- profile을 하나 이상의 selector에 bind합니다.
  - `pid`
  - `tgid`
  - `comm`
  - 향후: `cgroup_id`
- scope entry를 BPF map에 적재합니다.
- BPF event ABI가 준비되면 event JSON에 agent/profile 필드를 추가합니다.

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
