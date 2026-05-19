# MCP eBPF Guard

[English README](README.md)

MCP eBPF Guard는 로컬 Model Context Protocol(MCP) 에이전트를 위한 런타임
보안 프레임워크입니다. BPF LSM hook과 TLB-hit 모델 기반 3-tier 의사결정
파이프라인을 사용해, 낮은 오버헤드로 위험한 에이전트 동작을 탐지하고
차단합니다.

이 저장소는 다음 논문 아이디어를 구현합니다.

> Ultra-Low Overhead MCP Agent Behavioral Control Framework using
> TLB-Hit Modeled 3-Tier eBPF Pipeline

## 왜 필요한가

MCP는 LLM 에이전트가 로컬 도구, 파일, 데이터베이스, 네트워크 리소스에
접근하는 표준 방법을 제공합니다. 하지만 이 권한은 런타임 보안 문제도 함께
만듭니다. 프롬프트 인젝션이나 에이전트 탈취가 발생하면, 에이전트는 허가되지
않은 명령 실행, 민감 파일 접근, 외부 네트워크 연결을 시도할 수 있습니다.

기존 감시 방식에는 다음과 같은 한계가 있습니다.

- `ptrace`나 audit 기반 추적은 사용자 공간과 커널 공간 사이의 전환 비용이 클
  수 있습니다.
- 커널 모듈은 강한 집행이 가능하지만, 커널 무결성과 안정성 위험이 커집니다.
- 단순 eBPF 모니터는 더 안전하지만, 모든 이벤트마다 깊은 문자열 검사를 반복하면
  여전히 비용이 커질 수 있습니다.

MCP eBPF Guard는 커스텀 커널 모듈을 로드하지 않고 eBPF LSM으로 커널 수준
집행을 수행합니다. 비싼 정책 검사는 hot path 밖으로 밀어내고, 리소스 할당
시점에서 결정한 결과를 프로세스, hook, resource id 기준으로 캐시합니다.

## 논문 모델

이 논문은 하드웨어 TLB hit 아이디어를 보안 정책 검사 경로에 대응시킵니다.

### TLB-Hit 모델 기반이라는 의미

`TLB-Hit modeled`는 이 프로젝트가 CPU TLB를 직접 조작한다는 뜻이 아닙니다.
Translation Lookaside Buffer의 성능 원리를 보안 의사결정 경로에 적용했다는
뜻입니다.

CPU에서 TLB hit는 비용이 큰 page-table walk를 피합니다. MCP eBPF Guard에서
L1 policy-cache hit는 비용이 큰 security-policy walk를 피합니다. 대응 관계는
다음과 같습니다.

| 하드웨어 메모리 시스템 | MCP eBPF Guard |
|---|---|
| 가상 주소 변환 요청 | 런타임 보안 결정 요청 |
| TLB key | 프로세스, hook, 리소스 캐시 key |
| TLB entry | 캐시된 allow/deny/audit 결정 |
| TLB hit | L1 Fast Path cache hit |
| TLB miss | L2/L3 정책 평가로 fall-through |
| Page-table walk | Slow path rule matching과 event emission |
| TLB shootdown/invalidation | Global epoch 증가 |

핵심 설계 선택은 common case를 위해 hot path를 최적화하는 것입니다. 파일,
명령, 소켓에 대한 결정이 한 번 내려지면 이후 이벤트는 비싼 path parsing이나
policy scan을 반복하지 않습니다. 캐시된 결정이 현재 policy epoch에서 만들어진
것인지만 확인합니다.

모든 syscall에서 전체 검사를 반복하는 대신, 프레임워크는 검사를 세 단계로
나눕니다.

| Tier | 목적 | 예상 비용 모델 |
|---|---|---:|
| L1 Fast Path | 프로세스, hook, 리소스 기준 epoch-valid cache lookup | `0.018us` |
| L2 Semi-Fast Path | 안전한 non-regular file 같은 저비용 리소스 클래스 검사 | 누적 `0.023us` |
| L3 Slow Path | 깊은 정책 평가, path/command/socket rule matching, event emit | 누적 `0.989us` |

핵심 최적화는 resource-level hoisting입니다.

1. allocation/open/connect/exec 시점에 리소스를 한 번 평가합니다.
2. 현재 global epoch와 함께 결정을 L1 cache에 저장합니다.
3. 이후 read/write 또는 반복 hook 이벤트에서 결정을 재사용합니다.
4. global epoch를 증가시켜 모든 캐시 결정을 O(1)로 무효화합니다.

이 구조는 TLB 동작과 유사합니다. 대부분의 이벤트는 빠른 cache hit가 되고,
최초 접근이나 정책 변경 시점의 이벤트만 slow-path 비용을 지불합니다.

## 현재 구현 상태

현재 구현에는 다음 기능이 포함되어 있습니다.

- BPF LSM hook:
  - `bprm_check_security`
  - `file_open`
  - `file_permission`
  - `socket_connect`
- BPF LRU per-CPU hash map 기반 L1 decision cache.
- hook별 BPF tail-call `PROG_ARRAY` map을 이용한 물리적 L1 -> L2 -> L3 분리.
- file path, command prefix, IPv4/port network rule에 대한 generation-aware
  LPM trie 정책 lookup.
- follow-up file access를 위한 generation-aware resource-id hash lookup.
- hook, layer, action별 runtime metrics와 histogram counter.
- policy config에서 로드되는 설정 가능한 L2/cache 동작 flag.
- profile file과 `comm`/`pid`/`tgid` selector map을 이용한 MCP agent scoping.
- verifier stack 제한을 피하기 위한 per-CPU tail-call state와 scratch buffer.
- BPF array map 기반 global epoch invalidation.
- policy rule map과 config map.
- ring buffer event를 user space로 전달.
- libbpf skeleton 기반 user-space loader.
- `/tmp/mcp-guard.sock` Unix socket event publishing.
- exec, file access, socket connect, policy reload, L1 cache hit, path LPM trie
  policy, L2 flags/cache, metrics snapshot, atomic reload, MCP agent scoping
  deny test.
- `layer`, `duration_ns`, `duration_us`, `model_us`, `delta_us` timing
  instrumentation.

## 저장소 구조

```text
bpf/
  mcp_guard.bpf.c          BPF LSM hook entrypoint와 tail-call chain
  l1_fast_path.bpf.c       L1 cache lookup/store와 resource id helper
  l2_semi_fast_path.bpf.c  저비용 리소스 클래스 검사
  l3_slow_path.bpf.c       Policy matching과 ring buffer event emission
  maps.bpf.h               BPF map, tail-call program array, scratch state
  vmlinux.h                CO-RE kernel type header

include/
  common.h                 공유 상수와 enum
  cache_key.h              L1 cache key/value ABI
  policy.h                 Policy config/rule ABI
  event.h                  Ring buffer event ABI

loader/
  main.c                   Loader lifecycle, signal, stdout event
  bpf_loader.c             libbpf load/attach와 tail-call map 설정
  policy_loader.c          JSON policy loader와 epoch bump
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
  test_l1_cache.sh
  test_path_lpm_trie.sh
  test_l2_flags_cache.sh
  test_metrics_snapshot.sh
  test_atomic_reload.sh
  test_agent_scope.sh

docs/
  loader-development-guide*.md
  gui-development-guide*.md
```

## 아키텍처

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
       miss (tail call)                 |
       v                                |
  L2 Semi-Fast Path                     |
  cheap safe-resource checks            |
       | hit                            |
       v                                |
  allow + cache                         |
                                        |
       miss (tail call)                 |
       v                                |
  L3 Slow Path                          |
  trie/map lookup, path/socket/exec     |
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

## 의사결정 파이프라인

현재 구현은 물리적인 tail-call 분리를 사용합니다. 각 BPF LSM hook은 attached
L1 program에서 시작합니다. L1 miss가 발생하면 hook별 `BPF_MAP_TYPE_PROG_ARRAY`
를 통해 해당 L2 program으로 jump합니다. L2가 저비용 결정을 내릴 수 없으면
해당 L3 slow-path program으로 tail-call합니다.

```text
attached LSM program
  L1 cache lookup
    hit  -> allow/deny/audit 반환
    miss -> bpf_tail_call(..., L2)

tail-call target
  L2 cheap decision
    hit  -> cache + return
    miss -> bpf_tail_call(..., L3)

tail-call target
  L3 trie/map policy lookup
    -> cache + 필요 시 event emit + return
```

Tail-call program array:

| Hook | Program Array | Index 0 | Index 1 |
|---|---|---|---|
| `bprm_check_security` | `exec_pipeline` | exec L2 | exec L3 |
| `file_open` | `file_open_pipeline` | file-open L2 | file-open L3 |
| `file_permission` | `file_permission_pipeline` | file-permission L2 | file-permission L3 |
| `socket_connect` | `socket_connect_pipeline` | socket L2 | socket L3 |

LSM hook에는 L1 program만 attach됩니다. Loader는 내부 L2/L3 program의
auto-attach를 비활성화하고, skeleton으로 프로그램을 load한 뒤 관련
`PROG_ARRAY` entry에 program fd를 기록합니다. 예상된 tail call이 실행되지
못하면 hook은 fail closed 원칙에 따라 `-EACCES`를 반환합니다.

BPF tail call은 일반 C 함수 호출처럼 stack state를 보존하지 않기 때문에,
파이프라인은 layer 간 timing metadata를 per-CPU `tail_state` map에 저장합니다.
Path와 rule-name 같은 큰 임시 buffer는 per-CPU `scratch` map에 저장해 BPF
verifier stack 제한을 피합니다.

### L1 Fast Path

L1은 `struct mcp_cache_key`를 사용합니다.

- `tgid`
- `pid`
- `hook_id`
- `resource_id`

캐시 값은 다음을 저장합니다.

- decision epoch
- action: allow, deny, audit
- flags
- rule id
- reason

캐시 entry가 존재하고 entry의 epoch가 global epoch와 같으면, hook은 캐시된
action에 따라 즉시 반환합니다.

### L2 Semi-Fast Path

L2는 명백히 안전한 리소스에 대해 비싼 문자열/path logic을 피합니다. 예를 들어
non-regular file이나 선택된 directory read case는 policy string matching 없이
allow될 수 있습니다.

Loader는 `policy_config.flags`를 통해 일부 L2/cache 동작을 조정할 수 있습니다.
현재 flag에는 directory-read skipping, file follow-up cache population,
fail-closed tail-call behavior가 포함됩니다.

### L3 Slow Path

L3는 더 깊은 검사를 수행합니다.

- exec에 대한 generation-aware command-prefix trie check
- file-open policy에 대한 generation-aware path-prefix trie matching
- follow-up file access에 대한 generation-aware resource-id hash matching
- socket connect에 대한 generation-aware IPv4/port trie matching
- deny/audit decision에 대한 ring buffer event emission
- follow-up event를 위한 cache population

File policy에서는 path string과 inode 기반 `resource_id`를 함께 사용합니다.
이 방식은 반복 read/write enforcement가 모든 hook에서 path string availability에
의존하지 않도록 합니다.

## MCP Agent Scoping

Loader는 `policies/mcp_agent_profile.json`을 읽고 활성 profile을
`policy_config`에 기록합니다. 기본 정책은 system-wide입니다. `mode`가
`scoped`이면, BPF는 3-tier policy pipeline을 실행하기 전에 현재 프로세스를
전용 scope map과 비교합니다.

지원 profile field:

```json
{
  "profile": "python-agent",
  "profile_id": 42,
  "agent_id": 7,
  "mode": "scoped",
  "comms": ["python3"],
  "pids": [1234],
  "tgids": [1234]
}
```

Scope selector:

- `comm` 또는 `comms`: `python3` 같은 Linux task command name을 match합니다.
- `pid` 또는 `pids`: 특정 thread id를 match합니다.
- `tgid` 또는 `tgids`: process/thread-group id를 match합니다.

Scoped mode에서 match되지 않는 로컬 프로세스는 MCP Guard enforcement를
bypass하고 정상 실행됩니다. Match되는 프로세스는 활성 policy를 사용하며,
emitted event에는 `profile_id`와 `agent_id`가 포함되어 GUI가 결정을 MCP
profile에 연결할 수 있습니다.

## Epoch Invalidation

Policy reload는 모든 cache entry를 scan하고 삭제하지 않습니다. 대신 다음
순서로 동작합니다.

1. User space가 policy file을 memory에서 parse하고 validate합니다.
2. Validation이 성공한 뒤에만 policy map을 기록합니다.
3. 마지막에 `global_epoch`를 증가시킵니다.
4. 이전 epoch의 L1 cache entry는 자동으로 invalid 상태가 됩니다.

이 방식은 global invalidation을 O(1)로 만들며, 논문의 핵심 lock-free epoch
아이디어입니다.

Reload는 generation-aware policy index layout을 사용합니다. Loader는 새 policy를
먼저 parse/validate하고, path, command, network, resource index를 다음 inactive
generation 아래에 기록한 뒤 `policy_config`와 `global_epoch`를 마지막에
flip합니다. BPF lookup key에는 `active_generation`이 포함되므로, 부분적으로
기록된 future-generation entry는 실행 중인 policy에서 보이지 않습니다.
성공적으로 flip한 뒤 loader는 이전 generation의 indexed entry를 제거합니다.
Reload가 epoch bump 전에 실패하면 loader는 staged entry를 삭제하고 필요한 map
snapshot을 복원하며 `reload_result` JSON message를 emit합니다.

## Metrics

BPF 측은 hook, layer, action별 per-CPU metrics를 기록합니다. 각 metric entry는
다음을 추적합니다.

- decision count
- total latency
- minimum latency
- maximum latency
- 8개 coarse latency histogram bucket

Loader는 종료 시 metrics summary를 출력합니다. Ring buffer event는 상세
deny/audit record의 source이고, metrics map은 개별 allow event를 emit하지
않아도 aggregate visibility를 제공합니다.

주기적인 metrics snapshot도 활성화할 수 있습니다.

```bash
sudo ./mcp-guard policies --metrics-interval 1s
```

활성화하면 loader는 `metrics snapshot` output을 출력하고,
`"type":"metrics_snapshot"`을 포함한 newline-delimited JSON message를
`/tmp/mcp-guard.sock`으로 publish합니다.

## Policy Format

기본 policy:

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

## 요구사항

Runtime 요구사항:

- eBPF와 BPF LSM이 활성화된 Linux
- 활성 LSM chain에 `bpf` 포함
- `clang`
- `bpftool`
- `libbpf`
- BPF LSM program load를 위한 root 권한

BPF LSM 확인:

```bash
cat /sys/kernel/security/lsm
```

출력에는 다음 예시처럼 `bpf`가 포함되어야 합니다.

```text
lockdown,capability,landlock,yama,apparmor,bpf,ima,evm
```

`CONFIG_BPF_LSM=y`가 있지만 활성 LSM chain에 `bpf`가 없다면 kernel boot
parameter에 추가하고 GRUB을 update한 뒤 reboot해야 합니다.

```text
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

## 빌드

로컬 tool path와 libbpf linker flag를 설정합니다.

```bash
./configure
```

이후 빌드합니다.

```bash
make
```

빌드는 다음을 수행합니다.

1. 존재하면 `config.mk`를 읽습니다.
2. CO-RE type information을 위해 `bpf/vmlinux.h`를 사용합니다.
3. `bpf/mcp_guard.bpf.c`를 BPF target으로 compile합니다.
4. `bpftool`로 `build/mcp_guard.skel.h`를 생성합니다.
5. `mcp-guard` user-space loader를 link합니다.

`./configure` 없이 `make`를 직접 실행해도 됩니다. Makefile은 기존 default를
fallback으로 유지합니다. `configure.ac`를 수정한 뒤 `configure` script를 다시
생성하려면 다음을 실행합니다.

```bash
autoconf
```

Build output 정리:

```bash
make clean
```

로컬 `./configure` output까지 제거:

```bash
make distclean
```

## 실행

Guard 시작:

```bash
sudo ./mcp-guard policies
```

예상 startup output:

```text
loaded 7 policy rules, generation=1 epoch=1
policy flags: skip_dir_read=1 cache_file_followups=1 deny_tailcall_fail=1 skip_l2_safe=0
event socket listening at /tmp/mcp-guard.sock
mcp-guard running; send SIGHUP to reload policy, Ctrl-C to stop
```

Policy reload:

```bash
sudo kill -HUP $(pidof mcp-guard)
```

중지:

```bash
sudo kill -INT $(pidof mcp-guard)
```

GUI-facing event 읽기:

```bash
nc -U /tmp/mcp-guard.sock
```

## 테스트

전체 테스트:

```bash
sudo make test
```

개별 테스트:

```bash
sudo ./tests/test_execve.sh
sudo ./tests/test_file_access.sh
sudo ./tests/test_socket_connect.sh
sudo ./tests/test_policy_update.sh
sudo ./tests/test_l1_cache.sh
sudo ./tests/test_path_lpm_trie.sh
sudo ./tests/test_l2_flags_cache.sh
sudo ./tests/test_metrics_snapshot.sh
sudo ./tests/test_atomic_reload.sh
sudo ./tests/test_agent_scope.sh
```

테스트는 다음을 검증합니다.

- 위험 명령 실행 deny
- 보호 파일 접근 deny
- 의심스러운 IPv4 socket connect deny
- policy reload와 epoch invalidation
- 같은 프로세스의 반복 접근 이후 L1 cache hit
- LPM trie path-prefix deny와 longest-prefix allow 동작
- L2 safe-resource hit와 policy flag validation
- 주기적 metrics snapshot과 GUI-facing metrics JSON
- 실패한 reload rollback 시 active policy와 epoch 유지
- 선택된 MCP agent process에만 scoped policy enforcement 적용

Sample output:

```text
[deny] pid=15263 uid=0 hook=exec layer=L3 duration_ns=3887 duration_us=3.887 model_us=0.989 delta_us=2.898 rule=1 error=13 path=/usr/bin/true rule=test-true
```

## 변수통제 실험

이 저장소는 논문 평가를 위한 변수통제 실험 harness를 `experiments/` 아래에
포함합니다. 이 harness는 eBPF hook 내부 policy latency와 end-to-end workload
overhead를 분리합니다.

기본 실험 설정:

```text
EXPERIMENT_REPEATS=30
EXPERIMENT_EVENTS_PER_RUN=100000
EXPERIMENT_WARMUP_RUNS=3
EXPERIMENT_CPU_CORE=2
```

전체 suite 실행:

```bash
sudo make experiment-preflight
sudo make experiment-all
```

개별 실험 실행:

```bash
sudo make experiment-latency
sudo make experiment-hit-ratio
sudo make experiment-lpm
sudo make experiment-reload
sudo make experiment-e2e
```

중단 후 재실행 전 stale experiment state 정리:

```bash
sudo experiments/scripts/clean_experiment_state.sh
```

각 실험은 raw log, parsed metrics, CSV table, environment metadata, report를
`experiments/results/` 아래에 기록합니다. Result directory는 git에서 무시됩니다.

### 기준 실험 환경

검증된 기준 run은 다음 환경에서 측정되었습니다. 전체 raw environment file은
각 result directory의 `env/` 아래에 저장됩니다.

| 항목 | 측정값 |
|---|---|
| Host | `bobbook` |
| OS / kernel | Ubuntu `24.04.4 LTS (Noble Numbat)`, Linux `6.17.0-14-generic` |
| CPU | Intel Core Ultra 7 155H, online logical CPU 22개 |
| Memory | 총 RAM `15Gi` |
| Clang | Ubuntu clang `18.1.3` |
| GCC | Ubuntu GCC `13.3.0` |
| bpftool / libbpf | bpftool `v7.7.0`, libbpf `v1.7` |
| Active LSM chain | `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm` |
| BPF JIT | enabled, `/proc/sys/net/core/bpf_jit_enable=1` |
| CPU governor | 모든 online CPU에서 `performance` |
| Pinned CPU core | `EXPERIMENT_CPU_CORE=2` |
| Run volume | measured run당 `30` repeats, `100000` events |
| Warm-up | latency benchmark에서 `3` warm-up runs |
| Load average snapshot | `1.69 1.92 1.81` |
| Thermal snapshot | 노출된 zone이 약 `20C`에서 `82C` 범위였습니다. 이 값은 controlled constant가 아니라 가능한 throttling factor로 기록합니다. |

### 변수통제

실험 harness는 논문 해석에 필요한 주요 변수를 고정하거나 기록합니다.

- 같은 git commit, build flags, policy files, workload event counts
- 같은 root privilege, temp directory base, loopback target, measurement scripts
- 가능한 경우 `taskset`을 통한 CPU core pinning
- 각 result의 `env/` directory에 CPU governor, kernel version, compiler version,
  BPF JIT status, load average, thermal hints, policy hashes 기록
- warm-up run과 measured run 분리
- hook 내부 latency와 end-to-end workload time 분리 측정

일반 데스크톱 Linux에서는 scheduler activity, interrupt, cache state, thermal
behavior, background daemon을 완전히 제거할 수 없습니다. 따라서 harness는 통제
가능한 변수를 고정하고 나머지 환경을 기록해, 결과를 그 맥락 안에서 해석할 수
있게 합니다. 전체 protocol은 `experiments/VARIABLE_CONTROL.md`를 참고하세요.

### 실험 변인

| 구분 | Variables | 실험 내 처리 |
|---|---|---|
| 독립변인 / Independent variables | Processing layer: L1 Fast Path, L2 Semi-Fast Path, L3 Slow Path | hook metrics에서 `layer`별로 분리해 비교 |
| 독립변인 / Independent variables | Hook type: `exec`, `file_open`, `file_read`, `file_write`, `socket_connect` | latency, hit-ratio, LPM, e2e workload에서 hook별 측정 |
| 독립변인 / Independent variables | Policy type: exact command rule, exact file rule, LPM Trie path-prefix rule, socket port rule, reload/epoch policy | benchmark별 policy directory를 생성해 동일 조건으로 반복 |
| 독립변인 / Independent variables | Execution mode: guard off, guard on, cold/warm cache behavior | e2e benchmark는 guard off/on 비교, hit-ratio benchmark는 warm repeated I/O 측정 |
| 종속변인 / Dependent variables | Hook latency: `duration_ns`, `duration_us`, average, min, max, approximate p50/p95/p99 | `guard.log` metrics summary를 `metrics.csv`와 `latency_by_hook_layer.csv`로 파싱 |
| 종속변인 / Dependent variables | Path ratio: L1/L2/L3 count and ratio | `hit_ratio_by_workload.csv`에서 hook별 비율 계산 |
| 종속변인 / Dependent variables | Workload result: total event count, elapsed time, throughput, allow/deny count | `elapsed.txt`, workload logs, generated CSV tables에서 집계 |
| 종속변인 / Dependent variables | Reliability result: reload success, rollback success, exit status | reload benchmark의 `reload_consistency.csv`에서 반복 성공률 계산 |
| 통제변인 / Controlled variables | Hardware, OS, kernel, compiler, libbpf/bpftool, BPF JIT status | `collect_env.sh`가 각 result directory의 `env/`에 기록 |
| 통제변인 / Controlled variables | Git commit, build flags, policy files, policy hashes | 동일 repository state로 실행하고 `env/git.txt`, `env/policy_hash.txt`에 기록 |
| 통제변인 / Controlled variables | Workload event count, repeat count, warm-up count, measurement scripts | `experiment.env`의 기본값과 동일 scripts로 고정 |
| 통제변인 / Controlled variables | CPU governor, CPU core pinning, root privilege, temp directory base, loopback network target | 가능한 경우 `performance` governor와 `taskset` core pinning을 사용하고 환경에 기록 |
| 통제 불가능하지만 기록한 변수 / Recorded uncontrolled variables | Scheduler decisions, interrupts, cache/TLB state, thermal throttling, background services, filesystem cache | 일반 데스크톱 Linux에서 완전 제거가 어려우므로 반복 측정과 `env/loadavg.txt`, `env/thermal.txt` 기록으로 완화 |

검증된 local controlled run의 reference result:

| 주장 / 지표 | 결과 |
|---|---:|
| `file_open` L1 vs L3 average latency | `80.10ns` vs `1860.28ns` (`23.22x`) |
| `file_read` L1 vs L3 average latency | `70.80ns` vs `1680.20ns` (`23.73x`) |
| `file_write` L1 vs L3 average latency | `75.99ns` vs `1758.25ns` (`23.14x`) |
| `file_open` L1 hit ratio | `99.9056%` |
| `file_read` L1 hit ratio | `99.9976%` |
| `file_write` L1 hit ratio | `99.9996%` |
| Atomic reload / rollback | `30/30` successful runs |
| End-to-end guard-on overhead | `6.234%` |

해석 제한:

| 결과 유형 | 해석 제한 |
|---|---|
| L1/L3 average latency | hook 내부 BPF policy decision time을 측정한 값이며, 전체 syscall latency나 application response time이 아닙니다. |
| Hit ratio | 설정된 반복 warm I/O workload의 결과입니다. 다른 접근 패턴에서는 L1/L2/L3 ratio가 달라질 수 있습니다. |
| LPM Trie depth result | benchmark path에 대한 path extraction과 policy lookup 효과가 포함됩니다. filesystem/cache state는 elapsed workload time에 영향을 줄 수 있습니다. |
| Reload / rollback success | 테스트한 atomic reload failure/recovery scenario를 검증합니다. 가능한 모든 malformed policy나 runtime failure를 증명하지는 않습니다. |
| End-to-end overhead | 캡처된 machine에서 포함된 file-I/O workload에 대한 결과입니다. target environment에서 재실행하지 않고 일반화하면 안 됩니다. |
| p50/p95/p99 latency | 별도 debug raw-trace mode를 사용하지 않는 한, percentile은 histogram bucket 기반 근사값입니다. |
| Thermal readings | 노출된 thermal zone의 최고값이 약 `82C`였습니다. 이 값만으로 throttling을 증명하지는 않지만, 통제 불가능한 환경 요인으로 보고해야 합니다. |

이 수치는 같은 machine과 configuration에 대한 reference로 사용해야 하며, portable
constant로 해석하면 안 됩니다. Environment collector는 kernel, compiler, BPF JIT,
CPU governor, load average, git commit, policy hash를 기록해 결과가 측정 맥락과
함께 보고될 수 있게 합니다.

## Timing 해석

구현은 deny/audit event에 대해 timing data를 emit합니다.

Field:

- `layer`: decision이 내려진 layer
- `duration_ns`: hook entry부터 event emission까지의 시간
- `duration_us`: `duration_ns / 1000`
- `model_us`: 논문 기반 누적 비용 baseline
- `delta_us`: measured value에서 model baseline을 뺀 값

현재 baseline:

| Layer | Baseline |
|---|---:|
| L1 | `0.018us` |
| L2 | `0.023us` |
| L3 | `0.989us` |

측정 runtime 값은 순수 policy lookup만 포함하지 않습니다. Helper call, map lookup,
event preparation, ring buffer submission도 포함합니다. 따라서 L3 event는 이상화된
논문 모델보다 높게 나오는 것이 자연스럽습니다. 논문의 핵심 주장을 평가하려면,
첫 L3 miss 이후의 반복 접근을 측정하고 L1 hit behavior를 L3 slow path와 비교해야
합니다.

## 현재 한계

- Event timing은 deny/audit event에 대해 emit되며, 모든 allow event에 대해
  emit되지는 않습니다.
- GUI 파일은 완전한 operator dashboard를 향해 개발 중입니다.

## 개발 가이드

Loader 작업:

- `docs/loader-development-guide.md`
- `docs/loader-development-guide-ko.md`

GUI 작업:

- `docs/gui-development-guide.md`
- `docs/gui-development-guide-ko.md`

이 문서들은 loader/GUI 분리, socket event contract, 개발 task, acceptance
criteria를 정의해 여러 개발자가 병렬로 작업할 수 있게 합니다.

## 라이선스

이 프로젝트는 Apache License, Version 2.0으로 배포됩니다. 자세한 내용은
`LICENSE`를 참고하세요.

BPF object의 `char LICENSE[] SEC("license") = "GPL"` 선언은 BPF program
loading과 helper compatibility를 위한 커널 verifier metadata입니다. 저장소
전체의 프로젝트 라이선스 표기가 아닙니다.

## 안전 주의

이 프로젝트는 실험적 보안 프레임워크입니다. BPF LSM program을 attach하고 실제
process, file, socket operation을 deny할 수 있습니다. 주 사용 workstation에
적용하기 전에 개발 환경에서 먼저 테스트하세요.
