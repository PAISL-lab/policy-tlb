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
2. `loader/bpf_loader.c`가 `build/mcp_guard.skel.h`를 열고 BPF 프로그램을 load/attach합니다.
3. `loader/policy_loader.c`가 JSON 정책 파일을 읽고 BPF map에 씁니다.
4. 정책 load가 끝나면 `global_epoch`를 증가시킵니다.
5. `loader/ringbuf_reader.c`가 BPF ring buffer를 poll합니다.
6. `loader/main.c`가 이벤트를 stdout에 출력합니다.
7. `loader/unix_socket_server.c`가 같은 이벤트를 `/tmp/mcp-guard.sock`으로 GUI에 전달합니다.

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

