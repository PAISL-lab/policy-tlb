# GUI 개발 가이드

이 문서는 desktop GUI 담당 개발자를 위한 가이드입니다. GUI는 `/tmp/mcp-guard.sock`에서 loader 이벤트를 받아 보안 알림을 표시하고 MCP Guard의 런타임 상태를 보여줘야 합니다.

## 목표

loader의 socket event 계약이 유지되는 한 GUI 개발자가 독립적으로 작업할 수 있는 Qt GUI를 구현합니다.

현재 GUI 디렉토리는 skeleton 상태입니다.

- `gui/src/main.cpp`
- `gui/src/MainWindow.*`
- `gui/src/SocketClient.*`
- `gui/src/AlertPopup.*`
- `gui/resources/style.qss`
- `gui/resources/icon.png`

## 외부 계약

GUI는 Unix domain socket에 연결합니다.

```text
/tmp/mcp-guard.sock
```

loader는 한 줄에 JSON 객체 하나를 전송합니다. 예시는 다음과 같습니다.

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

v1 화면 표시를 위한 필수 필드:

- `ts_ns`
- `pid`
- `uid`
- `hook`
- `action`
- `layer`
- `duration_ns`
- `rule_id`
- `error`
- `path`
- `rule`
- `port`

GUI는 알 수 없는 필드를 무시해야 합니다.

## UI 요구사항

첫 화면은 landing page가 아니라 운영 대시보드여야 합니다.

기본 layout:

- 상단 status bar: 연결 상태, 이벤트 수, deny 수, 현재 filter.
- 메인 이벤트 테이블: 시간, action, hook, layer, duration, pid, path/destination, rule.
- 오른쪽 detail panel: 선택한 이벤트의 JSON 필드, 시간 비교, 대응 힌트.
- 하단 status area: socket path와 마지막 error.

보안 운영 도구이므로 장식보다 가독성과 빠른 스캔성을 우선합니다.

## 컴포넌트

### `SocketClient`

책임:

- `/tmp/mcp-guard.sock`에 연결합니다.
- newline-delimited JSON을 읽습니다.
- loader가 실행 중이 아니면 backoff를 두고 재연결합니다.
- parsing된 event object를 UI로 emit합니다.
- 연결 상태를 제공합니다: disconnected, connecting, connected, error.

구현 메모:

- `QLocalSocket`을 사용합니다.
- newline이 올 때까지 partial read를 buffer에 쌓습니다.
- `QJsonDocument`로 parsing합니다.
- UI thread를 blocking하면 안 됩니다.
- malformed JSON은 recoverable error로 처리하고 계속 읽습니다.

### `MainWindow`

책임:

- dashboard layout을 소유합니다.
- in-memory event model을 유지합니다.
- action, hook, layer, text search filter를 제공합니다.
- event counter와 최신 상태를 표시합니다.

권장 model field:

- `timestampNs`
- `pid`
- `uid`
- `hook`
- `action`
- `layer`
- `durationNs`
- `ruleId`
- `error`
- `path`
- `rule`
- `port`

### `AlertPopup`

책임:

- `action=deny` 이벤트에 대해 transient alert를 표시합니다.
- action, hook, path/destination, rule, duration을 포함합니다.
- focus를 빼앗지 않습니다.
- 짧은 timeout 후 자동으로 사라집니다.

기본값으로 allow/audit 이벤트마다 popup을 띄우면 안 됩니다.

## 시간 표시

시간은 raw 값과 비교 가능한 값으로 함께 표시합니다.

- `duration_ns`
- `duration_us = duration_ns / 1000`
- model baseline:
  - L1: `0.018us`
  - L2: `0.023us`
  - L3: `0.989us`
- delta:
  - `duration_us - model_us`

색상 가이드:

- 초록: model baseline 이하 또는 근접.
- 노랑: model baseline의 5배 이내.
- 빨강: model baseline의 5배 초과.

색상은 보조 신호로만 사용하고, 테이블 텍스트는 항상 읽기 쉬워야 합니다.

## 개발 작업

1. `gui/CMakeLists.txt`를 채웁니다.
   - Qt Widgets를 사용합니다.
   - `mcp-guard-gui` 실행 파일을 빌드합니다.
   - `gui/resources/style.qss`와 `gui/resources/icon.png`를 포함합니다.

2. `SocketClient`를 구현합니다.
   - 연결, 재연결, read buffer, JSON parsing, event signal을 추가합니다.
   - socket path를 설정 가능하게 하고 기본값은 `/tmp/mcp-guard.sock`으로 둡니다.

3. `MainWindow`를 구현합니다.
   - dashboard layout을 만듭니다.
   - event table과 detail panel을 추가합니다.
   - `SocketClient` signal을 event model에 연결합니다.
   - filter와 counter를 추가합니다.

4. `AlertPopup`을 구현합니다.
   - deny 이벤트에서 trigger합니다.
   - 압축된 이벤트 정보를 보여줍니다.
   - focus를 빼앗지 않고 자동으로 닫힙니다.

5. offline/demo mode를 추가합니다.
   - loader 없이도 UI 개발이 가능하도록 sample JSON event stream을 제공합니다.
   - GUI 개발자는 root 권한이나 BPF 접근 없이 화면 작업을 계속할 수 있어야 합니다.

## 테스트 계획

live loader로 수동 테스트:

```bash
sudo ./mcp-guard policies
./gui/build/mcp-guard-gui
curl https://example.com
```

기대 GUI 동작:

- 연결 상태가 connected로 바뀝니다.
- deny 이벤트가 table에 나타납니다.
- alert popup이 표시됩니다.
- detail panel에 `layer`, `duration_ns`, `rule`이 보입니다.

loader 없이 수동 테스트:

- `/tmp/mcp-guard.sock`이 없는 상태에서 GUI를 시작합니다.
- GUI는 disconnected 상태를 표시합니다.
- 나중에 loader를 시작합니다.
- GUI는 재시작 없이 reconnect합니다.

malformed input 테스트:

- test socket으로 잘못된 JSON line을 보냅니다.
- GUI는 error 상태를 기록하되 계속 실행되어야 합니다.

## Loader 개발자와의 협업 규칙

GUI는 loader의 JSON field name에 의존합니다. 변경 사항은 `docs/loader-development-guide-ko.md`와 함께 조율합니다.

호환성 규칙:

- 알 수 없는 필드는 무시합니다.
- optional field가 없으면 `-`로 표시합니다.
- required field가 없어도 crash하면 안 되며 malformed event로 표시합니다.
- loader의 새 필드는 먼저 detail panel에 추가하고, 필요할 때 table column으로 승격합니다.

