# GUI 개발 가이드

이 문서는 desktop GUI 담당 개발자를 위한 가이드입니다. GUI는 `/tmp/mcp-guard.sock`에서 loader 이벤트를 받아 보안 알림을 표시하고 MCP Guard의 런타임 상태를 보여줘야 합니다.

## 기술 선택

GUI는 **Python 3 + PySide6(Qt for Python)** 로 개발합니다.

PySide6를 선택하는 이유:

- repository에 이미 Qt stylesheet인 `gui/resources/style.qss`가 있습니다.
- Python에서 Unix socket JSON line client를 구현하기 쉽습니다.
- Qt Widgets는 table, filter, splitter, tab, dialog 구현이 안정적입니다.
- 현재 이벤트 양에는 PySide6 성능이 충분하고 반복 개발이 빠릅니다.
- sample JSON replay를 사용하면 root 권한 없이 GUI 개발이 가능합니다.

GTK도 Linux-native GUI로는 좋은 선택이지만, `style.qss`를 재사용할 수 없고 현재 dashboard처럼 table/chart 중심 화면에는 Qt가 더 편합니다. 프로젝트가 GNOME/libadwaita 앱으로 명확히 전환되지 않는 한 PySide6를 사용합니다.

## 목표

loader의 socket event 계약이 유지되는 한 GUI 개발자가 독립적으로 작업할 수 있는 PySide6 desktop GUI를 구현합니다.

GUI 트리는 Python 전용입니다. application code는 `gui/mcp_guard_gui/` 아래에 두고, `gui/resources/`는 Qt asset, `gui/samples/`는 replay 가능한 demo event를 보관합니다.

권장 구조:

```text
gui/
  run_gui.py
  requirements.txt
  mcp_guard_gui/
    __init__.py
    app.py
    socket_client.py
    models.py
    main_window.py
    alert_popup.py
    resources.py
  resources/
    style.qss
    icon.png
  samples/
    events.ndjson
```

나중에 UI가 커지면 `main_window.py`의 화면 로직을
`views/dashboard.py`, `views/events.py`, `views/metrics.py`,
`views/policy.py`로 분리합니다.

## 런타임 계약

GUI는 Unix domain socket에 연결합니다.

```text
/tmp/mcp-guard.sock
```

loader는 한 줄에 JSON 객체 하나를 전송합니다. 현재 event 예시는 다음과 같습니다.

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

v1 화면 표시를 위한 현재 필수 필드:

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

loader에서 곧 추가될 것으로 예상되는 필드:

- `type`: `event`, `metrics_snapshot`, `reload_result`, `health`
- `tgid`
- `comm`
- `epoch`
- `resource_id`
- `duration_us`
- `model_us`
- `delta_us`
- hook/layer/action counter와 histogram bucket을 담은 metrics payload

호환성 규칙: 알 수 없는 필드는 무시하고, optional field가 없으면 `-`로 표시합니다.

## UI 요구사항

첫 화면은 landing page가 아니라 운영 대시보드여야 합니다.

기본 layout:

- 상단 status bar: 연결 상태, socket path, event count, deny count, current epoch.
- 왼쪽 navigation tab: Dashboard, Events, Metrics, Policy.
- 메인 dashboard: L1/L2/L3 hit count, deny count, 최근 high-risk event, 평균 latency.
- Events table: 시간, action, hook, layer, duration, pid, path/destination, rule.
- Details panel: 선택된 event JSON, timing comparison, decision reason, process metadata.
- 하단 status area: 마지막 socket error와 마지막 reload result.

보안 운영 도구이므로 장식보다 가독성, 정보 밀도, 빠른 스캔성을 우선합니다.

## PySide6 컴포넌트

### `SocketClient`

책임:

- `/tmp/mcp-guard.sock`에 연결합니다.
- newline-delimited JSON을 읽습니다.
- loader가 실행 중이 아니면 exponential backoff로 재연결합니다.
- parsing된 Python dictionary를 UI로 emit합니다.
- 연결 상태를 제공합니다: `disconnected`, `connecting`, `connected`, `error`.

구현 메모:

- PySide6의 `QLocalSocket`을 사용합니다.
- newline이 올 때까지 partial read를 buffer에 쌓습니다.
- Python `json.loads`로 parsing합니다.
- UI thread를 blocking하면 안 됩니다.
- malformed JSON은 recoverable error로 처리하고 계속 읽습니다.

### `EventStore`

책임:

- 최근 event를 bounded in-memory list로 유지합니다.
- action, hook, layer별 counter를 유지합니다.
- 현재 filter와 filtered row index를 유지합니다.
- `QAbstractTableModel`에 데이터를 제공합니다.

권장 normalized field:

- `timestamp_ns`
- `pid`
- `tgid`
- `uid`
- `comm`
- `hook`
- `action`
- `layer`
- `duration_ns`
- `duration_us`
- `model_us`
- `delta_us`
- `rule_id`
- `error`
- `path`
- `rule`
- `port`
- `resource_id`
- `epoch`

### `MainWindow`

책임:

- main dashboard layout을 소유합니다.
- `SocketClient` signal을 model/view에 연결합니다.
- action/hook/layer/search filter를 제공합니다.
- counter, connection state, selected event detail을 표시합니다.
- 시작 시 `gui/resources/style.qss`를 로드합니다.

### `MetricsView`

책임:

- L1/L2/L3 count와 hit ratio를 표시합니다.
- metrics snapshot이 들어오면 latency average와 histogram bucket을 표시합니다.
- metrics snapshot이 아직 없으면 event-derived counter로 fallback합니다.

초기 구현은 `QTableWidget`/`QTableView`와 간단한 bar로 충분합니다. chart가 중요해지면 나중에 `pyqtgraph`를 추가합니다.

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
- loader가 보내지 않으면 `duration_us = duration_ns / 1000`
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

1. PySide6 packaging을 유지합니다.
   - `gui/requirements.txt`를 최소 dependency 목록으로 유지합니다.
   - `gui/run_gui.py`를 실행 entrypoint로 유지합니다.
   - application module은 `gui/mcp_guard_gui/` 아래에 둡니다.
   - `style.qss`와 `icon.png`는 `gui/resources/`에 유지합니다.

2. `SocketClient`를 확장합니다.
   - `/tmp/mcp-guard.sock` 연결/재연결을 구현합니다.
   - newline-delimited JSON을 parsing합니다.
   - `event_received`, `metrics_received`, `reload_result_received`, `connection_state_changed` signal을 emit합니다.
   - socket path를 설정 가능하게 만듭니다.

3. model을 확장합니다.
   - `EventStore`를 추가합니다.
   - `QAbstractTableModel` 기반 `EventTableModel`을 추가합니다.
   - action, hook, layer, text search filter를 추가합니다.
   - memory가 무한히 늘지 않도록 bounded event history를 사용합니다.

4. `MainWindow`를 확장합니다.
   - Dashboard, Events, Metrics, Policy tab을 만듭니다.
   - socket signal을 store/view에 연결합니다.
   - 선택한 row의 detail panel을 추가합니다.
   - deny/audit/allow 및 L1/L2/L3 counter를 표시합니다.

5. `AlertPopup`을 확장합니다.
   - deny event에서 trigger합니다.
   - focus를 빼앗지 않고 자동으로 닫힙니다.
   - popup 비활성화 settings toggle을 추가합니다.

6. offline/demo mode를 추가합니다.
   - `gui/samples/events.ndjson`를 제공합니다.
   - `--demo gui/samples/events.ndjson` option을 추가합니다.
   - root, BPF, loader 없이도 GUI 개발이 가능해야 합니다.

7. metrics message를 route합니다.
   - 초기에는 shutdown summary에서 유도 가능한 event counter를 표시합니다.
   - loader의 `metrics_snapshot` message를 `MetricsView`로 route합니다.
   - 알 수 없는 message type은 안전하게 무시합니다.

## 테스트 계획

live loader 수동 테스트:

```bash
sudo ./mcp-guard policies
python3 gui/run_gui.py
sudo cat /etc/shadow
```

기대 GUI 동작:

- 연결 상태가 connected로 바뀝니다.
- deny event가 table에 나타납니다.
- deny event에 대해 alert popup이 표시됩니다.
- detail panel에 `layer`, `duration_ns`, `rule`, `path`가 보입니다.

L2/metrics 관찰 수동 테스트:

```bash
sudo ./mcp-guard policies
python3 gui/run_gui.py
# 다른 터미널에서 network/file activity 실행
```

기대 동작:

- deny/audit record가 들어오면 event가 live update됩니다.
- L1/L2/L3 counter가 event-derived data로 갱신됩니다.
- loader의 `metrics_snapshot` message가 GUI 재시작 없이 Metrics tab을 갱신합니다.

loader 없이 수동 테스트:

- `/tmp/mcp-guard.sock`이 없는 상태에서 GUI를 시작합니다.
- GUI는 disconnected 상태를 표시합니다.
- 나중에 loader를 시작합니다.
- GUI는 재시작 없이 reconnect합니다.

Demo mode 테스트:

```bash
python3 gui/run_gui.py --demo gui/samples/events.ndjson
```

기대 동작:

- root 권한 없이 sample event가 표시됩니다.
- filter, detail panel, counter, popup logic이 동작합니다.

Malformed input 테스트:

- demo mode 또는 test socket으로 잘못된 JSON line을 입력합니다.
- GUI는 error 상태를 기록하되 계속 실행되어야 합니다.

## Loader 개발자와의 협업 규칙

GUI는 loader의 JSON field name에 의존합니다. 변경 사항은 `docs/loader-development-guide-ko.md`와 함께 조율합니다.

호환성 규칙:

- 알 수 없는 필드는 무시합니다.
- optional field가 없으면 `-`로 표시합니다.
- required field가 없어도 crash하면 안 되며 malformed event로 표시합니다.
- loader의 새 필드는 먼저 detail panel에 추가하고, 필요할 때 table column으로 승격합니다.
- loader가 `metrics_snapshot`, `reload_result`, `health` 같은 message type을 추가하면 GUI는 `type` 기준으로 route하고 event rendering과 분리해야 합니다.
