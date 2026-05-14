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
  "profile_id": 42,
  "agent_id": 7,
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
- `profile_id`
- `agent_id`
- `error`
- `path`
- `rule`
- `port`

loader가 보내는 추가 메시지 및 timing 필드:

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
- 차단 안내 popup: MCP Guard가 동작을 deny하면, 해당 작업이 차단되었다는
  사실을 사용자가 바로 알 수 있도록 popup을 표시합니다.

보안 운영 도구이므로 장식보다 가독성, 정보 밀도, 빠른 스캔성을 우선합니다.

## 7단계 구현 범위

GUI 단계의 목표는 현재 skeleton을 실제로 사용할 수 있는 운영
대시보드로 만드는 것입니다. 단순히 화면만 만드는 것이 아니라 loader
메시지를 실시간으로 소비하고, 최근 이벤트 상태를 유지하며, metrics를
표시하고, loader가 잠시 없을 때도 UI가 멈추지 않아야 합니다.

핵심 작업:

- PySide6 앱이 `gui/run_gui.py`에서 안정적으로 실행되게 합니다.
- `/tmp/mcp-guard.sock`용 `SocketClient`를 안정화합니다.
- `event`, `metrics_snapshot`, `reload_result` 메시지를 parsing합니다.
- deny/audit/allow 이벤트를 Events table에 표시합니다.
- 작업이 차단된 경우(`action=deny`) 명확한 popup 안내를 표시합니다.
- L1/L2/L3 hit count, hit ratio, latency summary를 표시합니다.
- MCP agent attribution을 위해 `profile_id`, `agent_id`를 표시합니다.
- focus를 빼앗지 않는 deny alert popup을 표시합니다.
- reconnect 처리와 연결 상태 표시를 추가합니다.
- root 권한이나 BPF 없이 개발할 수 있도록 sample replay mode를 추가합니다.
- `gui/README.md`에 setup, live mode, replay mode 실행법을 정리합니다.

구현 순서:

1. socket ingestion 완성.
   - `QLocalSocket`을 사용합니다.
   - newline이 올 때까지 partial read를 buffer에 쌓습니다.
   - `type`별로 메시지를 분기합니다.
   - malformed JSON은 recoverable error로 처리합니다.

2. data model 완성.
   - 없는 필드를 normalize합니다.
   - bounded recent event history를 유지합니다.
   - action, hook, layer, profile, agent별 counter를 유지합니다.
   - `EventTableModel`을 제공합니다.

3. dashboard 완성.
   - 상단 connection/status strip.
   - summary counter.
   - L1/L2/L3 ratio card 또는 compact panel.
   - 최근 deny/audit event panel.

4. Events view 완성.
   - 정렬 가능한 table.
   - action, hook, layer, profile/agent, text search filter.
   - raw JSON과 timing comparison을 보여주는 detail panel.

5. Metrics view 완성.
   - loader의 `metrics_snapshot` JSON을 소비합니다.
   - total count, layer ratio, average/min/max latency, histogram bucket을
     표시합니다.
   - snapshot이 아직 없으면 event-derived counter로 fallback합니다.

6. Policy/Runtime view 완성.
   - 마지막 reload result를 표시합니다.
   - 값이 있으면 active epoch/generation을 표시합니다.
   - 현재 socket path와 reconnect state를 표시합니다.

7. alert 완성.
   - 기본적으로 `action=deny` 이벤트에서만 popup을 띄웁니다.
   - hook, path/destination, rule, profile/agent, duration을 포함합니다.
   - popup 비활성화 UI toggle을 추가합니다.

8. replay와 문서 완성.
   - `gui/samples/events.ndjson`를 대표성 있게 유지합니다.
   - `run_gui.py` 또는 작은 helper module에 replay mode를 추가합니다.
   - live/replay workflow를 문서화합니다.

이번 단계에서 제외할 것:

- GUI에서 kernel policy file을 직접 편집하는 기능.
- GUI에서 privileged loader command를 실행하는 기능.
- TCP 기반 remote monitoring.
- 장기 event persistence 또는 database 저장.

## 개발 명세

이 섹션은 7단계 구현 계약입니다. 개발자는 repository의 다른 부분을
추측하지 않고도 이 섹션만 보고 GUI를 구현할 수 있어야 합니다.

### Command Line Interface

`gui/run_gui.py`는 다음 실행 모드를 지원해야 합니다.

```bash
python gui/run_gui.py
python gui/run_gui.py --socket /tmp/mcp-guard.sock
python gui/run_gui.py --replay gui/samples/events.ndjson
python gui/run_gui.py --no-popups
```

인자:

| 인자 | 필수 | 기본값 | 동작 |
|---|---:|---|---|
| `--socket PATH` | 아니오 | `/tmp/mcp-guard.sock` | live loader event용 Unix socket path |
| `--replay PATH` | 아니오 | 없음 | socket 연결 대신 newline-delimited sample JSON을 읽음 |
| `--no-popups` | 아니오 | false | deny popup 비활성화 상태로 시작 |
| `--max-events N` | 아니오 | `5000` | in-memory event history 최대 개수 |

규칙:

- `--replay`와 live socket mode는 동시에 사용할 수 없습니다.
- GUI는 `sudo`를 요구하면 안 됩니다.
- CLI parsing은 `gui/run_gui.py` 또는 `gui/mcp_guard_gui/app.py`에 둡니다.

### Module Contract

필수 module과 책임:

| Module | 필수 Class/Function | 책임 |
|---|---|---|
| `app.py` | `main(argv=None)`, `create_app()` | CLI parse, `QApplication` 생성, style load, `MainWindow` 생성 |
| `socket_client.py` | `SocketClient`, `ReplayClient` | live socket ingestion, sample replay ingestion |
| `models.py` | `EventRecord`, `EventStore`, `EventTableModel`, `MetricsSnapshot`, `RuntimeStatus` | message normalize, 상태 저장, table model 제공 |
| `main_window.py` | `MainWindow` | dashboard/events/metrics/runtime UI 구성 및 signal wiring |
| `alert_popup.py` | `AlertPopup`, optional `AlertManager` | focus를 빼앗지 않는 deny notification |
| `resources.py` | `load_stylesheet()`, `resource_path()` | `style.qss`, icon, sample path resolve |

`gui/src/` 아래에 C++/Qt source file을 다시 도입하지 않습니다. GUI 구현은
Python/PySide6 전용입니다.

### Signal Contract

`SocketClient`와 `ReplayClient`는 다음 Qt signal을 emit해야 합니다.

| Signal | Payload | 의미 |
|---|---|---|
| `message_received` | `dict` | routing 전 모든 parsed JSON object |
| `event_received` | `dict` | security event, 보통 `type=event` 또는 `type` 없음 |
| `metrics_received` | `dict` | `type=metrics_snapshot` message |
| `reload_result_received` | `dict` | `type=reload_result` message |
| `connection_state_changed` | `str` | `disconnected`, `connecting`, `connected`, `replaying`, `error` |
| `error_received` | `str` | recoverable socket, replay, JSON parse error |

Routing 규칙:

- `type`이 없으면 backward compatibility를 위해 `event`로 처리합니다.
- 알 수 없는 `type`은 `message_received`만 emit하고 event table에는 넣지 않습니다.
- malformed JSON은 `error_received`를 emit하고 ingestion을 계속합니다.

### Event Schema

들어온 event는 `EventRecord`로 normalize합니다.

| Field | Type | Default | 표시 |
|---|---|---|---|
| `timestamp_ns` | int | `ts_ns` 또는 `0` | Details, optional hidden sort key |
| `pid` | int | `0` | Table |
| `tgid` | int | `0` | Details |
| `uid` | int | `0` | Details |
| `comm` | str | `"-"` | Table/details |
| `hook` | str | `"-"` | Table/filter |
| `action` | str | `"-"` | Table/filter |
| `layer` | str | `"-"` | Table/filter |
| `duration_ns` | int | `0` | Table/details |
| `duration_us` | float | `duration_ns / 1000` | Table/details |
| `model_us` | float | layer 기준 | Details |
| `delta_us` | float | `duration_us - model_us` | Details |
| `rule_id` | int | `0` | Details |
| `profile_id` | int | `0` | Table/details |
| `agent_id` | int | `0` | Table/details |
| `error` | int | `0` | Details |
| `path` | str | `"-"` | Table/details |
| `rule` | str | `"-"` | Table/details |
| `port` | int | `0` | network event에서 Table/details |
| `resource_id` | int | `0` | Details |
| `epoch` | int | `0` | Status/details |
| `raw` | dict | 원본 message | Details JSON |

Layer별 model baseline:

| Layer | `model_us` |
|---|---:|
| `L1` | `0.018` |
| `L2` | `0.023` |
| `L3` | `0.989` |
| unknown | `0.0` |

### Metrics Schema

GUI는 현재와 미래의 metrics JSON을 모두 받아야 합니다. 최소 동작:

- `type=metrics_snapshot` 메시지는 event row로 추가하지 않습니다.
- field가 있으면 total count와 L1/L2/L3 ratio를 추출합니다.
- 상세 hook/layer/action entry가 있으면 Metrics view에 표시합니다.
- metrics snapshot이 아직 없으면 `EventStore`에서 유도한 counter를 사용합니다.

권장 normalized metrics field:

| Field | Type | Default |
|---|---|---|
| `total` | int | `0` |
| `l1_ratio` | float | derived 또는 `0.0` |
| `l2_ratio` | float | derived 또는 `0.0` |
| `l3_ratio` | float | derived 또는 `0.0` |
| `entries` | list[dict] | `[]` |
| `received_at` | datetime | now |

### Reload Result Schema

`type=reload_result` 메시지는 `RuntimeStatus`로 normalize합니다.

Fields:

| Field | Type | Default |
|---|---|---|
| `success` | bool | false |
| `rule_count` | int | `0` |
| `generation` | int | `0` |
| `epoch` | int | `0` |
| `error` | str | `""` |

UI 동작:

- 성공한 reload는 neutral/positive status color로 표시합니다.
- 실패한 reload는 warning status color로 표시합니다.
- reload가 발생해도 event table은 비우지 않습니다.

### Event Store Rules

`EventStore`는 event-derived UI state의 단일 source of truth입니다.

필수 동작:

- 최대 `max_events`개의 record만 유지합니다.
- capacity를 넘으면 가장 오래된 record부터 제거합니다.
- 다음 기준의 counter를 유지합니다.
  - action
  - hook
  - layer
  - profile_id
  - agent_id
- 최신 deny event를 유지합니다.
- observed epoch 중 0이 아닌 최댓값을 current epoch로 유지합니다.
- filter는 raw event list를 변경하지 않고 적용합니다.

Filters:

| Filter | Values |
|---|---|
| action | `all`, `allow`, `deny`, `audit` |
| hook | `all`, `exec`, `file_open`, `file_read`, `file_write`, `socket_connect` |
| layer | `all`, `L1`, `L2`, `L3` |
| profile/agent | `all` 또는 정확한 numeric id |
| text | `path`, `rule`, `comm`, `hook`, `action` substring match |

### Event Table Columns

필수 column 순서:

| Column | Source |
|---|---|
| Time | `timestamp_ns`, 가능하면 local time으로 format |
| Action | `action` |
| Hook | `hook` |
| Layer | `layer` |
| Duration | `duration_us`, 소수점 3자리 |
| PID | `pid` |
| Profile | `profile_id` |
| Agent | `agent_id` |
| Target | `path` 또는 network event의 `dst=:port` |
| Rule | `rule` |

Row 표시:

- `deny` row는 눈에 잘 띄되 읽기 쉬워야 합니다.
- `audit` row는 `allow`와 구분되어야 합니다.
- 색상에만 의존하지 말고 text label을 유지합니다.

### Window Layout Specification

첫 화면은 운영 dashboard여야 합니다.

권장 widget hierarchy:

```text
QMainWindow
  central QWidget
    QVBoxLayout
      Status strip
      QSplitter horizontal
        Navigation QListWidget or QTabWidget
        Main QStackedWidget
          Dashboard page
          Events page
          Metrics page
          Runtime page
      Bottom status line
```

Dashboard page:

- Summary row: connection, total events, deny count, current epoch/generation.
- Layer panel: L1/L2/L3 count와 ratio.
- Latency panel: layer별 average duration, latest event duration.
- Latest deny/audit panel.

Events page:

- Filter toolbar.
- `EventTableModel` 기반 `QTableView`.
- raw JSON과 timing comparison을 보여주는 details panel.

Metrics page:

- Snapshot timestamp.
- Layer ratio bar.
- 상세 entry가 있을 경우 hook/layer/action metrics table.
- Histogram bucket display.

Runtime page:

- Socket path.
- Connection state.
- Last socket error.
- Last reload result.
- Popup enabled/disabled setting.

### Alert Specification

Alert popup 동작:

- 기본값으로 `action=deny`에서만 trigger합니다.
- popup title은 작업이 차단되었다는 사실을 명확히 알려야 합니다.
  예: `MCP Guard가 작업을 차단했습니다`.
- action, hook, target, rule, profile_id, agent_id, duration_us를 포함합니다.
- 짧은 설명 문구를 포함합니다.
  예: `활성 MCP Guard 정책에 의해 이 요청이 거부되었습니다.`
- focus를 빼앗지 않습니다.
- 5초 후 자동으로 닫힙니다.
- 동시에 보이는 popup은 최대 3개입니다. 추가 alert는 counter로 합칩니다.
- 현재 session에서 popup을 끄는 UI toggle을 제공합니다.

### Replay Specification

Replay mode는 non-root GUI 개발을 위해 필수입니다.

입력 형식:

- 한 줄에 JSON 객체 하나.
- 빈 줄은 무시합니다.
- invalid line은 `error_received`를 emit하고 replay를 계속합니다.

Timing:

- 초기 구현은 100 ms 간격으로 line을 replay해도 됩니다.
- 향후 `--replay-speed`를 추가할 수 있지만 7단계 필수는 아닙니다.

Replay mode 상태:

- `connection_state_changed`는 `replaying`을 emit합니다.
- replay message는 live socket message와 같은 normalization path를 탑니다.

### Error Handling

필수 error handling:

- socket path 없음: disconnected 표시, retry.
- socket disconnect: disconnected 표시, backoff로 retry.
- JSON decode error: last error 표시, 계속 진행.
- required event field 없음: malformed event record를 만들고 없는 값은 `-`.
- message 처리 중 UI exception이 socket ingestion을 죽이면 안 됩니다. 가능한
  범위에서 catch하고 status/error 영역에 표시합니다.

차단 안내 notification 규칙:

- `action=deny` event마다 popup이 비활성화되어 있지 않다면 사용자에게 보이는
  notification을 정확히 하나 생성합니다.
- notification은 `path` 또는 `dst=:port`를 사용해 차단된 target을 식별해야
  합니다.
- 가능한 경우 matched `rule`을 보여줘야 합니다.
- 단순 실패처럼 표현하지 말고, MCP Guard 정책에 의해 차단되었다고 명확히
  표현해야 합니다.

Reconnect backoff:

- 250 ms에서 시작합니다.
- 최대 5초까지 두 배씩 늘립니다.
- 연결에 성공하면 250 ms로 reset합니다.

### Nonfunctional Requirements

- event ingest 중에도 UI가 반응해야 합니다.
- UI thread에서 blocking socket read를 하면 안 됩니다.
- memory는 `max_events`로 bounded되어야 합니다.
- 알 수 없는 JSON field는 `raw`를 통해 details에 보존합니다.
- 일반 사용자 계정에서 실행 가능해야 합니다.
- `gui/resources/style.qss`를 적용해도 가독성이 유지되어야 합니다.

### Implementation Checklist

- [ ] CLI가 live/replay mode를 지원합니다.
- [ ] `SocketClient`가 reconnect와 JSON lines를 처리합니다.
- [ ] `ReplayClient`가 `events.ndjson`를 읽습니다.
- [ ] `EventRecord` normalization이 missing field를 처리합니다.
- [ ] `EventStore`가 bounded history와 counter를 유지합니다.
- [ ] `EventTableModel`이 필수 column을 제공합니다.
- [ ] Dashboard가 counter, ratio, 최신 high-risk event를 표시합니다.
- [ ] Events page가 filter와 details panel을 지원합니다.
- [ ] Metrics page가 `metrics_snapshot`을 처리합니다.
- [ ] Runtime page가 socket/reload/error state를 표시합니다.
- [ ] Deny popup이 동작하고 비활성화할 수 있습니다.
- [ ] 차단 안내 popup이 MCP Guard가 action을 deny했다는 사실을 명확히 설명합니다.
- [ ] `gui/README.md`가 setup, live mode, replay mode, troubleshooting을 문서화합니다.
- [ ] 수동 테스트 계획을 통과합니다.

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
- `profile_id`
- `agent_id`
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

6. sample replay를 추가합니다.
   - `gui/samples/events.ndjson`를 읽습니다.
   - live socket event와 같은 model path로 message를 전달합니다.
   - `sudo`나 실행 중인 loader 없이 사용할 수 있어야 합니다.

7. GUI 문서를 업데이트합니다.
   - virtualenv setup을 문서화합니다.
   - `sudo ./mcp-guard policies`와 함께 쓰는 live mode를 문서화합니다.
   - replay mode를 문서화합니다.
   - screenshot은 UI가 안정화된 뒤 추가합니다.

## 완료 기준

- `python gui/run_gui.py`가 root 권한 없이 GUI를 실행합니다.
- loader가 실행 중이 아니면 GUI는 `disconnected`를 표시하고 멈추지 않은 채
  재연결을 시도합니다.
- `sudo ./mcp-guard policies`가 실행 중이면 GUI가 `/tmp/mcp-guard.sock`에서
  live event를 수신합니다.
- deny event가 Events table에 표시되고 기본값으로 popup 하나를 띄웁니다.
- metrics snapshot이 event ingestion을 막지 않고 dashboard를 갱신합니다.
- reload result가 runtime/status 영역에 표시됩니다.
- optional JSON field가 없으면 `-`로 표시하고, 알 수 없는 field는 app을
  crash시키지 않습니다.
- `gui/samples/events.ndjson`를 loader 없이 replay할 수 있습니다.
- table 또는 detail view에서 `profile_id`, `agent_id`를 볼 수 있습니다.
- `gui/README.md`에 setup, live run, replay run, troubleshooting이 정리되어
  있습니다.

## 수동 테스트 계획

Live mode:

```bash
sudo ./mcp-guard policies --metrics-interval 1s
python gui/run_gui.py
```

대표 이벤트 발생:

```bash
/usr/bin/true
cat /tmp/some-protected-file
nc -vz 127.0.0.1 4444
```

Replay mode:

```bash
python gui/run_gui.py --replay gui/samples/events.ndjson
```

확인할 것:

- connection indicator가 상태에 맞게 바뀝니다.
- Events table이 UI stall 없이 갱신됩니다.
- Dashboard counter가 들어온 message와 일치합니다.
- deny popup이 나타났다가 자동으로 닫힙니다.
- metrics/reload message가 의도 없이 일반 event row로 섞이지 않습니다.

## Loader 개발자와의 협업 규칙

GUI는 loader의 JSON field name에 의존합니다. 변경 사항은 `docs/loader-development-guide-ko.md`와 함께 조율합니다.

호환성 규칙:

- 알 수 없는 필드는 무시합니다.
- optional field가 없으면 `-`로 표시합니다.
- required field가 없어도 crash하면 안 되며 malformed event로 표시합니다.
- loader의 새 필드는 먼저 detail panel에 추가하고, 필요할 때 table column으로 승격합니다.
- loader가 `metrics_snapshot`, `reload_result`, `health` 같은 message type을 추가하면 GUI는 `type` 기준으로 route하고 event rendering과 분리해야 합니다.
