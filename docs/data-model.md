# Модель данных и версии

| Что | Версия | Где определено |
|---|---|---|
| События, `EndpointRecord` (JSON) | `EVENT_SCHEMA_VERSION = 1` | `crates/ni-core/src/lib.rs` |
| Сессия | `SESSION_SCHEMA_VERSION = 1` (поле `schema` в строке сессии) | `crates/ni-core/src/session.rs` |
| Вывод (`Finding`) | `FINDING_SCHEMA_VERSION = 1` | `crates/ni-core/src/finding.rs` |
| Результаты проверок | `PROBE_SCHEMA_VERSION = 1` | `crates/ni-core/src/probe.rs` |
| Схема SQLite | `PRAGMA user_version = 1` | `crates/ni-storage/src/migrations.rs` |
| Отчёт JSON | `format = "network-intelligence.session-report"`, `schema = 1` | `crates/ni-report/src/lib.rs` |

База, созданная более новой версией (`user_version` больше известного), не
открывается и не изменяется.

## Источники данных (`DataSource`)

| Значение | Смысл |
|---|---|
| `observed_process` | строка системной таблицы сокетов, отнесённая к отслеживаемому процессу |
| `active_probe` | проверка, выполненная самим Network Intelligence по запросу пользователя |
| `system_snapshot` | состояние системы: список процессов, ошибки снимка |
| `etw` | зарезервировано для событийного сборщика (в 0.1 не используется) |
| `user` | маркеры, заметки, начало/конец записи |

## Endpoint

Ключ: протокол, локальный адрес и порт, удалённый адрес и порт (для TCP),
`ProcessIdentity`. Поля записи: семейство сокета и удалённого адреса, область
адреса, текущее состояние и все виденные состояния, `first_seen`/`last_seen`,
число наблюдений (снимков с присутствием), эпизоды (сколько раз появлялся
заново), `present`, `gone_at` (время первого снимка без него), время создания
сокета (если ОС сообщает правдоподобное значение), источник и достоверность.

Не реализованные поля (DNS-имя, ASN, владелец сети, байты, пакеты, RTT,
повторные передачи, DPI-признаки) в модели 0.1 отсутствуют — в UI они
перечислены как «нет источника». Добавляются с `#[serde(default)]`.

## События (`EventKind`)

`sessionStarted`, `sessionStopped`, `processTracked`, `processExited`,
`pidReused`, `endpointAppeared` (с номером эпизода), `endpointStateChanged`,
`endpointDisappeared` (с `lastSeen`), `sourceError`, `probeStarted`,
`probeFinished`, `userMarker`. Время события — время снимка, в котором
изменение было замечено.

## Таблицы SQLite (версия 1)

| Таблица | Ключ | Содержимое |
|---|---|---|
| `sessions` | `id` (UUID) | метаданные, цель, настройки, охват (JSON), заметка, статус |
| `processes` | `(session_id, pid, created_key)` | отслеживаемые процессы (`created_key = -1`, если время создания неизвестно) |
| `endpoints` | `(session_id, id)` | endpoint + индексируемые столбцы протокола, адресов, состояния |
| `events` | `id` | событие (JSON) + `ts`, `kind`, `source`, `pid`, `protocol`, `remote_addr` для фильтров |
| `snapshots` | — | время, длительность, успех, число строк, ошибка каждого снимка |
| `probes` | `id` | проверка (JSON); `session_id` может быть пустым |
| `findings` | `(session_id, id)` | выводы последнего анализа |
| `settings` | `key` | настройки приложения (JSON) |

Все дочерние таблицы удаляются каскадно вместе с сессией.
