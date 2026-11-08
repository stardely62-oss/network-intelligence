# Тестирование

## Автоматические тесты

| Область | Где | Платформа |
|---|---|---|
| Нормализация и классификация адресов, IPv4/IPv6, IPv4-mapped | `ni-core/src/addr.rs` | любая |
| Идентичность процессов: PID + время создания, PID reuse, дочерние с переиспользованным PID родителя, перезапуск, PID-only | `ni-core/src/process.rs` | любая |
| Корреляция endpoints: появление/смена/исчезновение/эпизоды, сбой таблицы ≠ исчезновение, UDP без удалённого адреса | `ni-core/src/correlate.rs` | любая |
| Сериализация событий (JSON, теги, round-trip) | `ni-core/src/event.rs` | любая |
| Сборщик: завершение процесса во время сессии, PID reuse, недоступный источник, исключение LISTEN, поток старт/стоп | `ni-collector/tests/scripted.rs` | любая |
| Сквозной тест сборщика с реальным IP Helper: своё соединение появляется и исчезает, завершение дочернего процесса | `ni-collector/tests/windows_e2e.rs` | Windows |
| Реальные таблицы TCP/UDP IPv4/IPv6 (LISTEN, ESTABLISHED, UDP-привязки, закрытие) | `ni-windows/tests/socket_tables.rs` | Windows |
| Процессы: свой процесс с временем создания, System (PID 4), дочерний процесс | `ni-windows/src/proc.rs` | Windows |
| Иконка `notepad.exe` → PNG | `ni-windows/src/icon.rs` | Windows |
| Разбор полей IP Helper (порядок байтов) | `ni-windows/src/raw.rs` | любая |
| SQLite: миграции, отказ открывать более новую БД, права файла, round-trip сессии, фильтры событий, каскадное удаление, прерванные сессии, хранение | `ni-storage/tests/store.rs` | любая |
| DNS/TCP/UDP-проверки на локальных серверах: успех v4/v6, закрытый порт = отказ, контролируемый тайм-аут, UDP-ответ, UDP без ответа, ICMP port unreachable, фильтр семейств | `ni-probe/tests/local_probes.rs` | любая |
| Классификация ошибок WinSock/errno, разбор целей (диапазоны отклоняются), DNS-запрос, STUN | `ni-probe/src/*.rs` | любая |
| Правила: незавершённое рукопожатие, отказ ≠ фильтрация, сравнение с проверкой, IPv6-only отказ, DNS в служебный адрес, UDP-молчание, **политика уверенности** | `ni-diagnostics/tests/rules.rs` | любая |
| Экспорт: версия формата, редактирование IP/путей/заметок, round-trip без редактирования | `ni-report` | любая |
| Форматирование и поиск в UI | `apps/desktop/src/lib/format.test.ts` | любая |

## Локальные тестовые серверы

`crates/ni-probe/tests/support/mod.rs`: TCP echo, закрытый TCP-порт, TCP-слушатель
с backlog 0 (контролируемый тайм-аут: Linux отбрасывает SYN при полной очереди;
Windows обычно отвечает RST — тест проверяет, что тайм-аут соблюдён в любом
случае), UDP echo, «молчащий» UDP-сокет, закрытый UDP-порт. Все — только loopback.

Для ручной проверки: `cargo run -p ni-probe --example test_server`
(TCP echo 127.0.0.1:47001, UDP echo :47002, молчащий UDP :47003).

## Чего тесты не доказывают

- CI работает на Windows Server (`windows-latest`), а не на Windows 11.
- Интерфейс не проходит автоматических UI-тестов; в CI проверяется только, что
  собранное приложение запускается, держит окно и создаёт базу данных
  (`scripts/ci/smoke-start.ps1`).
- Поведение с реальными приложениями (Discord, браузеры, игры) проверяется
  вручную — [manual-testing.md](manual-testing.md).
