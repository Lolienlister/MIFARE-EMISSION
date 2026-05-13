# MIFARE-EMISSION SKUD — Архитектура

Stateful offline-СКУД на MIFARE Classic 1K через PC/SC (Windows) с криптографией
BELT (СТБ 34.101.31-2020), ротацией ключей и локальным JSON-хранилищем.

---

## 1. Высокоуровневая архитектура

```
                  ┌──────────────────────────────────────┐
                  │            Хост (Windows PC)         │
                  │                                      │
                  │  ┌───────────────┐  ┌─────────────┐  │
                  │  │ Vault         │  │ Config      │  │
                  │  │ (DPAPI/file)  │  │ (config.json)│ │
                  │  └──────┬────────┘  └──────┬──────┘  │
                  │         │ MASTER_KEY      │         │
                  │         ▼                 ▼         │
                  │  ┌────────────────────────────────┐ │
                  │  │       Access Control Engine    │ │
                  │  │  (decide + runOnce orchestr.)  │ │
                  │  └──┬───────────┬───────────┬─────┘ │
                  │     │           │           │       │
                  │     ▼           ▼           ▼       │
                  │ ┌──────┐  ┌─────────┐  ┌────────┐   │
                  │ │BELT  │  │JsonState│  │ Time   │   │
                  │ │KDF   │  │Store    │  │ Policy │   │
                  │ └──────┘  └────┬────┘  └────────┘   │
                  │                │                    │
                  │                ▼ state.json (atomic)│
                  │  ┌────────────────────────────────┐ │
                  │  │       RFID Interface Layer     │ │
                  │  │       (winscard / PC/SC)       │ │
                  │  └─────────────┬──────────────────┘ │
                  └────────────────┼────────────────────┘
                                   │ APDU (T=0/T=1)
                                   ▼
                       ┌──────────────────────┐
                       │ CCID PC/SC Reader    │
                       │  (e.g. ACR122U)      │
                       └──────────┬───────────┘
                                  │ 13.56 MHz
                                  ▼
                       ┌──────────────────────┐
                       │ MIFARE Classic 1K    │
                       │  UID + counter block │
                       └──────────────────────┘
```

## 2. Поток данных (Data Flow)

Каждая транзакция «приложили карту → решение»:

```
T0   reader.waitForCard()                          ── ждём PRESENT
T1   uid  ← reader.readUid()                       ── APDU FF CA 00 00 00
T2   stored ← state.find(uid)                      ── из JSON (in-memory map)
T3   probe_counter ← stored.counter or 0
T4   key  ← BELT_MAC(MASTER_KEY, UID || probe_counter)[0..5]
T5   reader.authenticateSector(sector=1, key, KEY_A)
       └── при ошибке: fallback на probe_counter=0
                  если опять fail → DENY/CRYPTO_ERROR
T6   block ← reader.readBlock(4)                   ── 16 байт «value-block»
T7   counter ← decodeCounter(block)
T8   AccessEngine.decide(uid, counter, now):
       a. time_policy.isAccessAllowed(now)?   нет → DENY/OUT_OF_TIME_WINDOW
       b. stored.status?     COMPROMISED/BLOCKED → DENY
       c. counter == stored.counter           → REPLAY  → mark COMPROMISED
       d. counter <  stored.counter           → REGRESSION → mark COMPROMISED
       e. иначе                               → ALLOW (counter+1, last_seen=now)
T9   if ALLOW:
       new_key ← BELT_MAC(MASTER_KEY, UID || counter+1)[0..5]
       reader.writeBlock(4,  encodeCounter(counter+1))
       reader.writeBlock(7,  trailer(new_key, ACL, new_key))
T10  state.upsert(uid, new_state)  → atomic JSON write (tmp + rename)
T11  Logger.info / .warn / .error                  ── аудит-журнал
```

Все шаги после `decide()` выполняются только при положительном решении;
при отрицательном — на карте ничего не пишется и ключ не ротируется
(иначе атакующий получил бы Oracle).

## 3. Разбивка по модулям (C++ классы)

| Модуль | Файлы | Главные классы / интерфейсы |
|---|---|---|
| Common types        | `include/mifare_emission/types.h`, `src/types.cpp` | `Uid`, `Counter`, `SectorKey`, `MasterKey`, `CardStatus`, `CardState`, `Decision`, `DenyReason`, `TransactionResult` |
| Time policy         | `time_policy.{h,cpp}` | `TimePolicy(start, end).isAccessAllowed(now)` |
| Crypto (BELT KDF)   | `crypto.{h,cpp}` | `BeltKdf(master_key).deriveSectorKey(uid, counter)` |
| State DB            | `json_state.{h,cpp}` | `JsonStateStore` — load / save (atomic) / find / upsert / markCompromised / markBlocked |
| RFID interface      | `rfid_reader.h`, `pcsc_reader.{h,cpp}` | `IRfidReader` (abstract), `PcscReader` (winscard) |
| Master key vault    | `master_key_vault.{h,cpp}` | `IMasterKeyVault`, `DpapiMasterKeyVault` (Win), `FilesystemMasterKeyVault` |
| Access engine       | `access_engine.{h,cpp}` | `AccessEngine.decide()` (pure), `AccessEngine.runOnce()` (I/O) |
| Logging             | `logger.{h,cpp}` | `Logger`: file + stdout/stderr, ISO-8601 |
| Tools               | `tools/emission_tool.cpp` | `gen-master`, `emit`, `revoke` CLI |
| Tests               | `tests/test_*.cpp`, `mock_rfid_reader.{h,cpp}` | GTest + `MockRfidReader` |

`AccessEngine.decide()` намеренно отделён от I/O: это чистая функция
от `(uid, counter_with_card, now)` и состояния — она и есть формальное
ядро политики безопасности.

## 4. Ключевые алгоритмы (псевдокод)

### 4.1 BELT KDF

```text
KEY(n)            = trunc6( BELT_MAC( MASTER_KEY, UID || LE32(counter_n) ) )
BELT_MAC          : СТБ 34.101.31-2020, ключ 256 бит, выход 128 бит
trunc6(mac)       : первые 6 байт (MIFARE Classic Crypto1 keysize)
KdfInput          = UID || counter_LE                  // BeltKdf::buildKdfInput
```

Свойства: детерминированность, лавинность (1 бит изменения UID или counter →
≈50 % бит выхода), отсутствие коллизий по `(UID, counter)` на практике.
MASTER_KEY никогда не покидает хост.

### 4.2 Транзакция

```text
function handle_transaction(now):
    uid       := reader.read_uid()
    stored    := state.find(uid)
    top       := stored ? stored.counter : 0
    floor     := max(0, top - max_auth_lookback)         // bounded окно ретрая

    # Хост последовательно пробует ключи KEY(top), KEY(top-1), ..., KEY(floor).
    # Это нужно ровно для одного класса атак: клон, отстающий по counter
    # на ≤ max_auth_lookback транзакций, должен пройти аутентификацию,
    # чтобы дальше быть пойманным как COUNTER_REGRESSION.
    for c in [top, top-1, ..., floor]:
        if reader.authenticate(sector=1, KDF(MASTER_KEY, uid, c), KEY_A):
            break
    else:
        return DENY(CRYPTO_ERROR)

    block     := reader.read_block(COUNTER_BLOCK)
    counter   := decode_counter(block)
    result    := AccessEngine.decide(uid, counter, now)
    if result.decision != ALLOW:
        return result

    new_ctr   := counter + 1
    new_key   := KDF(MASTER_KEY, uid, new_ctr)
    reader.write_block(COUNTER_BLOCK,   encode_counter(new_ctr))
    reader.write_block(TRAILER_BLOCK,   trailer(new_key, ACL, new_key))
    state.upsert(uid, {counter=new_ctr, status=OK, last_seen=now})
    return ALLOW
```

### 4.3 Decision (формальная политика)

```text
function decide(uid, counter_card, now):
    if not time_policy.allows(now):              return DENY(OUT_OF_TIME_WINDOW)
    stored := state.find(uid)
    if stored:
        if stored.status == COMPROMISED:         return DENY(COMPROMISED)
        if stored.status == BLOCKED:             return DENY(BLOCKED)
        if counter_card == stored.counter:
            state.mark_compromised(uid);         return DENY(REPLAY)
        if counter_card <  stored.counter:
            state.mark_compromised(uid);         return DENY(COUNTER_REGRESSION)
        if counter_card >= MAX_COUNTER - 1:      return DENY(COUNTER_OVERFLOW)
    else:
        // первое появление UID — создаём запись с counter+1
        if counter_card >= MAX_COUNTER - 1:      return DENY(COUNTER_OVERFLOW)
    state.upsert(uid, {counter=counter_card+1, status=OK, last_seen=now})
    return ALLOW
```

### 4.4 Атомарное сохранение JSON

```text
function save():
    write(state.tmp.<rnd>, json.dump(records))   // полный документ
    fsync(state.tmp.<rnd>)
    rename(state.tmp.<rnd> → state.json)         // атомарно
```

POSIX `rename`/Win32 `MoveFileEx` атомарны → состояние не порвётся при сбое
питания: либо старый файл, либо новый.

### 4.5 Time policy

```text
function isAccessAllowed(now):
    cur := local_minutes_since_midnight(now)
    if start == end:               return false               // окно нулевой ширины
    if start <  end:               return start <= cur < end  // обычное окно
    else:                          return cur >= start or cur < end  // через полночь
```

## 5. Анализ безопасности

| # | Атака / угроза | Митигация |
|---|---|---|
| A1 | **Чистое клонирование (UID + counter + trailer-key)** карты «как есть» | После использования оригинала на хосте `stored.counter > counter_card_клона`. Auth-цикл пробует ключи `KEY(top..floor)` (см. §4.2) — при `top - counter_card ≤ max_auth_lookback` клон аутентифицируется → `COUNTER_REGRESSION` → `COMPROMISED`. Если отставание больше окна — клон просто не пройдёт `authenticate` (`CRYPTO_ERROR`) и в систему не попадёт. |
| A2 | **Replay** старого APDU/value-block | `counter == stored.counter` → `REPLAY` → `COMPROMISED`. |
| A3 | **Brute-force Crypto1** (классическая слабость MIFARE Classic) | Атакующий получает на руки только текущий 6-байтовый sector key, который меняется на следующей валидной операции. Восстановленный ключ ни до, ни после транзакции не повторяется (свойство BELT-KDF). |
| A4 | **Атака вне рабочего окна** | Time gate срабатывает до любых криптопроверок; никакого state-mutation. |
| A5 | **Утечка `state.json`** | Файл содержит только публичные UID + counter + status. Ключи там не лежат. Тем не менее рекомендуется ACL только для service-account. |
| A6 | **Утечка MASTER_KEY** | На Windows ключ зашифрован DPAPI (`CryptProtectData`, `CRYPTPROTECT_LOCAL_MACHINE` опционально), расшифровывается только от имени того же пользователя/машины. Никогда не пишется на карту и в логи. |
| A7 | **Подмена JSON «откатом» состояния** атакующим с записью на диск | См. §6: предлагается хранить `state_mac = BELT-MAC(MASTER_KEY, payload)` рядом с документом, чтобы откатанный/подделанный файл отбрасывался при загрузке. |
| A8 | **Race на JSON** в многопоточном/мульти-инстанс сценарии | `JsonStateStore` сериализует доступ через mutex; запись atomically (`tmp+rename`). Для multi-instance — внешний `LockFile` (см. §6). |
| A9 | **Tearing записи на карту** (питание срывается между write_block(counter) и write_block(trailer)) | На следующей сессии `authenticate(KDF(uid,counter_stored))` падает → fallback `KDF(uid,0)`; если и это не работает, карта помечается через `revoke` (admin). Альтернатива: использовать MIFARE INCREMENT/RESTORE + TRANSFER для atomic value-block. |
| A10 | **Time spoofing** (атакующий с правами админа выводит часы за окно) | Time gate всё равно работает в пользу defense (закрывает доступ). Если же атакующий сдвинул часы внутрь окна — это компромисс хоста, а не СКУД. |
| A11 | **Side-channel** на BELT-MAC | Использовать `BELT_STD` реализацию без логов/таймингов чувствительных данных. SecureZeroMemory для MASTER_KEY-буфера. |
| A12 | **Compromised на карте больше не записывается; что, если COMPROMISED-карту переэмиссируют?** | Перевод `COMPROMISED → OK` запрещён в API `JsonStateStore` (есть только `markCompromised`/`markBlocked`); сброс — только ручным admin-инструментом (out of scope). |

### Слабые места и компенсирующие меры
1. **Сам Crypto1 уязвим** независимо от BELT. Защита — частая ротация sector-key:
   ключ живёт ровно одну транзакцию.
2. **Карта без секретов** означает, что любой, кто видит UID + counter, может
   попробовать собрать «клон». Защита — алгоритмическая: counter всегда
   проверяется монотонно, дубль ловится. Карта — только идентификатор.
3. **Offline → нет CRL.** Компромисс распространяется только при следующем
   тапе скомпрометированной карты на каждом конкретном ридере; если в системе
   несколько ридеров — нужен общий `state.json` (см. §6).

## 6. Улучшения JSON-схемы

Минимальная схема из ТЗ:
```json
{
  "AABBCCDD": {
    "counter": 0,
    "status": "OK",
    "last_seen": "2026-05-13T10:00:00Z"
  }
}
```

Реализованная (`schema_version = 1`):
```json
{
  "schema_version": 1,
  "cards": {
    "AABBCCDD": {
      "counter": 0,
      "status": "OK",
      "last_seen": "2026-05-13T10:00:00Z"
    }
  }
}
```
Старый «плоский» формат продолжает читаться (см. `JsonState.LegacyFlatFormatLoads`).

Рекомендуемые расширения (готовые точки расширения в коде):

```json
{
  "schema_version": 2,
  "issued_at_iso": "2026-05-13T08:00:00Z",
  "cards": {
    "AABBCCDD": {
      "counter": 17,
      "status": "OK",
      "last_seen": "2026-05-13T10:00:00Z",
      "first_seen": "2026-01-15T09:23:00Z",
      "user_id": "emp-1042",
      "label": "Иванов И. И.",
      "policy_id": "default",
      "max_counter": 4294967294,
      "allowed_windows": [
        { "start": "08:00", "end": "18:00", "weekdays": [1,2,3,4,5] }
      ],
      "revocation_reason": null,
      "transactions": 17,
      "last_decision": "ALLOW"
    }
  },
  "integrity": {
    "algo": "belt-mac",
    "mac": "<hex 16 bytes>"
  }
}
```

* `integrity.mac` — `BELT_MAC(MASTER_KEY, canonical_json(state))`, проверяется
  на каждой загрузке; ловит откат/подмену файла (см. A7).
* `allowed_windows[]` — per-card time-gate (например, ночная смена); глобальный
  `TimePolicy` остаётся как пресет по умолчанию.
* `transactions`, `last_decision` — для аудита/отчётности.
* `revocation_reason` — обязательное поле при `status != OK`.

## 7. Конфигурация и операционные процедуры

### Файлы (по умолчанию)
- `config.json` — параметры запуска.
- `state.json`  — БД UID → состояние (атомарная запись).
- `master.key`  — MASTER_KEY (DPAPI на Windows, иначе raw 32 байта).
- `skud.log`    — журнал событий.

### Жизненный цикл карты
1. **gen-master** на ПК: `mifare_emission_tool gen-master master.key`.
2. **Эмиссия карты**: `mifare_emission_tool emit state.json master.key` —
   с factory-key `FF FF FF FF FF FF` карта инициализируется counter=0,
   trailer перезаписывается на `KDF(uid, 0)`, в `state.json` появляется запись.
3. **Доступ** (production loop): `mifare_emission_app config.json`.
4. **Отзыв**: `mifare_emission_tool revoke state.json AABBCCDD`.

### Тесты
GoogleTest, 30+ кейсов:
- BELT KDF: детерминированность, чувствительность ко всем входам, длина выхода.
- TimePolicy: границы, выход за окно, окно через полночь.
- JsonStateStore: round-trip, версионирование, legacy-формат, corrupt-file.
- AccessEngine: unknown UID, монотонный counter, replay, regression,
  COMPROMISED/BLOCKED inertness, time gate, full `runOnce()` с моком ридера.

## 8. Точки расширения

| Хотим | Где править |
|---|---|
| Другой блок счётчика / сектор | `AccessEngineConfig` |
| Использовать KEY_B | `AccessEngineConfig::auth_key_type = KEY_B` |
| Mифare Plus / DESFire | реализовать новый `IRfidReader` |
| Linux pcsclite | сделать `PcscReaderPosix` и переключение в CMake |
| Распределённый state | заменить `JsonStateStore` на client к SQLite/Redis (тот же интерфейс) |
| Time-window per card | расширить `decide()` чтением `allowed_windows[]` из CardState |

