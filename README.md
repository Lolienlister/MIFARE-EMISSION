# MIFARE-EMISSION

Offline СКУД на базе MIFARE Classic 1K + PC/SC + BELT (СТБ 34.101.31-2020).

- Карта содержит **только UID и счётчик** — никаких секретов.
- `MASTER_KEY` хранится **только на хосте** (Windows DPAPI / raw-файл).
- Ключ авторизации сектора `KEY(n) = trunc6(BELT-MAC(MASTER_KEY, UID || counter))`
  пересчитывается на каждой успешной транзакции и перезаписывается в trailer карты.
- Любое нарушение монотонности счётчика (replay/regression) приводит к
  необратимому статусу `COMPROMISED`.
- Доступ разрешён только в окне `08:00 ≤ t < 18:00` (настраивается).
- Локальный JSON-файл (`state.json`) — единственное хранилище состояния.

Подробная инженерная архитектура, поток данных, security-анализ и схема
JSON: см. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Сборка

### Зависимости
- CMake ≥ 3.16
- C++17 компилятор (MSVC 2019+ / clang-cl / g++)
- На Windows: SDK с `winscard.h` (входит в стандартный Windows SDK)
- Внешние библиотеки — забираются автоматически:
    - `BELT_STD` (git submodule)
    - `nlohmann/json` (CMake FetchContent)
    - `googletest` (CMake FetchContent, только для тестов)

### Клонирование

```bash
git clone --recurse-submodules https://github.com/Lolienlister/MIFARE-EMISSION.git
cd MIFARE-EMISSION
# или, если клонировали без --recurse-submodules:
git submodule update --init --recursive
```

### Windows (Visual Studio / Ninja)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

### Linux (только ядро + юнит-тесты, без PC/SC)

```bash
cmake -S . -B build -DMIFARE_BUILD_APP=OFF -DMIFARE_BUILD_TOOLS=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Использование

1. Сгенерировать `MASTER_KEY` (один раз на инсталляцию):
   ```powershell
   .\mifare_emission_tool.exe gen-master master.key
   ```
2. Эмитировать карту (положите на ридер свежую карту с factory key `FF…`):
   ```powershell
   .\mifare_emission_tool.exe emit state.json master.key
   ```
   После эмиссии на карте: `counter=1`, `KEY_A=BELT-KDF(MASTER_KEY, UID, 1)`.
   В `state.json`: `counter=0, status=OK` — на первой же транзакции инкремент
   доводит счётчик до `2` на карте и `1` в состоянии.
3. Запустить СКУД-loop:
   ```powershell
   .\mifare_emission_app.exe config.json
   ```
4. Отозвать карту (UID в шестнадцатеричной форме):
   ```powershell
   .\mifare_emission_tool.exe revoke state.json AABBCCDD
   ```
5. Сбросить карту в factory state (например, перед повторной эмиссией или
   когда карта была случайно использована и помечена `COMPROMISED`):
   ```powershell
   .\mifare_emission_tool.exe reset state.json master.key
   ```
   Команда подбирает текущий ключ сектора с учётом `state.json`
   (`KDF(uid, stored.counter+1)` и окно вокруг него) + brute-force-скан
   `KDF(uid, 0..1024)` для карт без записи в state. После успеха записывает
   trailer `KEY_A=FF FF FF FF FF FF`, `KEY_B=FF FF FF FF FF FF`, ACL по
   умолчанию и обнуляет счётчик. Запись о UID удаляется из `state.json`.

Минимальный `config.json`:

```json
{
  "state_path": "state.json",
  "log_path": "skud.log",
  "master_key_path": "master.key",
  "dpapi": true,
  "reader_name": "",
  "poll_timeout_ms": 1000,
  "window": { "start_hour": 8, "start_minute": 0, "end_hour": 18, "end_minute": 0 }
}
```

## Структура репозитория

```
include/mifare_emission/   API заголовки
src/                       Имплементация (logger, time, crypto, state, engine, PC/SC)
tools/                     Сервисные утилиты (эмиссия, отзыв, gen-master)
tests/                     GTest unit-tests (включая MockRfidReader)
docs/                      Документация (ARCHITECTURE.md)
third_party/BELT_STD/      Реализация BELT (git submodule)
CMakeLists.txt             Сборка
```

## Лицензия / третьи стороны

- `BELT_STD` — внешний submodule, см. https://github.com/MikhailSklian/BELT_STD
- `nlohmann/json` — MIT
- `googletest` — BSD-3-Clause
