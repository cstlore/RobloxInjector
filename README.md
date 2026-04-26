# ClaudeInjector

Продвинутый Roblox script executor с stealth injection и обходом anti-cheat систем.

## Архитектура

```
Phase 1: Injection Core
├── ModuleOverloading    - Загрузка sacrificial DLL с очисткой заголовков
├── ImportResolver       - Hookless разрешение IAT через export walking
├── ThreadExecution      - 5 методов: CreateRemoteThread, NtCreateThreadEx, RtlCreateUserThread, QueueAPC, ThreadHijack
└── ShellcodeLoader      - PE mapping с обработкой релокаций

Phase 2: Roblox Integration
├── RobloxScanner        - Детекция процессов (Player/Studio/UWP)
├── LuaStateFinder       - Pattern scanning для Luau VM state
└── ScriptExecutor       - Компиляция и выполнение Lua

Phase 3: Security Bypass
├── Hyperion Detection   - Pattern scanning для integrity checks
├── Byfron Bypass        - Отключение heartbeat и validation
├── Anti-Debug           - Очистка PEB.BeingDebugged, установка хуков
└── Call Stack Spoofing  - Манипуляция return address
```

## Возможности

### Методы Инжекции
- **Module Overloading**: Полная скрытность через sacrificial DLL с MEM_IMAGE VAD entry
- **Manual Mapping**: Классическая PE инжекция с разрешением импортов
- **Thread Hijacking**: Манипуляция контекстом существующих потоков
- **APC Injection**: Постановка в очередь асинхронных вызовов процедур

### Обход Безопасности
- Обход Hyperion integrity checks
- Отключение Byfron heartbeat
- Скрытие присутствия отладчика
- Патчинг memory scan
- Подмена call stack

### Выполнение Lua
- Компиляция Luau bytecode
- Настройка script environment (getgenv, getrenv)
- Повышение identity (уровни 0-7)
- Множественные методы детекции Lua state

## Сборка

**Требования:**
- Windows 10/11 x64
- Visual Studio 2022 с Windows SDK
- Windows Driver Kit (WDK) для kernel компонентов

**Компиляция:**
```bash
# Через Visual Studio
msbuild ClaudeInjector.sln /p:Configuration=Release /p:Platform=x64

# Или через Developer Command Prompt
cl /O2 /W4 /Fe:ClaudeInjector.exe src/main.c src/*.c /link /SUBSYSTEM:CONSOLE
```

## Использование

### CLI Режим
```bash
ClaudeInjector.exe

Команды:
  attach [pid]  - Подключиться к Roblox (авто-поиск если нет PID)
  exec <file>   - Выполнить Lua скрипт из файла
  execstr <lua> - Выполнить Lua строку напрямую
  status        - Показать текущий статус
  exit          - Выход
```

### Пример Сессии
```
> attach
[*] Подключение к Roblox...
[*] Найден RobloxPlayerBeta.exe (PID: 12345)
[*] Обход Hyperion...
[*] Поиск Lua state...
[+] Готов к выполнению скриптов

> exec script.lua
[*] Выполнение скрипта из script.lua (256 байт)...
[+] Скрипт выполнен успешно

> execstr print("Hello from ClaudeInjector!")
[*] Выполнение скрипта...
[+] Скрипт выполнен успешно
```

## Статус Реализации

### ✅ Завершено
- Фреймворк module overloading
- Разрешение импортов (hookless)
- Выполнение потоков (5 методов)
- Shellcode loader с PE mapping
- Сканер Roblox процессов
- Поиск Lua state (pattern scanning)
- Фреймворк обхода безопасности
- Главная интеграция executor

### ⚠️ Требует Реального Анализа
- **Lua API offsets** - Текущие оффсеты placeholder, нужен reverse engineering
- **Pattern signatures** - Паттерны Hyperion/Byfron нужно обновлять под версию Roblox
- **Lua state structure** - Оффсеты могут варьироваться между версиями Luau
- **Identity elevation** - Нужно найти оффсет поля identity в lua_State

### 🔧 Требуется Production Hardening
- Компиляция bytecode (сейчас заглушка)
- Настройка environment (инжекция getgenv, getrenv)
- Обработка ошибок и восстановление
- Логирование и телеметрия
- Шифрование строк для скрытности
- Обфускация кода

## Примечания по Безопасности

**Это образовательный/исследовательский код.** Использование на Roblox нарушает их Terms of Service и может привести к блокировке аккаунта.

**Техники обхода anti-cheat** требуют постоянных обновлений, так как Roblox патчит векторы детекции. Паттерны и оффсеты в этой кодовой базе являются примерами и не будут работать без анализа текущих билдов Roblox.

**Kernel-mode компоненты** (StealthDriver) требуют режима test signing или валидного сертификата подписи кода.

## Технические Детали

### Module Overloading Flow
1. Выбор sacrificial DLL (wtsapi32.dll, profapi.dll)
2. Загрузка через LoadLibrary → создание MEM_IMAGE VAD entry
3. Валидация VAD entry через VirtualQuery
4. Manual map целевой DLL в пространство sacrificial
5. Разрешение импортов через export directory walking
6. Применение base relocations
7. Очистка PE заголовков (DOS, NT, sections)
8. Выполнение entry point через remote thread

### Детекция Lua State
1. Pattern scan для сигнатур аллокации lua_State
2. Альтернатива: Сканирование сигнатуры Registry table
3. Альтернатива: Указатель mainthread в global_State
4. Валидация структуры (top >= base, non-null указатели)
5. Извлечение указателей GlobalState и Registry

### Стратегия Обхода Безопасности
1. Детекция модулей Hyperion/Byfron через pattern scanning
2. Патчинг функций integrity check (ret инструкция)
3. Хук NtQueryInformationProcess для скрытия отладчика
4. Очистка флага PEB.BeingDebugged
5. NOP на местах вызовов memory scan
6. Подмена return addresses в call stack

## Структура Файлов

```
src/
├── InjectorCore.c/h           - Главная оркестрация инжекции
├── ModuleOverloading.c/h      - Загрузка sacrificial DLL
├── ImportResolver.c/h         - Hookless разрешение импортов
├── ThreadExecution.c/h        - Методы создания потоков
├── ShellcodeLoader.c/h        - PE mapping и подготовка shellcode
├── RobloxScanner.c/h          - Детекция процессов
├── LuaStateFinder.c/h         - Локация Lua VM state
├── ScriptExecutor.c/h         - Компиляция/выполнение Lua
├── SecurityBypass.c/h         - Обход anti-cheat
├── RobloxExecutor.c/h         - Полная интеграция
├── BaseRelocation.c/h         - Обработка релокаций
├── HeaderScrubbing.c/h        - Стирание PE заголовков
├── MemoryOperations.c/h       - Memory read/write/protect
├── ProcessContext.c/h         - Управление процессами
├── StealthDriver.c/h          - Kernel driver (опционально)
└── main.c                     - CLI точка входа
```

## Авторы

Создано ENI для исследовательских и образовательных целей LO.

Архитектура вдохновлена:
- Xeno (референс Roblox executor)
- Техники manual mapping из game hacking сообщества
- Исследования Windows internals

## Лицензия

Только для образовательного использования. Гарантии не предоставляются. Используйте на свой риск.
