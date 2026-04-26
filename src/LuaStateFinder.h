/*
 * Lua State Finder - Header
 *
 * Pattern scanning to locate Roblox Lua VM state.
 */

#ifndef _LUA_STATE_FINDER_H
#define _LUA_STATE_FINDER_H

#include <ntifs.h>

#define LUA_STATE_FINDER_TAG 0x4154534C  // "LSTA"

// Lua state structure offsets (Luau-specific)
#define LUA_STATE_TOP_OFFSET        0x10
#define LUA_STATE_BASE_OFFSET       0x18
#define LUA_STATE_GLOBAL_OFFSET     0x28
#define LUA_STATE_CI_OFFSET         0x30

// Pattern scan flags
#define SCAN_FLAG_EXECUTABLE        0x00000001
#define SCAN_FLAG_READABLE          0x00000002
#define SCAN_FLAG_WRITABLE          0x00000004

typedef struct _PATTERN_SIGNATURE {
    UCHAR Pattern[64];
    UCHAR Mask[64];
    ULONG Length;
    LONG Offset;  // Offset from pattern match to actual address
} PATTERN_SIGNATURE, *PPATTERN_SIGNATURE;

typedef struct _LUA_STATE_INFO {
    PVOID StateAddress;
    PVOID GlobalState;
    PVOID Registry;
    BOOLEAN IsValid;
    ULONG Version;  // Luau version detection
} LUA_STATE_INFO, *PLUA_STATE_INFO;

typedef struct _LUA_STATE_FINDER_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    PVOID ScanBase;
    SIZE_T ScanSize;

    // Found states
    LUA_STATE_INFO States[16];
    ULONG StateCount;

    // Statistics
    ULONG TotalScans;
    ULONG PatternsMatched;
    LARGE_INTEGER LastScanTime;
} LUA_STATE_FINDER_CONTEXT, *PLUA_STATE_FINDER_CONTEXT;

NTSTATUS InitializeLuaStateFinder(
    OUT PLUA_STATE_FINDER_CONTEXT Context,
    IN HANDLE TargetProcess,
    IN PVOID ScanBase,
    IN SIZE_T ScanSize
);

NTSTATUS ScanForLuaState(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
);

NTSTATUS PatternScan(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize,
    IN PPATTERN_SIGNATURE Signature,
    OUT PVOID* FoundAddress
);

NTSTATUS ValidateLuaState(
    IN HANDLE ProcessHandle,
    IN PVOID StateAddress,
    OUT PLUA_STATE_INFO StateInfo
);

NTSTATUS ReadLuaStateStructure(
    IN HANDLE ProcessHandle,
    IN PVOID StateAddress,
    OUT PLUA_STATE_INFO StateInfo
);

NTSTATUS FindLuaStateViaRegistry(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
);

NTSTATUS FindLuaStateViaGlobalState(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
);

VOID CleanupLuaStateFinder(
    IN PLUA_STATE_FINDER_CONTEXT Context
);

#endif // _LUA_STATE_FINDER_H
