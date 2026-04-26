/*
 * Roblox Scanner - Header
 *
 * Process detection and attachment for Roblox client.
 */

#ifndef _ROBLOX_SCANNER_H
#define _ROBLOX_SCANNER_H

#include <ntifs.h>

#define ROBLOX_SCANNER_TAG 0x584C4252  // "RBLX"

// Known Roblox process names
#define ROBLOX_PLAYER_EXE       L"RobloxPlayerBeta.exe"
#define ROBLOX_STUDIO_EXE       L"RobloxStudioBeta.exe"
#define ROBLOX_APP_EXE          L"Windows10Universal.exe"

// Roblox version detection
#define ROBLOX_VERSION_UNKNOWN  0
#define ROBLOX_VERSION_PLAYER   1
#define ROBLOX_VERSION_STUDIO   2
#define ROBLOX_VERSION_UWP      3

typedef struct _ROBLOX_PROCESS_INFO {
    ULONG ProcessId;
    HANDLE ProcessHandle;
    WCHAR ProcessName[MAX_PATH];
    PVOID BaseAddress;
    SIZE_T ImageSize;
    ULONG VersionType;
    BOOLEAN IsValid;
} ROBLOX_PROCESS_INFO, *PROBLOX_PROCESS_INFO;

typedef struct _ROBLOX_SCANNER_CONTEXT {
    ULONG Tag;
    ROBLOX_PROCESS_INFO ProcessInfo;
    ULONG ScanCount;
    LARGE_INTEGER LastScanTime;
    BOOLEAN ProcessFound;
} ROBLOX_SCANNER_CONTEXT, *PROBLOX_SCANNER_CONTEXT;

NTSTATUS InitializeRobloxScanner(
    OUT PROBLOX_SCANNER_CONTEXT Context
);

NTSTATUS ScanForRobloxProcess(
    IN PROBLOX_SCANNER_CONTEXT Context,
    OUT PROBLOX_PROCESS_INFO ProcessInfo
);

NTSTATUS FindRobloxProcessByName(
    IN PCWSTR ProcessName,
    OUT PROBLOX_PROCESS_INFO ProcessInfo
);

NTSTATUS AttachToRobloxProcess(
    IN PROBLOX_SCANNER_CONTEXT Context,
    IN ULONG ProcessId
);

NTSTATUS ValidateRobloxProcess(
    IN PROBLOX_PROCESS_INFO ProcessInfo
);

NTSTATUS GetRobloxModuleInfo(
    IN HANDLE ProcessHandle,
    OUT PVOID* BaseAddress,
    OUT PSIZE_T ImageSize
);

VOID CleanupRobloxScanner(
    IN PROBLOX_SCANNER_CONTEXT Context
);

#endif // _ROBLOX_SCANNER_H
