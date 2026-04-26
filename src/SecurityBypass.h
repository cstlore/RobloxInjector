/*
 * Security Bypass - Header
 *
 * Anti-cheat evasion and detection bypass for Roblox Byfron/Hyperion.
 */

#ifndef _SECURITY_BYPASS_H
#define _SECURITY_BYPASS_H

#include <ntifs.h>

#define SECURITY_BYPASS_TAG 0x50594253  // "SBYP"

// Bypass flags
#define BYPASS_FLAG_HYPERION_DISABLED   0x00000001
#define BYPASS_FLAG_BYFRON_DISABLED     0x00000002
#define BYPASS_FLAG_INTEGRITY_BYPASSED  0x00000004
#define BYPASS_FLAG_DEBUGGER_HIDDEN     0x00000008
#define BYPASS_FLAG_MEMORY_PROTECTED    0x00000010

// Detection types
typedef enum _DETECTION_TYPE {
    DetectionTypeDebugger,
    DetectionTypeVirtualization,
    DetectionTypeIntegrityCheck,
    DetectionTypeMemoryScan,
    DetectionTypeThreadScan,
    DetectionTypeModuleCheck
} DETECTION_TYPE;

typedef struct _HYPERION_INFO {
    PVOID BaseAddress;
    SIZE_T ImageSize;
    PVOID IntegrityCheckFunction;
    PVOID MemoryScanFunction;
    BOOLEAN IsActive;
} HYPERION_INFO, *PHYPERION_INFO;

typedef struct _BYFRON_INFO {
    PVOID BaseAddress;
    SIZE_T ImageSize;
    PVOID HeartbeatFunction;
    PVOID ValidationFunction;
    BOOLEAN IsActive;
} BYFRON_INFO, *PBYFRON_INFO;

typedef struct _SECURITY_BYPASS_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    ULONG BypassFlags;

    // Anti-cheat info
    HYPERION_INFO Hyperion;
    BYFRON_INFO Byfron;

    // Bypass state
    PVOID OriginalNtQueryInformationProcess;
    PVOID OriginalNtSetInformationThread;
    PVOID HookedFunctions[32];
    ULONG HookCount;

    // Statistics
    ULONG DetectionsBlocked;
    ULONG IntegrityChecksBypassed;
    LARGE_INTEGER LastBypassTime;

    BOOLEAN Initialized;
} SECURITY_BYPASS_CONTEXT, *PSECURITY_BYPASS_CONTEXT;

NTSTATUS InitializeSecurityBypass(
    OUT PSECURITY_BYPASS_CONTEXT Context,
    IN HANDLE TargetProcess
);

NTSTATUS DetectAntiCheat(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ProcessBase,
    IN SIZE_T ProcessSize
);

NTSTATUS BypassHyperion(
    IN PSECURITY_BYPASS_CONTEXT Context
);

NTSTATUS BypassByfron(
    IN PSECURITY_BYPASS_CONTEXT Context
);

NTSTATUS DisableIntegrityChecks(
    IN PSECURITY_BYPASS_CONTEXT Context
);

NTSTATUS HideDebugger(
    IN PSECURITY_BYPASS_CONTEXT Context
);

NTSTATUS PatchMemoryScan(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ScanFunction
);

NTSTATUS HookAntiDebugFunctions(
    IN PSECURITY_BYPASS_CONTEXT Context
);

NTSTATUS SpoofCallStack(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ThreadHandle
);

VOID CleanupSecurityBypass(
    IN PSECURITY_BYPASS_CONTEXT Context
);

#endif // _SECURITY_BYPASS_H
