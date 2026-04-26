/*
 * Lua State Finder
 *
 * Locates Roblox Luau VM state via pattern scanning and validation.
 */

#include "LuaStateFinder.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// Known Luau patterns (these need to be updated per Roblox version)
static PATTERN_SIGNATURE LuaStatePatterns[] = {
    // Pattern 1: lua_State allocation signature
    {
        .Pattern = {
            0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,  // mov rcx, [rip+offset]
            0x48, 0x85, 0xC9,                          // test rcx, rcx
            0x74, 0x00,                                // jz short
            0x48, 0x8B, 0x01                           // mov rax, [rcx]
        },
        .Mask = {
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF,
            0xFF, 0x00,
            0xFF, 0xFF, 0xFF
        },
        .Length = 15,
        .Offset = 3
    },

    // Pattern 2: lua_newstate call
    {
        .Pattern = {
            0x48, 0x89, 0x5C, 0x24, 0x08,              // mov [rsp+8], rbx
            0x57,                                       // push rdi
            0x48, 0x83, 0xEC, 0x20,                    // sub rsp, 20h
            0x48, 0x8B, 0xF9                           // mov rdi, rcx
        },
        .Mask = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF
        },
        .Length = 13,
        .Offset = 0
    },

    // Pattern 3: Global state reference
    {
        .Pattern = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, [rip+offset]
            0x48, 0x8B, 0x48, 0x28,                    // mov rcx, [rax+28h]
            0x48, 0x85, 0xC9                           // test rcx, rcx
        },
        .Mask = {
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF
        },
        .Length = 14,
        .Offset = 3
    }
};

NTSTATUS InitializeLuaStateFinder(
    OUT PLUA_STATE_FINDER_CONTEXT Context,
    IN HANDLE TargetProcess,
    IN PVOID ScanBase,
    IN SIZE_T ScanSize
)
{
    if (Context == NULL || TargetProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(LUA_STATE_FINDER_CONTEXT));
    Context->Tag = LUA_STATE_FINDER_TAG;
    Context->TargetProcess = TargetProcess;
    Context->ScanBase = ScanBase;
    Context->ScanSize = ScanSize;
    Context->StateCount = 0;

    return STATUS_SUCCESS;
}

NTSTATUS ScanForLuaState(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
)
{
    NTSTATUS Status;
    PVOID FoundAddress;
    ULONG PatternCount;

    if (Context == NULL || StateInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context->TotalScans++;
    Context->LastScanTime = KeQuerySystemTimePrecise();

    PatternCount = sizeof(LuaStatePatterns) / sizeof(PATTERN_SIGNATURE);

    // Try each pattern
    for (ULONG i = 0; i < PatternCount; i++) {
        Status = PatternScan(
            Context->TargetProcess,
            Context->ScanBase,
            Context->ScanSize,
            &LuaStatePatterns[i],
            &FoundAddress
        );

        if (NT_SUCCESS(Status)) {
            Context->PatternsMatched++;

            // Validate found address
            Status = ValidateLuaState(
                Context->TargetProcess,
                FoundAddress,
                StateInfo
            );

            if (NT_SUCCESS(Status)) {
                // Store in context
                if (Context->StateCount < 16) {
                    RtlCopyMemory(
                        &Context->States[Context->StateCount],
                        StateInfo,
                        sizeof(LUA_STATE_INFO)
                    );
                    Context->StateCount++;
                }
                return STATUS_SUCCESS;
            }
        }
    }

    // Try alternative methods
    Status = FindLuaStateViaRegistry(Context, StateInfo);
    if (NT_SUCCESS(Status)) {
        return Status;
    }

    Status = FindLuaStateViaGlobalState(Context, StateInfo);
    if (NT_SUCCESS(Status)) {
        return Status;
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS PatternScan(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize,
    IN PPATTERN_SIGNATURE Signature,
    OUT PVOID* FoundAddress
)
{
    PUCHAR Buffer;
    SIZE_T BytesRead;
    BOOLEAN Found = FALSE;

    if (ProcessHandle == NULL || BaseAddress == NULL || Signature == NULL || FoundAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate local buffer
    Buffer = (PUCHAR)VirtualAlloc(NULL, RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Buffer == NULL) {
        return STATUS_NO_MEMORY;
    }

    // Read target memory
    if (!ReadProcessMemory(ProcessHandle, BaseAddress, Buffer, RegionSize, &BytesRead)) {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Scan for pattern
    for (SIZE_T i = 0; i < BytesRead - Signature->Length; i++) {
        BOOLEAN Match = TRUE;

        for (ULONG j = 0; j < Signature->Length; j++) {
            if (Signature->Mask[j] == 0xFF) {
                if (Buffer[i + j] != Signature->Pattern[j]) {
                    Match = FALSE;
                    break;
                }
            }
        }

        if (Match) {
            // Calculate actual address with offset
            PVOID PatternAddress = (PUCHAR)BaseAddress + i;

            if (Signature->Offset != 0) {
                // Read RIP-relative offset
                LONG RelativeOffset;
                RtlCopyMemory(&RelativeOffset, &Buffer[i + Signature->Offset], sizeof(LONG));

                // Calculate absolute address
                *FoundAddress = (PUCHAR)PatternAddress + Signature->Offset + sizeof(LONG) + RelativeOffset;
            }
            else {
                *FoundAddress = PatternAddress;
            }

            Found = TRUE;
            break;
        }
    }

    VirtualFree(Buffer, 0, MEM_RELEASE);

    return Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS ValidateLuaState(
    IN HANDLE ProcessHandle,
    IN PVOID StateAddress,
    OUT PLUA_STATE_INFO StateInfo
)
{
    NTSTATUS Status;
    UCHAR Buffer[256];
    SIZE_T BytesRead;

    if (ProcessHandle == NULL || StateAddress == NULL || StateInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(StateInfo, sizeof(LUA_STATE_INFO));

    // Read potential lua_State structure
    if (!ReadProcessMemory(ProcessHandle, StateAddress, Buffer, sizeof(Buffer), &BytesRead)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Validate structure (Luau-specific checks)
    PVOID* Top = (PVOID*)&Buffer[LUA_STATE_TOP_OFFSET];
    PVOID* Base = (PVOID*)&Buffer[LUA_STATE_BASE_OFFSET];
    PVOID* Global = (PVOID*)&Buffer[LUA_STATE_GLOBAL_OFFSET];

    // Basic sanity checks
    if (*Top == NULL || *Base == NULL || *Global == NULL) {
        return STATUS_INVALID_ADDRESS;
    }

    // Top should be >= Base
    if ((ULONG_PTR)*Top < (ULONG_PTR)*Base) {
        return STATUS_INVALID_ADDRESS;
    }

    // Read full state info
    Status = ReadLuaStateStructure(ProcessHandle, StateAddress, StateInfo);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    StateInfo->StateAddress = StateAddress;
    StateInfo->IsValid = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS ReadLuaStateStructure(
    IN HANDLE ProcessHandle,
    IN PVOID StateAddress,
    OUT PLUA_STATE_INFO StateInfo
)
{
    UCHAR Buffer[256];
    SIZE_T BytesRead;

    if (!ReadProcessMemory(ProcessHandle, StateAddress, Buffer, sizeof(Buffer), &BytesRead)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Extract key pointers
    StateInfo->GlobalState = *(PVOID*)&Buffer[LUA_STATE_GLOBAL_OFFSET];

    // Read registry from global state
    if (StateInfo->GlobalState != NULL) {
        UCHAR GlobalBuffer[128];
        if (ReadProcessMemory(ProcessHandle, StateInfo->GlobalState, GlobalBuffer, sizeof(GlobalBuffer), &BytesRead)) {
            StateInfo->Registry = *(PVOID*)&GlobalBuffer[0x08];  // Registry offset in global_State
        }
    }

    // Detect Luau version (simplified)
    StateInfo->Version = 0x0500;  // Assume Luau 0.5

    return STATUS_SUCCESS;
}

NTSTATUS FindLuaStateViaRegistry(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
)
{
    // Alternative method: scan for registry table signature
    // Registry is a special table with known structure

    PATTERN_SIGNATURE RegistryPattern = {
        .Pattern = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // NULL padding
            0x00, 0x00, 0x00, 0x00,                          // Table type marker
            0x00, 0x00, 0x00, 0x00                           // Size fields
        },
        .Mask = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        },
        .Length = 16,
        .Offset = 0
    };

    PVOID FoundAddress;
    NTSTATUS Status = PatternScan(
        Context->TargetProcess,
        Context->ScanBase,
        Context->ScanSize,
        &RegistryPattern,
        &FoundAddress
    );

    if (NT_SUCCESS(Status)) {
        // Work backwards to find lua_State
        // This is heuristic-based and may need adjustment
        return ValidateLuaState(Context->TargetProcess, FoundAddress, StateInfo);
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS FindLuaStateViaGlobalState(
    IN PLUA_STATE_FINDER_CONTEXT Context,
    OUT PLUA_STATE_INFO StateInfo
)
{
    // Alternative method: scan for global_State signature
    // global_State has distinctive structure with mainthread pointer

    PATTERN_SIGNATURE GlobalStatePattern = {
        .Pattern = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mainthread
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // registry
            0x00, 0x00, 0x00, 0x00                           // GC state
        },
        .Mask = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00
        },
        .Length = 20,
        .Offset = 0
    };

    PVOID FoundAddress;
    NTSTATUS Status = PatternScan(
        Context->TargetProcess,
        Context->ScanBase,
        Context->ScanSize,
        &GlobalStatePattern,
        &FoundAddress
    );

    if (NT_SUCCESS(Status)) {
        // Read mainthread pointer from global_State
        PVOID MainThread;
        SIZE_T BytesRead;

        if (ReadProcessMemory(Context->TargetProcess, FoundAddress, &MainThread, sizeof(PVOID), &BytesRead)) {
            return ValidateLuaState(Context->TargetProcess, MainThread, StateInfo);
        }
    }

    return STATUS_NOT_FOUND;
}

VOID CleanupLuaStateFinder(
    IN PLUA_STATE_FINDER_CONTEXT Context
)
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(LUA_STATE_FINDER_CONTEXT));
    }
}
