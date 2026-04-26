/*
 * Security Bypass
 *
 * Evasion techniques for Roblox anti-cheat (Byfron/Hyperion).
 */

#include "SecurityBypass.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// Known Hyperion patterns (update per version)
static PATTERN_SIGNATURE HyperionPatterns[] = {
    // Hyperion integrity check signature
    {
        .Pattern = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x6C, 0x24, 0x10,
            0x48, 0x89, 0x74, 0x24, 0x18,
            0x57,
            0x48, 0x83, 0xEC, 0x30
        },
        .Mask = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF,
            0xFF, 0xFF, 0xFF, 0xFF
        },
        .Length = 20,
        .Offset = 0
    }
};

NTSTATUS InitializeSecurityBypass(
    OUT PSECURITY_BYPASS_CONTEXT Context,
    IN HANDLE TargetProcess
)
{
    if (Context == NULL || TargetProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(SECURITY_BYPASS_CONTEXT));
    Context->Tag = SECURITY_BYPASS_TAG;
    Context->TargetProcess = TargetProcess;
    Context->BypassFlags = 0;
    Context->HookCount = 0;
    Context->DetectionsBlocked = 0;
    Context->IntegrityChecksBypassed = 0;

    return STATUS_SUCCESS;
}

NTSTATUS DetectAntiCheat(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ProcessBase,
    IN SIZE_T ProcessSize
)
{
    NTSTATUS Status;
    PVOID FoundAddress;

    if (Context == NULL || ProcessBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Scan for Hyperion
    for (ULONG i = 0; i < sizeof(HyperionPatterns) / sizeof(PATTERN_SIGNATURE); i++) {
        Status = PatternScan(
            Context->TargetProcess,
            ProcessBase,
            ProcessSize,
            &HyperionPatterns[i],
            &FoundAddress
        );

        if (NT_SUCCESS(Status)) {
            Context->Hyperion.BaseAddress = ProcessBase;
            Context->Hyperion.ImageSize = ProcessSize;
            Context->Hyperion.IntegrityCheckFunction = FoundAddress;
            Context->Hyperion.IsActive = TRUE;
            break;
        }
    }

    // Scan for Byfron (similar pattern scanning)
    // Byfron typically loads as separate module
    HMODULE Modules[1024];
    DWORD BytesNeeded;

    if (EnumProcessModules(Context->TargetProcess, Modules, sizeof(Modules), &BytesNeeded)) {
        DWORD ModuleCount = BytesNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < ModuleCount; i++) {
            WCHAR ModuleName[MAX_PATH];
            if (GetModuleFileNameExW(Context->TargetProcess, Modules[i], ModuleName, MAX_PATH)) {
                // Check for Byfron module name patterns
                if (wcsstr(ModuleName, L"byfron") != NULL ||
                    wcsstr(ModuleName, L"hyperion") != NULL) {

                    MODULEINFO ModInfo;
                    if (GetModuleInformation(Context->TargetProcess, Modules[i], &ModInfo, sizeof(MODULEINFO))) {
                        Context->Byfron.BaseAddress = ModInfo.lpBaseOfDll;
                        Context->Byfron.ImageSize = ModInfo.SizeOfImage;
                        Context->Byfron.IsActive = TRUE;
                    }
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS BypassHyperion(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    NTSTATUS Status;

    if (Context == NULL || !Context->Hyperion.IsActive) {
        return STATUS_INVALID_PARAMETER;
    }

    // Method 1: Patch integrity check function
    if (Context->Hyperion.IntegrityCheckFunction != NULL) {
        Status = PatchMemoryScan(Context, Context->Hyperion.IntegrityCheckFunction);
        if (NT_SUCCESS(Status)) {
            Context->IntegrityChecksBypassed++;
        }
    }

    // Method 2: Hook memory scan callbacks
    Status = HookAntiDebugFunctions(Context);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Context->BypassFlags |= BYPASS_FLAG_HYPERION_DISABLED;
    Context->LastBypassTime = KeQuerySystemTimePrecise();

    return STATUS_SUCCESS;
}

NTSTATUS BypassByfron(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    NTSTATUS Status;
    DWORD OldProtect;

    if (Context == NULL || !Context->Byfron.IsActive) {
        return STATUS_INVALID_PARAMETER;
    }

    // Method 1: Disable heartbeat function
    if (Context->Byfron.HeartbeatFunction != NULL) {
        // Patch with immediate return (0xC3)
        UCHAR ReturnOpcode = 0xC3;
        SIZE_T BytesWritten;

        if (!VirtualProtectEx(
            Context->TargetProcess,
            Context->Byfron.HeartbeatFunction,
            1,
            PAGE_EXECUTE_READWRITE,
            &OldProtect
        )) {
            return STATUS_UNSUCCESSFUL;
        }

        if (!WriteProcessMemory(
            Context->TargetProcess,
            Context->Byfron.HeartbeatFunction,
            &ReturnOpcode,
            1,
            &BytesWritten
        )) {
            VirtualProtectEx(Context->TargetProcess, Context->Byfron.HeartbeatFunction, 1, OldProtect, &OldProtect);
            return STATUS_UNSUCCESSFUL;
        }

        VirtualProtectEx(Context->TargetProcess, Context->Byfron.HeartbeatFunction, 1, OldProtect, &OldProtect);
    }

    // Method 2: Disable validation callbacks
    Status = DisableIntegrityChecks(Context);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Context->BypassFlags |= BYPASS_FLAG_BYFRON_DISABLED;
    Context->LastBypassTime = KeQuerySystemTimePrecise();

    return STATUS_SUCCESS;
}

NTSTATUS DisableIntegrityChecks(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    // Patch common integrity check patterns
    // These typically involve CRC checks, hash validation, or memory comparison

    UCHAR NopSled[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };  // NOP instructions
    SIZE_T BytesWritten;
    DWORD OldProtect;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Example: NOP out integrity check calls
    // In production, these addresses would be found via pattern scanning
    PVOID IntegrityCheckSites[] = {
        // Placeholder addresses - need real analysis
        NULL
    };

    for (ULONG i = 0; i < sizeof(IntegrityCheckSites) / sizeof(PVOID); i++) {
        if (IntegrityCheckSites[i] == NULL) continue;

        if (!VirtualProtectEx(
            Context->TargetProcess,
            IntegrityCheckSites[i],
            sizeof(NopSled),
            PAGE_EXECUTE_READWRITE,
            &OldProtect
        )) {
            continue;
        }

        WriteProcessMemory(
            Context->TargetProcess,
            IntegrityCheckSites[i],
            NopSled,
            sizeof(NopSled),
            &BytesWritten
        );

        VirtualProtectEx(Context->TargetProcess, IntegrityCheckSites[i], sizeof(NopSled), OldProtect, &OldProtect);
        Context->IntegrityChecksBypassed++;
    }

    Context->BypassFlags |= BYPASS_FLAG_INTEGRITY_BYPASSED;
    return STATUS_SUCCESS;
}

NTSTATUS HideDebugger(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    // Hide debugger presence from anti-debug checks
    // Common checks:
    // - IsDebuggerPresent()
    // - CheckRemoteDebuggerPresent()
    // - NtQueryInformationProcess(ProcessDebugPort)
    // - PEB.BeingDebugged flag

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Clear PEB.BeingDebugged flag
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ReturnLength;

    NTSTATUS Status = NtQueryInformationProcess(
        Context->TargetProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ReturnLength
    );

    if (NT_SUCCESS(Status)) {
        // Read PEB
        UCHAR PebBuffer[0x1000];
        SIZE_T BytesRead;

        if (ReadProcessMemory(
            Context->TargetProcess,
            pbi.PebBaseAddress,
            PebBuffer,
            sizeof(PebBuffer),
            &BytesRead
        )) {
            // Clear BeingDebugged flag (offset 0x02)
            PebBuffer[0x02] = 0;

            // Write back
            SIZE_T BytesWritten;
            WriteProcessMemory(
                Context->TargetProcess,
                (PUCHAR)pbi.PebBaseAddress + 0x02,
                &PebBuffer[0x02],
                1,
                &BytesWritten
            );
        }
    }

    Context->BypassFlags |= BYPASS_FLAG_DEBUGGER_HIDDEN;
    Context->DetectionsBlocked++;

    return STATUS_SUCCESS;
}

NTSTATUS PatchMemoryScan(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ScanFunction
)
{
    DWORD OldProtect;
    SIZE_T BytesWritten;

    if (Context == NULL || ScanFunction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Patch memory scan function to always return success
    // Common pattern: replace with "xor eax, eax; ret" (0x31 0xC0 0xC3)
    UCHAR PatchBytes[] = { 0x31, 0xC0, 0xC3 };

    if (!VirtualProtectEx(
        Context->TargetProcess,
        ScanFunction,
        sizeof(PatchBytes),
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    )) {
        return STATUS_UNSUCCESSFUL;
    }

    if (!WriteProcessMemory(
        Context->TargetProcess,
        ScanFunction,
        PatchBytes,
        sizeof(PatchBytes),
        &BytesWritten
    )) {
        VirtualProtectEx(Context->TargetProcess, ScanFunction, sizeof(PatchBytes), OldProtect, &OldProtect);
        return STATUS_UNSUCCESSFUL;
    }

    VirtualProtectEx(Context->TargetProcess, ScanFunction, sizeof(PatchBytes), OldProtect, &OldProtect);

    Context->DetectionsBlocked++;
    return STATUS_SUCCESS;
}

NTSTATUS HookAntiDebugFunctions(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    // Hook common anti-debug API functions
    // - NtQueryInformationProcess
    // - NtSetInformationThread (ThreadHideFromDebugger)
    // - NtClose (invalid handle exception)

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID NtdllBase = GetModuleHandleW(L"ntdll.dll");
    if (NtdllBase == NULL) {
        return STATUS_DLL_NOT_FOUND;
    }

    // Get function addresses
    PVOID NtQueryInformationProcess = GetProcAddress(NtdllBase, "NtQueryInformationProcess");
    PVOID NtSetInformationThread = GetProcAddress(NtdllBase, "NtSetInformationThread");

    if (NtQueryInformationProcess != NULL) {
        Context->OriginalNtQueryInformationProcess = NtQueryInformationProcess;
        // In production, install inline hook here
        Context->HookedFunctions[Context->HookCount++] = NtQueryInformationProcess;
    }

    if (NtSetInformationThread != NULL) {
        Context->OriginalNtSetInformationThread = NtSetInformationThread;
        // In production, install inline hook here
        Context->HookedFunctions[Context->HookCount++] = NtSetInformationThread;
    }

    return STATUS_SUCCESS;
}

NTSTATUS SpoofCallStack(
    IN PSECURITY_BYPASS_CONTEXT Context,
    IN PVOID ThreadHandle
)
{
    // Spoof call stack to hide injection traces
    // This involves modifying return addresses on the stack
    // to point to legitimate Roblox code

    if (Context == NULL || ThreadHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    CONTEXT ThreadContext;
    ThreadContext.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(ThreadHandle, &ThreadContext)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Read stack
    UCHAR StackBuffer[0x1000];
    SIZE_T BytesRead;

    if (!ReadProcessMemory(
        Context->TargetProcess,
        (PVOID)ThreadContext.Rsp,
        StackBuffer,
        sizeof(StackBuffer),
        &BytesRead
    )) {
        return STATUS_UNSUCCESSFUL;
    }

    // Scan for suspicious return addresses (outside Roblox modules)
    // Replace with legitimate Roblox addresses
    // This is highly version-specific and requires analysis

    return STATUS_SUCCESS;
}

VOID CleanupSecurityBypass(
    IN PSECURITY_BYPASS_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    // Restore hooked functions
    for (ULONG i = 0; i < Context->HookCount; i++) {
        // In production, unhook here
    }

    RtlZeroMemory(Context, sizeof(SECURITY_BYPASS_CONTEXT));
}
