/*
 * Roblox Scanner
 *
 * Detects and attaches to Roblox processes.
 */

#include "RobloxScanner.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>
#include <tlhelp32.h>
#include <psapi.h>

NTSTATUS InitializeRobloxScanner(
    OUT PROBLOX_SCANNER_CONTEXT Context
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(ROBLOX_SCANNER_CONTEXT));
    Context->Tag = ROBLOX_SCANNER_TAG;
    Context->ProcessFound = FALSE;
    Context->ScanCount = 0;

    return STATUS_SUCCESS;
}

NTSTATUS ScanForRobloxProcess(
    IN PROBLOX_SCANNER_CONTEXT Context,
    OUT PROBLOX_PROCESS_INFO ProcessInfo
)
{
    NTSTATUS Status;

    if (Context == NULL || ProcessInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context->ScanCount++;
    Context->LastScanTime = KeQuerySystemTimePrecise();

    // Try RobloxPlayerBeta.exe first (most common)
    Status = FindRobloxProcessByName(ROBLOX_PLAYER_EXE, ProcessInfo);
    if (NT_SUCCESS(Status)) {
        ProcessInfo->VersionType = ROBLOX_VERSION_PLAYER;
        goto Found;
    }

    // Try RobloxStudioBeta.exe
    Status = FindRobloxProcessByName(ROBLOX_STUDIO_EXE, ProcessInfo);
    if (NT_SUCCESS(Status)) {
        ProcessInfo->VersionType = ROBLOX_VERSION_STUDIO;
        goto Found;
    }

    // Try UWP version
    Status = FindRobloxProcessByName(ROBLOX_APP_EXE, ProcessInfo);
    if (NT_SUCCESS(Status)) {
        ProcessInfo->VersionType = ROBLOX_VERSION_UWP;
        goto Found;
    }

    return STATUS_NOT_FOUND;

Found:
    RtlCopyMemory(&Context->ProcessInfo, ProcessInfo, sizeof(ROBLOX_PROCESS_INFO));
    Context->ProcessFound = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS FindRobloxProcessByName(
    IN PCWSTR ProcessName,
    OUT PROBLOX_PROCESS_INFO ProcessInfo
)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    BOOLEAN Found = FALSE;

    if (ProcessName == NULL || ProcessInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ProcessInfo, sizeof(ROBLOX_PROCESS_INFO));

    // Create process snapshot
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return STATUS_UNSUCCESSFUL;
    }

    // Walk processes
    do {
        if (_wcsicmp(pe32.szExeFile, ProcessName) == 0) {
            ProcessInfo->ProcessId = pe32.th32ProcessID;
            wcscpy_s(ProcessInfo->ProcessName, MAX_PATH, pe32.szExeFile);
            Found = TRUE;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (!Found) {
        return STATUS_NOT_FOUND;
    }

    // Open process handle
    ProcessInfo->ProcessHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        ProcessInfo->ProcessId
    );

    if (ProcessInfo->ProcessHandle == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    // Get module info
    NTSTATUS Status = GetRobloxModuleInfo(
        ProcessInfo->ProcessHandle,
        &ProcessInfo->BaseAddress,
        &ProcessInfo->ImageSize
    );

    if (NT_SUCCESS(Status)) {
        ProcessInfo->IsValid = TRUE;
    }

    return Status;
}

NTSTATUS AttachToRobloxProcess(
    IN PROBLOX_SCANNER_CONTEXT Context,
    IN ULONG ProcessId
)
{
    NTSTATUS Status;
    ROBLOX_PROCESS_INFO ProcessInfo;

    if (Context == NULL || ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&ProcessInfo, sizeof(ROBLOX_PROCESS_INFO));
    ProcessInfo.ProcessId = ProcessId;

    // Open process
    ProcessInfo.ProcessHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        ProcessId
    );

    if (ProcessInfo.ProcessHandle == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    // Get module info
    Status = GetRobloxModuleInfo(
        ProcessInfo.ProcessHandle,
        &ProcessInfo.BaseAddress,
        &ProcessInfo.ImageSize
    );

    if (!NT_SUCCESS(Status)) {
        CloseHandle(ProcessInfo.ProcessHandle);
        return Status;
    }

    // Validate it's actually Roblox
    Status = ValidateRobloxProcess(&ProcessInfo);
    if (!NT_SUCCESS(Status)) {
        CloseHandle(ProcessInfo.ProcessHandle);
        return Status;
    }

    ProcessInfo.IsValid = TRUE;
    RtlCopyMemory(&Context->ProcessInfo, &ProcessInfo, sizeof(ROBLOX_PROCESS_INFO));
    Context->ProcessFound = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS ValidateRobloxProcess(
    IN PROBLOX_PROCESS_INFO ProcessInfo
)
{
    WCHAR ModulePath[MAX_PATH];
    DWORD PathLength;

    if (ProcessInfo == NULL || ProcessInfo->ProcessHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get full module path
    PathLength = GetModuleFileNameExW(
        ProcessInfo->ProcessHandle,
        NULL,
        ModulePath,
        MAX_PATH
    );

    if (PathLength == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    // Check if path contains "Roblox"
    if (wcsstr(ModulePath, L"Roblox") == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Additional validation: check for Roblox-specific exports or patterns
    // This would involve reading PE headers and checking for known Roblox signatures

    return STATUS_SUCCESS;
}

NTSTATUS GetRobloxModuleInfo(
    IN HANDLE ProcessHandle,
    OUT PVOID* BaseAddress,
    OUT PSIZE_T ImageSize
)
{
    HMODULE hModules[1024];
    DWORD cbNeeded;
    MODULEINFO ModuleInfo;

    if (ProcessHandle == NULL || BaseAddress == NULL || ImageSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Enumerate modules
    if (!EnumProcessModules(ProcessHandle, hModules, sizeof(hModules), &cbNeeded)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Get info for main module (first in list)
    if (!GetModuleInformation(ProcessHandle, hModules[0], &ModuleInfo, sizeof(MODULEINFO))) {
        return STATUS_UNSUCCESSFUL;
    }

    *BaseAddress = ModuleInfo.lpBaseOfDll;
    *ImageSize = ModuleInfo.SizeOfImage;

    return STATUS_SUCCESS;
}

VOID CleanupRobloxScanner(
    IN PROBLOX_SCANNER_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    if (Context->ProcessInfo.ProcessHandle != NULL) {
        CloseHandle(Context->ProcessInfo.ProcessHandle);
    }

    RtlZeroMemory(Context, sizeof(ROBLOX_SCANNER_CONTEXT));
}
