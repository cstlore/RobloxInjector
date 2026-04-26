/*
 * Thread Execution Engine - Header
 */

#ifndef _THREAD_EXECUTION_H
#define _THREAD_EXECUTION_H

#include <ntifs.h>

#define THREAD_EXECUTOR_TAG 0x44524854  // "THRD"

typedef enum _THREAD_EXECUTION_METHOD {
    ThreadExecutionMethodCreateRemote,
    ThreadExecutionMethodNtCreateThreadEx,
    ThreadExecutionMethodRtlCreateUserThread,
    ThreadExecutionMethodQueueApc,
    ThreadExecutionMethodHijack
} THREAD_EXECUTION_METHOD;

typedef struct _THREAD_EXECUTOR_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    THREAD_EXECUTION_METHOD ExecutionMethod;
    BOOLEAN Initialized;

    // NT API function pointers
    PVOID NtCreateThreadEx;
    PVOID NtQueueApcThread;
    PVOID RtlCreateUserThread;

    // Statistics
    ULONG ExecutionCount;
    LARGE_INTEGER LastExecutionTime;
} THREAD_EXECUTOR_CONTEXT, *PTHREAD_EXECUTOR_CONTEXT;

NTSTATUS InitializeThreadExecutor(
    OUT PTHREAD_EXECUTOR_CONTEXT Context,
    IN HANDLE TargetProcess
);

NTSTATUS ExecutePayloadViaThread(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
);

NTSTATUS CreateRemoteThreadExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
);

NTSTATUS NtCreateThreadExExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
);

NTSTATUS RtlCreateUserThreadExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
);

NTSTATUS QueueApcExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter
);

NTSTATUS ThreadHijackExecution(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID PayloadAddress,
    IN PVOID PayloadParameter,
    OUT PHANDLE ThreadHandle
);

NTSTATUS FindAlertableThread(
    IN HANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle
);

NTSTATUS FindHijackableThread(
    IN HANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle
);

NTSTATUS ExecuteShellcode(
    IN PTHREAD_EXECUTOR_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
);

NTSTATUS WaitForThreadCompletion(
    IN HANDLE ThreadHandle,
    IN ULONG TimeoutMs,
    OUT PULONG ExitCode OPTIONAL
);

VOID CleanupThreadExecutor(
    IN PTHREAD_EXECUTOR_CONTEXT Context);

#endif // _THREAD_EXECUTION_H
