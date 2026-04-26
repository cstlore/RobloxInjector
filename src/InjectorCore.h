/*
 * Injector Core - Main Integration Header
 *
 * Combines all Phase 1 components into working injector.
 */

#ifndef _INJECTOR_CORE_H
#define _INJECTOR_CORE_H

#include <ntifs.h>
#include "ModuleOverloading.h"
#include "ImportResolver.h"
#include "ThreadExecution.h"
#include "ShellcodeLoader.h"

#define INJECTOR_CORE_TAG 0x524F4A49  // "INJR"

typedef enum _INJECTION_METHOD {
    InjectionMethodModuleOverloading,
    InjectionMethodClassicDllInjection,
    InjectionMethodManualMap,
    InjectionMethodThreadHijack
} INJECTION_METHOD;

typedef struct _INJECTOR_CORE_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    ULONG TargetProcessId;
    INJECTION_METHOD Method;

    // Component contexts
    MODULE_OVERLOADING_CONTEXT ModuleOverloading;
    IMPORT_RESOLVER_CONTEXT ImportResolver;
    THREAD_EXECUTOR_CONTEXT ThreadExecutor;
    SHELLCODE_LOADER_CONTEXT ShellcodeLoader;

    // Injection state
    PVOID InjectedImageBase;
    SIZE_T InjectedImageSize;
    PVOID InjectedEntryPoint;
    HANDLE ExecutionThread;

    // Statistics
    ULONG TotalInjections;
    LARGE_INTEGER LastInjectionTime;
    NTSTATUS LastError;

    BOOLEAN Initialized;
} INJECTOR_CORE_CONTEXT, *PINJECTOR_CORE_CONTEXT;

// Core initialization
NTSTATUS InitializeInjectorCore(
    OUT PINJECTOR_CORE_CONTEXT Context,
    IN ULONG TargetProcessId,
    IN INJECTION_METHOD Method
);

// Main injection workflow
NTSTATUS InjectDll(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
);

NTSTATUS InjectShellcode(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL
);

// Module overloading injection (full stealth)
NTSTATUS InjectViaModuleOverloading(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
);

// Classic manual map injection
NTSTATUS InjectViaManualMap(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PHANDLE ThreadHandle OPTIONAL
);

// Wait for injection completion
NTSTATUS WaitForInjectionCompletion(
    IN PINJECTOR_CORE_CONTEXT Context,
    IN ULONG TimeoutMs,
    OUT PULONG ExitCode OPTIONAL
);

// Cleanup
VOID CleanupInjectorCore(
    IN PINJECTOR_CORE_CONTEXT Context
);

#endif // _INJECTOR_CORE_H
