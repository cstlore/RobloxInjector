/*
 * Roblox Executor - Main Integration Header
 *
 * Complete Roblox script executor combining all phases.
 */

#ifndef _ROBLOX_EXECUTOR_H
#define _ROBLOX_EXECUTOR_H

#include <ntifs.h>
#include "InjectorCore.h"
#include "RobloxScanner.h"
#include "LuaStateFinder.h"
#include "ScriptExecutor.h"
#include "SecurityBypass.h"

#define ROBLOX_EXECUTOR_TAG 0x58455242  // "RBEX"

typedef enum _EXECUTOR_STATE {
    ExecutorStateUninitialized,
    ExecutorStateScanning,
    ExecutorStateInjecting,
    ExecutorStateBypassingSecurity,
    ExecutorStateFindingLuaState,
    ExecutorStateReady,
    ExecutorStateExecuting,
    ExecutorStateError
} EXECUTOR_STATE;

typedef struct _ROBLOX_EXECUTOR_CONTEXT {
    ULONG Tag;
    EXECUTOR_STATE State;

    // Component contexts
    INJECTOR_CORE_CONTEXT Injector;
    ROBLOX_SCANNER_CONTEXT Scanner;
    LUA_STATE_FINDER_CONTEXT LuaFinder;
    SCRIPT_EXECUTOR_CONTEXT ScriptExecutor;
    SECURITY_BYPASS_CONTEXT SecurityBypass;

    // Execution state
    BOOLEAN Initialized;
    BOOLEAN SecurityBypassed;
    BOOLEAN LuaStateFound;
    BOOLEAN Ready;

    // Statistics
    ULONG TotalScriptsExecuted;
    ULONG TotalErrors;
    LARGE_INTEGER InitializationTime;
    LARGE_INTEGER LastExecutionTime;

    NTSTATUS LastError;
} ROBLOX_EXECUTOR_CONTEXT, *PROBLOX_EXECUTOR_CONTEXT;

// Main workflow
NTSTATUS InitializeRobloxExecutor(
    OUT PROBLOX_EXECUTOR_CONTEXT Context
);

NTSTATUS AttachToRoblox(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    IN ULONG ProcessId OPTIONAL
);

NTSTATUS PrepareExecution(
    IN PROBLOX_EXECUTOR_CONTEXT Context
);

NTSTATUS ExecuteRobloxScript(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PSCRIPT_EXECUTION_RESULT Result
);

// Utility functions
NTSTATUS GetExecutorStatus(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    OUT EXECUTOR_STATE* State,
    OUT PBOOLEAN Ready
);

VOID CleanupRobloxExecutor(
    IN PROBLOX_EXECUTOR_CONTEXT Context
);

#endif // _ROBLOX_EXECUTOR_H
