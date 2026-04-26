/*
 * Roblox Executor - Complete Integration
 *
 * Full workflow: Scan → Inject → Bypass → Find Lua → Execute
 */

#include "RobloxExecutor.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

NTSTATUS InitializeRobloxExecutor(
    OUT PROBLOX_EXECUTOR_CONTEXT Context
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(ROBLOX_EXECUTOR_CONTEXT));
    Context->Tag = ROBLOX_EXECUTOR_TAG;
    Context->State = ExecutorStateUninitialized;
    Context->Initialized = FALSE;
    Context->SecurityBypassed = FALSE;
    Context->LuaStateFound = FALSE;
    Context->Ready = FALSE;
    Context->TotalScriptsExecuted = 0;
    Context->TotalErrors = 0;

    Context->InitializationTime = KeQuerySystemTimePrecise();

    return STATUS_SUCCESS;
}

NTSTATUS AttachToRoblox(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    IN ULONG ProcessId OPTIONAL
)
{
    NTSTATUS Status;
    ROBLOX_PROCESS_INFO ProcessInfo;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context->State = ExecutorStateScanning;

    // Step 1: Find or attach to Roblox process
    Status = InitializeRobloxScanner(&Context->Scanner);
    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    if (ProcessId != 0) {
        // Attach to specific process
        Status = AttachToRobloxProcess(&Context->Scanner, ProcessId);
    }
    else {
        // Scan for any Roblox process
        Status = ScanForRobloxProcess(&Context->Scanner, &ProcessInfo);
    }

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    // Step 2: Initialize injector
    Context->State = ExecutorStateInjecting;

    Status = InitializeInjectorCore(
        &Context->Injector,
        Context->Scanner.ProcessInfo.ProcessId,
        InjectionMethodModuleOverloading
    );

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    // Step 3: Bypass security
    Context->State = ExecutorStateBypassingSecurity;

    Status = InitializeSecurityBypass(
        &Context->SecurityBypass,
        Context->Scanner.ProcessInfo.ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    // Detect anti-cheat
    Status = DetectAntiCheat(
        &Context->SecurityBypass,
        Context->Scanner.ProcessInfo.BaseAddress,
        Context->Scanner.ProcessInfo.ImageSize
    );

    if (NT_SUCCESS(Status)) {
        // Bypass Hyperion if detected
        if (Context->SecurityBypass.Hyperion.IsActive) {
            BypassHyperion(&Context->SecurityBypass);
        }

        // Bypass Byfron if detected
        if (Context->SecurityBypass.Byfron.IsActive) {
            BypassByfron(&Context->SecurityBypass);
        }

        // Hide debugger presence
        HideDebugger(&Context->SecurityBypass);

        Context->SecurityBypassed = TRUE;
    }

    // Step 4: Find Lua state
    Context->State = ExecutorStateFindingLuaState;

    Status = InitializeLuaStateFinder(
        &Context->LuaFinder,
        Context->Scanner.ProcessInfo.ProcessHandle,
        Context->Scanner.ProcessInfo.BaseAddress,
        Context->Scanner.ProcessInfo.ImageSize
    );

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    LUA_STATE_INFO LuaState;
    Status = ScanForLuaState(&Context->LuaFinder, &LuaState);

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    Context->LuaStateFound = TRUE;

    // Step 5: Initialize script executor
    Status = InitializeScriptExecutor(
        &Context->ScriptExecutor,
        Context->Scanner.ProcessInfo.ProcessHandle,
        &LuaState
    );

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    // Resolve Lua API functions
    Status = ResolveLuaApiFunctions(
        &Context->ScriptExecutor,
        Context->Scanner.ProcessInfo.BaseAddress,
        Context->Scanner.ProcessInfo.ImageSize
    );

    if (!NT_SUCCESS(Status)) {
        Context->State = ExecutorStateError;
        Context->LastError = Status;
        return Status;
    }

    Context->State = ExecutorStateReady;
    Context->Ready = TRUE;
    Context->Initialized = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS PrepareExecution(
    IN PROBLOX_EXECUTOR_CONTEXT Context
)
{
    NTSTATUS Status;

    if (Context == NULL || !Context->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Setup script environment
    Status = SetupScriptEnvironment(
        &Context->ScriptExecutor,
        Context->ScriptExecutor.LuaState.StateAddress
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Elevate identity to level 6 (CoreScript)
    Status = ElevateScriptIdentity(
        &Context->ScriptExecutor,
        Context->ScriptExecutor.LuaState.StateAddress,
        6
    );

    return Status;
}

NTSTATUS ExecuteRobloxScript(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PSCRIPT_EXECUTION_RESULT Result
)
{
    NTSTATUS Status;

    if (Context == NULL || !Context->Ready || ScriptSource == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context->State = ExecutorStateExecuting;
    Context->LastExecutionTime = KeQuerySystemTimePrecise();

    // Execute script
    Status = ExecuteScript(
        &Context->ScriptExecutor,
        ScriptSource,
        SourceLength,
        Result
    );

    if (NT_SUCCESS(Status)) {
        Context->TotalScriptsExecuted++;
        Context->State = ExecutorStateReady;
    }
    else {
        Context->TotalErrors++;
        Context->State = ExecutorStateError;
        Context->LastError = Status;
    }

    return Status;
}

NTSTATUS GetExecutorStatus(
    IN PROBLOX_EXECUTOR_CONTEXT Context,
    OUT EXECUTOR_STATE* State,
    OUT PBOOLEAN Ready
)
{
    if (Context == NULL || State == NULL || Ready == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = Context->State;
    *Ready = Context->Ready;

    return STATUS_SUCCESS;
}

VOID CleanupRobloxExecutor(
    IN PROBLOX_EXECUTOR_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    CleanupScriptExecutor(&Context->ScriptExecutor);
    CleanupLuaStateFinder(&Context->LuaFinder);
    CleanupSecurityBypass(&Context->SecurityBypass);
    CleanupInjectorCore(&Context->Injector);
    CleanupRobloxScanner(&Context->Scanner);

    RtlZeroMemory(Context, sizeof(ROBLOX_EXECUTOR_CONTEXT));
}
