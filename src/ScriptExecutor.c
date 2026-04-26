/*
 * Script Executor
 *
 * Compiles and executes Lua scripts in Roblox Luau VM.
 */

#include "ScriptExecutor.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// Lua API function patterns (need updating per Roblox version)
static PATTERN_SIGNATURE LuaApiPatterns[] = {
    // lua_pcall pattern
    {
        .Pattern = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x57,
            0x48, 0x83, 0xEC, 0x20
        },
        .Mask = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF,
            0xFF, 0xFF, 0xFF, 0xFF
        },
        .Length = 15,
        .Offset = 0
    }
};

NTSTATUS InitializeScriptExecutor(
    OUT PSCRIPT_EXECUTOR_CONTEXT Context,
    IN HANDLE TargetProcess,
    IN PLUA_STATE_INFO LuaState
)
{
    if (Context == NULL || TargetProcess == NULL || LuaState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(SCRIPT_EXECUTOR_CONTEXT));
    Context->Tag = SCRIPT_EXECUTOR_TAG;
    Context->TargetProcess = TargetProcess;
    RtlCopyMemory(&Context->LuaState, LuaState, sizeof(LUA_STATE_INFO));
    Context->ExecutionFlags = EXEC_FLAG_YIELD_SAFE;
    Context->ScriptsExecuted = 0;
    Context->TotalErrors = 0;

    return STATUS_SUCCESS;
}

NTSTATUS ResolveLuaApiFunctions(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID RobloxBase,
    IN SIZE_T RobloxSize
)
{
    NTSTATUS Status;

    if (Context == NULL || RobloxBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Pattern scan for Lua API functions
    // In production, these would be resolved via signature scanning
    // For now, using placeholder offsets (need real analysis)

    // These offsets are EXAMPLES and need to be found via reverse engineering
    Context->LuaApi.lua_pcall = (PVOID)((PUCHAR)RobloxBase + 0x100000);
    Context->LuaApi.lua_tolstring = (PVOID)((PUCHAR)RobloxBase + 0x100100);
    Context->LuaApi.lua_settop = (PVOID)((PUCHAR)RobloxBase + 0x100200);
    Context->LuaApi.luau_compile = (PVOID)((PUCHAR)RobloxBase + 0x100300);
    Context->LuaApi.luau_load = (PVOID)((PUCHAR)RobloxBase + 0x100400);
    Context->LuaApi.lua_pushstring = (PVOID)((PUCHAR)RobloxBase + 0x100500);
    Context->LuaApi.lua_getfield = (PVOID)((PUCHAR)RobloxBase + 0x100600);
    Context->LuaApi.lua_setfield = (PVOID)((PUCHAR)RobloxBase + 0x100700);
    Context->LuaApi.lua_getglobal = (PVOID)((PUCHAR)RobloxBase + 0x100800);
    Context->LuaApi.lua_setglobal = (PVOID)((PUCHAR)RobloxBase + 0x100900);

    Context->Initialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS ExecuteScript(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PSCRIPT_EXECUTION_RESULT Result
)
{
    NTSTATUS Status;
    PVOID Bytecode = NULL;
    SIZE_T BytecodeSize = 0;

    if (Context == NULL || !Context->Initialized || ScriptSource == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(SCRIPT_EXECUTION_RESULT));
    Context->LastExecutionTime = KeQuerySystemTimePrecise();

    // Step 1: Compile script to bytecode
    Status = CompileLuaScript(
        Context,
        ScriptSource,
        SourceLength,
        &Bytecode,
        &BytecodeSize
    );

    if (!NT_SUCCESS(Status)) {
        Result->Status = Status;
        Result->Success = FALSE;
        Result->ErrorCode = 1;
        strcpy_s(Result->ErrorMessage, sizeof(Result->ErrorMessage), "Compilation failed");
        Context->TotalErrors++;
        return Status;
    }

    // Step 2: Execute bytecode
    Status = ExecuteBytecode(
        Context,
        Bytecode,
        BytecodeSize,
        Result
    );

    if (Bytecode != NULL) {
        VirtualFree(Bytecode, 0, MEM_RELEASE);
    }

    if (NT_SUCCESS(Status)) {
        Context->ScriptsExecuted++;
        Result->Success = TRUE;
    }
    else {
        Context->TotalErrors++;
    }

    Result->Status = Status;
    return Status;
}

NTSTATUS CompileLuaScript(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PVOID* Bytecode,
    OUT PSIZE_T BytecodeSize
)
{
    // This is a simplified stub - real implementation would:
    // 1. Allocate memory in target process for source
    // 2. Write source to target
    // 3. Call luau_compile via remote thread
    // 4. Read back bytecode

    if (Context == NULL || ScriptSource == NULL || Bytecode == NULL || BytecodeSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate local buffer for bytecode (placeholder)
    SIZE_T EstimatedSize = SourceLength * 2;
    PVOID LocalBytecode = VirtualAlloc(NULL, EstimatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (LocalBytecode == NULL) {
        return STATUS_NO_MEMORY;
    }

    // In real implementation:
    // - Write source to target process
    // - Execute luau_compile in target
    // - Read bytecode back
    // For now, just copy source as placeholder
    RtlCopyMemory(LocalBytecode, ScriptSource, SourceLength);

    *Bytecode = LocalBytecode;
    *BytecodeSize = SourceLength;

    return STATUS_SUCCESS;
}

NTSTATUS ExecuteBytecode(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID Bytecode,
    IN SIZE_T BytecodeSize,
    OUT PSCRIPT_EXECUTION_RESULT Result
)
{
    NTSTATUS Status;
    PVOID RemoteBytecode = NULL;
    SIZE_T BytesWritten;

    if (Context == NULL || Bytecode == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate memory in target process
    RemoteBytecode = VirtualAllocEx(
        Context->TargetProcess,
        NULL,
        BytecodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (RemoteBytecode == NULL) {
        return STATUS_NO_MEMORY;
    }

    // Write bytecode to target
    if (!WriteProcessMemory(
        Context->TargetProcess,
        RemoteBytecode,
        Bytecode,
        BytecodeSize,
        &BytesWritten
    )) {
        VirtualFreeEx(Context->TargetProcess, RemoteBytecode, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Real implementation would:
    // 1. Setup script environment (getgenv, getrenv, etc.)
    // 2. Elevate identity if needed
    // 3. Call luau_load with bytecode
    // 4. Call lua_pcall to execute
    // 5. Read return values and errors

    // For now, mark as success (stub)
    Result->Success = TRUE;
    Result->ErrorCode = 0;
    strcpy_s(Result->ErrorMessage, sizeof(Result->ErrorMessage), "Execution completed (stub)");

    VirtualFreeEx(Context->TargetProcess, RemoteBytecode, 0, MEM_RELEASE);

    return STATUS_SUCCESS;
}

NTSTATUS SetupScriptEnvironment(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID LuaState
)
{
    // Setup custom environment for script execution
    // This includes:
    // - getgenv() - get global environment
    // - getrenv() - get registry environment
    // - getrawmetatable() - get raw metatable
    // - setreadonly() - modify table readonly state
    // - Custom functions for Roblox API access

    if (Context == NULL || LuaState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Real implementation would inject custom C functions
    // into the Lua environment via lua_pushcclosure

    return STATUS_SUCCESS;
}

NTSTATUS ElevateScriptIdentity(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID LuaState,
    IN ULONG TargetIdentity
)
{
    // Roblox uses "identity" levels for security:
    // 0 = LocalScript (restricted)
    // 1-5 = Various privilege levels
    // 6 = CoreScript (full access)
    // 7 = Studio/Internal

    // This would modify the identity field in lua_State
    // Offset varies by Roblox version

    if (Context == NULL || LuaState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Placeholder - real implementation would:
    // 1. Find identity offset in lua_State
    // 2. Write new identity value
    // 3. Validate change

    Context->ExecutionFlags |= EXEC_FLAG_IDENTITY_ELEVATED;

    return STATUS_SUCCESS;
}

VOID CleanupScriptExecutor(
    IN PSCRIPT_EXECUTOR_CONTEXT Context
)
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(SCRIPT_EXECUTOR_CONTEXT));
    }
}
