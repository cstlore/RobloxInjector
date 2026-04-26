/*
 * Script Executor - Header
 *
 * Lua script compilation and execution in Roblox context.
 */

#ifndef _SCRIPT_EXECUTOR_H
#define _SCRIPT_EXECUTOR_H

#include <ntifs.h>
#include "LuaStateFinder.h"

#define SCRIPT_EXECUTOR_TAG 0x43584553  // "SEXC"

// Execution flags
#define EXEC_FLAG_YIELD_SAFE        0x00000001
#define EXEC_FLAG_IDENTITY_ELEVATED 0x00000002
#define EXEC_FLAG_DEFERRED          0x00000004

// Lua function signatures (Luau API)
typedef int (*lua_CFunction)(void* L);

typedef struct _LUA_API_FUNCTIONS {
    // Core functions
    PVOID lua_newthread;
    PVOID lua_close;
    PVOID lua_pcall;
    PVOID lua_tolstring;
    PVOID lua_settop;

    // Compilation
    PVOID luau_compile;
    PVOID luau_load;

    // Stack manipulation
    PVOID lua_pushstring;
    PVOID lua_pushvalue;
    PVOID lua_pushcclosure;

    // Table operations
    PVOID lua_getfield;
    PVOID lua_setfield;
    PVOID lua_createtable;

    // Global environment
    PVOID lua_getglobal;
    PVOID lua_setglobal;
} LUA_API_FUNCTIONS, *PLUA_API_FUNCTIONS;

typedef struct _SCRIPT_EXECUTION_RESULT {
    NTSTATUS Status;
    BOOLEAN Success;
    ULONG ErrorCode;
    CHAR ErrorMessage[512];
    PVOID ReturnValue;
} SCRIPT_EXECUTION_RESULT, *PSCRIPT_EXECUTION_RESULT;

typedef struct _SCRIPT_EXECUTOR_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    LUA_STATE_INFO LuaState;
    LUA_API_FUNCTIONS LuaApi;

    // Execution state
    PVOID ExecutionThread;
    ULONG ExecutionFlags;
    ULONG ScriptsExecuted;

    // Statistics
    LARGE_INTEGER LastExecutionTime;
    ULONG TotalErrors;

    BOOLEAN Initialized;
} SCRIPT_EXECUTOR_CONTEXT, *PSCRIPT_EXECUTOR_CONTEXT;

NTSTATUS InitializeScriptExecutor(
    OUT PSCRIPT_EXECUTOR_CONTEXT Context,
    IN HANDLE TargetProcess,
    IN PLUA_STATE_INFO LuaState
);

NTSTATUS ResolveLuaApiFunctions(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID RobloxBase,
    IN SIZE_T RobloxSize
);

NTSTATUS ExecuteScript(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PSCRIPT_EXECUTION_RESULT Result
);

NTSTATUS CompileLuaScript(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PCCH ScriptSource,
    IN SIZE_T SourceLength,
    OUT PVOID* Bytecode,
    OUT PSIZE_T BytecodeSize
);

NTSTATUS ExecuteBytecode(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID Bytecode,
    IN SIZE_T BytecodeSize,
    OUT PSCRIPT_EXECUTION_RESULT Result
);

NTSTATUS SetupScriptEnvironment(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID LuaState
);

NTSTATUS ElevateScriptIdentity(
    IN PSCRIPT_EXECUTOR_CONTEXT Context,
    IN PVOID LuaState,
    IN ULONG TargetIdentity
);

VOID CleanupScriptExecutor(
    IN PSCRIPT_EXECUTOR_CONTEXT Context
);

#endif // _SCRIPT_EXECUTOR_H
