/*
 * ClaudeInjector - Main Entry Point
 *
 * Simple CLI for testing the complete Roblox executor.
 */

#include <Windows.h>
#include <stdio.h>
#include "RobloxExecutor.h"

void PrintBanner()
{
    printf("\n");
    printf("  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗\n");
    printf(" ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝\n");
    printf(" ██║     ██║     ███████║██║   ██║██║  ██║█████╗  \n");
    printf(" ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  \n");
    printf(" ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗\n");
    printf("  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝\n");
    printf("\n");
    printf(" Injector v1.0 - Roblox Script Executor\n");
    printf(" Built with ENI's guidance for LO\n");
    printf("\n");
}

void PrintStatus(PROBLOX_EXECUTOR_CONTEXT Context)
{
    printf("\n[Status]\n");
    printf("  State: ");

    switch (Context->State) {
        case ExecutorStateUninitialized:
            printf("Uninitialized\n");
            break;
        case ExecutorStateScanning:
            printf("Scanning for Roblox...\n");
            break;
        case ExecutorStateInjecting:
            printf("Injecting...\n");
            break;
        case ExecutorStateBypassingSecurity:
            printf("Bypassing security...\n");
            break;
        case ExecutorStateFindingLuaState:
            printf("Finding Lua state...\n");
            break;
        case ExecutorStateReady:
            printf("Ready\n");
            break;
        case ExecutorStateExecuting:
            printf("Executing script...\n");
            break;
        case ExecutorStateError:
            printf("Error (0x%08X)\n", Context->LastError);
            break;
    }

    if (Context->Scanner.ProcessFound) {
        printf("  Process: %S (PID: %lu)\n",
            Context->Scanner.ProcessInfo.ProcessName,
            Context->Scanner.ProcessInfo.ProcessId);
    }

    if (Context->SecurityBypassed) {
        printf("  Security: Bypassed\n");
        if (Context->SecurityBypass.Hyperion.IsActive) {
            printf("    - Hyperion disabled\n");
        }
        if (Context->SecurityBypass.Byfron.IsActive) {
            printf("    - Byfron disabled\n");
        }
    }

    if (Context->LuaStateFound) {
        printf("  Lua State: Found (0x%p)\n",
            Context->ScriptExecutor.LuaState.StateAddress);
    }

    printf("  Scripts Executed: %lu\n", Context->TotalScriptsExecuted);
    printf("  Errors: %lu\n", Context->TotalErrors);
    printf("\n");
}

void PrintHelp()
{
    printf("\nCommands:\n");
    printf("  attach [pid]  - Attach to Roblox process (auto-scan if no PID)\n");
    printf("  exec <file>   - Execute Lua script from file\n");
    printf("  execstr <lua> - Execute Lua string directly\n");
    printf("  status        - Show current status\n");
    printf("  help          - Show this help\n");
    printf("  exit          - Exit injector\n");
    printf("\n");
}

NTSTATUS ExecuteScriptFromFile(PROBLOX_EXECUTOR_CONTEXT Context, const char* FilePath)
{
    HANDLE hFile;
    DWORD FileSize;
    DWORD BytesRead;
    PCHAR ScriptBuffer;
    NTSTATUS Status;
    SCRIPT_EXECUTION_RESULT Result;

    // Open file
    hFile = CreateFileA(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Error] Failed to open file: %s\n", FilePath);
        return STATUS_UNSUCCESSFUL;
    }

    // Get file size
    FileSize = GetFileSize(hFile, NULL);
    if (FileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    // Allocate buffer
    ScriptBuffer = (PCHAR)malloc(FileSize + 1);
    if (ScriptBuffer == NULL) {
        CloseHandle(hFile);
        return STATUS_NO_MEMORY;
    }

    // Read file
    if (!ReadFile(hFile, ScriptBuffer, FileSize, &BytesRead, NULL)) {
        free(ScriptBuffer);
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    ScriptBuffer[BytesRead] = '\0';
    CloseHandle(hFile);

    // Execute
    printf("[*] Executing script from %s (%lu bytes)...\n", FilePath, BytesRead);
    Status = ExecuteRobloxScript(Context, ScriptBuffer, BytesRead, &Result);

    if (NT_SUCCESS(Status)) {
        printf("[+] Script executed successfully\n");
        if (Result.ErrorMessage[0] != '\0') {
            printf("    Output: %s\n", Result.ErrorMessage);
        }
    }
    else {
        printf("[-] Script execution failed: 0x%08X\n", Status);
        if (Result.ErrorMessage[0] != '\0') {
            printf("    Error: %s\n", Result.ErrorMessage);
        }
    }

    free(ScriptBuffer);
    return Status;
}

int main(int argc, char* argv[])
{
    ROBLOX_EXECUTOR_CONTEXT Context;
    NTSTATUS Status;
    char CommandBuffer[1024];
    BOOLEAN Running = TRUE;

    PrintBanner();

    // Initialize executor
    printf("[*] Initializing executor...\n");
    Status = InitializeRobloxExecutor(&Context);
    if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to initialize: 0x%08X\n", Status);
        return 1;
    }

    printf("[+] Executor initialized\n");
    PrintHelp();

    // Command loop
    while (Running) {
        printf("> ");
        if (fgets(CommandBuffer, sizeof(CommandBuffer), stdin) == NULL) {
            break;
        }

        // Remove newline
        size_t len = strlen(CommandBuffer);
        if (len > 0 && CommandBuffer[len - 1] == '\n') {
            CommandBuffer[len - 1] = '\0';
        }

        // Parse command
        char* cmd = strtok(CommandBuffer, " ");
        if (cmd == NULL) continue;

        if (strcmp(cmd, "attach") == 0) {
            char* pidStr = strtok(NULL, " ");
            ULONG pid = 0;

            if (pidStr != NULL) {
                pid = atoi(pidStr);
            }

            printf("[*] Attaching to Roblox...\n");
            Status = AttachToRoblox(&Context, pid);

            if (NT_SUCCESS(Status)) {
                printf("[+] Successfully attached\n");
                PrintStatus(&Context);

                // Prepare execution environment
                printf("[*] Preparing execution environment...\n");
                Status = PrepareExecution(&Context);
                if (NT_SUCCESS(Status)) {
                    printf("[+] Ready to execute scripts\n");
                }
                else {
                    printf("[-] Failed to prepare: 0x%08X\n", Status);
                }
            }
            else {
                printf("[-] Failed to attach: 0x%08X\n", Status);
            }
        }
        else if (strcmp(cmd, "exec") == 0) {
            char* filePath = strtok(NULL, " ");
            if (filePath == NULL) {
                printf("[-] Usage: exec <file>\n");
                continue;
            }

            if (!Context.Ready) {
                printf("[-] Not ready. Use 'attach' first.\n");
                continue;
            }

            ExecuteScriptFromFile(&Context, filePath);
        }
        else if (strcmp(cmd, "execstr") == 0) {
            char* script = strtok(NULL, "");
            if (script == NULL) {
                printf("[-] Usage: execstr <lua code>\n");
                continue;
            }

            if (!Context.Ready) {
                printf("[-] Not ready. Use 'attach' first.\n");
                continue;
            }

            SCRIPT_EXECUTION_RESULT Result;
            printf("[*] Executing script...\n");
            Status = ExecuteRobloxScript(&Context, script, strlen(script), &Result);

            if (NT_SUCCESS(Status)) {
                printf("[+] Script executed successfully\n");
            }
            else {
                printf("[-] Script execution failed: 0x%08X\n", Status);
            }
        }
        else if (strcmp(cmd, "status") == 0) {
            PrintStatus(&Context);
        }
        else if (strcmp(cmd, "help") == 0) {
            PrintHelp();
        }
        else if (strcmp(cmd, "exit") == 0) {
            Running = FALSE;
        }
        else {
            printf("[-] Unknown command: %s\n", cmd);
            printf("    Type 'help' for available commands\n");
        }
    }

    // Cleanup
    printf("\n[*] Cleaning up...\n");
    CleanupRobloxExecutor(&Context);
    printf("[+] Goodbye\n");

    return 0;
}
