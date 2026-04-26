/*
 * Shellcode Loader - Header
 */

#ifndef _SHELLCODE_LOADER_H
#define _SHELLCODE_LOADER_H

#include <ntifs.h>

#define SHELLCODE_LOADER_TAG 0x4C485348  // "SHLL"

#define SHELLCODE_FLAG_ALLOCATED    0x00000001
#define SHELLCODE_FLAG_EXECUTABLE   0x00000002
#define SHELLCODE_FLAG_PE_IMAGE     0x00000004
#define SHELLCODE_FLAG_ALLOCATE_RWX 0x00000008

typedef struct _SHELLCODE_ENTRY {
    PVOID ShellcodeAddress;
    SIZE_T ShellcodeSize;
    PVOID EntryPoint;
    ULONG Flags;
} SHELLCODE_ENTRY, *PSHELLCODE_ENTRY;

typedef struct _SHELLCODE_LOADER_CONTEXT {
    ULONG Tag;
    HANDLE TargetProcess;
    ULONG LoaderFlags;
    ULONG LoadedShellcodeCount;
} SHELLCODE_LOADER_CONTEXT, *PSHELLCODE_LOADER_CONTEXT;

NTSTATUS InitializeShellcodeLoader(
    OUT PSHELLCODE_LOADER_CONTEXT Context,
    IN HANDLE TargetProcess
);

NTSTATUS PrepareShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    OUT PSHELLCODE_ENTRY Entry
);

NTSTATUS LoadDllShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PSHELLCODE_ENTRY Entry
);

NTSTATUS ProcessRelocationsForShellcode(
    IN PVOID ImageBase,
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN ULONGLONG NewBase
);

NTSTATUS CreateBootstrapShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID TargetFunction,
    IN PVOID Parameter,
    OUT PVOID* BootstrapCode,
    OUT PSIZE_T BootstrapSize
);

NTSTATUS UnloadShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PSHELLCODE_ENTRY Entry
);

VOID CleanupShellcodeLoader(
    IN PSHELLCODE_LOADER_CONTEXT Context);

#endif // _SHELLCODE_LOADER_H
