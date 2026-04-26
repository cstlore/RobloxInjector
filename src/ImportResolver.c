/*
 * Import Resolver - Complete Implementation
 *
 * Hookless import resolution via manual export directory walking.
 * Resolves imports without calling GetProcAddress to avoid hooks.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "ImportResolver.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// Forward declarations
static PVOID GetModuleBaseAddress(IN PCWSTR ModuleName);
static PIMAGE_EXPORT_DIRECTORY GetExportDirectory(IN PVOID ModuleBase);
static PVOID ResolveExportByNameInternal(
    IN PVOID ModuleBase,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN PCCH FunctionName
);
static PVOID ResolveExportByOrdinalInternal(
    IN PVOID ModuleBase,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN USHORT Ordinal
);

NTSTATUS InitializeImportResolver(
    OUT PIMPORT_RESOLVER_CONTEXT Context
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(IMPORT_RESOLVER_CONTEXT));
    Context->Tag = IMPORT_RESOLVER_TAG;
    Context->ResolvedCount = 0;

    // Cache ntdll.dll base and export directory
    Context->NtdllBase = GetModuleBaseAddress(L"ntdll.dll");
    if (Context->NtdllBase == NULL) {
        return STATUS_DLL_NOT_FOUND;
    }

    Context->NtdllExports = GetExportDirectory(Context->NtdllBase);
    if (Context->NtdllExports == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Cache kernel32.dll for usermode imports
    Context->Kernel32Base = GetModuleBaseAddress(L"kernel32.dll");
    if (Context->Kernel32Base != NULL) {
        Context->Kernel32Exports = GetExportDirectory(Context->Kernel32Base);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ResolveImportTable(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PVOID ImageBase,
    IN PIMAGE_NT_HEADERS NtHeaders
)
{
    PIMAGE_DATA_DIRECTORY ImportDir;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
    ULONG ImportDirRva;

    if (Context == NULL || ImageBase == NULL || NtHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get import directory
    ImportDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (ImportDir->Size == 0 || ImportDir->VirtualAddress == 0) {
        return STATUS_SUCCESS; // No imports
    }

    ImportDirRva = ImportDir->VirtualAddress;
    ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)ImageBase + ImportDirRva);

    // Walk import descriptors
    while (ImportDesc->Name != 0) {
        PCCH ModuleName = (PCCH)((PUCHAR)ImageBase + ImportDesc->Name);
        PVOID ModuleBase = NULL;
        PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;

        // Determine which module to resolve from
        if (_stricmp(ModuleName, "ntdll.dll") == 0) {
            ModuleBase = Context->NtdllBase;
            ExportDir = Context->NtdllExports;
        }
        else if (_stricmp(ModuleName, "kernel32.dll") == 0) {
            ModuleBase = Context->Kernel32Base;
            ExportDir = Context->Kernel32Exports;
        }
        else {
            // Load additional module if needed
            WCHAR WideModuleName[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, WideModuleName, MAX_PATH);
            ModuleBase = GetModuleBaseAddress(WideModuleName);
            if (ModuleBase != NULL) {
                ExportDir = GetExportDirectory(ModuleBase);
            }
        }

        if (ModuleBase == NULL || ExportDir == NULL) {
            return STATUS_DLL_NOT_FOUND;
        }

        // Resolve thunks
        PIMAGE_THUNK_DATA OriginalThunk = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase + ImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase + ImportDesc->FirstThunk);

        while (OriginalThunk->u1.AddressOfData != 0) {
            PVOID FunctionAddress = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal)) {
                // Import by ordinal
                USHORT Ordinal = (USHORT)IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);
                FunctionAddress = ResolveExportByOrdinalInternal(ModuleBase, ExportDir, Ordinal);
            }
            else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)ImageBase + OriginalThunk->u1.AddressOfData);
                FunctionAddress = ResolveExportByNameInternal(ModuleBase, ExportDir, (PCCH)ImportByName->Name);
            }

            if (FunctionAddress == NULL) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            // Write resolved address to IAT
            FirstThunk->u1.Function = (ULONGLONG)FunctionAddress;

            Context->ResolvedCount++;
            OriginalThunk++;
            FirstThunk++;
        }

        ImportDesc++;
    }

    return STATUS_SUCCESS;
}

PVOID ResolveExportByName(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PCWSTR ModuleName,
    IN PCCH FunctionName
)
{
    PVOID ModuleBase;
    PIMAGE_EXPORT_DIRECTORY ExportDir;

    if (Context == NULL || ModuleName == NULL || FunctionName == NULL) {
        return NULL;
    }

    // Check cached modules first
    if (_wcsicmp(ModuleName, L"ntdll.dll") == 0) {
        ModuleBase = Context->NtdllBase;
        ExportDir = Context->NtdllExports;
    }
    else if (_wcsicmp(ModuleName, L"kernel32.dll") == 0) {
        ModuleBase = Context->Kernel32Base;
        ExportDir = Context->Kernel32Exports;
    }
    else {
        ModuleBase = GetModuleBaseAddress(ModuleName);
        if (ModuleBase == NULL) {
            return NULL;
        }
        ExportDir = GetExportDirectory(ModuleBase);
    }

    if (ExportDir == NULL) {
        return NULL;
    }

    return ResolveExportByNameInternal(ModuleBase, ExportDir, FunctionName);
}

PVOID ResolveExportByOrdinal(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PCWSTR ModuleName,
    IN USHORT Ordinal
)
{
    PVOID ModuleBase;
    PIMAGE_EXPORT_DIRECTORY ExportDir;

    if (Context == NULL || ModuleName == NULL) {
        return NULL;
    }

    if (_wcsicmp(ModuleName, L"ntdll.dll") == 0) {
        ModuleBase = Context->NtdllBase;
        ExportDir = Context->NtdllExports;
    }
    else if (_wcsicmp(ModuleName, L"kernel32.dll") == 0) {
        ModuleBase = Context->Kernel32Base;
        ExportDir = Context->Kernel32Exports;
    }
    else {
        ModuleBase = GetModuleBaseAddress(ModuleName);
        if (ModuleBase == NULL) {
            return NULL;
        }
        ExportDir = GetExportDirectory(ModuleBase);
    }

    if (ExportDir == NULL) {
        return NULL;
    }

    return ResolveExportByOrdinalInternal(ModuleBase, ExportDir, Ordinal);
}

static PVOID GetModuleBaseAddress(IN PCWSTR ModuleName)
{
    PPEB Peb;
    PPEB_LDR_DATA Ldr;
    PLIST_ENTRY ListHead, ListEntry;

    // Get PEB
#ifdef _WIN64
    Peb = (PPEB)__readgsqword(0x60);
#else
    Peb = (PPEB)__readfsdword(0x30);
#endif

    Ldr = Peb->Ldr;
    ListHead = &Ldr->InMemoryOrderModuleList;
    ListEntry = ListHead->Flink;

    // Walk loaded modules
    while (ListEntry != ListHead) {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (Entry->BaseDllName.Buffer != NULL) {
            if (_wcsicmp(Entry->BaseDllName.Buffer, ModuleName) == 0) {
                return Entry->DllBase;
            }
        }

        ListEntry = ListEntry->Flink;
    }

    return NULL;
}

static PIMAGE_EXPORT_DIRECTORY GetExportDirectory(IN PVOID ModuleBase)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY ExportDir;

    if (ModuleBase == NULL) {
        return NULL;
    }

    DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    ExportDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir->VirtualAddress == 0) {
        return NULL;
    }

    return (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ExportDir->VirtualAddress);
}

static PVOID ResolveExportByNameInternal(
    IN PVOID ModuleBase,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN PCCH FunctionName
)
{
    PULONG AddressOfFunctions;
    PULONG AddressOfNames;
    PUSHORT AddressOfNameOrdinals;
    ULONG i;

    if (ModuleBase == NULL || ExportDir == NULL || FunctionName == NULL) {
        return NULL;
    }

    AddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + ExportDir->AddressOfFunctions);
    AddressOfNames = (PULONG)((PUCHAR)ModuleBase + ExportDir->AddressOfNames);
    AddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + ExportDir->AddressOfNameOrdinals);

    // Binary search would be faster, but linear is simpler and reliable
    for (i = 0; i < ExportDir->NumberOfNames; i++) {
        PCCH ExportName = (PCCH)((PUCHAR)ModuleBase + AddressOfNames[i]);

        if (strcmp(ExportName, FunctionName) == 0) {
            USHORT OrdinalIndex = AddressOfNameOrdinals[i];
            ULONG FunctionRva = AddressOfFunctions[OrdinalIndex];

            // Check for forwarded export
            ULONG ExportDirStart = (ULONG)((PUCHAR)ExportDir - (PUCHAR)ModuleBase);
            ULONG ExportDirEnd = ExportDirStart + ExportDir->Size;

            if (FunctionRva >= ExportDirStart && FunctionRva < ExportDirEnd) {
                // Forwarded export - not implemented for simplicity
                return NULL;
            }

            return (PVOID)((PUCHAR)ModuleBase + FunctionRva);
        }
    }

    return NULL;
}

static PVOID ResolveExportByOrdinalInternal(
    IN PVOID ModuleBase,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN USHORT Ordinal
)
{
    PULONG AddressOfFunctions;
    ULONG OrdinalIndex;
    ULONG FunctionRva;

    if (ModuleBase == NULL || ExportDir == NULL) {
        return NULL;
    }

    // Adjust ordinal by base
    OrdinalIndex = Ordinal - (USHORT)ExportDir->Base;

    if (OrdinalIndex >= ExportDir->NumberOfFunctions) {
        return NULL;
    }

    AddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + ExportDir->AddressOfFunctions);
    FunctionRva = AddressOfFunctions[OrdinalIndex];

    if (FunctionRva == 0) {
        return NULL;
    }

    return (PVOID)((PUCHAR)ModuleBase + FunctionRva);
}

VOID CleanupImportResolver(IN PIMPORT_RESOLVER_CONTEXT Context)
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(IMPORT_RESOLVER_CONTEXT));
    }
}
