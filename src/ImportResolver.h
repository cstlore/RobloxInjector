/*
 * Import Resolver - Header
 *
 * Hookless import resolution interface.
 */

#ifndef _IMPORT_RESOLVER_H
#define _IMPORT_RESOLVER_H

#include <ntifs.h>

#define IMPORT_RESOLVER_TAG 0x524D5049  // "IMPR"

typedef struct _IMPORT_RESOLVER_CONTEXT {
    ULONG Tag;
    PVOID NtdllBase;
    PIMAGE_EXPORT_DIRECTORY NtdllExports;
    PVOID Kernel32Base;
    PIMAGE_EXPORT_DIRECTORY Kernel32Exports;
    ULONG ResolvedCount;
} IMPORT_RESOLVER_CONTEXT, *PIMPORT_RESOLVER_CONTEXT;

NTSTATUS InitializeImportResolver(
    OUT PIMPORT_RESOLVER_CONTEXT Context
);

NTSTATUS ResolveImportTable(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PVOID ImageBase,
    IN PIMAGE_NT_HEADERS NtHeaders
);

PVOID ResolveExportByName(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PCWSTR ModuleName,
    IN PCCH FunctionName
);

PVOID ResolveExportByOrdinal(
    IN PIMPORT_RESOLVER_CONTEXT Context,
    IN PCWSTR ModuleName,
    IN USHORT Ordinal
);

VOID CleanupImportResolver(
    IN PIMPORT_RESOLVER_CONTEXT Context
);

#endif // _IMPORT_RESOLVER_H
