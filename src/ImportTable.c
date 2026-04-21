#include "ImportTable.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

/**
 * Import table processing structures for custom resolution
 */

typedef struct _IMPORT_CONTEXT {
    PVOID MappingBase;
    ULONG MappingSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY ImportDir;
    PIMAGE_IMPORT_DESCRIPTOR FirstDescriptor;
    ULONG DescriptorCount;
    BOOLEAN Processed;
    BOOLEAN CustomResolved;
} IMPORT_CONTEXT, *PIMPORT_CONTEXT;

// Forward declarations
static NTSTATUS ParseImportDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PIMPORT_CONTEXT pContext
);

static NTSTATUS ProcessImportDescriptors(
    _In_ PIMPORT_CONTEXT pContext
);

static NTSTATUS ResolveImportDescriptor(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
);

static NTSTATUS ResolveImportByName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ PCCH ImportName,
    _In_ PCCH FunctionName
);

static NTSTATUS ResolveImportByOrdinal(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ ULONG Ordinal
);

static PVOID LocateImportData(
    _In_ PIMAGE_THUNK_DATA pThunk,
    _In_ BOOLEAN IsOriginal
);

/**
 * Initialize import table processing context
 *
 * Creates and initializes the import context with parsed
 * import directory information from the mapped driver image.
 *
 * @param MappingBase Base address of the mapped driver image
 * @param MappingSize Size of the mapped image in bytes
 * @param ppContext Output pointer to receive initialized import context
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS ImportContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PIMPORT_CONTEXT* ppContext
)
{
    NTSTATUS status;
    PIMPORT_CONTEXT pContext = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    ULONG ntHeadersOffset;

    if (MappingBase == NULL || ppContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate import context
    pContext = (PIMPORT_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPool,
        sizeof(IMPORT_CONTEXT),
        DRIVER_TAG
    );

    if (pContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pContext, sizeof(IMPORT_CONTEXT));

    // Parse DOS header
    pDosHeader = (PIMAGE_DOS_HEADER)MappingBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    // Parse NT headers
    ntHeadersOffset = pDosHeader->e_lfanew;
    if (ntHeadersOffset == 0 || ntHeadersOffset >= MappingSize) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)MappingBase + ntHeadersOffset);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    // Initialize context with header information
    pContext->MappingBase = MappingBase;
    pContext->MappingSize = MappingSize;
    pContext->NtHeaders = pNtHeaders;
    pContext->Processed = FALSE;
    pContext->CustomResolved = FALSE;

    // Parse import directory
    status = ParseImportDirectory(MappingBase, MappingSize,
                                  pNtHeaders, pContext);

    if (NT_SUCCESS(status)) {
        *ppContext = pContext;
    }
    else {
        ExFreePool(pContext);
        *ppContext = NULL;
    }

    return status;

Cleanup:
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
    return status;
}

/**
 * Cleanup import table processing context
 *
 * Releases resources associated with the import context.
 *
 * @param pContext Pointer to the import context
 */
VOID ImportContextCleanup(_In_opt_ PIMPORT_CONTEXT pContext)
{
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
}

/**
 * Process import table
 *
 * Iterates through all import descriptors and resolves
 * imported functions using custom resolution mechanisms.
 *
 * @param pContext Pointer to the import context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS ProcessImportTable(_In_ PIMPORT_CONTEXT pContext)
{
    NTSTATUS status;

    if (pContext == NULL || pContext->Processed) {
        return pContext == NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }

    // Process import descriptors
    status = ProcessImportDescriptors(pContext);

    if (NT_SUCCESS(status)) {
        pContext->Processed = TRUE;
        pContext->CustomResolved = TRUE;
    }

    return status;
}

/**
 * Parse import directory from PE image
 *
 * Locates and validates the import directory, extracting
 * the descriptor chain and import information.
 *
 * @param MappingBase Base address of the mapped image
 * @param MappingSize Size of the mapped image
 * @param pNtHeaders Pointer to NT headers
 * @param pContext Output import context
 * @return STATUS_SUCCESS on successful parsing
 */
static NTSTATUS ParseImportDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PIMPORT_CONTEXT pContext
)
{
    PIMAGE_DATA_DIRECTORY pImportDir;
    PIMAGE_IMPORT_DESCRIPTOR pFirstDescriptor;
    ULONG importDirOffset;

    // Get import directory entry
    pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Check if import directory exists
    if (pImportDir->Size == 0 || pImportDir->VirtualAddress == 0) {
        pContext->FirstDescriptor = NULL;
        pContext->DescriptorCount = 0;
        return STATUS_SUCCESS;
    }

    // Calculate import directory offset
    importDirOffset = (ULONG)(pImportDir->VirtualAddress);

    // Validate import directory bounds
    if (importDirOffset >= MappingSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get first import descriptor
    pFirstDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)MappingBase + importDirOffset);

    // Validate first descriptor
    if ((ULONG_PTR)pFirstDescriptor >= (ULONG_PTR)pImportDir ||
        (ULONG_PTR)pFirstDescriptor >= ((ULONG_PTR)MappingBase + MappingSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Store import directory information
    pContext->ImportDir = pImportDir;
    pContext->FirstDescriptor = pFirstDescriptor;

    // Count import descriptors
    pContext->DescriptorCount = CalculateDescriptorCount(pFirstDescriptor);

    return STATUS_SUCCESS;
}

/**
 * Process import descriptors
 *
 * Iterates through the chain of import descriptors and resolves
 * each imported function.
 *
 * @param pContext Pointer to the import context
 * @return STATUS_SUCCESS on successful processing
 */
static NTSTATUS ProcessImportDescriptors(_In_ PIMPORT_CONTEXT pContext)
{
    PIMAGE_IMPORT_DESCRIPTOR pCurrentDescriptor;
    NTSTATUS status;

    pCurrentDescriptor = pContext->FirstDescriptor;

    // Process each import descriptor until null terminator
    while (pCurrentDescriptor != NULL && pCurrentDescriptor->Name != 0) {
        // Resolve current import descriptor
        status = ResolveImportDescriptor(pContext, pCurrentDescriptor);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Advance to next descriptor
        pCurrentDescriptor++;
    }

    return STATUS_SUCCESS;
}

/**
 * Resolve a single import descriptor
 *
 * Processes all imported functions within a descriptor,
 * resolving both name-based and ordinal-based imports.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportDescriptor(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
)
{
    PIMAGE_THUNK_DATA pOriginalThunk;
    PIMAGE_THUNK_DATA pThunk;
    PIMAGE_THUNK_DATA pCurrentOriginal;
    PIMAGE_THUNK_DATA pCurrentThunk;

    // Get original and bound thunks
    pOriginalThunk = (PIMAGE_THUNK_DATA)((PUCHAR)pContext->MappingBase +
                                          pDescriptor->OriginalFirstThunk);
    pThunk = (PIMAGE_THUNK_DATA)((PUCHAR)pContext->MappingBase +
                                  pDescriptor->FirstThunk);

    // Validate thunks
    if (pOriginalThunk == NULL || pThunk == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Process each import thunk
    pCurrentOriginal = pOriginalThunk;
    pCurrentThunk = pThunk;

    while (pCurrentOriginal->AddressOfData != 0) {
        BOOLEAN isOrdinal = FALSE;
        ULONG ordinal = 0;
        PCCH importName = NULL;
        PCCH functionName = NULL;

        // Determine if import is by ordinal or name
        if (IMAGE_SNAP_BY_ORDINAL(pCurrentOriginal->u1.Ordinal)) {
            isOrdinal = TRUE;
            ordinal = (ULONG)IMAGE_ORDINAL(pCurrentOriginal->u1.Ordinal);
        }
        else {
            // Resolve import by name
            importName = GetImportLibraryName(pDescriptor);
            functionName = GetImportFunctionName(pCurrentOriginal);
        }

        // Resolve import based on type
        if (isOrdinal) {
            status = ResolveImportByOrdinal(pContext, pDescriptor,
                                            pCurrentOriginal, ordinal);
        }
        else {
            status = ResolveImportByName(pContext, pDescriptor,
                                         pCurrentOriginal, importName, functionName);
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Advance thunks
        pCurrentOriginal++;
        pCurrentThunk++;
    }

    return STATUS_SUCCESS;
}

/**
 * Resolve import by function name
 *
 * Resolves an imported function using the library and function names.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @param pOriginalThunk Pointer to the original thunk
 * @param ImportName Name of the import library
 * @param FunctionName Name of the imported function
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportByName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ PCCH ImportName,
    _In_ PCCH FunctionName
)
{
    // Placeholder for custom name-based resolution
    // In a complete implementation, this would resolve the function
    // address and update the thunk with the resolved address

    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pDescriptor);
    UNREFERENCED_PARAMETER(pOriginalThunk);
    UNREFERENCED_PARAMETER(ImportName);
    UNREFERENCED_PARAMETER(FunctionName);

    return STATUS_SUCCESS;
}

/**
 * Resolve import by ordinal
 *
 * Resolves an imported function using the ordinal value.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @param pOriginalThunk Pointer to the original thunk
 * @param Ordinal Ordinal value of the imported function
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportByOrdinal(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ ULONG Ordinal
)
{
    // Placeholder for custom ordinal-based resolution
    // In a complete implementation, this would resolve the function
    // address using the ordinal and update the thunk

    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pDescriptor);
    UNREFERENCED_PARAMETER(pOriginalThunk);
    UNREFERENCED_PARAMETER(Ordinal);

    return STATUS_SUCCESS;
}

/**
 * Locate import data from thunk
 *
 * Extracts the appropriate data from a thunk based on whether
 * it's the original or bound thunk.
 *
 * @param pThunk Pointer to the thunk
 * @param IsOriginal TRUE if original thunk, FALSE if bound
 * @return Pointer to the located data
 */
static PVOID LocateImportData(
    _In_ PIMAGE_THUNK_DATA pThunk,
    _In_ BOOLEAN IsOriginal
)
{
    if (pThunk == NULL) {
        return NULL;
    }

    if (IsOriginal) {
        return (PVOID)pThunk->AddressOfData;
    }
    else {
        return (PVOID)pThunk->u1.Address;
    }
}

/**
 * Calculate import descriptor count
 *
 * Iterates through import descriptors to determine total count.
 *
 * @param pFirstDescriptor Pointer to first import descriptor
 * @return Number of import descriptors
 */
ULONG CalculateDescriptorCount(_In_ PIMAGE_IMPORT_DESCRIPTOR pFirstDescriptor)
{
    ULONG count = 0;
    PIMAGE_IMPORT_DESCRIPTOR pCurrent;

    if (pFirstDescriptor == NULL) {
        return 0;
    }

    pCurrent = pFirstDescriptor;

    // Count descriptors until null terminator
    while (pCurrent->Name != 0) {
        count++;
        pCurrent++;
    }

    return count;
}

/**
 * Get import library name
 *
 * Retrieves the name of the imported library from a descriptor.
 *
 * @param pDescriptor Pointer to the import descriptor
 * @return Pointer to the library name string
 */
PCCH GetImportLibraryName(_In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor)
{
    if (pDescriptor == NULL || pDescriptor->Name == 0) {
        return NULL;
    }

    return (PCCH)((PUCHAR)pDescriptor + pDescriptor->Name);
}

/**
 * Get import function name
 *
 * Retrieves the name of an imported function from a thunk.
 *
 * @param pOriginalThunk Pointer to the original thunk
 * @return Pointer to the function name string
 */
PCCH GetImportFunctionName(_In_ PIMAGE_THUNK_DATA pOriginalThunk)
{
    PIMAGE_IMPORT_BY_NAME pImportByName;

    if (pOriginalThunk == NULL ||
        IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
        return NULL;
    }

    pImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)pOriginalThunk +
                                             pOriginalThunk->u1.AddressOfData);

    return (PCCH)pImportByName->Name;
}

/**
 * Get import table statistics
 *
 * Retrieves detailed statistics about the import table processing.
 *
 * @param pContext Pointer to the import context
 * @param pStats Output pointer to receive statistics
 * @return STATUS_SUCCESS on successful retrieval
 */
NTSTATUS GetImportTableStatistics(
    _In_ PIMPORT_CONTEXT pContext,
    _Out_ PIMPORT_STATISTICS pStats
)
{
    if (pContext == NULL || pStats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlSecureZeroMemory(pStats, sizeof(IMPORT_STATISTICS));

    pStats->DescriptorCount = pContext->DescriptorCount;
    pStats->Processed = pContext->Processed;
    pStats->CustomResolved = pContext->CustomResolved;
    pStats->HasImports = (pContext->FirstDescriptor != NULL);

    return STATUS_SUCCESS;
}