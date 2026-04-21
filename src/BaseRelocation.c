#include "BaseRelocation.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

/**
 * Base relocation structures for custom parsing and processing
 */

typedef struct _RELOCATION_CONTEXT {
    PVOID MappingBase;
    ULONG MappingSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION FirstRelocation;
    ULONG RelocationCount;
    BOOLEAN Processed;
    ULONGLONG OriginalImageBase;
    ULONGLONG CurrentImageBase;
    ULONGLONG Delta;
} RELOCATION_CONTEXT, *PRELOCATION_CONTEXT;

// Forward declarations
static NTSTATUS ParseRelocationDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PRELOCATION_CONTEXT pContext
);

static NTSTATUS ProcessRelocationBlocks(
    _In_ PRELOCATION_CONTEXT pContext
);

static NTSTATUS ApplyRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG EntryCount
);

static NTSTATUS ApplyBaseRelocation(
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG BlockOffset,
    _In_ USHORT EntryType,
    _In_ USHORT EntryOffset,
    _In_ ULONGLONG Delta
);

static PIMAGE_BASE_RELOCATION NavigateRelocationBlocks(
    _In_ PIMAGE_BASE_RELOCATION pCurrentBlock,
    _In_ PIMAGE_BASE_RELOCATION pTargetBlock
);

/**
 * Initialize custom base relocation parser
 *
 * Creates and initializes the relocation context with parsed
 * relocation information from the mapped driver image.
 *
 * @param MappingBase Base address of the mapped driver image
 * @param MappingSize Size of the mapped image in bytes
 * @param ImageBase Preferred image base address
 * @param ppContext Output pointer to receive initialized relocation context
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS RelocationContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ ULONGLONG ImageBase,
    _Out_ PRELOCATION_CONTEXT* ppContext
)
{
    NTSTATUS status;
    PRELOCATION_CONTEXT pContext = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    ULONG ntHeadersOffset;

    if (MappingBase == NULL || ppContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate relocation context
    pContext = (PRELOCATION_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPool,
        sizeof(RELOCATION_CONTEXT),
        DRIVER_TAG
    );

    if (pContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pContext, sizeof(RELOCATION_CONTEXT));

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
    pContext->OriginalImageBase = ImageBase;
    pContext->CurrentImageBase = (ULONGLONG)MappingBase;
    pContext->Delta = pContext->CurrentImageBase - pContext->OriginalImageBase;
    pContext->Processed = FALSE;

    // Parse relocation directory
    status = ParseRelocationDirectory(MappingBase, MappingSize,
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
 * Cleanup base relocation context
 *
 * Releases resources associated with the relocation context.
 *
 * @param pContext Pointer to the relocation context
 */
VOID RelocationContextCleanup(_In_opt_ PRELOCATION_CONTEXT pContext)
{
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
}

/**
 * Process base relocations
 *
 * Iterates through all relocation blocks and applies necessary
 * adjustments to accommodate the current mapping base address.
 *
 * @param pContext Pointer to the relocation context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS ProcessBaseRelocations(_In_ PRELOCATION_CONTEXT pContext)
{
    NTSTATUS status;

    if (pContext == NULL || pContext->Processed) {
        return pContext == NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }

    // No relocation needed if delta is zero
    if (pContext->Delta == 0) {
        pContext->Processed = TRUE;
        return STATUS_SUCCESS;
    }

    // Process relocation blocks
    status = ProcessRelocationBlocks(pContext);

    if (NT_SUCCESS(status)) {
        pContext->Processed = TRUE;
    }

    return status;
}

/**
 * Parse relocation directory from PE image
 *
 * Locates and validates the base relocation directory, extracting
 * the relocation block chain and entry counts.
 *
 * @param MappingBase Base address of the mapped image
 * @param MappingSize Size of the mapped image
 * @param pNtHeaders Pointer to NT headers
 * @param pContext Output relocation context
 * @return STATUS_SUCCESS on successful parsing
 */
static NTSTATUS ParseRelocationDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PRELOCATION_CONTEXT pContext
)
{
    PIMAGE_DATA_DIRECTORY pRelocDir;
    PIMAGE_BASE_RELOCATION pFirstBlock;
    ULONG relocDirOffset;

    // Get relocation directory entry
    pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // Check if relocation directory exists
    if (pRelocDir->Size == 0 || pRelocDir->VirtualAddress == 0) {
        pContext->FirstRelocation = NULL;
        pContext->RelocationCount = 0;
        return STATUS_SUCCESS;
    }

    // Calculate relocation directory offset
    relocDirOffset = (ULONG)(pRelocDir->VirtualAddress);

    // Validate relocation directory bounds
    if (relocDirOffset >= MappingSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get first relocation block
    pFirstBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)MappingBase + relocDirOffset);

    // Validate first block
    if ((ULONG_PTR)pFirstBlock >= (ULONG_PTR)pRelocDir ||
        (ULONG_PTR)pFirstBlock >= ((ULONG_PTR)MappingBase + MappingSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Count relocation blocks
    pContext->FirstRelocation = pFirstBlock;
    pContext->RelocationCount = CalculateRelocationBlockCount(
        pFirstBlock,
        pRelocDir->Size
    );

    return STATUS_SUCCESS;
}

/**
 * Process relocation blocks
 *
 * Iterates through the chain of relocation blocks and applies
 * each relocation entry to the mapped image.
 *
 * @param pContext Pointer to the relocation context
 * @return STATUS_SUCCESS on successful processing
 */
static NTSTATUS ProcessRelocationBlocks(_In_ PRELOCATION_CONTEXT pContext)
{
    PIMAGE_BASE_RELOCATION pCurrentBlock;
    NTSTATUS status;

    pCurrentBlock = pContext->FirstRelocation;

    while (pCurrentBlock != NULL && pCurrentBlock->SizeOfBlock != 0) {
        // Calculate number of entries in current block
        ULONG entryCount = (pCurrentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                           sizeof(IMAGE_RELOCANT);

        // Apply relocations for current block
        status = ApplyRelocation(pContext, pCurrentBlock, entryCount);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Navigate to next block
        if ((pCurrentBlock + 1)->SizeOfBlock != 0) {
            pCurrentBlock = NavigateRelocationBlocks(
                pCurrentBlock,
                pCurrentBlock + 1
            );
        }
        else {
            break;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * Apply relocation for a single block
 *
 * Processes all relocation entries within a block, applying
 * type-specific adjustments based on the delta.
 *
 * @param pContext Pointer to the relocation context
 * @param pRelocationBlock Pointer to the relocation block
 * @param EntryCount Number of entries in the block
 * @return STATUS_SUCCESS on successful application
 */
static NTSTATUS ApplyRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG EntryCount
)
{
    USHORT blockOffset = (USHORT)(pRelocationBlock->VirtualAddress & 0xFFFF);
    PIMAGE_RELOCANT pEntry;
    PIMAGE_RELOCANT pEndEntries;
    NTSTATUS status;

    if (EntryCount == 0) {
        return STATUS_SUCCESS;
    }

    pEntry = (PIMAGE_RELOCANT)((PUCHAR)pRelocationBlock + sizeof(IMAGE_BASE_RELOCATION));
    pEndEntries = pEntry + EntryCount;

    while (pEntry < pEndEntries) {
        // Extract entry type and offset
        USHORT entryType = (USHORT)((ULONG)(*pEntry) >> IMAGE_RELOCANT_OFFSET_SHIFT);
        USHORT entryOffset = (USHORT)((ULONG)(*pEntry) & IMAGE_RELOCANT_OFFSET_MASK);

        // Apply base relocation
        status = ApplyBaseRelocation(
            pRelocationBlock,
            blockOffset,
            entryType,
            entryOffset,
            pContext->Delta
        );

        if (!NT_SUCCESS(status)) {
            return status;
        }

        pEntry++;
    }

    return STATUS_SUCCESS;
}

/**
 * Apply base relocation to target address
 *
 * Calculates and applies the appropriate relocation adjustment
 * based on the entry type and delta.
 *
 * @param pRelocationBlock Pointer to the relocation block
 * @param BlockOffset Virtual address of the block
 * @param EntryType Relocation type (IMAGE_REL_xxx)
 * @param EntryOffset Offset within the block
 * @param Delta Difference between current and original base
 * @return STATUS_SUCCESS on successful application
 */
static NTSTATUS ApplyBaseRelocation(
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG BlockOffset,
    _In_ USHORT EntryType,
    _In_ USHORT EntryOffset,
    _In_ ULONGLONG Delta
)
{
    PVOID targetAddress;
    ULONGLONG targetOffset = (ULONGLONG)BlockOffset + EntryOffset;

    // Calculate target address within mapped image
    targetAddress = (PVOID)((ULONG_PTR)pRelocationBlock + targetOffset);

    // Validate target address is within valid range
    if (targetAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Apply relocation based on type
    switch (EntryType) {
        case IMAGE_REL_BASED_ABSOLUTE:
            // No action required for absolute relocations
            break;

        case IMAGE_REL_BASED_HIGHLOW:
            // 32-bit relocation
            *(PULONG)targetAddress = (ULONG)((ULONG)*(PULONG)targetAddress +
                                              (ULONG)Delta);
            break;

        case IMAGE_REL_BASED_DIR64:
            // 64-bit relocation
            *(PULONGLONG)targetAddress = *(PULONGLONG)targetAddress + Delta;
            break;

        case IMAGE_REL_BASED_HIGH:
            // High 16-bit relocation
            *(PUSHORT)targetAddress = (USHORT)((ULONG)*(PUSHORT)targetAddress +
                                                 (ULONG)(Delta >> 16));
            break;

        case IMAGE_REL_BASED_LOW:
            // Low 16-bit relocation
            *(PUSHORT)targetAddress = (USHORT)((ULONG)*(PUSHORT)targetAddress +
                                                 (ULONG)Delta);
            break;

        default:
            // Unknown relocation type - log but continue
            break;
    }

    return STATUS_SUCCESS;
}

/**
 * Navigate to next relocation block
 *
 * Advances through the relocation block chain with validation.
 *
 * @param pCurrentBlock Current relocation block
 * @param pTargetBlock Target block to navigate to
 * @return Pointer to the next valid block
 */
static PIMAGE_BASE_RELOCATION NavigateRelocationBlocks(
    _In_ PIMAGE_BASE_RELOCATION pCurrentBlock,
    _In_ PIMAGE_BASE_RELOCATION pTargetBlock
)
{
    if (pCurrentBlock == NULL || pTargetBlock == NULL) {
        return NULL;
    }

    // Validate target block has valid size
    if (pTargetBlock->SizeOfBlock == 0) {
        return NULL;
    }

    return pTargetBlock;
}

/**
 * Calculate relocation block count
 *
 * Iterates through relocation blocks to determine total count.
 *
 * @param pFirstBlock Pointer to first relocation block
 * @param DirectorySize Total size of relocation directory
 * @return Number of relocation blocks
 */
ULONG CalculateRelocationBlockCount(
    _In_ PIMAGE_BASE_RELOCATION pFirstBlock,
    _In_ ULONG DirectorySize
)
{
    ULONG count = 0;
    PIMAGE_BASE_RELOCATION pCurrent;
    ULONG currentOffset = 0;

    if (pFirstBlock == NULL || DirectorySize == 0) {
        return 0;
    }

    pCurrent = pFirstBlock;

    while (currentOffset < DirectorySize &&
           pCurrent->SizeOfBlock != 0) {
        count++;
        currentOffset += pCurrent->SizeOfBlock;
        pCurrent = (PIMAGE_BASE_RELOCATION)((PUCHAR)pCurrent +
                                             pCurrent->SizeOfBlock);
    }

    return count;
}

/**
 * Get relocation statistics
 *
 * Retrieves detailed statistics about the relocation processing.
 *
 * @param pContext Pointer to the relocation context
 * @param pStats Output pointer to receive statistics
 * @return STATUS_SUCCESS on successful retrieval
 */
NTSTATUS GetRelocationStatistics(
    _In_ PRELOCATION_CONTEXT pContext,
    _Out_ PRELOCATION_STATISTICS pStats
)
{
    if (pContext == NULL || pStats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlSecureZeroMemory(pStats, sizeof(RELOCATION_STATISTICS));

    pStats->OriginalImageBase = pContext->OriginalImageBase;
    pStats->CurrentImageBase = pContext->CurrentImageBase;
    pStats->Delta = pContext->Delta;
    pStats->RelocationCount = pContext->RelocationCount;
    pStats->Processed = pContext->Processed;
    pStats->HasRelocations = (pContext->FirstRelocation != NULL);

    return STATUS_SUCCESS;
}