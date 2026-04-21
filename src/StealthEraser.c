/*
 * Stealth Kernel Driver - Erasure Operations
 *
 * Implements erasure routines for PiDDBCacheTable, KernelHashBucketList,
 * and MmUnloadedDrivers to remove traces from kernel structures.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, ErasePiDDBCacheTable)
    #pragma alloc_tag(PAGE, EraseKernelHashBucketList)
    #pragma alloc_tag(PAGE, EraseMmUnloadedDrivers)
    #pragma alloc_tag(PAGE, ExecuteErasureOperations)
    #pragma alloc_tag(PAGE, ClearErasureStatistics)
#endif // ALLOC_PRAGMA

//------------------------------------------------------------------------------
// Internal Function Prototypes
//------------------------------------------------------------------------------

static VOID EraseCacheTableEntry(
    IN PCACHE_TABLE_ENTRY Entry
);

static VOID EraseHashBucketEntry(
    IN PHASH_BUCKET_ENTRY Entry
);

static VOID EraseUnloadedDriverEntry(
    IN PUNLOADED_DRIVER_ENTRY Entry
);

static NTSTATUS InitializeErasureContext(
    IN OUT PERASURE_CONTEXT Context,
    IN ULONG ErasureFlags
);

//------------------------------------------------------------------------------
// PiDDBCacheTable Erasure Routine
//------------------------------------------------------------------------------

/*
 * ErasePiDDBCacheTable
 *
 * Erases process information from the PiDDB (Process Information Database)
 * cache table to remove traces of process instrumentation.
 *
 * Parameters:
 *   CacheTable - Pointer to the cache table structure containing process entries
 *
 * Notes:
 *   - Clears device path strings from cache entries
 *   - Zeroes cached data buffers
 *   - Resets timestamps and state information
 *   - Operates without acquiring global locks (caller responsible)
 */

VOID NTAPI ErasePiDDBCacheTable(
    IN PVOID CacheTable
)
{
    PCACHE_TABLE_ENTRY Entry;
    PCACHE_TABLE_ENTRY CurrentEntry;
    LIST_ENTRY* ListHead;
    LIST_ENTRY* CurrentList;
    ULONG EntryCount;
    ULONG ErasedCount;

    if (CacheTable == NULL) {
        return;
    }

    Entry = (PCACHE_TABLE_ENTRY)CacheTable;
    EntryCount = 0;
    ErasedCount = 0;

    // Iterate through cache table entries
    // Assuming cache table contains array of CACHE_TABLE_ENTRY structures
    CurrentEntry = Entry;

    for (ULONG i = 0; i < HASH_BUCKET_COUNT; i++) {
        // Clear device path Unicode string
        if (CurrentEntry->DeviceObject.Buffer != NULL) {
            RtlSecureZeroMemory(
                &CurrentEntry->DevicePath,
                sizeof(UNICODE_STRING)
            );
        }

        // Zero cached data pointer and size
        CurrentEntry->CachedData = NULL;
        CurrentEntry->CachedDataSize = 0;

        // Clear timestamps
        CurrentEntry->CreationTime.QuadPart = 0;
        CurrentEntry->LastAccessTime.QuadPart = 0;
        CurrentEntry->ExpirationTime.QuadPart = 0;

        // Reset state and flags
        CurrentEntry->State = 0;
        CurrentEntry->IsDirty = FALSE;
        CurrentEntry->ReferenceCount = 0;

        // Clear list entry
        RtlSecureZeroMemory(
            &CurrentEntry->ListEntry,
            sizeof(LIST_ENTRY)
        );

        // Clear reserved fields
        RtlSecureZeroMemory(
            CurrentEntry->Reserved,
            sizeof(CurrentEntry->Reserved)
        );

        ErasedCount++;
        CurrentEntry++;
        EntryCount++;
    }
}

//------------------------------------------------------------------------------
// Kernel Hash Bucket List Erasure Routine
//------------------------------------------------------------------------------

/*
 * EraseKernelHashBucketList
 *
 * Erases entries from a specific kernel hash bucket list to remove
 * instrumentation artifacts from kernel hash tables.
 *
 * Parameters:
 *   HashBucketIndex - Index of the hash bucket to erase
 *
 * Notes:
 *   - Targets specific bucket based on index parameter
 *   - Clears entry data pointers and metadata
 *   - Resets reference counts and timestamps
 *   - Preserves bucket structure for future allocations
 */

VOID NTAPI EraseKernelHashBucketList(
    IN USHORT HashBucketIndex
)
{
    PHASH_BUCKET_LIST BucketList;
    PHASH_BUCKET_ENTRY CurrentEntry;
    PHASH_BUCKET_ENTRY NextEntry;
    ULONG EntryCount;

    if (HashBucketIndex >= HASH_BUCKET_COUNT) {
        return;
    }

    // Obtain pointer to target hash bucket
    // BucketList is accessed through global kernel structure
    BucketList = (PHASH_BUCKET_LIST)(&((PHASH_BUCKET_LIST)0)->Entries[HashBucketIndex]);

    if (BucketList == NULL) {
        return;
    }

    EntryCount = 0;

    // Traverse entries in the specified bucket
    CurrentEntry = BucketList->Entries[HashBucketIndex];

    while (CurrentEntry != NULL) {
        NextEntry = CurrentEntry->Next;

        // Clear entry key and data
        CurrentEntry->HashKey = 0;
        CurrentEntry->EntryData = NULL;
        CurrentEntry->EntrySize = 0;

        // Reset timestamps
        CurrentEntry->CreationTime.QuadPart = 0;
        CurrentEntry->LastAccessTime.QuadPart = 0;

        // Clear reference count and flags
        CurrentEntry->ReferenceCount = 0;
        CurrentEntry->Flags = 0;

        // Clear reserved fields
        RtlSecureZeroMemory(
            CurrentEntry->Reserved,
            sizeof(CurrentEntry->Reserved)
        );

        // Move to next entry
        CurrentEntry = NextEntry;
        EntryCount++;
    }

    // Update bucket statistics
    if (BucketList != NULL) {
        BucketList->TotalEntryCount -= EntryCount;
        if (EntryCount > 0) {
            BucketList->OccupiedBucketCount--;
        }
    }
}

//------------------------------------------------------------------------------
// MmUnloadedDrivers Erasure Routine
//------------------------------------------------------------------------------

/*
 * EraseMmUnloadedDrivers
 *
 * Erases unloaded driver entries from the MmUnloadedDrivers list to
 * remove evidence of previously loaded kernel modules.
 *
 * Parameters:
 *   UnloadedDriverCount - Number of unloaded driver entries to process
 *
 * Notes:
 *   - Processes up to UnloadedDriverCount entries
 *   - Clears driver name strings and memory ranges
 *   - Resets checksum and timestamp information
 *   - Maintains list integrity for subsequent operations
 */

VOID NTAPI EraseMmUnloadedDrivers(
    IN ULONG UnloadedDriverCount
)
{
    PUNLOADED_DRIVER_ENTRY Entry;
    PUNLOADED_DRIVER_ENTRY CurrentEntry;
    ULONG ProcessedCount;
    ULONG MaxEntries;

    if (UnloadedDriverCount == 0) {
        return;
    }

    // Limit to maximum supported entries
    MaxEntries = (UnloadedDriverCount < UNLOADED_DRIVER_MAX) ?
                  UnloadedDriverCount : UNLOADED_DRIVER_MAX;

    // Access unloaded driver array (global kernel structure)
    Entry = (PUNLOADED_DRIVER_ENTRY)((PUNLOADED_DRIVER_ENTRY)0);

    CurrentEntry = Entry;
    ProcessedCount = 0;

    for (ULONG i = 0; i < MaxEntries; i++) {
        // Clear driver name Unicode string
        if (CurrentEntry->DriverName.Buffer != NULL) {
            RtlSecureZeroMemory(
                &CurrentEntry->DriverName,
                sizeof(UNICODE_STRING)
            );
        }
        CurrentEntry->DriverNameLength = 0;

        // Clear memory range information
        CurrentEntry->StartAddress = 0;
        CurrentEntry->EndAddress = 0;
        CurrentEntry->ImageSize = 0;

        // Reset checksum and timestamp
        CurrentEntry->CheckSum = 0;
        CurrentEntry->TimeDateStamp = 0;

        // Clear module characteristics
        CurrentEntry->Characteristics = 0;
        CurrentEntry->NumberOfSections = 0;

        // Reset list entry
        RtlSecureZeroMemory(
            &CurrentEntry->ListEntry,
            sizeof(LIST_ENTRY)
        );

        // Clear unload timestamp
        CurrentEntry->UnloadTime.QuadPart = 0;

        // Clear reserved fields
        RtlSecureZeroMemory(
            CurrentEntry->Reserved,
            sizeof(CurrentEntry->Reserved)
        );

        CurrentEntry++;
        ProcessedCount++;
    }
}

//------------------------------------------------------------------------------
// Erasure Operation Execution
//------------------------------------------------------------------------------

/*
 * ExecuteErasureOperations
 *
 * Executes a coordinated set of erasure operations based on the
 * provided erasure context and flags.
 *
 * Parameters:
 *   ErasureContext - Context structure containing erasure parameters and statistics
 *
 * Returns:
 *   STATUS_SUCCESS on completion, appropriate NTSTATUS code on error
 *
 * Notes:
 *   - Processes operations based on ErasureFlags in context
 *   - Updates statistics for monitoring and debugging
 *   - Supports selective or comprehensive erasure via flags
 */

NTSTATUS ExecuteErasureOperations(
    IN OUT PERASURE_CONTEXT ErasureContext
)
{
    NTSTATUS Status;

    if (ErasureContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize context if needed
    if (ErasureContext->ErasureFlags == 0) {
        Status = InitializeErasureContext(
            ErasureContext,
            ERASURE_FLAG_ALL
        );

        if (!IS_SUCCESS(Status)) {
            return Status;
        }
    }

    // Record start time
    ErasureContext->StartTime = KeQueryPerformanceCounter(NULL);

    // Execute PiDDBCacheTable erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_PIDDDB_CACHE) != 0) {
        ErasePiDDBCacheTable(ErasureContext->PiDDBCacheBase);
        ErasureContext->CompletedFlags |= ERASURE_FLAG_PIDDDB_CACHE;
    }

    // Execute Hash Bucket erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_HASH_BUCKET) != 0) {
        for (USHORT i = 0; i < HASH_BUCKET_COUNT; i++) {
            EraseKernelHashBucketList(i);
        }
        ErasureContext->CompletedFlags |= ERASURE_FLAG_HASH_BUCKET;
    }

    // Execute Unloaded Drivers erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_UNLOADED_DRIVER) != 0) {
        EraseMmUnloadedDrivers(ErasureContext->UnloadedDriverCount);
        ErasureContext->CompletedFlags |= ERASURE_FLAG_UNLOADED_DRIVER;
    }

    // Record end time and calculate statistics
    ErasureContext->EndTime = KeQueryPerformanceCounter(NULL);

    // Calculate total operations completed
    ErasureContext->EntriesProcessed =
        ErasureContext->PiDDBCacheEntriesProcessed +
        ErasureContext->HashBucketsCleared +
        ErasureContext->DriversErased;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// Erasure Statistics Management
//------------------------------------------------------------------------------

/*
 * ClearErasureStatistics
 *
 * Resets all statistics counters and timing information in the
 * erasure context structure.
 *
 * Parameters:
 *   ErasureContext - Context structure containing statistics to clear
 *
 * Notes:
 *   - Preserves configuration flags
 *   - Clears operational statistics only
 *   - Suitable for periodic statistics reset
 */

VOID ClearErasureStatistics(
    IN PERASURE_CONTEXT ErasureContext
)
{
    if (ErasureContext == NULL) {
        return;
    }

    // Clear statistics counters
    ErasureContext->TotalBytesErased = 0;
    ErasureContext->EntriesProcessed = 0;
    ErasureContext->ErrorsEncountered = 0;

    // Clear PiDDBCacheTable statistics
    ErasureContext->PiDDBCacheEntriesProcessed = 0;

    // Clear Hash Bucket statistics
    ErasureContext->HashBucketsCleared = 0;

    // Clear Unloaded Driver statistics
    ErasureContext->DriversErased = 0;

    // Reset timing information
    ErasureContext->StartTime.QuadPart = 0;
    ErasureContext->EndTime.QuadPart = 0;

    // Clear completed flags (preserve ErasureFlags configuration)
    ErasureContext->CompletedFlags = 0;
}

//------------------------------------------------------------------------------
// Internal Helper Functions
//------------------------------------------------------------------------------

/*
 * InitializeErasureContext
 *
 * Initializes the erasure context structure with default values
 * based on specified operation flags.
 *
 * Parameters:
 *   Context - Erasure context structure to initialize
 *   ErasureFlags - Flags specifying which operations to configure
 *
 * Returns:
 *   STATUS_SUCCESS on completion, appropriate NTSTATUS code on error
 */

static NTSTATUS InitializeErasureContext(
    IN OUT PERASURE_CONTEXT Context,
    IN ULONG ErasureFlags
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Set operation flags
    Context->ErasureFlags = ErasureFlags;
    Context->CompletedFlags = 0;

    // Initialize statistics to zero
    Context->TotalBytesErased = 0;
    Context->EntriesProcessed = 0;
    Context->ErrorsEncountered = 0;
    Context->PiDDBCacheEntriesProcessed = 0;
    Context->HashBucketsCleared = 0;
    Context->DriversErased = 0;

    // Initialize timing
    Context->StartTime.QuadPart = 0;
    Context->EndTime.QuadPart = 0;

    // Clear reserved fields
    RtlSecureZeroMemory(
        Context->Reserved,
        sizeof(Context->Reserved)
    );

    return STATUS_SUCCESS;
}

/*
 * EraseCacheTableEntry
 *
 * Erases a single cache table entry.
 *
 * Parameters:
 *   Entry - Cache table entry to erase
 */

static VOID EraseCacheTableEntry(
    IN PCACHE_TABLE_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }

    // Clear device path
    RtlSecureZeroMemory(
        &Entry->DevicePath,
        sizeof(UNICODE_STRING)
    );

    // Clear cached data
    Entry->DeviceObject = NULL;
    Entry->CachedData = NULL;
    Entry->CachedDataSize = 0;

    // Reset timestamps
    Entry->CreationTime.QuadPart = 0;
    Entry->LastAccessTime.QuadPart = 0;
    Entry->ExpirationTime.QuadPart = 0;

    // Clear state
    Entry->State = 0;
    Entry->IsDirty = FALSE;
    Entry->ReferenceCount = 0;
}

/*
 * EraseHashBucketEntry
 *
 * Erases a single hash bucket entry.
 *
 * Parameters:
 *   Entry - Hash bucket entry to erase
 */

static VOID EraseHashBucketEntry(
    IN PHASH_BUCKET_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }

    // Clear entry data
    Entry->HashKey = 0;
    Entry->EntryData = NULL;
    Entry->EntrySize = 0;

    // Reset timestamps
    Entry->CreationTime.QuadPart = 0;
    Entry->LastAccessTime.QuadPart = 0;

    // Clear metadata
    Entry->ReferenceCount = 0;
    Entry->Flags = 0;

    // Clear list pointers
    Entry->Next = NULL;
    Entry->Prev = NULL;
}

/*
 * EraseUnloadedDriverEntry
 *
 * Erases a single unloaded driver entry.
 *
 * Parameters:
 *   Entry - Unloaded driver entry to erase
 */

static VOID EraseUnloadedDriverEntry(
    IN PUNLOADED_DRIVER_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }

    // Clear driver identification
    RtlSecureZeroMemory(
        &Entry->DriverName,
        sizeof(UNICODE_STRING)
    );
    Entry->DriverNameLength = 0;

    // Clear memory range
    Entry->StartAddress = 0;
    Entry->EndAddress = 0;
    Entry->ImageSize = 0;

    // Reset checksum and characteristics
    Entry->CheckSum = 0;
    Entry->TimeDateStamp = 0;
    Entry->Characteristics = 0;
    Entry->NumberOfSections = 0;

    // Clear timestamp
    Entry->UnloadTime.QuadPart = 0;
}
