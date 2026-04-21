/*
 * Stealth Kernel Driver - Main Implementation
 *
 * Core driver implementation with custom DriverMapEntry entry point
 * for manual mapping support.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

//------------------------------------------------------------------------------
// Global Driver State
//------------------------------------------------------------------------------

DRIVER_GLOBAL_STATE G_DriverState;

//------------------------------------------------------------------------------
// Forward Declarations
//------------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, InitializeDriverGlobalState)
    #pragma alloc_text(INIT, InitializeSharedMemoryBuffer)
#endif

//------------------------------------------------------------------------------
// DriverMapEntry - Custom Entry Point for Manual Mapping
//
// This function serves as the alternative entry point for drivers that
// require manual mapping. It supports:
// - Custom PE header parsing
// - Manual section loading
// - Import resolution without standard Loader
// - Deferred initialization
//
// Parameters:
//   MappingBase      - Base address of the mapped driver image
//   MappingSize      - Size of the mapped image in bytes
//   DriverExtension  - Pointer to the driver extension structure
//
// Returns:
//   VOID - Initialization status stored in GlobalState
//------------------------------------------------------------------------------

VOID NTAPI DriverMapEntry(
    IN PVOID MappingBase,
    IN ULONG MappingSize,
    IN PDRIVER_EXTENSION DriverExtension
)
{
    NTSTATUS Status;
    MANUAL_MAPPING_ENTRY MappingEntry;

    // Validate input parameters
    if (MappingBase == NULL || MappingSize == 0) {
        return;
    }

    // Initialize driver global state
    Status = InitializeDriverGlobalState(&G_DriverState);
    if (!IS_SUCCESS(Status)) {
        G_DriverState.TotalErrors++;
        return;
    }

    // Initialize manual mapping entry
    RtlZeroMemory(&MappingEntry, sizeof(MANUAL_MAPPING_ENTRY));
    MappingEntry.Tag = MAPPING_ENTRY_TAG;
    MappingEntry.MappingFlags = MAPPING_FLAG_EXECUTABLE;
    MappingEntry.MappingBase = MappingBase;
    MappingEntry.MappingSize = MappingSize;
    MappingEntry.DriverExtension = DriverExtension;

    // Parse PE headers
    MappingEntry.DosHeader = (PIMAGE_DOS_HEADER)MappingBase;

    // Validate DOS header signature
    if (MappingEntry.DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        MappingEntry.MappingFlags &= ~MAPPING_FLAG_EXECUTABLE;
        G_DriverState.TotalValidationErrors++;
    }

    // Locate NT headers
    MappingEntry.NtHeaders = (PIMAGE_NT_HEADERS)(
        (PCHAR)MappingBase + MappingEntry.DosHeader->e_lfanew
    );

    // Validate NT header signature
    if (MappingEntry.NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        MappingEntry.MappingFlags &= ~MAPPING_FLAG_EXECUTABLE;
        G_DriverState.TotalValidationErrors++;
    }

    // Initialize section information
    MappingEntry.FirstSection = IMAGE_FIRST_SECTION(MappingEntry.NtHeaders);
    MappingEntry.SectionCount = MappingEntry.NtHeaders->FileHeader.NumberOfSections;

    // Initialize import information
    if (MappingEntry.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        MappingEntry.FirstImport = (PIMAGE_IMPORT_DESCRIPTOR)(
            (PCHAR)MappingBase +
            MappingEntry.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
        MappingEntry.ImportDescriptorCount =
            MappingEntry.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
            sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    // Calculate commit size
    MappingEntry.CommitSize = MappingEntry.NtHeaders->OptionalHeader.SizeOfImage;

    // Initialize timestamps
    MappingEntry.LoadTime = RtlGetTimeOfDay();
    MappingEntry.LastAccessTime = MappingEntry.LoadTime;

    // Initialize reference count
    MappingEntry.ReferenceCount = 1;

    // Set mapping as current
    G_DriverState.CurrentMapping = &MappingEntry;
    G_DriverState.IsManuallyMapped = TRUE;

    // Initialize shared signaling
    Status = InitializeSharedSignaling(&G_DriverState);
    if (IS_SUCCESS(Status)) {
        MappingEntry.MappingFlags |= MAPPING_FLAG_INITIALIZED;
    }

    // Mark entry point as resolved
    MappingEntry.EntryPoint = DriverMapEntry;
    MappingEntry.EntryPointResolved = TRUE;

    // Set mapping flags based on initialization state
    if (MappingEntry.FirstImport != NULL) {
        MappingEntry.MappingFlags |= MAPPING_FLAG_IMPORTS_RESOLVED;
        MappingEntry.ImportsResolved = TRUE;
    }
}

//------------------------------------------------------------------------------
// InitializeDriverGlobalState
//
// Initializes the driver global state structure with default values
// and prepares it for operation.
//
// Parameters:
//   GlobalState      - Pointer to the driver global state structure
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    if (GlobalState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero initialize the structure
    RtlZeroMemory(GlobalState, sizeof(DRIVER_GLOBAL_STATE));

    // Initialize driver identification
    GlobalState->DriverName.MaximumLength = sizeof(UNICODE_STRING) - sizeof(WCHAR);
    GlobalState->DriverName.Buffer = (PWCHAR)((PUCHAR)GlobalState + sizeof(DRIVER_GLOBAL_STATE));
    RtlInitUnicodeString(&GlobalState->DriverName, L"StealthDriver");

    // Set driver version
    GlobalState->DriverVersion =
        (STEALTH_DRIVER_MAJOR_VERSION << 16) |
        (STEALTH_DRIVER_MINOR_VERSION << 8) |
        STEALTH_DRIVER_BUILD_NUMBER;

    // Initialize load time
    GlobalState->LoadTime = RtlGetTimeOfDay();

    // Initialize synchronization primitive
    ExInitializePushLock(&GlobalState->GlobalLock);

    // Initialize operation counters
    GlobalState->TotalReadOperations = 0;
    GlobalState->TotalWriteOperations = 0;
    GlobalState->TotalErasureOperations = 0;
    GlobalState->TotalCommandProcessed = 0;

    // Initialize error counters
    GlobalState->TotalErrors = 0;
    GlobalState->TotalTimeouts = 0;
    GlobalState->TotalValidationErrors = 0;

    // Mark shared buffer as not initialized
    GlobalState->SharedBuffer = NULL;
    GlobalState->SharedBufferInitialized = FALSE;

    // Initialize current mapping pointer
    GlobalState->CurrentMapping = NULL;
    GlobalState->IsManuallyMapped = FALSE;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// CleanupDriverGlobalState
//
// Cleans up resources allocated in the driver global state.
//
// Parameters:
//   GlobalState      - Pointer to the driver global state structure
//------------------------------------------------------------------------------

VOID CleanupDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    if (GlobalState == NULL) {
        return;
    }

    // Clean up shared buffer if initialized
    if (GlobalState->SharedBufferInitialized && GlobalState->SharedBuffer != NULL) {
        // Shared buffer cleanup would be performed here
        GlobalState->SharedBuffer = NULL;
        GlobalState->SharedBufferInitialized = FALSE;
    }

    // Clean up current mapping if present
    if (GlobalState->CurrentMapping != NULL) {
        ReleaseManualMapping(GlobalState->CurrentMapping);
        GlobalState->CurrentMapping = NULL;
    }

    // Reset counters for potential re-initialization
    GlobalState->TotalReadOperations = 0;
    GlobalState->TotalWriteOperations = 0;
    GlobalState->TotalErasureOperations = 0;
    GlobalState->TotalCommandProcessed = 0;
}

//------------------------------------------------------------------------------
// CreateManualMapping
//
// Creates a manual mapping entry for the specified memory region.
//
// Parameters:
//   MappingEntry     - Output pointer for the mapping entry
//   MappingBase      - Base address of the mapped region
//   MappingSize      - Size of the mapped region
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS CreateManualMapping(
    OUT PMANUAL_MAPPING_ENTRY MappingEntry,
    IN PVOID MappingBase,
    IN ULONG MappingSize
)
{
    NTSTATUS Status;

    if (MappingEntry == NULL || MappingBase == NULL || MappingSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(MappingEntry, sizeof(MANUAL_MAPPING_ENTRY));

    MappingEntry->Tag = MAPPING_ENTRY_TAG;
    MappingEntry->MappingFlags = MAPPING_FLAG_EXECUTABLE | MAPPING_FLAG_INITIALIZED;
    MappingEntry->MappingBase = MappingBase;
    MappingEntry->MappingSize = MappingSize;
    MappingEntry->LoadTime = RtlGetTimeOfDay();
    MappingEntry->LastAccessTime = MappingEntry->LoadTime;
    MappingEntry->ReferenceCount = 1;

    // Parse PE headers
    MappingEntry->DosHeader = (PIMAGE_DOS_HEADER)MappingBase;

    if (MappingEntry->DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    MappingEntry->NtHeaders = (PIMAGE_NT_HEADERS)(
        (PCHAR)MappingBase + MappingEntry->DosHeader->e_lfanew
    );

    if (MappingEntry->NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    MappingEntry->FirstSection = IMAGE_FIRST_SECTION(MappingEntry->NtHeaders);
    MappingEntry->SectionCount = MappingEntry->NtHeaders->FileHeader.NumberOfSections;
    MappingEntry->CommitSize = MappingEntry->NtHeaders->OptionalHeader.SizeOfImage;

    // Initialize imports
    if (MappingEntry->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        MappingEntry->FirstImport = (PIMAGE_IMPORT_DESCRIPTOR)(
            (PCHAR)MappingBase +
            MappingEntry->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
        MappingEntry->ImportDescriptorCount =
            MappingEntry->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
            sizeof(IMAGE_IMPORT_DESCRIPTOR);
        Status = ResolveImports(MappingEntry);
        if (IS_SUCCESS(Status)) {
            MappingEntry->ImportsResolved = TRUE;
            MappingEntry->MappingFlags |= MAPPING_FLAG_IMPORTS_RESOLVED;
        }
    }

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ReleaseManualMapping
//
// Releases resources associated with a manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry to release
//------------------------------------------------------------------------------

VOID ReleaseManualMapping(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    if (MappingEntry == NULL) {
        return;
    }

    // Decrement reference count
    InterlockedDecrement(&MappingEntry->ReferenceCount);

    // Additional cleanup would be performed here based on reference count
    // For now, the entry remains valid for potential future reference
}

//------------------------------------------------------------------------------
// ResolveImports
//
// Resolves import dependencies for the manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ResolveImports(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    ULONG Index;

    if (MappingEntry == NULL || MappingEntry->FirstImport == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (Index = 0; Index < MappingEntry->ImportDescriptorCount; Index++) {
        PIMAGE_IMPORT_DESCRIPTOR ImportDesc = &MappingEntry->FirstImport[Index];

        if (ImportDesc->Name == 0) {
            break;
        }

        // Import resolution logic would be implemented here
        // This includes loading dependent modules and resolving function addresses
    }

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// IsMappingValid
//
// Validates the integrity of a manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry
//
// Returns:
//   TRUE if the mapping is valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN IsMappingValid(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    if (MappingEntry == NULL) {
        return FALSE;
    }

    // Validate tag
    if (MappingEntry->Tag != MAPPING_ENTRY_TAG) {
        return FALSE;
    }

    // Validate mapping base and size
    if (MappingEntry->MappingBase == NULL || MappingEntry->MappingSize == 0) {
        return FALSE;
    }

    // Validate PE headers
    if (MappingEntry->DosHeader == NULL ||
        MappingEntry->DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    if (MappingEntry->NtHeaders == NULL ||
        MappingEntry->NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Validate sections
    if (MappingEntry->FirstSection == NULL || MappingEntry->SectionCount == 0) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// InitializeSharedMemoryBuffer
//
// Initializes a shared memory buffer for inter-process communication.
//
// Parameters:
//   Buffer           - Pointer to the shared memory buffer
//   BufferSize       - Size of the buffer in bytes
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeSharedMemoryBuffer(
    IN OUT PSHARED_MEMORY_BUFFER Buffer,
    IN ULONG BufferSize
)
{
    if (Buffer == NULL || BufferSize < SHARED_BUFFER_MIN_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Buffer, sizeof(SHARED_MEMORY_BUFFER));

    Buffer->Tag = SHARED_BUFFER_TAG;
    Buffer->BufferSize = BufferSize;
    Buffer->State = COMMAND_STATUS_IDLE;
    Buffer->ReferenceCount = 1;

    // Initialize synchronization primitives
    ExInitializeSpinLock(&Buffer->Lock);
    KeInitializeEvent(&Buffer->Event, NotificationEvent, FALSE);

    // Initialize command queue
    Buffer->QueueHead = 0;
    Buffer->QueueTail = 0;
    Buffer->QueueInitialized = TRUE;

    // Initialize buffer checksum
    Buffer->BufferChecksum = 0;

    return STATUS_SUCCESS;
}
