#pragma once

/*
 * Stealth Kernel Driver - Constants
 *
 * Contains driver identifiers, command types, memory operation constants,
 * and erasure constants for the stealth memory operations driver.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

//------------------------------------------------------------------------------
// Driver Identifiers
//------------------------------------------------------------------------------

#define STEALTH_DRIVER_TAG            'SMLT'  // SMLT = Stealth
#define SHARED_BUFFER_TAG             'SGNL'  // SGNL = Signaling
#define MEMORY_OPERATION_TAG          'MMOP'  // MMOP = Memory Operation
#define ERASER_OPERATION_TAG          'ERAS'  // ERAS = Eraser

//------------------------------------------------------------------------------
// Driver Version
//------------------------------------------------------------------------------

#define STEALTH_DRIVER_MAJOR_VERSION  1
#define STEALTH_DRIVER_MINOR_VERSION  0
#define STEALTH_DRIVER_BUILD_NUMBER   1

//------------------------------------------------------------------------------
// Shared Command Types
//------------------------------------------------------------------------------

#define SHARED_COMMAND_READ           0x00000001
#define SHARED_COMMAND_WRITE          0x00000002
#define SHARED_COMMAND_QUERY          0x00000003
#define SHARED_COMMAND_SIGNAL         0x00000004
#define SHARED_COMMAND_READ_WRITE     0x00000005

//------------------------------------------------------------------------------
// Command Status Flags
//------------------------------------------------------------------------------

#define COMMAND_STATUS_IDLE           0x00000000
#define COMMAND_STATUS_PENDING        0x00000001
#define COMMAND_STATUS_PROCESSING     0x00000002
#define COMMAND_STATUS_COMPLETED      0x00000003
#define COMMAND_STATUS_ERROR          0x00000004

//------------------------------------------------------------------------------
// Memory Operation Constants
//------------------------------------------------------------------------------

#define PAGE_SIZE                     0x1000
#define PAGE_SIZE_SHIFT               12
#define MAX_BUFFER_SIZE               0x100000  // 1MB
#define MAX_PAYLOAD_SIZE              0x100      // 256 bytes inline payload
#define MAX_MEMORY_MIRROR_SIZE        0x10000000 // 256MB

// Memory protection flags (aligned with Windows PAGE_* constants)
#define MEMORY_PROTECT_READ_ONLY      0x02      // PAGE_READONLY
#define MEMORY_PROTECT_READ_WRITE     0x04      // PAGE_READWRITE
#define MEMORY_PROTECT_EXECUTE        0x10      // PAGE_EXECUTE
#define MEMORY_PROTECT_EXECUTE_READ   0x20      // PAGE_EXECUTE_READ

//------------------------------------------------------------------------------
// Process Management Constants
//------------------------------------------------------------------------------

#define MAX_PROCESS_COUNT             256
#define MAX_PROCESS_NAME_LENGTH       256
#define PROCESS_HANDLE_CACHE_SIZE     64

//------------------------------------------------------------------------------
// Erasure Constants
//------------------------------------------------------------------------------

#define HASH_BUCKET_SIZE              65536
#define HASH_BUCKET_COUNT             16
#define CACHE_ENTRY_SIZE              0x80      // 128 bytes per cache entry
#define UNLOADED_DRIVER_MAX           256
#define MAX_DEVICE_PATH_LENGTH        512

// Erasure operation flags
#define ERASURE_FLAG_PIDDDB_CACHE     0x00000001
#define ERASURE_FLAG_HASH_BUCKET      0x00000002
#define ERASURE_FLAG_UNLOADED_DRIVER  0x00000004
#define ERASURE_FLAG_ALL              0xFFFFFFFF

//------------------------------------------------------------------------------
// Shared Memory Buffer Configuration
//------------------------------------------------------------------------------

#define SHARED_BUFFER_MIN_SIZE        0x1000    // 4KB minimum
#define SHARED_BUFFER_MAX_SIZE        0x100000  // 1MB maximum
#define SHARED_BUFFER_DEFAULT_SIZE    0x4000    // 16KB default
#define SHARED_BUFFER_ALIGNMENT       0x1000    // Page-aligned

// Shared buffer section flags
#define BUFFER_FLAG_VALID             0x00000001
#define BUFFER_FLAG_DIRTY             0x00000002
#define BUFFER_FLAG_ENCRYPTED         0x00000004
#define BUFFER_FLAG_COMPRESSED        0x00000008

//------------------------------------------------------------------------------
// Polling Configuration
//------------------------------------------------------------------------------

#define POLL_INTERVAL_MIN_MS          1         // Minimum 1ms
#define POLL_INTERVAL_DEFAULT_MS      10        // Default 10ms
#define POLL_INTERVAL_MAX_MS          1000      // Maximum 1000ms
#define POLL_TIMEOUT_MS               5000      // 5 second timeout

//------------------------------------------------------------------------------
// Checksum Constants
//------------------------------------------------------------------------------

#define CHECKSUM_ALGORITHM_CRC32      1
#define CHECKSUM_ALGORITHM_CRC64      2
#define CHECKSUM_ALGORITHM_SHA256     3
#define DEFAULT_CHECKSUM_ALGORITHM    CHECKSUM_ALGORITHM_CRC32

//------------------------------------------------------------------------------
// Manual Mapping Constants
//------------------------------------------------------------------------------

#define MAPPING_ENTRY_TAG             'MAPN'    // MAPPING
#define MIN_MAPPING_SIZE              0x1000
#define MAX_MAPPING_SIZE              0x10000000 // 256MB

// Mapping flags
#define MAPPING_FLAG_EXECUTABLE       0x00000001
#define MAPPING_FLAG_INITIALIZED      0x00000002
#define MAPPING_FLAG_IMPORTS_RESOLVED 0x00000004
#define MAPPING_FLAG_DELAYED_LOAD     0x00000008

//------------------------------------------------------------------------------
// NT Status Code Helpers
//------------------------------------------------------------------------------

#define IS_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define IS_PENDING(Status) (((NTSTATUS)(Status)) == STATUS_PENDING)
#define IS_INFO(Status) ((((ULONG)(Status)) >= 0x40000000) && \
                         (((ULONG)(Status)) <= 0x7FFFFFFF))
#define IS_WARNING(Status) ((((ULONG)(Status)) >= 0x80000000) && \
                            (((ULONG)(Status)) <= 0xBFFFFFFF))
#define IS_ERROR(Status) ((((ULONG)(Status)) >= 0xC0000000) && \
                          (((ULONG)(Status)) <= 0xDFFFFFFF))

//------------------------------------------------------------------------------
// Utility Macros
//------------------------------------------------------------------------------

// Alignment macros
#define ALIGN_DOWN(Value, Alignment) \
    ((Value) & ~((Alignment) - 1))

#define ALIGN_UP(Value, Alignment) \
    ALIGN_DOWN((Value) + (Alignment) - 1, (Alignment))

#define ALIGN_UP_POINTER(Value, Alignment) \
    ((PVOID)ALIGN_UP((ULONG64)(Value), (Alignment)))

// Container-of macros
#define FIELD_OFFSET(Type, Field) \
    ((ULONG)(&(((Type *)0)->Field)))

#define CONTAINING_RECORD(Address, Type, Field) \
    ((Type *)((PCHAR)(Address) - (PCHAR)(&(Type *)0)->Field))

// Buffer size calculations
#define SIZEOF_ARRAY(Array) \
    (sizeof(Array) / sizeof((Array)[0]))

#define BUFFER_ENTRY_SIZE(Index, ElementSize) \
    ((Index) * (ElementSize))
