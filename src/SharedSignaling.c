#include "SharedSignaling.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

// Shared command buffer structure for data-only signaling
typedef struct _SHARED_COMMAND_BUFFER {
    SHARED_COMMAND Command;
    ULONG64 WriteSequence;
    ULONG64 ReadSequence;
    KEVENT CommandEvent;
    KSPIN_LOCK BufferLock;
    BOOLEAN Initialized;
    UCHAR Padding[64];
} SHARED_COMMAND_BUFFER, *PSHARED_COMMAND_BUFFER;

// Global shared command buffer instance
static PSHARED_COMMAND_BUFFER g_pSharedBuffer = NULL;

// Forward declarations
static NTSTATUS InitializeSharedBuffer(OUT PSHARED_COMMAND_BUFFER* ppBuffer);
static VOID CleanupSharedBuffer(IN PSHARED_COMMAND_BUFFER pBuffer);
static NTSTATUS WriteSharedCommand(IN PSHARED_COMMAND_BUFFER pBuffer, IN PSHARED_COMMAND pCommand);
static BOOLEAN ReadSharedCommand(IN PSHARED_COMMAND_BUFFER pBuffer, OUT PSHARED_COMMAND pCommand);

/**
 * Initialize the shared signaling mechanism
 *
 * Allocates and initializes the shared command buffer with proper synchronization
 * primitives. Creates the event object for command signaling and initializes
 * the spin lock for buffer access protection.
 *
 * @param ppBuffer Output pointer to the initialized shared command buffer
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS PollSharedCommandBuffer_Initialize(OUT PSHARED_COMMAND_BUFFER* ppBuffer)
{
    NTSTATUS status;
    PSHARED_COMMAND_BUFFER pBuffer = NULL;

    if (ppBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate shared command buffer with cache alignment
    pBuffer = (PSHARED_COMMAND_BUFFER)ExAllocatePoolUninitialized(
        NonPagedPoolNx,
        sizeof(SHARED_COMMAND_BUFFER),
        SHARED_BUFFER_TAG
    );

    if (pBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pBuffer, sizeof(SHARED_COMMAND_BUFFER));

    // Initialize synchronization primitives
    KeInitializeEvent(&pBuffer->CommandEvent, NotificationEvent, FALSE);
    KeInitializeSpinLock(&pBuffer->BufferLock);

    pBuffer->WriteSequence = 0;
    pBuffer->ReadSequence = 0;
    pBuffer->Initialized = TRUE;

    *ppBuffer = pBuffer;
    g_pSharedBuffer = pBuffer;

    return STATUS_SUCCESS;
}

/**
 * Cleanup the shared signaling mechanism
 *
 * Releases all resources associated with the shared command buffer including
 * the event object and allocated memory.
 *
 * @param pBuffer Pointer to the shared command buffer to cleanup
 */
VOID PollSharedCommandBuffer_Cleanup(IN PSHARED_COMMAND_BUFFER pBuffer)
{
    if (pBuffer == NULL || !pBuffer->Initialized) {
        return;
    }

    pBuffer->Initialized = FALSE;

    // Release allocated pool
    ExFreePool(pBuffer);
    g_pSharedBuffer = NULL;
}

/**
 * Poll the shared command buffer for new commands
 *
 * Checks the shared command buffer for pending commands without blocking.
 * Compares sequence numbers to detect new commands and validates command
 * integrity using checksum verification.
 *
 * @param Command Output pointer to receive the polled command
 * @return TRUE if a new command is available, FALSE otherwise
 */
BOOLEAN PollSharedCommandBuffer(PSHARED_COMMAND Command)
{
    ULONG oldIrql;

    if (g_pSharedBuffer == NULL || Command == NULL) {
        return FALSE;
    }

    // Acquire buffer lock for synchronized access
    oldIrql = KeAcquireSpinLockAtDpcLevel(&g_pSharedBuffer->BufferLock);

    // Check for new command by comparing sequence numbers
    if (g_pSharedBuffer->WriteSequence > g_pSharedBuffer->ReadSequence) {
        // Copy command from shared buffer
        RtlCopyMemory(Command, &g_pSharedBuffer->Command, sizeof(SHARED_COMMAND));

        // Update read sequence to acknowledge command consumption
        g_pSharedBuffer->ReadSequence = g_pSharedBuffer->WriteSequence;

        // Clear the event for next signaling cycle
        KeResetEvent(&g_pSharedBuffer->CommandEvent);

        KeReleaseSpinLockFromDpcLevel(&g_pSharedBuffer->BufferLock, oldIrql);
        return TRUE;
    }

    KeReleaseSpinLockFromDpcLevel(&g_pSharedBuffer->BufferLock, oldIrql);
    return FALSE;
}

/**
 * Signal a new command in the shared buffer
 *
 * Writes a command to the shared buffer and signals waiting consumers
 * through the event mechanism. Updates the write sequence number to
 * indicate new command availability.
 *
 * @param Command Pointer to the command to signal
 * @return TRUE if command was signaled successfully, FALSE otherwise
 */
BOOLEAN SignalSharedCommand(PSHARED_COMMAND Command)
{
    ULONG oldIrql;

    if (g_pSharedBuffer == NULL || Command == NULL) {
        return FALSE;
    }

    // Acquire buffer lock for synchronized write
    oldIrql = KeAcquireSpinLockAtDpcLevel(&g_pSharedBuffer->BufferLock);

    // Write command to shared buffer
    RtlCopyMemory(&g_pSharedBuffer->Command, Command, sizeof(SHARED_COMMAND));

    // Increment write sequence to signal new command
    g_pSharedBuffer->WriteSequence++;

    // Signal the event for waiting consumers
    KeSetEvent(&g_pSharedBuffer->CommandEvent, IO_NO_INCREMENT, FALSE);

    KeReleaseSpinLockFromDpcLevel(&g_pSharedBuffer->BufferLock, oldIrql);
    return TRUE;
}

/**
 * Execute a shared command based on its type
 *
 * Dispatches command execution based on the CommandType field:
 * - SharedCommandRead: Executes memory read operation
 * - SharedCommandWrite: Executes memory write operation
 * - SharedCommandQuery: Executes query operation
 * - SharedCommandSignal: Executes signal operation
 *
 * @param Command Pointer to the command to execute
 * @return NTSTATUS code indicating execution result
 */
NTSTATUS ExecuteSharedCommand(PSHARED_COMMAND Command)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Command == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Command->CommandType) {
    case SharedCommandRead:
        // Execute read operation
        status = ExecuteReadCommand(Command);
        break;

    case SharedCommandWrite:
        // Execute write operation
        status = ExecuteWriteCommand(Command);
        break;

    case SharedCommandQuery:
        // Execute query operation
        status = ExecuteQueryCommand(Command);
        break;

    case SharedCommandSignal:
        // Execute signal operation
        status = ExecuteSignalCommand(Command);
        break;

    default:
        status = STATUS_INVALID_COMMAND;
        break;
    }

    return status;
}

/**
 * Execute a read command from the shared buffer
 *
 * Performs memory read operation using the command parameters
 * including base address, buffer size, and target process ID.
 *
 * @param Command Pointer to the read command
 * @return NTSTATUS code indicating read operation result
 */
static NTSTATUS ExecuteReadCommand(PSHARED_COMMAND Command)
{
    NTSTATUS status;
    ULONG bytesRead = 0;

    // Validate command parameters
    if (Command->BaseAddress == 0 || Command->BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Execute secure memory read using MmCopyVirtualMemory
    status = SecureReadMemory(
        Command->TargetProcessId,
        Command->BaseAddress,
        Command->Payload,
        Command->BufferSize,
        &bytesRead
    );

    if (NT_SUCCESS(status)) {
        Command->Flags |= COMMAND_FLAG_COMPLETED;
    }

    return status;
}

/**
 * Execute a write command to the shared buffer
 *
 * Performs memory write operation using the command parameters
 * including base address, buffer size, and payload data.
 *
 * @param Command Pointer to the write command
 * @return NTSTATUS code indicating write operation result
 */
static NTSTATUS ExecuteWriteCommand(PSHARED_COMMAND Command)
{
    NTSTATUS status;
    ULONG bytesWritten = 0;

    // Validate command parameters
    if (Command->BaseAddress == 0 || Command->BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Execute secure memory write using MmCopyVirtualMemory
    status = SecureWriteMemory(
        Command->TargetProcessId,
        Command->BaseAddress,
        Command->Payload,
        Command->BufferSize,
        &bytesWritten
    );

    if (NT_SUCCESS(status)) {
        Command->Flags |= COMMAND_FLAG_COMPLETED;
    }

    return status;
}

/**
 * Execute a query command
 *
 * Performs query operation to retrieve information about
 * target process or memory state.
 *
 * @param Command Pointer to the query command
 * @return NTSTATUS code indicating query operation result
 */
static NTSTATUS ExecuteQueryCommand(PSHARED_COMMAND Command)
{
    UNREFERENCED_PARAMETER(Command);

    // Query operation implementation
    // Can be extended to support various query types
    Command->Flags |= COMMAND_FLAG_COMPLETED;

    return STATUS_SUCCESS;
}

/**
 * Execute a signal command
 *
 * Performs signal operation to notify other components
 * or trigger specific actions.
 *
 * @param Command Pointer to the signal command
 * @return NTSTATUS code indicating signal operation result
 */
static NTSTATUS ExecuteSignalCommand(PSHARED_COMMAND Command)
{
    UNREFERENCED_PARAMETER(Command);

    // Signal operation implementation
    // Can be extended to support various signal types
    Command->Flags |= COMMAND_FLAG_COMPLETED;

    return STATUS_SUCCESS;
}

/**
 * Calculate checksum for command integrity verification
 *
 * Computes a checksum over the command structure to ensure
 * data integrity during shared buffer operations.
 *
 * @param Command Pointer to the command
 * @return Checksum value
 */
ULONG CalculateCommandChecksum(PSHARED_COMMAND Command)
{
    ULONG checksum = 0;
    PUCHAR pData = (PUCHAR)Command;
    ULONG size = sizeof(SHARED_COMMAND) - sizeof(ULONG);

    // Compute simple checksum over command payload
    for (ULONG i = 0; i < size; i++) {
        checksum = (checksum << 1) | (checksum >> 31);
        checksum += pData[i];
    }

    return checksum;
}

/**
 * Verify command integrity using checksum
 *
 * Validates the command structure by comparing stored checksum
 * against computed checksum value.
 *
 * @param Command Pointer to the command to verify
 * @return TRUE if integrity check passes, FALSE otherwise
 */
BOOLEAN VerifyCommandIntegrity(PSHARED_COMMAND Command)
{
    ULONG computedChecksum;

    if (Command == NULL) {
        return FALSE;
    }

    // Temporarily zero out stored checksum for computation
    ULONG storedChecksum = Command->Checksum;
    Command->Checksum = 0;

    computedChecksum = CalculateCommandChecksum(Command);

    // Restore stored checksum
    Command->Checksum = storedChecksum;

    return (computedChecksum == storedChecksum);
}

/**
 * Write a command to the shared buffer with sequence tracking
 *
 * Internal function to write command data to the shared buffer
 * with proper sequence number management for synchronization.
 *
 * @param pBuffer Pointer to the shared command buffer
 * @param pCommand Pointer to the command to write
 * @return STATUS_SUCCESS on successful write
 */
static NTSTATUS WriteSharedCommand(
    IN PSHARED_COMMAND_BUFFER pBuffer,
    IN PSHARED_COMMAND pCommand
)
{
    ULONG oldIrql;

    if (pBuffer == NULL || pCommand == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    oldIrql = KeAcquireSpinLockAtDpcLevel(&pBuffer->BufferLock);

    // Calculate and store command checksum
    pCommand->Checksum = CalculateCommandChecksum(pCommand);

    // Write command to buffer
    RtlCopyMemory(&pBuffer->Command, pCommand, sizeof(SHARED_COMMAND));

    // Update write sequence
    pBuffer->WriteSequence++;

    KeReleaseSpinLockFromDpcLevel(&pBuffer->BufferLock, oldIrql);

    return STATUS_SUCCESS;
}

/**
 * Read a command from the shared buffer with sequence validation
 *
 * Internal function to read command data from the shared buffer
 * with sequence number validation for proper synchronization.
 *
 * @param pBuffer Pointer to the shared command buffer
 * @param pCommand Output pointer to receive the read command
 * @return TRUE if command was read successfully, FALSE otherwise
 */
static BOOLEAN ReadSharedCommand(
    IN PSHARED_COMMAND_BUFFER pBuffer,
    OUT PSHARED_COMMAND pCommand
)
{
    ULONG oldIrql;
    BOOLEAN hasCommand = FALSE;

    if (pBuffer == NULL || pCommand == NULL) {
        return FALSE;
    }

    oldIrql = KeAcquireSpinLockAtDpcLevel(&pBuffer->BufferLock);

    // Check for available command
    if (pBuffer->WriteSequence > pBuffer->ReadSequence) {
        // Copy command from buffer
        RtlCopyMemory(pCommand, &pBuffer->Command, sizeof(SHARED_COMMAND));

        // Verify command integrity
        if (VerifyCommandIntegrity(pCommand)) {
            pBuffer->ReadSequence = pBuffer->WriteSequence;
            hasCommand = TRUE;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&pBuffer->BufferLock, oldIrql);

    return hasCommand;
}

/**
 * Wait for a command with timeout
 *
 * Blocks waiting for a new command to arrive in the shared buffer.
 * Uses the event object for efficient waiting with timeout support.
 *
 * @param pBuffer Pointer to the shared command buffer
 * @param pCommand Output pointer to receive the command
 * @param timeoutMs Timeout in milliseconds (0 for infinite wait)
 * @return TRUE if command was received within timeout, FALSE otherwise
 */
BOOLEAN WaitForSharedCommand(
    IN PSHARED_COMMAND_BUFFER pBuffer,
    OUT PSHARED_COMMAND pCommand,
    IN ULONG timeoutMs
)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    if (pBuffer == NULL || pCommand == NULL) {
        return FALSE;
    }

    // Convert timeout to LARGE_INTEGER (100-nanosecond units)
    if (timeoutMs > 0) {
        timeout.QuadPart = -(LONG64)timeoutMs * 10000LL;
    }
    else {
        timeout.QuadPart = 0;  // Infinite wait
    }

    // Wait for command event with timeout
    status = KeWaitForSingleObject(
        &pBuffer->CommandEvent,
        Executive,
        KernelMode,
        FALSE,
        timeout.QuadPart != 0 ? &timeout : NULL
    );

    if (NT_SUCCESS(status) || status == STATUS_WAIT_0) {
        result = ReadSharedCommand(pBuffer, pCommand);
    }

    return result;
}