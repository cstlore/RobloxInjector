# Kronos Framework

## Advanced Ring 0 to Ring 3 Stealth Execution and Injection Ecosystem

## Abstract

**Kronos** is a next-generation kernel-level framework designed for covert execution and stealth injection on Windows 10/11 x64 architectures. Built for advanced security research, red team operations, and defensive analysis, Kronos establishes a sophisticated bridge between user-mode injectors and kernel-mode execution primitives while maintaining an intentionally minimized detection surface.

The framework leverages manual PE mapping, trace erasure, and direct process manipulation to achieve transparent operation across the Ring 0/Ring 3 boundary without relying on traditional driver loading mechanisms or standard I/O Control interfaces.

---

## Core Architecture

Kronos employs a four-layer architecture designed for minimal footprint and maximal operational security:

### 1. Kernel Bridge (StealthDriver)

A custom kernel-mode driver loaded via manual PE mapping, bypassing standard Windows driver enumeration mechanisms:

- **Manual Mapping**: Avoids `IoCreateDriver`, `DriverEntry`, and standard device object creation
- **StealthEraser Module**: Clears process identification traces from:
  - **PiDDB Cache**: Process Identifier Database entry removal
  - **MmUnloadedDrivers**: Erasure of driver load/unload history
- **Trace Erasure**: Systematic removal of driver signatures from memory structures

### 2. Covert Communication (SharedSignaling)

Data-only inter-process communication channel operating without traditional I/O interfaces:

- **Shared Memory Buffer**: Page-aligned, zero-copy communication medium
- **Sequence Number Protocol**: Event-driven signaling with deterministic ordering
- **Zero IOCTL Design**: No `DeviceIoControl` calls or dispatch routines
- **Handle Transparency**: No persistent open handles visible in process handle tables

### 3. User-Mode Payload

Advanced injection and persistence mechanisms:

- **ModuleOverloading**: Hijacks legitimate DLL `.text` sections for payload embedding
- **HeaderScrubbing**: Post-mapping PE header normalization:
  - DOS header signature obfuscation
  - NT headers trace removal
  - Section characteristic optimization
  - Data directory stealth configuration

### 4. Execution Engine (ProcessContext)

Direct kernel process manipulation with architecture-compliant execution primitives:

- **KPROCESS Manipulation**: Direct modification of process structures
- **ProcessInstrumentationCallback Hijacking**: Hooks the `_KPROCESS.ProcessInstrumentationCallback` field (offset `0x28`)
- **x64 ABI Compliance**: Assembly stubs conforming to Microsoft x64 calling conventions:
  - Shadow space reservation (32 bytes)
  - Caller-saved register preservation
  - 16-byte stack alignment
  - Deferred return for callback chain continuity

---

## Key Features

### No-CRT Design

Complete avoidance of the C Runtime library ensures:

- Eliminated dependencies on standard library initialization
- Reduced attack surface by removing CRT export signatures
- Fully deterministic memory allocation via `ExAllocatePool` and `RtlSecureZeroMemory`

### Atomic Operations

Kernel-synchronized operations utilizing:

- Interlocked primitives for lock-free state transitions
- Reference counting for shared resource lifecycle management
- Memory barriers ensuring ordering guarantees across CPUs

### Anti-Forensics Capabilities

Comprehensive detection avoidance:

- **Process Trace Erasure**: Selective clearing of process enumeration artifacts
- **Driver History Sanitization**: Removal from unloaded driver tracking structures
- **Header Normalization**: PE structural modification for signature evasion
- **Memory Layout Optimization**: Section alignment and characteristic flag standardization

---

## Prerequisites

### Development Environment

| Component | Specification |
|-----------|---------------|
| **Operating System** | Windows 10/11 x64 |
| **Windows SDK** | 10.0.19041.0 or later |
| **Windows Driver Kit (WDK)** | Matching SDK version |
| **Compiler** | Microsoft Visual C++ (`cl.exe`) |
| **Assembler** | Microsoft Macro Assembler (`ml64.exe`) |
| **Build Tools** | Developer Command Prompt for VS or equivalent environment |

### Test Environment

- **Driver Signature Enforcement**: Disabled (Test Signing Mode)
- **Virtualization-Based Security (VBS)**: Configured for kernel research
- **Antivirus/EDR**: Temporarily suspended during evaluation

---

## Build Instructions

Kronos provides a streamlined build process via `build.bat`:

```batch
build.bat
```

The build script orchestrates:

1. Environment initialization (WDK/SDK paths)
2. C source compilation with `/O2 /EHsc /Zi` optimization flags
3. MASM assembly compilation for x64 ABI stubs
4. Linking into final driver binary

All source files reside in `src/` with associated headers, while assembly modules are contained in `asm/`.

---

## Usage

### Deployment Sequence

1. **Kernel Driver Mapping**
   - Execute the mapping routine to load `StealthDriver` into kernel space
   - Manual memory allocation and PE header parsing occur without standard driver entry

2. **Shared Memory Initialization**
   - Establish shared buffer between kernel and user modes
   - Sequence number protocol becomes active for signaling

3. **Injector Execution**
   - Launch user-mode injector to initiate `ModuleOverloading`
   - `HeaderScrubbing` applies post-mapping trace erasure

4. **Process Hijacking**
   - Target process identified and `KPROCESS` structure accessed
   - `ProcessInstrumentationCallback` installed with ASM stub entry

5. **Payload Execution**
   - Covert payload execution via hijacked callback
   - Communication maintained through `SharedSignaling` channel

---

## Disclaimer

> **Educational and Research Use Only**
>
> The Kronos Framework is designed exclusively for educational purposes, reverse engineering studies, and advanced threat research. This framework demonstrates kernel-level techniques including manual driver mapping, process structure manipulation, and covert execution mechanisms.
>
> This implementation is intended for:
> - Academic and security research environments
> - Red team methodology development and validation
> - Defensive capability assessment and detection engineering
> - System internals education and Windows kernel study
>
> Not intended for production deployment or commercial use without additional engineering, testing, and compliance validation.
>
> Users should evaluate and adapt all techniques within their specific operational contexts, security requirements, and compliance frameworks.

---

## Source Structure

```text
Kronos/
├── src/
│   ├── BaseRelocation.c/h       # Import address rebasing
│   ├── Constants.h              # Global definitions and identifiers
│   ├── HeaderScrubbing.c/h      # PE header trace erasure
│   ├── ImportTable.c/h          # Import Address Table resolution
│   ├── MemoryOperations.c/h     # Manual mapping and memory management
│   ├── ModuleOverloading.c/h    # DLL section payload embedding
│   ├── ProcessContext.c/h       # KPROCESS manipulation
│   ├── SharedSignaling.c/h      # Shared memory IPC
│   ├── StealthDriver.c/h        # Main driver entry and mapping
│   ├── StealthEraser.c/h        # PiDDB and MmUnloadedDrivers clearing
│   └── TypeDefinitions.h        # Core type definitions
├── asm/
│   └── x64_abi_stubs.asm        # ABI-compliant assembly primitives
├── ProcessInstrumentationCallback/
│   └── ProcessInstrumentation.h # Callback research documentation
└── build.bat                    # Build automation script
```

---

## Footer

**Kronos Framework — Ring 0 to Ring 3 Stealth Execution Ecosystem**  
For the advancement of defensive security research and operational excellence
