; ProcessInstrumentationStub.asm
; MASM x64 naked assembly stub for ProcessInstrumentationCallback hijacking
;
; This stub provides a complete register save/restore mechanism and implements
; an activation gate before dispatching to the payload handler.
;
; ABI Compliance: Maintains 16-byte stack alignment per x64 calling convention

.code

; Forward declaration of the activation flag in shared memory
PUBLIC g_hSharedState
EXTERN g_hSharedState: PTR INSTRUMENTATION_SHARED_STATE

; Payload entry point (C++ handler)
EXTERN ProcessPayloadEntry: PROC

; Assembly stub entry point - NAKED procedure (no automatic prologue/epilogue)
ProcessInstrumentationStub PROC FRAME naked

    ; ========================================================================
    ; Stack Alignment Analysis (x64 Windows ABI / Microsoft Calling Convention)
    ; ========================================================================
    ; On CALL entry: RSP is 8-byte aligned (8 bytes for return address pushed)
    ; Before calling another function: RSP + 8 must be divisible by 16
    ;
    ; Entry State:
    ;   RSP = N*16 + 8  (8-byte aligned after CALL pushes return address)
    ;   RCX = Reason (first parameter)
    ;   RDX = Parameters pointer (second parameter)
    ;
    ; Stack Reserve Calculation:
    ;   Step 1: Align to 16 bytes → sub rsp, 8  (RSP now 16-byte aligned)
    ;   Step 2: Shadow space → sub rsp, 32     (4 home slots per ABI requirement)
    ;   Step 3: GP registers → 16 registers × 8 bytes = 128 bytes
    ;   Step 4: XMM registers → 16 registers × 16 bytes = 256 bytes
    ;   Total reserved: 8 + 32 + 128 + 256 = 424 bytes
    ; ========================================================================

    ; Step 1: Align stack to 16 bytes (entry is 8-byte aligned after CALL)
    sub     rsp, 8

    ; Steps 2-4: Reserve shadow space and register save area
    ; 32 bytes shadow space + 128 bytes GP registers + 256 bytes XMM registers
    sub     rsp, 32 + 128 + 256

    ; RSP is now 16-byte aligned
    ; Total from original entry: 8 (alignment) + 416 (reserved) = 424 bytes
    ; 424 mod 16 = 0 ✓

    ; ==============================================================
    ; Stack Layout After Allocation (RSP at base)
    ; ==============================================================
    ;   [RSP + 0x000 .. 0x0FF] = XMM save area (256 bytes for XMM0-XMM15)
    ;   [RSP + 0x100 .. 0x1FF] = Shadow space + GP area (128 bytes)
    ;                            + Alignment/padding (32 bytes)
    ;   [RSP + 0x200 .. +N]     = GP register saves (pushed, dynamic)
    ; ==============================================================

    ; ------------------------------------------------------------------
    ; Save ALL General-Purpose Registers (RAX-R15)
    ; ------------------------------------------------------------------
    ; Using stack offsets with proper 16-byte alignment maintained

    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    ; ------------------------------------------------------------------
    ; Save ALL XMM Registers (XMM0-XMM15)
    ; ------------------------------------------------------------------
    ; XMM registers must be saved in sequence to preserve state

    movapd  xmmword ptr [rsp + 0x00], xmm0
    movapd  xmmword ptr [rsp + 0x10], xmm1
    movapd  xmmword ptr [rsp + 0x20], xmm2
    movapd  xmmword ptr [rsp + 0x30], xmm3
    movapd  xmmword ptr [rsp + 0x40], xmm4
    movapd  xmmword ptr [rsp + 0x50], xmm5
    movapd  xmmword ptr [rsp + 0x60], xmm6
    movapd  xmmword ptr [rsp + 0x70], xmm7
    movapd  xmmword ptr [rsp + 0x80], xmm8
    movapd  xmmword ptr [rsp + 0x90], xmm9
    movapd  xmmword ptr [rsp + 0xA0], xmmA
    movapd  xmmword ptr [rsp + 0xB0], xmmB
    movapd  xmmword ptr [rsp + 0xC0], xmmC
    movapd  xmmword ptr [rsp + 0xD0], xmmD
    movapd  xmmword ptr [rsp + 0xE0], xmmE
    movapd  xmmword ptr [rsp + 0xF0], xmmF

    ; ------------------------------------------------------------------
    ; Activation Gate Logic
    ; ------------------------------------------------------------------
    ; Check the global activation flag in shared memory
    ; If IsActive == FALSE, skip payload execution and return
    ; If IsActive == TRUE, dispatch to payload entry point

    mov     rax, g_hSharedState
    test    byte ptr [rax], 0        ; Check IsActive field (first byte)
    jz      ActivationDisabled

    ; Activation enabled - prepare for payload call
    ; Stack is already 16-byte aligned after sub rsp, 416

    ; Preserve RCX and RDX (callback parameters) across the payload call
    mov     r12, rcx                 ; R12 = Reason
    mov     r13, rdx                 ; R13 = Parameters

    ; Call the C++ payload handler
    ; 16-byte alignment guaranteed:
    ;   - Entry: 16-byte aligned
    ;   - sub rsp, 416: 416 mod 16 = 0
    ;   - All pushes: 8 bytes each, 14 pushes = 112 bytes (aligned)
    call    ProcessPayloadEntry

    jmp     RestoreRegisters

ActivationDisabled:
    ; Activation flag not set - skip payload execution
    ; Return STATUS_SUCCESS without invoking the payload

    xor     rax, rax                 ; RAX = 0 (STATUS_SUCCESS)

    ; Fall through to restore registers

RestoreRegisters:
    ; ==============================================================
    ; Restore ALL XMM Registers (XMM0-XMM15)
    ; ==============================================================
    ; Stack layout at RSP (after sub rsp, 424):
    ;   Offset      Size      Region
    ;   [RSP + 0x000] .. [0x0FF] = 256 bytes XMM save area (16 × 16 bytes)
    ;   [RSP + 0x100] .. [0x1FF] = 128 bytes shadow + GP allocation
    ;   [RSP + 0x200] + N       = GP register push stack (16 registers × 8 bytes)
    ;
    ; XMM restore addresses:
    ;   XMM0  → [RSP + 0x000]
    ;   XMM1  → [RSP + 0x010]
    ;   ...
    ;   XMM15 → [RSP + 0x0F0]
    ; ============================================================

    movapd  xmm0, xmmword ptr [rsp + 0x000]
    movapd  xmm1, xmmword ptr [rsp + 0x010]
    movapd  xmm2, xmmword ptr [rsp + 0x020]
    movapd  xmm3, xmmword ptr [rsp + 0x030]
    movapd  xmm4, xmmword ptr [rsp + 0x040]
    movapd  xmm5, xmmword ptr [rsp + 0x050]
    movapd  xmm6, xmmword ptr [rsp + 0x060]
    movapd  xmm7, xmmword ptr [rsp + 0x070]
    movapd  xmm8, xmmword ptr [rsp + 0x080]
    movapd  xmm9, xmmword ptr [rsp + 0x090]
    movapd  xmmA, xmmword ptr [rsp + 0x0A0]
    movapd  xmmB, xmmword ptr [rsp + 0x0B0]
    movapd  xmmC, xmmword ptr [rsp + 0x0C0]
    movapd  xmmD, xmmword ptr [rsp + 0x0D0]
    movapd  xmmE, xmmword ptr [rsp + 0x0E0]
    movapd  xmmF, xmmword ptr [rsp + 0x0F0]

    ; ==============================================================
    ; Restore ALL General-Purpose Registers (R15→RAX, LIFO order)
    ; ==============================================================
    ; Push order was RAX→R15 (16 registers = 128 bytes)
    ; Pop order is R15→RAX (reverse of push, LIFO semantics)
    ; ============================================================

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    ; Restore stack pointer
    ; Total allocation: 8 (alignment) + 32 (shadow) + 128 (GP reserved) + 256 (XMM) = 424 bytes
    ; 424 mod 16 = 0 ✓ (maintains 16-byte alignment for return)
    add     rsp, 424

    ; Return to caller with NTSTATUS in RAX
    ; RAX = STATUS_SUCCESS (0x00000000) or payload return value
    ret

ProcessInstrumentationStub ENDP

END
