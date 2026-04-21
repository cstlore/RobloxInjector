#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

// ProcessInstrumentationCallback Information Class (0x28)
#define PROCESS_INSTRUMENTATION_CALLBACK 0x28

// Shared state for activation control
#pragma pack(push, 1)
typedef struct _INSTRUMENTATION_SHARED_STATE {
    volatile BOOLEAN IsActive;           // Global activation flag
    volatile ULONG64 CallbackCookie;     // Per-process identification cookie
    volatile ULONG64 Reserved[2];        // Reserved for future use
} INSTRUMENTATION_SHARED_STATE, *PINSTRUMENTATION_SHARED_STATE;
#pragma pack(pop)

// Process Instrumentation Callback parameters
typedef struct _PROCESS_INSTRUMENTATION_PARAMETERS {
    PVOID CallbackRoutine;                // Address of callback entry point
    ULONG64 Cookie;                       // Identification cookie
    PVOID Reserved;                       // Reserved field
} PROCESS_INSTRUMENTATION_PARAMETERS, *PPROCESS_INSTRUMENTATION_PARAMETERS;

// Callback notification type
typedef enum _INSTRUMENTATION_CALLBACK_REASON {
    InstrumentationCallbackReasonProcessAttach = 1,
    InstrumentationCallbackReasonProcessDetach = 2,
    InstrumentationCallbackReasonThreadAttach = 3,
    InstrumentationCallbackReasonThreadDetach = 4,
    InstrumentationCallbackReasonMax = 0x7FFFFFFF
} INSTRUMENTATION_CALLBACK_REASON;

// Process Instrumentation Callback handler signature
typedef NTSTATUS (NTAPI* PPROCESS_INSTRUMENTATION_CALLBACK)(
    _In_ INSTRUMENTATION_CALLBACK_REASON Reason,
    _In_ PPROCESS_INSTRUMENTATION_PARAMETERS Parameters
);

class CProcessInstrumentation {
public:
    CProcessInstrumentation();
    ~CProcessInstrumentation();

    BOOL Initialize();
    void Cleanup();

    BOOL RegisterCallback(PPROCESS_INSTRUMENTATION_CALLBACK CallbackRoutine);
    void UnregisterCallback();

    void Activate();
    void Deactivate();
    BOOL IsActive() const { return m_sharedState.IsActive != FALSE; }

    static const INSTRUMENTATION_SHARED_STATE* GetSharedState();

private:
    static NTSTATUS NTAPI CallbackHandler(
        _In_ INSTRUMENTATION_CALLBACK_REASON Reason,
        _In_ PPROCESS_INSTRUMENTATION_PARAMETERS Parameters
    );

    INSTRUMENTATION_SHARED_STATE m_sharedState;
    HANDLE m_hProcess;
    BOOL m_bRegistered;
};
