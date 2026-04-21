#include <Windows.h>
#include <iostream>
#include "ProcessInstrumentation.h"

// Shared state instance (referenced by assembly stub)
INSTRUMENTATION_SHARED_STATE g_hSharedState;

// Payload handler - invoked when activation gate passes
void ProcessPayloadEntry(INSTRUMENTATION_CALLBACK_REASON reason,
                          PPROCESS_INSTRUMENTATION_PARAMETERS params)
{
    switch (reason) {
    case InstrumentationCallbackReasonProcessAttach:
        std::wcout << L"[*] Process instrumentation: attaching to process\n";
        break;
    case InstrumentationCallbackReasonProcessDetach:
        std::wcout << L"[*] Process instrumentation: detaching from process\n";
        break;
    case InstrumentationCallbackReasonThreadAttach:
        std::wcout << L"[*] Thread instrumentation: attaching to thread\n";
        break;
    case InstrumentationCallbackReasonThreadDetach:
        std::wcout << L"[*] Thread instrumentation: detaching from thread\n";
        break;
    default:
        std::wcout << L"[*] Process instrumentation: reason 0x"
                   << std::hex << static_cast<unsigned int>(reason) << std::dec << L"\n";
        break;
    }

    if (params) {
        std::wcout << L"[*] Callback cookie: 0x"
                   << std::hex << params->Cookie << std::dec << L"\n";
    }
}

// External assembly stub entry point
extern "C" PPROCESS_INSTRUMENTATION_CALLBACK asm_ProcessInstrumentationStub;

int main()
{
    std::wcout << L"ProcessInstrumentationCallback Hijack Demo\n"
               << L"==========================================\n\n";

    CProcessInstrumentation instrumentation;

    // Initialize and register the callback
    if (instrumentation.Initialize()) {
        std::wcout << L"[+] Callback registered successfully\n\n";
    }
    else {
        std::wcout << L"[-] Failed to register callback (error: "
                   << GetLastError() << L")\n";
        return 1;
    }

    // Display shared state
    const auto* state = instrumentation.GetSharedState();
    std::wcout << L"[i] Shared state address: 0x"
               << std::hex << reinterpret_cast<ULONG64>(state) << std::dec << L"\n";
    std::wcout << L"[i] Activation status: "
               << (state->IsActive ? L"ACTIVE" : L"INACTIVE") << L"\n\n";

    // Activation control demonstration
    std::wcout << L"[->] Activating instrumentation callback...\n";
    instrumentation.Activate();
    std::wcout << L"[i] Activation status: "
               << (instrumentation.IsActive() ? L"ACTIVE" : L"INACTIVE") << L"\n\n";

    // Keep process alive for demonstration
    std::wcout << L"[i] Process instrumentation active. Press Enter to deactivate...\n";
    std::wcin.get();

    instrumentation.Deactivate();
    std::wcout << L"[i] Activation status: "
               << (instrumentation.IsActive() ? L"ACTIVE" : L"INACTIVE") << L"\n\n";

    // Cleanup
    instrumentation.Cleanup();
    std::wcout << L"[+] Cleanup complete\n";

    return 0;
}
