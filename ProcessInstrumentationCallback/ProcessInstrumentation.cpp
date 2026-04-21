#include "ProcessInstrumentation.h"
#include <algorithm>

extern "C" {
    // Assembly stub entry point (implemented in stub.asm)
    extern PPROCESS_INSTRUMENTATION_CALLBACK asm_ProcessInstrumentationStub;
}

CProcessInstrumentation::CProcessInstrumentation()
    : m_hProcess(GetCurrentProcess())
    , m_bRegistered(FALSE)
{
    ZeroMemory(&m_sharedState, sizeof(m_sharedState));
    m_sharedState.IsActive = FALSE;
    m_sharedState.CallbackCookie = 0;
}

CProcessInstrumentation::~CProcessInstrumentation()
{
    Cleanup();
}

BOOL CProcessInstrumentation::Initialize()
{
    if (m_bRegistered) {
        return TRUE;
    }

    m_sharedState.IsActive = FALSE;
    m_sharedState.CallbackCookie = reinterpret_cast<ULONG64>(this);

    return RegisterCallback(CallbackHandler);
}

void CProcessInstrumentation::Cleanup()
{
    if (m_bRegistered) {
        UnregisterCallback();
    }

    ZeroMemory(&m_sharedState, sizeof(m_sharedState));
}

BOOL CProcessInstrumentation::RegisterCallback(PPROCESS_INSTRUMENTATION_CALLBACK CallbackRoutine)
{
    PROCESS_INSTRUMENTATION_PARAMETERS params = {};
    params.CallbackRoutine = CallbackRoutine;
    params.Cookie = m_sharedState.CallbackCookie;

    NTSTATUS status = NtSetInformationProcess(
        m_hProcess,
        static_cast<PROCESS_INFORMATION_CLASS>(PROCESS_INSTRUMENTATION_CALLBACK),
        &params,
        sizeof(params)
    );

    if (NT_SUCCESS(status)) {
        m_bRegistered = TRUE;
        return TRUE;
    }

    return FALSE;
}

void CProcessInstrumentation::UnregisterCallback()
{
    PROCESS_INSTRUMENTATION_PARAMETERS params = {};
    NtSetInformationProcess(
        m_hProcess,
        static_cast<PROCESS_INFORMATION_CLASS>(PROCESS_INSTRUMENTATION_CALLBACK),
        &params,
        sizeof(params)
    );

    m_bRegistered = FALSE;
}

void CProcessInstrumentation::Activate()
{
    m_sharedState.IsActive = TRUE;
}

void CProcessInstrumentation::Deactivate()
{
    m_sharedState.IsActive = FALSE;
}

const INSTRUMENTATION_SHARED_STATE* CProcessInstrumentation::GetSharedState()
{
    return &m_sharedState;
}

NTSTATUS NTAPI CProcessInstrumentation::CallbackHandler(
    _In_ INSTRUMENTATION_CALLBACK_REASON Reason,
    _In_ PPROCESS_INSTRUMENTATION_PARAMETERS Parameters
)
{
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(Parameters);

    return STATUS_SUCCESS;
}
