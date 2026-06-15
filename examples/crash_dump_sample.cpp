#include "minidump_inproc.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace {

LONG WINAPI DumpUnhandledExceptionFilter(PEXCEPTION_POINTERS exceptionPointers)
{
    HANDLE hFile = CreateFileW(
        L"inproc_sample.dmp",
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    MINIDUMP_EXCEPTION_INFORMATION exceptionInfo = {};
    exceptionInfo.ThreadId = GetCurrentThreadId();
    exceptionInfo.ExceptionPointers = exceptionPointers;
    exceptionInfo.ClientPointers = FALSE;

    (void)WriteMiniDumpInproc(
        hFile,
        static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo),
        &exceptionInfo,
        0); // 0 = no size limit

    CloseHandle(hFile);
    return EXCEPTION_EXECUTE_HANDLER;
}

} // namespace

int wmain()
{
    // No explicit initialization needed; the library resolves its NTDLL routines at load time.
    SetUnhandledExceptionFilter(DumpUnhandledExceptionFilter);


    volatile int* crash = nullptr;
    *crash = 1;

    return 0;
}
