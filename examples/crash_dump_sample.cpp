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

    // Demonstrate UserStreamParam: attach an arbitrary application-defined stream. The Type uses the
    // CommentStreamA id here only so generic dump viewers print it; real apps use their own ids
    // (>= LastReservedStream, e.g. 0xffff0000+) for custom payloads.
    static const char kUserNote[] = "MiniDumpInprocSample user stream: build info / app state here.";
    MINIDUMP_USER_STREAM userStream = {};
    userStream.Type = CommentStreamA;
    userStream.BufferSize = static_cast<ULONG>(sizeof(kUserNote));
    userStream.Buffer = const_cast<char*>(kUserNote);
    MINIDUMP_USER_STREAM_INFORMATION userStreamInfo = {};
    userStreamInfo.UserStreamCount = 1;
    userStreamInfo.UserStreamArray = &userStream;

    (void)WriteMiniDumpInproc(
        hFile,
        static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo),
        &exceptionInfo,
        &userStreamInfo,
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
