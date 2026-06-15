#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Writes SystemInfoStream using kernel system information and pre-resolved RtlGetVersion when available.

BOOL WriteSystemInfo(HANDLE hFile) noexcept
{
    MINIDUMP_SYSTEM_INFO info = {};
    SYSTEM_INFO sys = {};
    RTL_OSVERSIONINFOEXW_INPROC version = {};
    RtlGetVersionFn rtlGetVersion = g_Apis.RtlGetVersion;

    GetNativeSystemInfo(&sys);
    info.ProcessorArchitecture = sys.wProcessorArchitecture;
    info.ProcessorLevel = sys.wProcessorLevel;
    info.ProcessorRevision = sys.wProcessorRevision;
    info.NumberOfProcessors = static_cast<UCHAR>(sys.dwNumberOfProcessors);

    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion != nullptr && rtlGetVersion(&version) >= 0) {

        info.MajorVersion = version.dwMajorVersion;
        info.MinorVersion = version.dwMinorVersion;
        info.BuildNumber = version.dwBuildNumber;
        info.PlatformId = version.dwPlatformId;
        info.ProductType = version.wProductType;
        info.SuiteMask = version.wSuiteMask;
    }

    return WriteAll(hFile, &info, sizeof(info));
}


// Writes MiscInfoStream with process id and process timing information.

BOOL WriteMiscInfo(HANDLE hFile) noexcept
{
    MINIDUMP_MISC_INFO info = {};
    FILETIME createTime = {};
    FILETIME exitTime = {};
    FILETIME kernelTime = {};
    FILETIME userTime = {};

    info.SizeOfInfo = sizeof(info);
    info.Flags1 = MINIDUMP_MISC1_PROCESS_ID;
    info.ProcessId = GetCurrentProcessId();

    if (GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime)) {
        info.Flags1 |= MINIDUMP_MISC1_PROCESS_TIMES;
        info.ProcessCreateTime = FileTimeToUnixSeconds(createTime);
        info.ProcessUserTime = FileTimeDurationSeconds(userTime);
        info.ProcessKernelTime = FileTimeDurationSeconds(kernelTime);
    }

    return WriteAll(hFile, &info, sizeof(info));
}


// Writes ExceptionStream and points it at the already-laid-out exception thread context record.

BOOL WriteExceptionStream(HANDLE hFile, ULONG32 contextRva, PMINIDUMP_EXCEPTION_INFORMATION exceptionParam) noexcept
{
    MINIDUMP_EXCEPTION_STREAM stream = {};
    const CONTEXT* context = nullptr;

    if (!CaptureExceptionStreamInfo(exceptionParam, &stream, &context)) {
        return FALSE;
    }

    stream.ThreadContext.Rva = contextRva;
    stream.ThreadContext.DataSize = sizeof(CONTEXT);

    return WriteAll(hFile, &stream, sizeof(stream));
}


} // namespace minidump_inproc::internal
