#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Writes SystemInfoStream using kernel system information and pre-resolved RtlGetVersion when available.

BOOL WriteSystemInfo(HANDLE hFile) noexcept
{
    MINIDUMP_SYSTEM_INFO info = {};
    const SYSTEM_INFO& sys = g_NativeSystemInfo;
    RTL_OSVERSIONINFOEXW_INPROC version = {};
    RtlGetVersionFn rtlGetVersion = g_Apis.RtlGetVersion;

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


namespace {

// Minimal, heap-free ASCII formatting helpers for the comment stream. All append at `pos`, never
// overflow `cap`, and always leave room for a later NUL terminator (pos + 1 < cap).
ULONG32 CommentAppendStr(char* buf, ULONG32 cap, ULONG32 pos, const char* text) noexcept
{
    while (text != nullptr && *text != '\0' && pos + 1 < cap) {
        buf[pos++] = *text++;
    }
    return pos;
}

ULONG32 CommentAppendU64(char* buf, ULONG32 cap, ULONG32 pos, ULONG64 value) noexcept
{
    char digits[24];
    ULONG32 count = 0;
    if (value == 0) {
        digits[count++] = '0';
    }
    while (value != 0 && count < sizeof(digits)) {
        digits[count++] = static_cast<char>('0' + static_cast<int>(value % 10));
        value /= 10;
    }
    while (count != 0 && pos + 1 < cap) {
        buf[pos++] = digits[--count];
    }
    return pos;
}

// Appends a byte count rendered in whole megabytes, e.g. "4096MB".
ULONG32 CommentAppendMB(char* buf, ULONG32 cap, ULONG32 pos, ULONG64 bytes) noexcept
{
    pos = CommentAppendU64(buf, cap, pos, bytes >> 20);
    pos = CommentAppendStr(buf, cap, pos, "MB");
    return pos;
}

// Appends a byte count rendered in whole kilobytes, e.g. "512KB". Used for kernel-pool quotas,
// which are typically KB-to-a-few-MB and would round to 0 under megabyte granularity.
ULONG32 CommentAppendKB(char* buf, ULONG32 cap, ULONG32 pos, ULONG64 bytes) noexcept
{
    pos = CommentAppendU64(buf, cap, pos, bytes >> 10);
    pos = CommentAppendStr(buf, cap, pos, "KB");
    return pos;
}

BOOL QuerySystemMemory(MEMORYSTATUSEX* status) noexcept
{
    status->dwLength = sizeof(*status);
#if defined(_MSC_VER)
    __try {
        return GlobalMemoryStatusEx(status);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#else
    return GlobalMemoryStatusEx(status);
#endif
}

BOOL QueryProcessMemory(INPROC_VM_COUNTERS_EX* counters) noexcept
{
    if (g_Apis.NtQueryInformationProcess == nullptr) {
        return FALSE;
    }
#if defined(_MSC_VER)
    __try {
        ULONG returnLength = 0;
        LONG status = g_Apis.NtQueryInformationProcess(
            GetCurrentProcess(), kProcessVmCounters, counters, sizeof(*counters), &returnLength);
        return NT_SUCCESS(status);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#else
    ULONG returnLength = 0;
    LONG status = g_Apis.NtQueryInformationProcess(
        GetCurrentProcess(), kProcessVmCounters, counters, sizeof(*counters), &returnLength);
    return NT_SUCCESS(status);
#endif
}

// Open-handle count (+ peak/high watermark). Tries the extended PROCESS_HANDLE_INFORMATION form
// first, then the legacy ULONG-only form, then the kernel32 wrapper. All heap-free and SEH-guarded.
BOOL QueryProcessHandleCounts(ULONG* count, ULONG* peak) noexcept
{
    *count = 0;
    *peak = 0;
#if defined(_MSC_VER)
    __try {
#endif
        if (g_Apis.NtQueryInformationProcess != nullptr) {
            INPROC_PROCESS_HANDLE_INFORMATION info = {};
            ULONG returnLength = 0;
            LONG status = g_Apis.NtQueryInformationProcess(
                GetCurrentProcess(), kProcessHandleCount, &info, sizeof(info), &returnLength);
            if (NT_SUCCESS(status)) {
                *count = info.HandleCount;
                *peak = info.HandleCountHighWatermark;
                return TRUE;
            }
            ULONG only = 0;
            status = g_Apis.NtQueryInformationProcess(
                GetCurrentProcess(), kProcessHandleCount, &only, sizeof(only), &returnLength);
            if (NT_SUCCESS(status)) {
                *count = only;
                return TRUE;
            }
        }
        DWORD handles = 0;
        if (GetProcessHandleCount(GetCurrentProcess(), &handles)) {
            *count = handles;
            return TRUE;
        }
        return FALSE;
#if defined(_MSC_VER)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#endif
}

// GDI/USER object counts via user32!GetGuiResources, only when user32 was already loaded (pointer
// resolved at init). SEH-guarded because it crosses into the win32k GUI subsystem.
BOOL QueryGuiResources(ULONG* gdiObjects, ULONG* userObjects) noexcept
{
    *gdiObjects = 0;
    *userObjects = 0;
    if (g_Apis.GetGuiResources == nullptr) {
        return FALSE;
    }
#if defined(_MSC_VER)
    __try {
#endif
        *gdiObjects = g_Apis.GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        *userObjects = g_Apis.GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
        return TRUE;
#if defined(_MSC_VER)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#endif
}

} // namespace


// Builds the ANSI comment text (system + process memory summary) into g_CommentBuffer. The crash
// path stays heap-free: values come from a kernel32 syscall wrapper (GlobalMemoryStatusEx) and a
// pre-resolved NtQueryInformationProcess, both SEH-guarded, and the text is formatted in place.
// WinDbg automatically prints CommentStreamA when the dump is opened.

ULONG32 BuildMemoryCommentText() noexcept
{
    char* buf = g_CommentBuffer;
    const ULONG32 cap = kCommentBufferBytes;
    ULONG32 pos = CommentAppendStr(buf, cap, 0, "\n");

    MEMORYSTATUSEX sysMem = {};
    pos = CommentAppendStr(buf, cap, pos, "SysMem: ");
    if (QuerySystemMemory(&sysMem)) {
        pos = CommentAppendStr(buf, cap, pos, "Load=");
        pos = CommentAppendU64(buf, cap, pos, sysMem.dwMemoryLoad);
        pos = CommentAppendStr(buf, cap, pos, "% PhysTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalPhys);
        pos = CommentAppendStr(buf, cap, pos, " PhysAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailPhys);
        pos = CommentAppendStr(buf, cap, pos, " CommitTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalPageFile);
        pos = CommentAppendStr(buf, cap, pos, " CommitAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailPageFile);
        pos = CommentAppendStr(buf, cap, pos, " VirtTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalVirtual);
        pos = CommentAppendStr(buf, cap, pos, " VirtAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailVirtual);
    } else {
        pos = CommentAppendStr(buf, cap, pos, "unavailable");
    }

    pos = CommentAppendStr(buf, cap, pos, "\n");

    INPROC_VM_COUNTERS_EX procMem = {};
    const BOOL gotProcMem = QueryProcessMemory(&procMem);
    pos = CommentAppendStr(buf, cap, pos, "ProcMem: ");
    if (gotProcMem) {
        pos = CommentAppendStr(buf, cap, pos, "WorkingSet=");
        pos = CommentAppendMB(buf, cap, pos, procMem.WorkingSetSize);
        pos = CommentAppendStr(buf, cap, pos, " PeakWorkingSet=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakWorkingSetSize);
        pos = CommentAppendStr(buf, cap, pos, " PrivateCommit=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PrivateUsage);
        pos = CommentAppendStr(buf, cap, pos, " PeakCommit=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakPagefileUsage);
        pos = CommentAppendStr(buf, cap, pos, " VirtSize=");
        pos = CommentAppendMB(buf, cap, pos, procMem.VirtualSize);
        pos = CommentAppendStr(buf, cap, pos, " PeakVirtSize=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakVirtualSize);
        pos = CommentAppendStr(buf, cap, pos, " PageFaults=");
        pos = CommentAppendU64(buf, cap, pos, procMem.PageFaultCount);
    } else {
        pos = CommentAppendStr(buf, cap, pos, "unavailable");
    }

    pos = CommentAppendStr(buf, cap, pos, "\n");

    // Kernel-pool quota, handle counts and GUI object counts: the key signals for kernel-object /
    // handle / GDI-USER leak diagnosis.
    pos = CommentAppendStr(buf, cap, pos, "ProcRes: ");
    if (gotProcMem) {
        pos = CommentAppendStr(buf, cap, pos, "PagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, " PeakPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPeakPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, " NonPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaNonPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, " PeakNonPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPeakNonPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, " ");
    }

    ULONG handleCount = 0;
    ULONG handlePeak = 0;
    if (QueryProcessHandleCounts(&handleCount, &handlePeak)) {
        pos = CommentAppendStr(buf, cap, pos, "Handles=");
        pos = CommentAppendU64(buf, cap, pos, handleCount);
        pos = CommentAppendStr(buf, cap, pos, " PeakHandles=");
        pos = CommentAppendU64(buf, cap, pos, handlePeak);
    } else {
        pos = CommentAppendStr(buf, cap, pos, "Handles=n/a");
    }

    ULONG gdiObjects = 0;
    ULONG userObjects = 0;
    if (QueryGuiResources(&gdiObjects, &userObjects)) {
        pos = CommentAppendStr(buf, cap, pos, " GDI=");
        pos = CommentAppendU64(buf, cap, pos, gdiObjects);
        pos = CommentAppendStr(buf, cap, pos, " USER=");
        pos = CommentAppendU64(buf, cap, pos, userObjects);
    } else {
        pos = CommentAppendStr(buf, cap, pos, " GDI=n/a USER=n/a");
    }

    pos = CommentAppendStr(buf, cap, pos, "\n");

    // 4th line: total dump elapsed time. The value is unknown here (it depends on how long the rest
    // of the dump takes), so reserve a fixed-width, space-padded digit field and remember its offset;
    // PatchCommentElapsed fills it in right before CommentStreamA is written last. Reserving keeps the
    // stream's DataSize stable while still letting the final number vary in width.
    pos = CommentAppendStr(buf, cap, pos, "ProcTime: Elapsed=");
    g_CommentElapsedOffset = kCommentElapsedUnset;
    if (pos + kCommentElapsedWidth + 4u < cap) { // room for the field + "us" + "\n" + NUL
        g_CommentElapsedOffset = pos;
        for (ULONG32 i = 0; i < kCommentElapsedWidth; ++i) {
            buf[pos++] = ' ';
        }
        pos = CommentAppendStr(buf, cap, pos, "us");
    }
    pos = CommentAppendStr(buf, cap, pos, "\n");

    // NUL-terminate, then pad to a 4-byte boundary. The buffer is zero-initialized, so the padding
    // bytes are already 0; WinDbg reads CommentStreamA as a NUL-terminated string so trailing zeros
    // are harmless. DataSize == the returned aligned length.
    if (pos < cap) {
        buf[pos++] = '\0';
    } else {
        buf[cap - 1] = '\0';
        pos = cap;
    }
    ULONG32 aligned = (pos + 3u) & ~3u;
    if (aligned > cap) {
        aligned = cap;
    }
    g_CommentBytes = aligned;
    return aligned;
}


// Patches the reserved fixed-width elapsed-time field with the measured total dump duration
// (microseconds), right-justified and space-padded. Heap-free; safe no-op if no field was reserved.

void PatchCommentElapsed(ULONG64 elapsedMicros) noexcept
{
    if (g_CommentElapsedOffset == kCommentElapsedUnset ||
        g_CommentElapsedOffset + kCommentElapsedWidth > kCommentBufferBytes) {
        return;
    }

    // Render the decimal digits least-significant-first.
    char digits[24];
    ULONG32 count = 0;
    if (elapsedMicros == 0) {
        digits[count++] = '0';
    }
    while (elapsedMicros != 0 && count < sizeof(digits)) {
        digits[count++] = static_cast<char>('0' + static_cast<int>(elapsedMicros % 10));
        elapsedMicros /= 10;
    }
    // Clamp to the reserved width (overflow would be absurdly long; keep the low digits).
    if (count > kCommentElapsedWidth) {
        count = kCommentElapsedWidth;
    }

    char* field = g_CommentBuffer + g_CommentElapsedOffset;
    const ULONG32 padding = kCommentElapsedWidth - count; // right-justify with leading spaces
    for (ULONG32 i = 0; i < padding; ++i) {
        field[i] = ' ';
    }
    for (ULONG32 i = 0; i < count; ++i) {
        field[padding + i] = digits[count - 1 - i];
    }
}


// Writes the prebuilt CommentStreamA bytes. The content was captured by BuildMemoryCommentText
// before file layout, so this pass only streams the fixed-size buffer and cannot fault.

INPROC_STREAM_WRITE_RESULT WriteCommentStream(HANDLE hFile, ULONG32 byteLen) noexcept
{
    if (byteLen == 0) {
        return InprocStreamSkip;
    }
    if (byteLen > kCommentBufferBytes) {
        byteLen = kCommentBufferBytes;
    }
    return StreamResultFromBool(WriteAll(hFile, g_CommentBuffer, byteLen));
}


// Snapshots the caller-provided user streams into the fixed g_UserStreams plan. The caller structure
// and array are read under SEH (SafeCopyBytes) so a malformed UserStreamParam cannot fault the dump.
// NULL/empty entries are skipped; the count is capped to kMaxUserStreams.

void SnapshotUserStreams(PMINIDUMP_USER_STREAM_INFORMATION userStreamParam) noexcept
{
    g_UserStreamCount = 0;
    if (userStreamParam == nullptr) {
        return;
    }

    MINIDUMP_USER_STREAM_INFORMATION info = {};
    if (!SafeCopyBytes(&info, userStreamParam, sizeof(info))) {
        return;
    }
    if (info.UserStreamArray == nullptr || info.UserStreamCount == 0) {
        return;
    }

    for (ULONG i = 0; i < info.UserStreamCount && g_UserStreamCount < kMaxUserStreams; ++i) {
        MINIDUMP_USER_STREAM entry = {};
        if (!SafeCopyBytes(&entry, &info.UserStreamArray[i], sizeof(entry))) {
            break;
        }
        if (entry.Buffer == nullptr || entry.BufferSize == 0) {
            continue;
        }
        g_UserStreams[g_UserStreamCount].Type = entry.Type;
        g_UserStreams[g_UserStreamCount].BufferSize = entry.BufferSize;
        g_UserStreams[g_UserStreamCount].Buffer = entry.Buffer;
        g_UserStreams[g_UserStreamCount].Rva = 0;
        ++g_UserStreamCount;
    }
}


// Writes the admitted user-stream byte blobs contiguously at their laid-out RVAs, each padded to a
// 4-byte boundary. The blobs are placed contiguously by the layout pass, so one initial seek (done
// by the caller's emit macro) plus sequential writes lands every stream at its descriptor's RVA.
// Unreadable caller buffers are zero-filled (best-effort) rather than aborting the dump.

BOOL WriteUserStreams(HANDLE hFile, ULONG32 count) noexcept
{
    for (ULONG32 i = 0; i < count && i < g_UserStreamCount; ++i) {
        const ULONG32 size = g_UserStreams[i].BufferSize;
        const BYTE* buffer = static_cast<const BYTE*>(g_UserStreams[i].Buffer);

        if (SafeReadBytes(buffer, size)) {
            if (!WriteAll(hFile, buffer, size)) {
                return FALSE;
            }
        } else if (!WriteZeros(hFile, size)) {
            return FALSE;
        }

        const ULONG32 padding = static_cast<ULONG32>(Align4(size)) - size;
        if (padding != 0 && !WriteZeros(hFile, padding)) {
            return FALSE;
        }
    }
    return TRUE;
}


// Writes ExceptionStream and points it at the already-laid-out exception thread context record.

INPROC_STREAM_WRITE_RESULT WriteExceptionStream(HANDLE hFile, ULONG32 contextRva, const MINIDUMP_EXCEPTION_STREAM* capturedException) noexcept
{
    if (capturedException == nullptr) {
        return InprocStreamSkip;
    }

    MINIDUMP_EXCEPTION_STREAM stream = *capturedException;
    stream.ThreadContext.Rva = contextRva;
    stream.ThreadContext.DataSize = sizeof(CONTEXT);

    return StreamResultFromBool(WriteAll(hFile, &stream, sizeof(stream)));
}


} // namespace minidump_inproc::internal
