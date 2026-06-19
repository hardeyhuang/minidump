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

// ---- CommentStreamA buffer helpers --------------------------------------------------------
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

// ---- CommentStreamW INI buffer helpers --------------------------------------------------------
// The user comment is kept as a flat, NUL-terminated wide INI text in g_CommentBufferW, e.g.
//   [Section]\nKey1=Value1\nKey2=Value2\n[Other]\nKeyA=ValueA\n
// All edits are performed in place under g_CommentLock; no heap is used.

// Wide string length without depending on the CRT (also keeps the crash path self-contained).
ULONG32 CommentWStrLen(const wchar_t* s) noexcept
{
    ULONG32 n = 0;
    while (s[n] != L'\0') {
        ++n;
    }
    return n;
}

// Exact n-WCHAR comparison.
BOOL CommentWRangeEqual(const wchar_t* a, const wchar_t* b, ULONG32 n) noexcept
{
    for (ULONG32 i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

// Replaces g_CommentBufferW[at, at+removeLen) with `insLen` WCHARs from `ins`, keeping the buffer
// NUL-terminated. Returns FALSE (leaving the buffer unchanged) if the result would not fit.
BOOL CommentSplice(ULONG32 at, ULONG32 removeLen, const wchar_t* ins, ULONG32 insLen) noexcept
{
    const ULONG32 len = g_CommentWChars;
    const ULONG32 newLen = len - removeLen + insLen;
    if (newLen + 1u > kCommentBufferWChars) {
        return FALSE; // no room for the content + terminating NUL
    }
    wchar_t* buf = g_CommentBufferW;
    const ULONG32 tailStart = at + removeLen;
    const ULONG32 tailLen = len - tailStart;
    if (tailLen != 0 && insLen != removeLen) {
        MoveMemory(buf + at + insLen, buf + tailStart, tailLen * sizeof(wchar_t));
    }
    for (ULONG32 i = 0; i < insLen; ++i) {
        buf[at + i] = ins[i];
    }
    g_CommentWChars = newLen;
    buf[newLen] = L'\0';
    return TRUE;
}

// Normalizes a user value into `dst` for flat-INI storage and returns the number of WCHARs written
// (never more than kCommentMaxValueChars). Drops '\r', maps each '\n' to U+21B5 (a visible return
// arrow) and each ';' to the full-width '；' (U+FF1B) so stored values never collide with the ';'
// token separator MERGE/APPEND rely on. Every surviving source char maps to exactly one WCHAR, so
// callers can size buffers by kCommentMaxValueChars. `dst` is NOT NUL-terminated by this helper.
ULONG32 CommentNormalizeValue(wchar_t* dst, const wchar_t* src) noexcept
{
    const wchar_t kFullWidthSemicolon = static_cast<wchar_t>(0xFF1B);
    const wchar_t kReturnArrow = static_cast<wchar_t>(0x21B5);
    ULONG32 t = 0;
    for (ULONG32 i = 0; i < kCommentMaxValueChars && src[i] != L'\0'; ++i) {
        const wchar_t c = src[i];
        if (c == L'\r') {
            continue;
        }
        if (c == L'\n') {
            dst[t++] = kReturnArrow;
        } else if (c == L';') {
            dst[t++] = kFullWidthSemicolon;
        } else {
            dst[t++] = c;
        }
    }
    return t;
}

// Core in-place INI mutation. Pointers are dereferenced here (the caller wraps this in SEH).
BOOL CommentIniApply(const wchar_t* section, const wchar_t* key, const wchar_t* value,
                     COMMENT_STRING_OPER_TYPE oper) noexcept
{
    const ULONG32 secLen = CommentWStrLen(section);
    const ULONG32 keyLen = CommentWStrLen(key);
    if (secLen == 0 || keyLen == 0) {
        return FALSE;
    }
    // Reject over-long identifiers outright (no truncation for section/key).
    if (secLen > kCommentMaxSectionKeyChars || keyLen > kCommentMaxSectionKeyChars) {
        return FALSE;
    }
    const BOOL hasValue = (value != nullptr);

    // Single small scratch buffer reused by every branch that needs to build text before handing it
    // to CommentSplice. Sized to the largest fragment (kCommentMaxFragmentWChars), so this function's
    // stack frame stays under 1KB. The user value is normalized straight into this buffer on demand
    // (CommentNormalizeValue) at the exact slot each branch needs, so no separate value buffer is
    // required. `value` keeps pointing at the raw caller string throughout.
    wchar_t frag[kCommentMaxFragmentWChars];

    wchar_t* buf = g_CommentBufferW;
    const ULONG32 len = g_CommentWChars;

    // Locate the section header line "[section]" and the byte span of its body.
    BOOL secFound = FALSE;
    ULONG32 bodyStart = 0, bodyEnd = len;
    {
        ULONG32 p = 0;
        while (p < len) {
            const ULONG32 ls = p;
            ULONG32 nl = ls;
            while (nl < len && buf[nl] != L'\n') {
                ++nl;
            }
            const ULONG32 lineLen = nl - ls;
            const BOOL isHeader = (lineLen >= 2 && buf[ls] == L'[' && buf[nl - 1] == L']');
            if (isHeader) {
                if (!secFound) {
                    const ULONG32 nameLen = lineLen - 2;
                    if (nameLen == secLen && CommentWRangeEqual(buf + ls + 1, section, secLen)) {
                        secFound = TRUE;
                        bodyStart = (nl < len) ? nl + 1 : len;
                        bodyEnd = len;
                    }
                } else {
                    bodyEnd = ls; // next section header ends the body
                    break;
                }
            }
            p = (nl < len) ? nl + 1 : len;
        }
    }

    // Section absent: a NULL value (delete / no-op) changes nothing; otherwise append a new section.
    if (!secFound) {
        if (!hasValue) {
            return TRUE;
        }
        ULONG32 t = 0;
        frag[t++] = L'[';
        for (ULONG32 i = 0; i < secLen; ++i) frag[t++] = section[i];
        frag[t++] = L']';
        frag[t++] = L'\n';
        for (ULONG32 i = 0; i < keyLen; ++i) frag[t++] = key[i];
        frag[t++] = L'=';
        t += CommentNormalizeValue(frag + t, value);
        frag[t++] = L'\n';
        return CommentSplice(len, 0, frag, t);
    }

    // Locate "key=" within the section body; remember the value span [valStart, valEnd).
    BOOL keyFound = FALSE;
    ULONG32 keyLineStart = 0, valStart = 0, valEnd = 0;
    {
        ULONG32 q = bodyStart;
        while (q < bodyEnd) {
            const ULONG32 ls = q;
            ULONG32 nl = ls;
            while (nl < bodyEnd && buf[nl] != L'\n') {
                ++nl;
            }
            ULONG32 eq = ls;
            while (eq < nl && buf[eq] != L'=') {
                ++eq;
            }
            if (eq < nl) {
                const ULONG32 klen = eq - ls;
                if (klen == keyLen && CommentWRangeEqual(buf + ls, key, keyLen)) {
                    keyFound = TRUE;
                    keyLineStart = ls;
                    valStart = eq + 1;
                    valEnd = nl;
                    break;
                }
            }
            q = (nl < bodyEnd) ? nl + 1 : bodyEnd;
        }
    }

    // Key absent: a NULL value is a no-op; otherwise insert "key=value\n" at the end of the section.
    if (!keyFound) {
        if (!hasValue) {
            return TRUE;
        }
        ULONG32 t = 0;
        for (ULONG32 i = 0; i < keyLen; ++i) frag[t++] = key[i];
        frag[t++] = L'=';
        t += CommentNormalizeValue(frag + t, value);
        frag[t++] = L'\n';
        return CommentSplice(bodyEnd, 0, frag, t);
    }

    // Key present: apply the requested operation to its value.
    switch (oper) {
        case CommentStringReplace: {
            if (!hasValue) {
                // Delete the whole key line, including its trailing newline.
                ULONG32 removeEnd = valEnd;
                if (removeEnd < len && buf[removeEnd] == L'\n') {
                    ++removeEnd;
                }
                return CommentSplice(keyLineStart, removeEnd - keyLineStart, nullptr, 0);
            }
            const ULONG32 valLen = CommentNormalizeValue(frag, value);
            return CommentSplice(valStart, valEnd - valStart, frag, valLen);
        }
        case CommentStringAppend: {
            if (!hasValue) {
                return TRUE;
            }
            // Reserve frag[0] for the ';' separator and normalize the value right after it.
            frag[0] = L';';
            const ULONG32 valLen = CommentNormalizeValue(frag + 1, value);
            return CommentSplice(valEnd, 0, frag, valLen + 1u);
        }
        case CommentStringMerge: {
            if (!hasValue) {
                return TRUE;
            }
            // Normalize the new value into frag+1, reserving frag[0] for a possible ';' separator so
            // the same buffer serves both the dedup comparison and the eventual splice.
            frag[0] = L';';
            const wchar_t* const val = frag + 1;
            const ULONG32 valLen = CommentNormalizeValue(frag + 1, value);
            // Empty current value: just set it (avoids producing a leading ';').
            if (valEnd == valStart) {
                return CommentSplice(valStart, 0, val, valLen);
            }
            // Deduplicate: scan the existing ';'-separated tokens for an exact match.
            ULONG32 s = valStart;
            while (s <= valEnd) {
                ULONG32 e = s;
                while (e < valEnd && buf[e] != L';') {
                    ++e;
                }
                const ULONG32 tokLen = e - s;
                if (tokLen == valLen && CommentWRangeEqual(buf + s, val, valLen)) {
                    return TRUE; // already present, leave unchanged
                }
                if (e >= valEnd) {
                    break;
                }
                s = e + 1;
            }
            return CommentSplice(valEnd, 0, frag, valLen + 1u);
        }
        default:
            return FALSE;
    }
}

} // namespace


// Builds the ANSI comment text (system + process memory summary) into g_CommentBuffer, formatted as
// INI ([Section] + Key=Value lines) to mirror the user CommentStreamW layout. The crash path stays
// heap-free: values come from a kernel32 syscall wrapper (GlobalMemoryStatusEx) and a pre-resolved
// NtQueryInformationProcess, both SEH-guarded, and the text is formatted in place. WinDbg
// automatically prints CommentStreamA when the dump is opened.

ULONG32 BuildMemoryCommentText() noexcept
{
    char* buf = g_CommentBuffer;
    const ULONG32 cap = kCommentBufferBytes;
    // INI layout: each metric group is a [Section] header followed by one Key=Value per line, matching
    // the user CommentStreamW format so the same parsers/eyes can read both. A leading newline keeps
    // the first section on its own line when WinDbg prints the comment.
    ULONG32 pos = CommentAppendStr(buf, cap, 0, "\n");

    MEMORYSTATUSEX sysMem = {};
    pos = CommentAppendStr(buf, cap, pos, "[SysMem]\n");
    if (QuerySystemMemory(&sysMem)) {
        pos = CommentAppendStr(buf, cap, pos, "Load=");
        pos = CommentAppendU64(buf, cap, pos, sysMem.dwMemoryLoad);
        pos = CommentAppendStr(buf, cap, pos, "%\nPhysTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalPhys);
        pos = CommentAppendStr(buf, cap, pos, "\nPhysAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailPhys);
        pos = CommentAppendStr(buf, cap, pos, "\nCommitTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalPageFile);
        pos = CommentAppendStr(buf, cap, pos, "\nCommitAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailPageFile);
        pos = CommentAppendStr(buf, cap, pos, "\nVirtTotal=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullTotalVirtual);
        pos = CommentAppendStr(buf, cap, pos, "\nVirtAvail=");
        pos = CommentAppendMB(buf, cap, pos, sysMem.ullAvailVirtual);
        pos = CommentAppendStr(buf, cap, pos, "\n");
    } else {
        pos = CommentAppendStr(buf, cap, pos, "State=unavailable\n");
    }

    INPROC_VM_COUNTERS_EX procMem = {};
    const BOOL gotProcMem = QueryProcessMemory(&procMem);
    pos = CommentAppendStr(buf, cap, pos, "[ProcMem]\n");
    if (gotProcMem) {
        pos = CommentAppendStr(buf, cap, pos, "WorkingSet=");
        pos = CommentAppendMB(buf, cap, pos, procMem.WorkingSetSize);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakWorkingSet=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakWorkingSetSize);
        pos = CommentAppendStr(buf, cap, pos, "\nPrivateCommit=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PrivateUsage);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakCommit=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakPagefileUsage);
        pos = CommentAppendStr(buf, cap, pos, "\nVirtSize=");
        pos = CommentAppendMB(buf, cap, pos, procMem.VirtualSize);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakVirtSize=");
        pos = CommentAppendMB(buf, cap, pos, procMem.PeakVirtualSize);
        pos = CommentAppendStr(buf, cap, pos, "\nPageFaults=");
        pos = CommentAppendU64(buf, cap, pos, procMem.PageFaultCount);
        pos = CommentAppendStr(buf, cap, pos, "\n");
    } else {
        pos = CommentAppendStr(buf, cap, pos, "State=unavailable\n");
    }

    // [ProcRes]: kernel-pool quota, handle counts and GUI object counts: the key signals for
    // kernel-object / handle / GDI-USER leak diagnosis.
    pos = CommentAppendStr(buf, cap, pos, "[ProcRes]\n");
    if (gotProcMem) {
        pos = CommentAppendStr(buf, cap, pos, "PagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPeakPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, "\nNonPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaNonPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakNonPagedPool=");
        pos = CommentAppendKB(buf, cap, pos, procMem.QuotaPeakNonPagedPoolUsage);
        pos = CommentAppendStr(buf, cap, pos, "\n");
    }

    ULONG handleCount = 0;
    ULONG handlePeak = 0;
    if (QueryProcessHandleCounts(&handleCount, &handlePeak)) {
        pos = CommentAppendStr(buf, cap, pos, "Handles=");
        pos = CommentAppendU64(buf, cap, pos, handleCount);
        pos = CommentAppendStr(buf, cap, pos, "\nPeakHandles=");
        pos = CommentAppendU64(buf, cap, pos, handlePeak);
        pos = CommentAppendStr(buf, cap, pos, "\n");
    } else {
        pos = CommentAppendStr(buf, cap, pos, "Handles=n/a\n");
    }

    ULONG gdiObjects = 0;
    ULONG userObjects = 0;
    if (QueryGuiResources(&gdiObjects, &userObjects)) {
        pos = CommentAppendStr(buf, cap, pos, "GDI=");
        pos = CommentAppendU64(buf, cap, pos, gdiObjects);
        pos = CommentAppendStr(buf, cap, pos, "\nUSER=");
        pos = CommentAppendU64(buf, cap, pos, userObjects);
        pos = CommentAppendStr(buf, cap, pos, "\n");
    } else {
        pos = CommentAppendStr(buf, cap, pos, "GDI=n/a\nUSER=n/a\n");
    }

    // [ProcTime] Elapsed: total dump elapsed time. The value is unknown here (it depends on how long
    // the rest of the dump takes), so reserve a fixed-width, space-padded digit field and remember its
    // offset; PatchCommentElapsed fills it in right before CommentStreamA is written last. Reserving
    // keeps the stream's DataSize stable while still letting the final number vary in width.
    pos = CommentAppendStr(buf, cap, pos, "[ProcTime]\nElapsed=");
    g_CommentElapsedOffset = kCommentElapsedUnset;
    if (pos + kCommentElapsedWidth + 4u < cap) { // room for the field + "ms" + "\n" + NUL
        g_CommentElapsedOffset = pos;
        for (ULONG32 i = 0; i < kCommentElapsedWidth; ++i) {
            buf[pos++] = ' ';
        }
        pos = CommentAppendStr(buf, cap, pos, "ms");
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
// (milliseconds), right-justified and space-padded. Heap-free; safe no-op if no field was reserved.

void PatchCommentElapsed(ULONG64 elapsedMillis) noexcept
{
    if (g_CommentElapsedOffset == kCommentElapsedUnset ||
        g_CommentElapsedOffset + kCommentElapsedWidth > kCommentBufferBytes) {
        return;
    }

    // Render the decimal digits least-significant-first.
    char digits[24];
    ULONG32 count = 0;
    if (elapsedMillis == 0) {
        digits[count++] = '0';
    }
    while (elapsedMillis != 0 && count < sizeof(digits)) {
        digits[count++] = static_cast<char>('0' + static_cast<int>(elapsedMillis % 10));
        elapsedMillis /= 10;
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


// Applies one user (section, key, value) operation to the persistent CommentStreamW INI buffer.
// Serialized via g_CommentLock and SEH-guarded so a bad caller pointer cannot crash the process.

BOOL SetCommentIniW(const wchar_t* section, const wchar_t* key, const wchar_t* value,
                    COMMENT_STRING_OPER_TYPE oper) noexcept
{
    if (section == nullptr || key == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Lightweight spin lock: serializes concurrent setters. (Not intended to be held against an
    // in-progress dump; see the public header note.)
    while (InterlockedExchange(&g_CommentLock, 1) != 0) {
        YieldProcessor();
    }

    BOOL ok = FALSE;
#if defined(_MSC_VER)
    __try {
        ok = CommentIniApply(section, key, value, oper);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
#else
    ok = CommentIniApply(section, key, value, oper);
#endif

    InterlockedExchange(&g_CommentLock, 0);
    if (!ok) {
        SetLastError(ERROR_INVALID_PARAMETER);
    }
    return ok;
}


// Returns the 4-byte-aligned on-disk byte size of CommentStreamW (wide text + NUL), or 0 if unset.

ULONG32 CommentStreamWBytes() noexcept
{
    if (g_CommentWChars == 0) {
        return 0;
    }
    const ULONG64 bytes = (static_cast<ULONG64>(g_CommentWChars) + 1) * sizeof(WCHAR);
    return static_cast<ULONG32>(Align4(bytes));
}


// Writes the prebuilt CommentStreamW bytes (wide INI text + NUL), zero-filling any alignment slack.

INPROC_STREAM_WRITE_RESULT WriteCommentStreamW(HANDLE hFile, ULONG32 byteLen) noexcept
{
    if (byteLen == 0) {
        return InprocStreamSkip;
    }
    ULONG32 contentBytes = (g_CommentWChars + 1u) * static_cast<ULONG32>(sizeof(WCHAR));
    if (contentBytes > byteLen) {
        contentBytes = byteLen;
    }
    if (!WriteAll(hFile, g_CommentBufferW, contentBytes)) {
        return InprocStreamIoFailed;
    }
    if (byteLen > contentBytes) {
        if (!WriteZeros(hFile, byteLen - contentBytes)) {
            return InprocStreamIoFailed;
        }
    }
    return InprocStreamOk;
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
