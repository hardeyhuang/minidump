#include "minidump_inproc.h"
#include "minidump_inproc_internal.h"
#include <errhandlingapi.h>


namespace minidump_inproc::internal {

#if defined(_MSC_VER)
// Forward declaration: the per-stream SEH guards below use this as their __except filter.
LONG WINAPI SwallowMiniDumpFault(DWORD code) noexcept;
#endif

// Lays out the complete minidump file, computes stream RVAs, writes directories, and serializes each enabled stream.
BOOL WriteMiniDumpInprocImpl(
    HANDLE hFile,
    MINIDUMP_TYPE dumpType,
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    ULONG64 maxFileSize) noexcept
{
    ULONG64 fullMemoryRangeCount = 0;
    ULONG64 stackRangeCount = 0, stackBytes = 0, extraRangeCount = 0, extraBytes = 0;
    ULONG64 indirectRangeCount = 0, indirectBytes = 0;
    ULONG64 memoryInfoRangeCount = 0;

    ULONG32 moduleCount = 0, moduleNameBytes = 0, moduleCodeViewBytes = 0, threadCount = 0, exceptionThreadIndex = 0;

    BOOL hasException = FALSE;
    MINIDUMP_EXCEPTION_STREAM exceptionProbe = {};
    const CONTEXT* contextProbe = nullptr;
    ULONG32 streamCount = 6;
    ULONG32 streamIndex = 0;

    // The crash path must never resolve exports lazily (GetModuleHandleW/GetProcAddress can take
    // the loader lock, which may already be held or corrupted at crash time). We depend entirely on
    // the load-time auto-initializer (AutoInitInprocApis) having cached system information and
    // pre-resolved the NTDLL routines. If it somehow did not run (extremely unusual init ordering),
    // we fail outright rather than touching the loader from the crash path.
    if (g_ApisInitialized == 0) {
        SetLastError(ERROR_NOT_READY);
        return FALSE;
    }

    const ULONG64 hardMaxFileSize = NormalizeHardMaxFileSize(maxFileSize);
    ULONG64 requestedFlags = static_cast<ULONG64>(dumpType) & MiniDumpValidTypeFlags;
    const BOOL writeFullMemory = (requestedFlags & MiniDumpWithFullMemory) != 0;
    const BOOL writeMemoryInfo = (requestedFlags & MiniDumpWithFullMemoryInfo) != 0;
    const BOOL writeThreadInfo = ((requestedFlags & MiniDumpWithThreadInfo) != 0) ||
                                 ((requestedFlags & MiniDumpWithProcessThreadData) != 0);
    BOOL includeDataSegs = (requestedFlags & MiniDumpWithDataSegs) != 0;
    const BOOL includeIndirectMemory = (requestedFlags & MiniDumpWithIndirectlyReferencedMemory) != 0;
    // MiniDumpIgnoreInaccessibleMemory is intentionally not honored: unreadable pages are always
    // zero-filled so a partially unreadable region never aborts the dump (best-effort output).

    const BOOL writeSelectedMemory = !writeFullMemory;

    ULONG32 headerRva = 0, directoryRva = sizeof(MINIDUMP_HEADER);
    ULONG32 systemInfoRva = 0, miscInfoRva = 0, commentRva = 0, moduleListRva = 0, threadListRva = 0;
    ULONG32 threadInfoListRva = 0, memoryInfoListRva = 0, memoryListRva = 0;
    ULONG32 exceptionRva = 0, threadContextsRva = 0, contextRva = 0;
    ULONG64 memoryBaseRva = 0;

    ULONG32 moduleListStreamSize = 0, moduleListStorageSize = 0, threadListStreamSize = 0;
    ULONG64 threadContextsSize64 = 0, threadInfoListSize64 = 0, memoryInfoListSize64 = 0;
    ULONG64 memoryListSize64 = 0, selectedMemoryRangeCount = 0;

    ULONG32 threadContextsSize = 0, threadInfoListSize = 0, memoryInfoListSize = 0, memoryListSize = 0;
    ULONG32 exceptionStreamSize = 0;

    MINIDUMP_HEADER header = {};
    MINIDUMP_DIRECTORY directories[14] = {};
    LARGE_INTEGER pos = {};

    hasException = CaptureExceptionStreamInfo(exceptionParam, &exceptionProbe, &contextProbe);
    // streamCount already accounts for the 6 always-present streams: SystemInfo, MiscInfo,
    // CommentStreamA, ModuleList, ThreadList and the (Memory|Memory64) list.
    if (hasException) { ++streamCount; exceptionStreamSize = sizeof(MINIDUMP_EXCEPTION_STREAM); }
    if (writeThreadInfo) ++streamCount;
    if (writeMemoryInfo) ++streamCount;

    // Build the ANSI comment text (system + process memory summary) before file layout so its size
    // is fixed. The query is heap-free and SEH-guarded, and always yields a valid NUL-terminated
    // string, so the reserved directory size stays correct even if the queries fail.
    const ULONG32 commentStreamSize = BuildMemoryCommentText();

    // Freeze every other thread and snapshot the process exactly once. All later passes read this
    // immutable plan, which is what keeps descriptor counts/sizes consistent with the byte streams.
    const DWORD preferredThreadId = hasException ? exceptionProbe.ThreadId : GetCurrentThreadId();
    (void)BuildThreadPlanAndFreeze(preferredThreadId);
    threadCount = g_ThreadPlanCount;
    exceptionThreadIndex = g_ExceptionThreadIndex;

    // Counting touches potentially corrupted process structures (PEB/LDR, VAD). On failure we
    // degrade the affected stream to empty rather than aborting the whole dump, so the rest of
    // the streams (threads, contexts, exception, stacks) still get written.
    if (!CountModules(&moduleCount, &moduleNameBytes, &moduleCodeViewBytes)) {
        moduleCount = 0; moduleNameBytes = 0; moduleCodeViewBytes = 0;
    }
    if (writeMemoryInfo && !CountMemoryInfoRanges(&memoryInfoRangeCount)) {
        memoryInfoRangeCount = 0; // keep a structurally valid, empty MemoryInfoList stream
    }

    // Sizes of the fixed (non-truncatable) streams. These do not depend on the size budget.
    moduleListStreamSize = sizeof(ULONG32) + moduleCount * sizeof(MINIDUMP_MODULE);
    moduleListStorageSize = moduleListStreamSize + moduleNameBytes + moduleCodeViewBytes;
    threadListStreamSize = sizeof(ULONG32) + threadCount * sizeof(MINIDUMP_THREAD);
    threadContextsSize64 = static_cast<ULONG64>(threadCount) * sizeof(CONTEXT);
    threadInfoListSize64 = sizeof(MINIDUMP_THREAD_INFO_LIST) + static_cast<ULONG64>(threadCount) * sizeof(MINIDUMP_THREAD_INFO);
    memoryInfoListSize64 = sizeof(MINIDUMP_MEMORY_INFO_LIST) + memoryInfoRangeCount * sizeof(MINIDUMP_MEMORY_INFO);

    // Hard size budget. Fixed metadata must fit; selected-memory dumps then add stack windows and
    // optional memory by priority. Full-memory dumps keep complete full-memory semantics and fail if
    // the complete range set would exceed the cap.
    const ULONG64 fixedSize =
        sizeof(MINIDUMP_HEADER) +
        static_cast<ULONG64>(streamCount) * sizeof(MINIDUMP_DIRECTORY) +
        sizeof(MINIDUMP_SYSTEM_INFO) +
        sizeof(MINIDUMP_MISC_INFO) +
        commentStreamSize +
        moduleListStorageSize +
        threadListStreamSize +
        threadContextsSize64 +
        (hasException ? exceptionStreamSize : 0) +
        (writeThreadInfo ? threadInfoListSize64 : 0) +
        (writeMemoryInfo ? memoryInfoListSize64 : 0);

    if (writeFullMemory) {
        // Full-memory dumps use the 64-bit Memory64List and are meant to capture the COMPLETE set of
        // committed/readable regions. We never truncate that set by address order; the production hard
        // MaxFileSize is enforced by failing cleanly if the complete full-memory dump would exceed the cap.
        if (!CaptureFullMemoryRanges()) {
            return FALSE;
        }
        fullMemoryRangeCount = g_FullMemoryRangeCount;
    } else {
        // The MemoryList stream addresses each region's bytes with a 32-bit RVA, so a selected-memory
        // dump must stay under 4 GB or those RVAs would silently truncate and corrupt the file. We
        // clamp the effective hard budget to just under 4 GB, then trim stack windows and optional
        // memory by production priority before any RVA can overflow.
        constexpr ULONG64 kSelectedDumpRvaLimit = 0xFFFF0000ULL; // < 4 GB, with headroom for padding
        const ULONG64 effectiveBudget =
            hardMaxFileSize < kSelectedDumpRvaLimit ? hardMaxFileSize : kSelectedDumpRvaLimit;

        if (!ApplyThreadStackCapturePolicy(preferredThreadId,
                                           hasException ? exceptionProbe.ExceptionRecord.ExceptionCode : 0,
                                           contextProbe,
                                           fixedSize,
                                           effectiveBudget)) {
            return FALSE;
        }

        // Thread stacks are the highest-value selected memory; include only windows kept by the
        // production stack policy and hard-size priority order.
        if (!CountStackMemoryRanges(threadCount, &stackRangeCount, &stackBytes)) {
            stackRangeCount = 0; stackBytes = 0;
        }
        ULONG64 used = fixedSize + sizeof(ULONG32) +
                       stackRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + stackBytes;

        // Priority 1: writable data segments (all-or-nothing against the remaining budget; a
        // counting failure simply drops them).
        if (includeDataSegs) {
            if (!CountExtraMemoryRanges(includeDataSegs, &extraRangeCount, &extraBytes)) {
                includeDataSegs = FALSE;
                extraRangeCount = 0;
                extraBytes = 0;
            } else {
                ULONG64 dataSegCost = extraRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + extraBytes;
                if (used + dataSegCost > effectiveBudget) {
                    includeDataSegs = FALSE;
                    extraRangeCount = 0;
                    extraBytes = 0;
                } else {
                    used += dataSegCost;
                }
            }
        }

        // Priority 2 (lowest): indirectly-referenced memory, capped by whatever budget is left.
        if (includeIndirectMemory) {
            ULONG32 cap = IndirectMemoryRangesCapacity();
            const ULONG64 perPage = sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + kIndirectMemoryRangeSize;
            const ULONG64 remaining = effectiveBudget > used ? effectiveBudget - used : 0;
            const ULONG64 fit = remaining / perPage;
            if (fit < cap) cap = static_cast<ULONG32>(fit);
            g_IndirectMemoryRangeCap = cap;
            if (cap != 0) {
                CollectKnownSelectedMemoryRanges(threadCount, includeDataSegs);
                if (!CollectIndirectMemoryRanges(threadCount, preferredThreadId, contextProbe,
                                                 &indirectRangeCount, &indirectBytes)) {
                    indirectRangeCount = 0; indirectBytes = 0;
                }
            }
        }

        selectedMemoryRangeCount = stackRangeCount + extraRangeCount + indirectRangeCount;
    }

    memoryListSize64 = writeFullMemory
        ? sizeof(ULONG64) + sizeof(ULONG64) + fullMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64)
        : sizeof(ULONG32) + selectedMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR);

    if (writeFullMemory && fixedSize + memoryListSize64 + g_FullMemoryBytes > hardMaxFileSize) {
        SetLastError(ERROR_FILE_TOO_LARGE);
        return FALSE;
    }

    if (threadContextsSize64 > 0xffffffffULL || threadInfoListSize64 > 0xffffffffULL ||
        memoryInfoListSize64 > 0xffffffffULL || memoryListSize64 > 0xffffffffULL) {
        SetLastError(ERROR_FILE_TOO_LARGE);
        return FALSE;
    }
    threadContextsSize = static_cast<ULONG32>(threadContextsSize64);
    threadInfoListSize = static_cast<ULONG32>(threadInfoListSize64);
    memoryInfoListSize = static_cast<ULONG32>(memoryInfoListSize64);
    memoryListSize = static_cast<ULONG32>(memoryListSize64);

    // Compute every stream's file offset (RVA) up front by bumping a running cursor in the exact
    // order regions are physically laid out on disk. Doing the full layout before writing lets each
    // stream's directory entry point at a fixed, final offset, and lets us write streams with simple
    // SetFilePointerEx seeks (so a skipped/faulting stream cannot shift any other stream's position).
    // Physical order: header -> directory -> SystemInfo -> MiscInfo -> CommentStreamA ->
    // ModuleList(+strings/CV) -> ThreadList -> [ThreadInfoList] -> [MemoryInfoList] ->
    // Memory(64)List descriptors -> [Exception] -> thread CONTEXT records -> memory bytes backing store.
    ULONG32 nextRva = directoryRva + streamCount * sizeof(MINIDUMP_DIRECTORY);
    systemInfoRva = nextRva; nextRva += sizeof(MINIDUMP_SYSTEM_INFO);
    miscInfoRva = nextRva; nextRva += sizeof(MINIDUMP_MISC_INFO);
    commentRva = nextRva; nextRva += commentStreamSize;
    moduleListRva = nextRva; nextRva += moduleListStorageSize;
    threadListRva = nextRva; nextRva += threadListStreamSize;
    if (writeThreadInfo) { threadInfoListRva = nextRva; nextRva += threadInfoListSize; }
    if (writeMemoryInfo) { memoryInfoListRva = nextRva; nextRva += memoryInfoListSize; }
    memoryListRva = nextRva; nextRva += memoryListSize;
    if (hasException) { exceptionRva = nextRva; nextRva += exceptionStreamSize; }
    // All thread CONTEXT records sit contiguously; ThreadList entries and the ExceptionStream both
    // reference into this single block. The exception thread's context is not stored separately --
    // contextRva simply aliases the exception thread's slot inside the contiguous context array.
    threadContextsRva = nextRva; nextRva += threadContextsSize;
    contextRva = threadContextsRva + exceptionThreadIndex * sizeof(CONTEXT);
    // The Memory(64)List descriptors carry RVAs that point here; the actual region bytes are the
    // last thing in the file, streamed after all fixed-size structures are placed.
    memoryBaseRva = nextRva;

    // HARD SIZE GUARD for selected-memory dumps. MINIDUMP_MEMORY_DESCRIPTOR.Memory.Rva is 32-bit, so
    // every selected region's bytes must start below 4 GB and the final file must stay within the
    // production MaxFileSize cap. Rather than emit a silently truncated corrupt dump, re-check the
    // final byte-store extent in full 64-bit precision here.
    if (writeSelectedMemory) {
        // nextRva is a 32-bit running cursor; reconstruct the byte-store end in 64-bit from the fixed
        // base and the selected byte totals so a wrapped cursor cannot hide the overflow.
        const ULONG64 selectedMemoryBytes = stackBytes + extraBytes + indirectBytes;
        const ULONG64 memoryEndRva64 = memoryBaseRva + selectedMemoryBytes;
        if (memoryBaseRva > 0xffffffffULL || memoryEndRva64 > 0xffffffffULL || memoryEndRva64 > hardMaxFileSize) {
            SetLastError(ERROR_FILE_TOO_LARGE);
            return FALSE;
        }
    }

    header.Signature = MINIDUMP_SIGNATURE;
    header.Version = MINIDUMP_VERSION;
    header.NumberOfStreams = streamCount;
    header.StreamDirectoryRva = directoryRva;
    header.Flags = requestedFlags;

    directories[streamIndex].StreamType = SystemInfoStream;
    directories[streamIndex].Location.Rva = systemInfoRva;
    directories[streamIndex].Location.DataSize = sizeof(MINIDUMP_SYSTEM_INFO);
    ++streamIndex;
    directories[streamIndex].StreamType = MiscInfoStream;
    directories[streamIndex].Location.Rva = miscInfoRva;
    directories[streamIndex].Location.DataSize = sizeof(MINIDUMP_MISC_INFO);
    ++streamIndex;
    directories[streamIndex].StreamType = CommentStreamA;
    directories[streamIndex].Location.Rva = commentRva;
    directories[streamIndex].Location.DataSize = commentStreamSize;
    ++streamIndex;
    directories[streamIndex].StreamType = ModuleListStream;
    directories[streamIndex].Location.Rva = moduleListRva;
    directories[streamIndex].Location.DataSize = moduleListStreamSize;
    ++streamIndex;
    directories[streamIndex].StreamType = ThreadListStream;
    directories[streamIndex].Location.Rva = threadListRva;
    directories[streamIndex].Location.DataSize = threadListStreamSize;
    ++streamIndex;
    if (writeThreadInfo) {
        directories[streamIndex].StreamType = ThreadInfoListStream;
        directories[streamIndex].Location.Rva = threadInfoListRva;
        directories[streamIndex].Location.DataSize = threadInfoListSize;
        ++streamIndex;
    }
    if (writeMemoryInfo) {
        directories[streamIndex].StreamType = MemoryInfoListStream;
        directories[streamIndex].Location.Rva = memoryInfoListRva;
        directories[streamIndex].Location.DataSize = memoryInfoListSize;
        ++streamIndex;
    }
    directories[streamIndex].StreamType = writeFullMemory ? Memory64ListStream : MemoryListStream;
    directories[streamIndex].Location.Rva = memoryListRva;
    directories[streamIndex].Location.DataSize = memoryListSize;
    ++streamIndex;
    if (hasException) {
        directories[streamIndex].StreamType = ExceptionStream;
        directories[streamIndex].Location.Rva = exceptionRva;
        directories[streamIndex].Location.DataSize = exceptionStreamSize;
        ++streamIndex;
    }

    // Mandatory file structure: header + stream directory. A failure here means the file is
    // unusable, so it is the only part that hard-aborts the dump.
    pos.QuadPart = headerRva;
    if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)
        || !SetEndOfFile(hFile)) return FALSE;
    if (!WriteAll(hFile, &header, sizeof(header))) return FALSE;
    if (!WriteAll(hFile, directories, streamCount * sizeof(MINIDUMP_DIRECTORY))) return FALSE;

    // Each content stream is emitted under its own SEH guard. If gathering a stream faults because
    // process memory is severely corrupted, that single stream is skipped (its pre-laid-out region
    // is left zero-filled) and the dump continues with every other stream intact. Only a genuine
    // file-I/O failure (bad handle, disk full) still aborts, since nothing further can be written.
    BOOL ioFailed = FALSE;
#if defined(_MSC_VER)
#define INPROC_EMIT_STREAM_RESULT(seekRva, writeResultExpr)                                  \
    do {                                                                                     \
        __try {                                                                              \
            pos.QuadPart = static_cast<LONGLONG>(seekRva);                                   \
            INPROC_STREAM_WRITE_RESULT streamResult = InprocStreamIoFailed;                  \
            if (SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) {                         \
                streamResult = (writeResultExpr);                                            \
            }                                                                                \
            if (streamResult == InprocStreamIoFailed) {                                      \
                ioFailed = TRUE;                                                             \
            }                                                                                \
        } __except (SwallowMiniDumpFault(GetExceptionCode())) {                              \
            /* memory fault while gathering this stream: skip it, keep the rest of the dump */ \
        }                                                                                    \
        if (ioFailed) return FALSE;                                                          \
    } while (0)
#define INPROC_EMIT_STREAM(seekRva, writeExpr)                                              \
    INPROC_EMIT_STREAM_RESULT((seekRva), StreamResultFromBool((writeExpr)))
#else
#define INPROC_EMIT_STREAM_RESULT(seekRva, writeResultExpr)                                  \
    do {                                                                                     \
        pos.QuadPart = static_cast<LONGLONG>(seekRva);                                       \
        if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) {                            \
            return FALSE;                                                                    \
        }                                                                                    \
        INPROC_STREAM_WRITE_RESULT streamResult = (writeResultExpr);                         \
        if (streamResult == InprocStreamIoFailed) {                                          \
            return FALSE;                                                                    \
        }                                                                                    \
    } while (0)
#define INPROC_EMIT_STREAM(seekRva, writeExpr)                                              \
    INPROC_EMIT_STREAM_RESULT((seekRva), StreamResultFromBool((writeExpr)))
#endif

    INPROC_EMIT_STREAM(systemInfoRva, WriteSystemInfo(hFile));
    INPROC_EMIT_STREAM(miscInfoRva, WriteMiscInfo(hFile));
    INPROC_EMIT_STREAM_RESULT(commentRva, WriteCommentStream(hFile, commentStreamSize));
    INPROC_EMIT_STREAM(moduleListRva, WriteModuleList(hFile, moduleCount, moduleListRva));
    INPROC_EMIT_STREAM(threadListRva, WriteThreadList(hFile, threadCount, threadContextsRva, \
        memoryBaseRva, writeSelectedMemory));
    if (writeThreadInfo) {
        INPROC_EMIT_STREAM(threadInfoListRva, WriteThreadInfoList(hFile, threadCount));
    }
    if (writeMemoryInfo) {
        INPROC_EMIT_STREAM(memoryInfoListRva, WriteMemoryInfoList(hFile, memoryInfoRangeCount));
    }
    if (writeFullMemory) {
        INPROC_EMIT_STREAM(memoryListRva, WriteMemoryDescriptors(hFile, fullMemoryRangeCount, memoryBaseRva));
    } else {
        INPROC_EMIT_STREAM(memoryListRva, WriteSelectedMemoryDescriptors(hFile, threadCount, includeDataSegs, \
            stackRangeCount, extraRangeCount, indirectRangeCount, memoryBaseRva));
    }
    if (hasException) {
        INPROC_EMIT_STREAM_RESULT(exceptionRva, WriteExceptionStream(hFile, contextRva, &exceptionProbe));
    }
    INPROC_EMIT_STREAM(threadContextsRva, WriteThreadContexts(hFile, threadCount, exceptionParam));
    if (writeFullMemory) {
        INPROC_EMIT_STREAM(memoryBaseRva, WriteMemoryBytes(hFile, fullMemoryRangeCount));
    } else {
        INPROC_EMIT_STREAM(memoryBaseRva, WriteSelectedMemoryBytes(hFile, threadCount, includeDataSegs, indirectRangeCount));
    }
#undef INPROC_EMIT_STREAM
#undef INPROC_EMIT_STREAM_RESULT

    return TRUE;
}


#if defined(_MSC_VER)
// Converts any unexpected writer fault into a FALSE return from the public API.
LONG WINAPI SwallowMiniDumpFault(DWORD code) noexcept
{
    SetLastError(code);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

} // namespace minidump_inproc::internal

// Optional explicit initialization (see header). Lets callers force system-info caching and NTDLL
// entry-point resolution at a well-defined point instead of relying on cross-translation-unit
// global-constructor ordering. Delegates to the internal resolver, which is itself idempotent and
// no-ops after the first successful resolution, so this is safe to call any number of times.
extern "C" MINIDUMP_INPROC_API void WINAPI ResolveInprocApis(void) noexcept
{
    minidump_inproc::internal::ResolveInprocApis();
}

// Public crash-path writer. The caller owns file creation and lifetime; this function only
// serializes minidump streams and converts unexpected access violations into FALSE. The required
// NTDLL routines are resolved automatically at module load, so no explicit init call is needed.
extern "C" MINIDUMP_INPROC_API BOOL WINAPI WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    ULONG64 MaxFileSize) noexcept
{
    if (hFile == nullptr || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    // This is an IN-PROCESS self-dump: every pointer (exception record, context, scanned memory) is
    // read directly from our own address space. ClientPointers != FALSE means the caller is claiming
    // the pointers belong to a *different* process, which this implementation cannot honor. Reject it
    // rather than silently misinterpreting foreign-process addresses as local ones.
    if (ExceptionParam != nullptr) {
        BOOL clientPointers = FALSE;
        if (minidump_inproc::internal::SafeCopyBytes(
                &clientPointers, &ExceptionParam->ClientPointers, sizeof(clientPointers)) &&
            clientPointers != FALSE) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    // Serialize concurrent crashes: only one thread writes a dump at a time. The shared static
    // capture buffers and thread freeze are not reentrant, so a second crasher must back off.
    if (InterlockedCompareExchange(&minidump_inproc::internal::g_DumpInProgress, 1, 0) != 0) {
        SetLastError(ERROR_BUSY);
        return FALSE;
    }

    BOOL result = FALSE;
#if defined(_MSC_VER)
    __try {
#endif
        result = minidump_inproc::internal::WriteMiniDumpInprocImpl(hFile, DumpType, ExceptionParam, MaxFileSize);
#if defined(_MSC_VER)
    } __except (minidump_inproc::internal::SwallowMiniDumpFault(GetExceptionCode())) {
        result = FALSE;
    }
#endif

    // Always resume/close any threads frozen by the writer, even if it faulted mid-dump.
    minidump_inproc::internal::ResumeThreadPlan();
    InterlockedExchange(&minidump_inproc::internal::g_DumpInProgress, 0);
    return result;
}
