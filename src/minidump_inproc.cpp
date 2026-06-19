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
    PMINIDUMP_USER_STREAM_INFORMATION userStreamParam,
    ULONG64 maxFileSize) noexcept
{
    // Start the total-elapsed stopwatch as early as possible so the duration patched into
    // CommentStreamA covers nearly the entire dump. QueryPerformanceCounter reads the shared
    // user-mode timer page: no heap, no syscall, no loader lock -- safe on the crash path.
    LARGE_INTEGER perfStart = {};
    QueryPerformanceCounter(&perfStart);

    // Caller user streams that survive budget admission (in array order), and their total padded
    // byte size. Admitted with higher priority than indirectly-referenced memory, subject to the cap.
    ULONG32 includedUserStreamCount = 0;
    ULONG64 userStreamBytes = 0;

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
    // UnloadedModuleListStream is opt-in: the caller must request MiniDumpWithUnloadedModules, matching
    // MiniDumpWriteDump's behavior. Without the flag the ntdll unload ring is never touched.
    const BOOL includeUnloadedModules = (requestedFlags & MiniDumpWithUnloadedModules) != 0;
    // MiniDumpIgnoreInaccessibleMemory is intentionally not honored: unreadable pages are always
    // zero-filled so a partially unreadable region never aborts the dump (best-effort output).

    const BOOL writeSelectedMemory = !writeFullMemory;

    ULONG32 headerRva = 0, directoryRva = sizeof(MINIDUMP_HEADER);
    ULONG32 systemInfoRva = 0, miscInfoRva = 0, commentRva = 0, commentWRva = 0, moduleListRva = 0, threadListRva = 0;
    ULONG32 unloadedModuleListRva = 0;
    ULONG32 threadInfoListRva = 0, memoryInfoListRva = 0, memoryListRva = 0;
    ULONG32 exceptionRva = 0, threadContextsRva = 0, contextRva = 0;
    ULONG64 memoryBaseRva = 0;

    ULONG32 moduleListStreamSize = 0, moduleListStorageSize = 0, threadListStreamSize = 0;
    // UnloadedModuleListStream: present only when MiniDumpWithUnloadedModules is requested AND ntdll's
    // unload ring has at least one entry. Both the stream content (header + fixed entries) and trailing
    // MINIDUMP_STRING name storage are fixed.
    ULONG32 unloadedModuleCount = 0, unloadedModuleNameBytes = 0;
    ULONG32 unloadedModuleListStreamSize = 0, unloadedModuleListStorageSize = 0;
    BOOL writeUnloadedModules = FALSE;
    ULONG64 threadContextsSize64 = 0, threadInfoListSize64 = 0, memoryInfoListSize64 = 0;
    ULONG64 memoryListSize64 = 0, selectedMemoryRangeCount = 0;

    ULONG32 threadContextsSize = 0, threadInfoListSize = 0, memoryInfoListSize = 0, memoryListSize = 0;
    ULONG32 exceptionStreamSize = 0;

    // ThreadNamesStream: present only when at least one thread has a kernel-stored name. Its content
    // size (descriptor list) and the trailing MINIDUMP_STRING storage are both fixed (non-truncatable).
    ULONG32 threadNameCount = 0, threadNameStorageBytes = 0;
    ULONG32 threadNamesStreamSize = 0, threadNamesStorageSize = 0, threadNamesRva = 0;
    BOOL writeThreadNames = FALSE;

    MINIDUMP_HEADER header = {};
    // Up to 12 built-in stream entries (6 always-present + CommentStreamW/Exception/ThreadInfo/
    // MemoryInfo/ThreadNames/UnloadedModuleList) plus one entry per admitted user stream.
    MINIDUMP_DIRECTORY directories[12 + kMaxUserStreams] = {};
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

    // The user-supplied CommentStreamW (INI sections/keys set via SetMiniDumpInprocComment*) is a
    // separate, optional wide-text stream. Its content was accumulated before the dump, so its size
    // is already fixed; emit a directory entry only when something was actually set.
    const ULONG32 commentWStreamSize = CommentStreamWBytes();
    const BOOL writeCommentW = (commentWStreamSize != 0);
    if (writeCommentW) ++streamCount;

    // Snapshot the caller's user streams once (validated under SEH) so layout and the write pass
    // agree on which streams are present and their sizes. Admission against the budget happens below.
    SnapshotUserStreams(userStreamParam);

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

    // Unloaded modules: a crash IP or return address landing in a DLL unloaded shortly before the
    // fault (plugin/COM/delay-load teardown) cannot be named by ModuleList alone. The ntdll ring read
    // here lets WinDbg resolve such frames. Opt-in via MiniDumpWithUnloadedModules; without the flag
    // the ring is never read. Degrade to no stream on failure rather than aborting.
    if (includeUnloadedModules && !CountUnloadedModules(&unloadedModuleCount, &unloadedModuleNameBytes)) {
        unloadedModuleCount = 0; unloadedModuleNameBytes = 0;
    }
    writeUnloadedModules = includeUnloadedModules && (unloadedModuleCount != 0);
    if (writeUnloadedModules) {
        ++streamCount;
        unloadedModuleListStreamSize = static_cast<ULONG32>(sizeof(INPROC_MINIDUMP_UNLOADED_MODULE_LIST)) +
                                       unloadedModuleCount * static_cast<ULONG32>(sizeof(INPROC_MINIDUMP_UNLOADED_MODULE));
        unloadedModuleListStorageSize = unloadedModuleListStreamSize + unloadedModuleNameBytes;
    }
    if (writeMemoryInfo && !CountMemoryInfoRanges(&memoryInfoRangeCount)) {
        memoryInfoRangeCount = 0; // keep a structurally valid, empty MemoryInfoList stream
    }

    // ThreadNamesStream is emitted only if any thread actually has a name; an empty stream would just
    // waste a directory entry. Names were captured into the frozen plan by BuildThreadPlanAndFreeze.
    if (!CountThreadNames(threadCount, &threadNameCount, &threadNameStorageBytes)) {
        threadNameCount = 0; threadNameStorageBytes = 0;
    }
    writeThreadNames = (threadNameCount != 0);
    if (writeThreadNames) {
        ++streamCount;
        threadNamesStreamSize = static_cast<ULONG32>(sizeof(INPROC_MINIDUMP_THREAD_NAME_LIST)) +
                                threadNameCount * static_cast<ULONG32>(sizeof(INPROC_MINIDUMP_THREAD_NAME));
        threadNamesStorageSize = threadNamesStreamSize + threadNameStorageBytes;
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
        (writeCommentW ? commentWStreamSize : 0) +
        moduleListStorageSize +
        (writeUnloadedModules ? unloadedModuleListStorageSize : 0) +
        threadListStreamSize +
        threadContextsSize64 +
        (hasException ? exceptionStreamSize : 0) +
        (writeThreadInfo ? threadInfoListSize64 : 0) +
        (writeMemoryInfo ? memoryInfoListSize64 : 0) +
        (writeThreadNames ? threadNamesStorageSize : 0);

    if (writeFullMemory) {
        // Full-memory dumps use the 64-bit Memory64List and are meant to capture the COMPLETE set of
        // committed/readable regions. We never truncate that set by address order; the production hard
        // MaxFileSize is enforced by failing cleanly if the complete full-memory dump would exceed the cap.
        if (!CaptureFullMemoryRanges()) {
            return FALSE;
        }
        fullMemoryRangeCount = g_FullMemoryRangeCount;

        // User streams: admit in array order against the hard cap, beyond the complete memory set.
        // Each is all-or-nothing; once one would not fit, stop (keeps inclusion deterministic).
        const ULONG64 fullListBytes = sizeof(ULONG64) + sizeof(ULONG64) +
                                      fullMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64);
        ULONG64 fullUsed = fixedSize + fullListBytes + g_FullMemoryBytes;
        for (ULONG32 i = 0; i < g_UserStreamCount; ++i) {
            const ULONG64 cost = sizeof(MINIDUMP_DIRECTORY) + Align4(g_UserStreams[i].BufferSize);
            if (fullUsed + cost > hardMaxFileSize) {
                break;
            }
            fullUsed += cost;
            userStreamBytes += Align4(g_UserStreams[i].BufferSize);
            ++includedUserStreamCount;
        }
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

        // Priority 2: caller user streams. Higher priority than indirectly-referenced memory; each
        // is all-or-nothing against the remaining budget, included in array order until one would
        // exceed the cap (then stop, so inclusion stays a deterministic prefix).
        for (ULONG32 i = 0; i < g_UserStreamCount; ++i) {
            const ULONG64 cost = sizeof(MINIDUMP_DIRECTORY) + Align4(g_UserStreams[i].BufferSize);
            if (used + cost > effectiveBudget) {
                break;
            }
            used += cost;
            userStreamBytes += Align4(g_UserStreams[i].BufferSize);
            ++includedUserStreamCount;
        }

        // Priority 3 (lowest): indirectly-referenced memory, capped by whatever budget is left.
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

    // Every admitted user stream adds one directory entry; fold them into the total stream count now
    // so the directory size and all downstream RVAs account for them.
    streamCount += includedUserStreamCount;

    memoryListSize64 = writeFullMemory
        ? sizeof(ULONG64) + sizeof(ULONG64) + fullMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64)
        : sizeof(ULONG32) + selectedMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR);

    if (writeFullMemory &&
        fixedSize + memoryListSize64 + g_FullMemoryBytes + userStreamBytes +
                static_cast<ULONG64>(includedUserStreamCount) * sizeof(MINIDUMP_DIRECTORY) >
            hardMaxFileSize) {
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
    // ModuleList(+strings/CV) -> [UnloadedModuleList(+name strings)] -> ThreadList ->
    // [ThreadNames(+name strings)] -> [ThreadInfoList] -> [MemoryInfoList] -> Memory(64)List
    // descriptors -> [Exception] -> thread CONTEXT records -> memory bytes backing store.
    ULONG32 nextRva = directoryRva + streamCount * sizeof(MINIDUMP_DIRECTORY);
    systemInfoRva = nextRva; nextRva += sizeof(MINIDUMP_SYSTEM_INFO);
    miscInfoRva = nextRva; nextRva += sizeof(MINIDUMP_MISC_INFO);
    commentRva = nextRva; nextRva += commentStreamSize;
    if (writeCommentW) { commentWRva = nextRva; nextRva += commentWStreamSize; }
    moduleListRva = nextRva; nextRva += moduleListStorageSize;
    if (writeUnloadedModules) { unloadedModuleListRva = nextRva; nextRva += unloadedModuleListStorageSize; }
    threadListRva = nextRva; nextRva += threadListStreamSize;
    if (writeThreadNames) { threadNamesRva = nextRva; nextRva += threadNamesStorageSize; }
    if (writeThreadInfo) { threadInfoListRva = nextRva; nextRva += threadInfoListSize; }
    if (writeMemoryInfo) { memoryInfoListRva = nextRva; nextRva += memoryInfoListSize; }
    memoryListRva = nextRva; nextRva += memoryListSize;
    if (hasException) { exceptionRva = nextRva; nextRva += exceptionStreamSize; }
    // All thread CONTEXT records sit contiguously; ThreadList entries and the ExceptionStream both
    // reference into this single block. The exception thread's context is not stored separately --
    // contextRva simply aliases the exception thread's slot inside the contiguous context array.
    threadContextsRva = nextRva; nextRva += threadContextsSize;
    contextRva = threadContextsRva + exceptionThreadIndex * sizeof(CONTEXT);
    // Caller user-stream byte blobs, laid out contiguously (each 4-byte padded) right after the
    // thread contexts. Their directory entries (added below) point at these RVAs.
    for (ULONG32 i = 0; i < includedUserStreamCount; ++i) {
        g_UserStreams[i].Rva = nextRva;
        nextRva += static_cast<ULONG32>(Align4(g_UserStreams[i].BufferSize));
    }
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
    if (writeCommentW) {
        directories[streamIndex].StreamType = CommentStreamW;
        directories[streamIndex].Location.Rva = commentWRva;
        directories[streamIndex].Location.DataSize = commentWStreamSize;
        ++streamIndex;
    }
    directories[streamIndex].StreamType = ModuleListStream;
    directories[streamIndex].Location.Rva = moduleListRva;
    directories[streamIndex].Location.DataSize = moduleListStreamSize;
    ++streamIndex;
    if (writeUnloadedModules) {
        directories[streamIndex].StreamType = kUnloadedModuleListStreamType;
        directories[streamIndex].Location.Rva = unloadedModuleListRva;
        directories[streamIndex].Location.DataSize = unloadedModuleListStreamSize;
        ++streamIndex;
    }
    directories[streamIndex].StreamType = ThreadListStream;
    directories[streamIndex].Location.Rva = threadListRva;
    directories[streamIndex].Location.DataSize = threadListStreamSize;
    ++streamIndex;
    if (writeThreadNames) {
        directories[streamIndex].StreamType = kThreadNamesStreamType;
        directories[streamIndex].Location.Rva = threadNamesRva;
        directories[streamIndex].Location.DataSize = threadNamesStreamSize;
        ++streamIndex;
    }
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
    // One directory entry per admitted user stream, using the caller-supplied StreamType and the
    // RVA assigned during layout. StreamType collisions with built-in streams are the caller's
    // responsibility, exactly as with MiniDumpWriteDump's UserStreamParam.
    for (ULONG32 i = 0; i < includedUserStreamCount; ++i) {
        directories[streamIndex].StreamType = g_UserStreams[i].Type;
        directories[streamIndex].Location.Rva = g_UserStreams[i].Rva;
        directories[streamIndex].Location.DataSize = g_UserStreams[i].BufferSize;
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
    // CommentStreamW holds the user's accumulated INI comment, fixed before the dump began, so it can
    // be written here (unlike CommentStreamA, which is patched with the elapsed time and written last).
    if (writeCommentW) {
        INPROC_EMIT_STREAM_RESULT(commentWRva, WriteCommentStreamW(hFile, commentWStreamSize));
    }
    // CommentStreamA is intentionally written LAST (after all other streams below) so the elapsed
    // time patched into it reflects almost the entire dump. Its file region was laid out at
    // commentRva and is seeked to at the end.
    INPROC_EMIT_STREAM(moduleListRva, WriteModuleList(hFile, moduleCount, moduleListRva));
    if (writeUnloadedModules) {
        INPROC_EMIT_STREAM(unloadedModuleListRva, \
            WriteUnloadedModuleList(hFile, unloadedModuleCount, unloadedModuleListRva));
    }
    INPROC_EMIT_STREAM(threadListRva, WriteThreadList(hFile, threadCount, threadContextsRva, \
        memoryBaseRva, writeSelectedMemory));
    if (writeThreadNames) {
        INPROC_EMIT_STREAM(threadNamesRva, WriteThreadNames(hFile, threadCount, threadNamesRva));
    }
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
    // Caller user-stream blobs are laid out contiguously from the first stream's RVA; one seek there
    // plus sequential writes places every stream. Guarded by the same per-stream SEH as the rest.
    if (includedUserStreamCount != 0) {
        INPROC_EMIT_STREAM(g_UserStreams[0].Rva, WriteUserStreams(hFile, includedUserStreamCount));
    }

    // Everything else is on disk now: measure total elapsed (microseconds), patch it into the
    // prebuilt comment buffer, and write CommentStreamA last so its duration is representative.
    {
        LARGE_INTEGER perfEnd = {};
        LARGE_INTEGER perfFreq = {};
        QueryPerformanceCounter(&perfEnd);
        QueryPerformanceFrequency(&perfFreq);
        ULONG64 elapsedMicros = 0;
        if (perfFreq.QuadPart > 0 && perfEnd.QuadPart > perfStart.QuadPart) {
            elapsedMicros = static_cast<ULONG64>(perfEnd.QuadPart - perfStart.QuadPart) * 1000000ULL /
                            static_cast<ULONG64>(perfFreq.QuadPart);
        }
        PatchCommentElapsed(elapsedMicros);
    }
    INPROC_EMIT_STREAM_RESULT(commentRva, WriteCommentStream(hFile, commentStreamSize));
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
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
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
        result = minidump_inproc::internal::WriteMiniDumpInprocImpl(hFile, DumpType, ExceptionParam, UserStreamParam, MaxFileSize);
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

// Records a wide-character (section, key, value) entry into the dump's CommentStreamW. See the header
// for the full per-operation semantics. Thin wrapper over the internal INI worker.
extern "C" MINIDUMP_INPROC_API BOOL WINAPI SetMiniDumpInprocCommentW(
    const wchar_t* section,
    const wchar_t* key,
    const wchar_t* value,
    COMMENT_STRING_OPER_TYPE oper) noexcept
{
    return minidump_inproc::internal::SetCommentIniW(section, key, value, oper);
}

// ANSI counterpart: converts each non-NULL input from the active ANSI code page (CP_ACP) to UTF-16
// and forwards to the wide worker, so A and W data land in the same CommentStreamW. A NULL value is
// forwarded as NULL (preserving the delete/no-op semantics); a conversion failure fails the call.
// The section/key conversion buffers are intentionally sized to kCommentMaxSectionKeyChars + 1, so a
// section/key that exceeds the limit overflows the buffer and fails here, matching the wide worker's
// length check. The value buffer is left large; its truncation to kCommentMaxValueChars and INI
// escaping are performed by the wide worker.
extern "C" MINIDUMP_INPROC_API BOOL WINAPI SetMiniDumpInprocCommentA(
    const char* section,
    const char* key,
    const char* value,
    COMMENT_STRING_OPER_TYPE oper) noexcept
{
    constexpr int kIdCap = static_cast<int>(minidump_inproc::internal::kCommentMaxSectionKeyChars) + 1;
    constexpr int kValCap = static_cast<int>(minidump_inproc::internal::kCommentMaxValueChars) + 1;
    wchar_t wsection[kIdCap];
    wchar_t wkey[kIdCap];
    wchar_t wvalue[kValCap];
    const wchar_t* ps = nullptr;
    const wchar_t* pk = nullptr;
    const wchar_t* pv = nullptr;

    // The conversions dereference caller-owned char* buffers; guard them so a bad pointer fails the
    // call instead of crashing (the wide worker is itself SEH-guarded for its inputs).
#if defined(_MSC_VER)
    __try {
#endif
        if (section != nullptr) {
            if (MultiByteToWideChar(CP_ACP, 0, section, -1, wsection, kIdCap) == 0) {
                return FALSE;
            }
            ps = wsection;
        }
        if (key != nullptr) {
            if (MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, kIdCap) == 0) {
                return FALSE;
            }
            pk = wkey;
        }
        if (value != nullptr) {
            if (MultiByteToWideChar(CP_ACP, 0, value, -1, wvalue, kValCap) == 0) {
                return FALSE;
            }
            pv = wvalue;
        }
#if defined(_MSC_VER)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
#endif

    return minidump_inproc::internal::SetCommentIniW(ps, pk, pv, oper);
}
