#include "minidump_inproc.h"
#include "minidump_inproc_internal.h"


namespace minidump_inproc::internal {

// Lays out the complete minidump file, computes stream RVAs, writes directories, and serializes each enabled stream.
BOOL WriteMiniDumpInprocImpl(
    HANDLE hFile,
    MINIDUMP_TYPE dumpType,
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    ULONG64 maxFileSize) noexcept
{
    ULONG64 fullMemoryRangeCount = 0, fullMemoryBytes = 0;
    ULONG64 stackRangeCount = 0, stackBytes = 0, extraRangeCount = 0, extraBytes = 0;
    ULONG64 indirectRangeCount = 0, indirectBytes = 0;
    ULONG64 memoryInfoRangeCount = 0;

    ULONG32 moduleCount = 0, moduleNameBytes = 0, moduleCodeViewBytes = 0, threadCount = 0, exceptionThreadIndex = 0;

    BOOL hasException = FALSE;
    MINIDUMP_EXCEPTION_STREAM exceptionProbe = {};
    const CONTEXT* contextProbe = nullptr;
    ULONG32 streamCount = 5;
    ULONG32 streamIndex = 0;

    // Safety net in case the load-time auto-initializer did not run (unusual init ordering).
    if (g_ApisInitialized == 0) {
        (void)ResolveInprocApis();
    }

    ULONG64 requestedFlags = static_cast<ULONG64>(dumpType) & MiniDumpValidTypeFlags;
    const BOOL writeFullMemory = (requestedFlags & MiniDumpWithFullMemory) != 0;
    const BOOL writeMemoryInfo = (requestedFlags & MiniDumpWithFullMemoryInfo) != 0;
    const BOOL writeThreadInfo = ((requestedFlags & MiniDumpWithThreadInfo) != 0) ||
                                 ((requestedFlags & MiniDumpWithProcessThreadData) != 0);
    const BOOL writeUnloadedModules = (requestedFlags & MiniDumpWithUnloadedModules) != 0;
    BOOL includeDataSegs = (requestedFlags & MiniDumpWithDataSegs) != 0;
    const BOOL includeIndirectMemory = (requestedFlags & MiniDumpWithIndirectlyReferencedMemory) != 0;
    const BOOL ignoreInaccessible = (requestedFlags & MiniDumpIgnoreInaccessibleMemory) != 0;

    const BOOL writeSelectedMemory = !writeFullMemory;

    ULONG32 headerRva = 0, directoryRva = sizeof(MINIDUMP_HEADER);
    ULONG32 systemInfoRva = 0, miscInfoRva = 0, moduleListRva = 0, threadListRva = 0;
    ULONG32 threadInfoListRva = 0, memoryInfoListRva = 0, memoryListRva = 0;
    ULONG32 unloadedModuleListRva = 0;
    ULONG32 exceptionRva = 0, threadContextsRva = 0, contextRva = 0;
    ULONG64 memoryBaseRva = 0;

    ULONG32 moduleListStreamSize = 0, moduleListStorageSize = 0, threadListStreamSize = 0;
    ULONG64 threadContextsSize64 = 0, threadInfoListSize64 = 0, memoryInfoListSize64 = 0;
    ULONG64 memoryListSize64 = 0, selectedMemoryRangeCount = 0;

    ULONG32 threadContextsSize = 0, threadInfoListSize = 0, memoryInfoListSize = 0, memoryListSize = 0;
    ULONG32 unloadedModuleListSize = 0, exceptionStreamSize = 0;

    MINIDUMP_HEADER header = {};
    MINIDUMP_DIRECTORY directories[14] = {};
    LARGE_INTEGER pos = {};

    hasException = CaptureExceptionStreamInfo(exceptionParam, &exceptionProbe, &contextProbe);
    // streamCount already accounts for the 5 always-present streams:
    // SystemInfo, MiscInfo, ModuleList, ThreadList and the (Memory|Memory64) list.
    if (hasException) { ++streamCount; exceptionStreamSize = sizeof(MINIDUMP_EXCEPTION_STREAM); }
    if (writeThreadInfo) ++streamCount;
    if (writeMemoryInfo) ++streamCount;
    if (writeUnloadedModules) { ++streamCount; unloadedModuleListSize = sizeof(MINIDUMP_UNLOADED_MODULE_LIST); }

    // Freeze every other thread and snapshot the process exactly once. All later passes read this
    // immutable plan, which is what keeps descriptor counts/sizes consistent with the byte streams.
    const DWORD preferredThreadId = hasException ? exceptionProbe.ThreadId : GetCurrentThreadId();
    (void)BuildThreadPlanAndFreeze(preferredThreadId);
    threadCount = g_ThreadPlanCount;
    exceptionThreadIndex = g_ExceptionThreadIndex;

    if (!CountModules(&moduleCount, &moduleNameBytes, &moduleCodeViewBytes)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
    if (writeMemoryInfo && !CountMemoryInfoRanges(&memoryInfoRangeCount)) return FALSE;

    // Sizes of the fixed (non-truncatable) streams. These do not depend on the size budget.
    moduleListStreamSize = sizeof(ULONG32) + moduleCount * sizeof(MINIDUMP_MODULE);
    moduleListStorageSize = moduleListStreamSize + moduleNameBytes + moduleCodeViewBytes;
    threadListStreamSize = sizeof(ULONG32) + threadCount * sizeof(MINIDUMP_THREAD);
    threadContextsSize64 = static_cast<ULONG64>(threadCount) * sizeof(CONTEXT);
    threadInfoListSize64 = sizeof(MINIDUMP_THREAD_INFO_LIST) + static_cast<ULONG64>(threadCount) * sizeof(MINIDUMP_THREAD_INFO);
    memoryInfoListSize64 = sizeof(MINIDUMP_MEMORY_INFO_LIST) + memoryInfoRangeCount * sizeof(MINIDUMP_MEMORY_INFO);

    // Soft size budget. Mandatory data is always written; only memory content is truncated.
    const ULONG64 budget = maxFileSize;
    const BOOL hasBudget = budget != 0;
    const ULONG64 fixedSize =
        sizeof(MINIDUMP_HEADER) +
        static_cast<ULONG64>(streamCount) * sizeof(MINIDUMP_DIRECTORY) +
        sizeof(MINIDUMP_SYSTEM_INFO) +
        sizeof(MINIDUMP_MISC_INFO) +
        moduleListStorageSize +
        threadListStreamSize +
        threadContextsSize64 +
        (hasException ? exceptionStreamSize : 0) +
        (writeThreadInfo ? threadInfoListSize64 : 0) +
        (writeMemoryInfo ? memoryInfoListSize64 : 0) +
        (writeUnloadedModules ? unloadedModuleListSize : 0);

    if (writeFullMemory) {
        // Capture every committed region once, then keep as many whole ranges as the budget allows.
        CaptureFullMemoryRanges();
        const INPROC_MEMORY_RANGE64* fullRanges = FullMemoryRanges();
        ULONG64 used = fixedSize + sizeof(ULONG64) + sizeof(ULONG64); // Memory64 header
        ULONG32 keptRanges = 0;
        ULONG64 keptBytes = 0;
        for (ULONG32 i = 0; i < g_FullMemoryRangeCount; ++i) {
            ULONG64 cost = sizeof(MINIDUMP_MEMORY_DESCRIPTOR64) + fullRanges[i].Size;
            if (hasBudget && used + cost > budget) break;
            used += cost;
            keptBytes += fullRanges[i].Size;
            ++keptRanges;
        }
        g_FullMemoryRangeCount = keptRanges;
        fullMemoryRangeCount = keptRanges;
        fullMemoryBytes = keptBytes;
    } else {
        // Thread stacks are mandatory (needed to reconstruct call stacks); always included.
        if (!CountStackMemoryRanges(threadCount, &stackRangeCount, &stackBytes)) return FALSE;
        ULONG64 used = fixedSize + sizeof(ULONG32) +
                       stackRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + stackBytes;

        // Priority 1: writable data segments (all-or-nothing against the remaining budget).
        if (includeDataSegs) {
            if (!CountExtraMemoryRanges(includeDataSegs, &extraRangeCount, &extraBytes)) return FALSE;
            ULONG64 dataSegCost = extraRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + extraBytes;
            if (hasBudget && used + dataSegCost > budget) {
                includeDataSegs = FALSE;
                extraRangeCount = 0;
                extraBytes = 0;
            } else {
                used += dataSegCost;
            }
        }

        // Priority 2 (lowest): indirectly-referenced memory, capped by whatever budget is left.
        if (includeIndirectMemory) {
            ULONG32 cap = IndirectMemoryRangesCapacity();
            if (hasBudget) {
                const ULONG64 perPage = sizeof(MINIDUMP_MEMORY_DESCRIPTOR) + kIndirectMemoryRangeSize;
                const ULONG64 remaining = budget > used ? budget - used : 0;
                const ULONG64 fit = remaining / perPage;
                if (fit < cap) cap = static_cast<ULONG32>(fit);
            }
            g_IndirectMemoryRangeCap = cap;
            if (cap != 0) {
                CollectKnownSelectedMemoryRanges(threadCount, includeDataSegs);
                if (!CollectIndirectMemoryRanges(threadCount, preferredThreadId, contextProbe,
                                                 &indirectRangeCount, &indirectBytes)) return FALSE;
            }
        }

        selectedMemoryRangeCount = stackRangeCount + extraRangeCount + indirectRangeCount;
    }

    memoryListSize64 = writeFullMemory
        ? sizeof(ULONG64) + sizeof(ULONG64) + fullMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64)
        : sizeof(ULONG32) + selectedMemoryRangeCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR);

    if (threadContextsSize64 > 0xffffffffULL || threadInfoListSize64 > 0xffffffffULL ||
        memoryInfoListSize64 > 0xffffffffULL || memoryListSize64 > 0xffffffffULL) {
        SetLastError(ERROR_FILE_TOO_LARGE);
        return FALSE;
    }
    threadContextsSize = static_cast<ULONG32>(threadContextsSize64);
    threadInfoListSize = static_cast<ULONG32>(threadInfoListSize64);
    memoryInfoListSize = static_cast<ULONG32>(memoryInfoListSize64);
    memoryListSize = static_cast<ULONG32>(memoryListSize64);

    ULONG32 nextRva = directoryRva + streamCount * sizeof(MINIDUMP_DIRECTORY);
    systemInfoRva = nextRva; nextRva += sizeof(MINIDUMP_SYSTEM_INFO);
    miscInfoRva = nextRva; nextRva += sizeof(MINIDUMP_MISC_INFO);
    moduleListRva = nextRva; nextRva += moduleListStorageSize;
    threadListRva = nextRva; nextRva += threadListStreamSize;
    if (writeThreadInfo) { threadInfoListRva = nextRva; nextRva += threadInfoListSize; }
    if (writeMemoryInfo) { memoryInfoListRva = nextRva; nextRva += memoryInfoListSize; }
    memoryListRva = nextRva; nextRva += memoryListSize;
    if (writeUnloadedModules) { unloadedModuleListRva = nextRva; nextRva += unloadedModuleListSize; }
    if (hasException) { exceptionRva = nextRva; nextRva += exceptionStreamSize; }
    threadContextsRva = nextRva; nextRva += threadContextsSize;
    contextRva = threadContextsRva + exceptionThreadIndex * sizeof(CONTEXT);
    memoryBaseRva = nextRva;

    header.Signature = MINIDUMP_SIGNATURE;
    header.Version = MINIDUMP_VERSION;
    header.NumberOfStreams = streamCount;
    header.StreamDirectoryRva = directoryRva;
    header.Flags = requestedFlags;

    directories[streamIndex].StreamType = SystemInfoStream; directories[streamIndex].Location.Rva = systemInfoRva; directories[streamIndex].Location.DataSize = sizeof(MINIDUMP_SYSTEM_INFO); ++streamIndex;
    directories[streamIndex].StreamType = MiscInfoStream; directories[streamIndex].Location.Rva = miscInfoRva; directories[streamIndex].Location.DataSize = sizeof(MINIDUMP_MISC_INFO); ++streamIndex;
    directories[streamIndex].StreamType = ModuleListStream; directories[streamIndex].Location.Rva = moduleListRva; directories[streamIndex].Location.DataSize = moduleListStreamSize; ++streamIndex;
    directories[streamIndex].StreamType = ThreadListStream; directories[streamIndex].Location.Rva = threadListRva; directories[streamIndex].Location.DataSize = threadListStreamSize; ++streamIndex;
    if (writeThreadInfo) { directories[streamIndex].StreamType = ThreadInfoListStream; directories[streamIndex].Location.Rva = threadInfoListRva; directories[streamIndex].Location.DataSize = threadInfoListSize; ++streamIndex; }
    if (writeMemoryInfo) { directories[streamIndex].StreamType = MemoryInfoListStream; directories[streamIndex].Location.Rva = memoryInfoListRva; directories[streamIndex].Location.DataSize = memoryInfoListSize; ++streamIndex; }
    directories[streamIndex].StreamType = writeFullMemory ? Memory64ListStream : MemoryListStream; directories[streamIndex].Location.Rva = memoryListRva; directories[streamIndex].Location.DataSize = memoryListSize; ++streamIndex;
    if (writeUnloadedModules) { directories[streamIndex].StreamType = UnloadedModuleListStream; directories[streamIndex].Location.Rva = unloadedModuleListRva; directories[streamIndex].Location.DataSize = unloadedModuleListSize; ++streamIndex; }
    if (hasException) { directories[streamIndex].StreamType = ExceptionStream; directories[streamIndex].Location.Rva = exceptionRva; directories[streamIndex].Location.DataSize = exceptionStreamSize; ++streamIndex; }

    pos.QuadPart = headerRva;
    if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) return FALSE;
    if (!WriteAll(hFile, &header, sizeof(header))) return FALSE;
    if (!WriteAll(hFile, directories, streamCount * sizeof(MINIDUMP_DIRECTORY))) return FALSE;
    if (!WriteSystemInfo(hFile)) return FALSE;
    pos.QuadPart = miscInfoRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteMiscInfo(hFile)) return FALSE;
    pos.QuadPart = moduleListRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteModuleList(hFile, moduleCount, moduleListRva)) return FALSE;
    pos.QuadPart = threadListRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteThreadList(hFile, threadCount, threadContextsRva, memoryBaseRva, writeSelectedMemory)) return FALSE;
    if (writeThreadInfo) { pos.QuadPart = threadInfoListRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteThreadInfoList(hFile, threadCount)) return FALSE; }
    if (writeMemoryInfo) { pos.QuadPart = memoryInfoListRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteMemoryInfoList(hFile, memoryInfoRangeCount)) return FALSE; }
    pos.QuadPart = memoryListRva;
    if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) return FALSE;
    if (writeFullMemory) {
        if (!WriteMemoryDescriptors(hFile, fullMemoryRangeCount, memoryBaseRva)) return FALSE;
    } else {
        if (!WriteSelectedMemoryDescriptors(hFile, threadCount, includeDataSegs, stackRangeCount, extraRangeCount, indirectRangeCount, memoryBaseRva)) return FALSE;

    }
    if (writeUnloadedModules) { pos.QuadPart = unloadedModuleListRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteEmptyUnloadedModuleList(hFile)) return FALSE; }
    if (hasException) { pos.QuadPart = exceptionRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteExceptionStream(hFile, contextRva, exceptionParam)) return FALSE; }
    pos.QuadPart = threadContextsRva; if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) || !WriteThreadContexts(hFile, threadCount, exceptionParam)) return FALSE;
    pos.QuadPart = static_cast<LONGLONG>(memoryBaseRva);
    if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) return FALSE;
    if (writeFullMemory) {
        if (!WriteMemoryBytes(hFile, fullMemoryRangeCount)) return FALSE;
    } else {
        if (!WriteSelectedMemoryBytes(hFile, threadCount, includeDataSegs, indirectRangeCount, ignoreInaccessible)) return FALSE;

    }

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
