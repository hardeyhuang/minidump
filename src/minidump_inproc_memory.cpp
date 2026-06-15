#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Captures committed, dumpable regions for MiniDumpWithFullMemory into the shared scratch buffer
// in a single VirtualQuery walk. Both the descriptor pass and the byte pass replay this fixed
// plan, so they can never disagree on count or size even if the live address space changes.

void CaptureFullMemoryRanges() noexcept
{
    SYSTEM_INFO sys = {};
    MEMORY_BASIC_INFORMATION mbi = {};
    INPROC_MEMORY_RANGE64* ranges = FullMemoryRanges();
    const ULONG32 capacity = FullMemoryRangesCapacity();

    g_FullMemoryRangeCount = 0;
    GetNativeSystemInfo(&sys);
    BYTE* address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    BYTE* maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);

    while (address < maximum && g_FullMemoryRangeCount < capacity) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }

        if (mbi.State == MEM_COMMIT && IsDumpableProtect(mbi.Protect)) {
            ranges[g_FullMemoryRangeCount].Start = reinterpret_cast<ULONG64>(mbi.BaseAddress);
            ranges[g_FullMemoryRangeCount].Size = static_cast<ULONG64>(mbi.RegionSize);
            ++g_FullMemoryRangeCount;
        }

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }
}


// Counts VirtualQuery regions for MiniDumpWithFullMemoryInfo.

BOOL CountMemoryInfoRanges(ULONG64* rangeCount) noexcept
{
    SYSTEM_INFO sys = {};
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG64 count = 0;

    GetNativeSystemInfo(&sys);
    address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);

    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }

        ++count;

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    *rangeCount = count;
    return TRUE;
}


// Writes MemoryInfoListStream and pads missing entries with zeroes if the address map changes between count and write passes.

BOOL WriteMemoryInfoList(HANDLE hFile, ULONG64 rangeCount) noexcept
{
    SYSTEM_INFO sys = {};
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    MINIDUMP_MEMORY_INFO_LIST header = {};
    MINIDUMP_MEMORY_INFO info = {};
    ULONG64 writtenCount = 0;

    header.SizeOfHeader = sizeof(header);
    header.SizeOfEntry = sizeof(info);
    header.NumberOfEntries = rangeCount;
    if (!WriteAll(hFile, &header, sizeof(header))) {
        return FALSE;
    }

    GetNativeSystemInfo(&sys);
    address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);

    while (address < maximum && writtenCount < rangeCount) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }

        ZeroMemory(&info, sizeof(info));
        info.BaseAddress = reinterpret_cast<ULONG64>(mbi.BaseAddress);
        info.AllocationBase = reinterpret_cast<ULONG64>(mbi.AllocationBase);
        info.AllocationProtect = mbi.AllocationProtect;
        info.RegionSize = static_cast<ULONG64>(mbi.RegionSize);
        info.State = mbi.State;
        info.Protect = mbi.Protect;
        info.Type = mbi.Type;
        if (!WriteAll(hFile, &info, sizeof(info))) {
            return FALSE;
        }
        ++writtenCount;

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    ZeroMemory(&info, sizeof(info));
    while (writtenCount < rangeCount) {
        if (!WriteAll(hFile, &info, sizeof(info))) {
            return FALSE;
        }
        ++writtenCount;
    }

    return TRUE;
}


// Checks half-open range intersection with overflow guards.

BOOL RangesOverlap(ULONG64 leftStart, ULONG64 leftSize, ULONG64 rightStart, ULONG64 rightSize) noexcept
{
    if (leftSize == 0 || rightSize == 0) {
        return FALSE;
    }
    ULONG64 leftEnd = leftStart + leftSize;
    ULONG64 rightEnd = rightStart + rightSize;
    if (leftEnd <= leftStart || rightEnd <= rightStart) {
        return FALSE;
    }
    return leftStart < rightEnd && rightStart < leftEnd;
}


// Clears the fixed table of already-planned MemoryList ranges.

void ResetKnownMemoryRanges() noexcept
{
    g_KnownMemoryRangeCount = 0;
}


// Adds a stack or data-segment range to the known MemoryList table, coalescing by overlap to keep lookups bounded.

void AddKnownMemoryRange(ULONG64 start, ULONG64 size) noexcept
{
    if (size == 0 || size > 0xffffffffULL || g_KnownMemoryRangeCount >= kMaxKnownMemoryRanges) {
        return;
    }
    for (ULONG32 i = 0; i < g_KnownMemoryRangeCount; ++i) {
        if (RangesOverlap(start, size, g_KnownMemoryRanges[i].Start, g_KnownMemoryRanges[i].Size)) {
            return;
        }
    }
    g_KnownMemoryRanges[g_KnownMemoryRangeCount].Start = start;
    g_KnownMemoryRanges[g_KnownMemoryRangeCount].Size = static_cast<ULONG32>(size);
    ++g_KnownMemoryRangeCount;
}


// Tests whether a candidate indirect page overlaps memory already planned for MemoryList.

BOOL KnownMemoryRangeOverlaps(ULONG64 start, ULONG64 size) noexcept
{
    for (ULONG32 i = 0; i < g_KnownMemoryRangeCount; ++i) {
        if (RangesOverlap(start, size, g_KnownMemoryRanges[i].Start, g_KnownMemoryRanges[i].Size)) {
            return TRUE;
        }
    }
    return FALSE;
}


// One-entry VirtualQuery region cache. Indirect scanning probes huge numbers of candidate
// pointers, most of which cluster into the same region; caching the last region avoids a
// VirtualQuery per pointer. Safe because all other threads are frozen, so the map is stable.
namespace {
ULONG64 g_RegionCacheStart = 0;
ULONG64 g_RegionCacheEnd = 0;
BOOL g_RegionCacheValid = FALSE;
BOOL g_RegionCacheDumpable = FALSE;
BOOL g_RegionCacheImage = FALSE;

void ResetRegionCache() noexcept
{
    g_RegionCacheValid = FALSE;
}

// Returns the committed/dumpable/image classification and bounds of the region containing value.
BOOL ClassifyRegionCached(ULONG64 value, ULONG64* regionStart, ULONG64* regionEnd,
                          BOOL* dumpable, BOOL* isImage) noexcept
{
    if (g_RegionCacheValid && value >= g_RegionCacheStart && value < g_RegionCacheEnd) {
        *regionStart = g_RegionCacheStart;
        *regionEnd = g_RegionCacheEnd;
        *dumpable = g_RegionCacheDumpable;
        *isImage = g_RegionCacheImage;
        return TRUE;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(value)), &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }
    g_RegionCacheStart = reinterpret_cast<ULONG64>(mbi.BaseAddress);
    g_RegionCacheEnd = g_RegionCacheStart + static_cast<ULONG64>(mbi.RegionSize);
    g_RegionCacheDumpable = (mbi.State == MEM_COMMIT && IsDumpableProtect(mbi.Protect));
    g_RegionCacheImage = (mbi.Type == MEM_IMAGE);
    g_RegionCacheValid = TRUE;

    *regionStart = g_RegionCacheStart;
    *regionEnd = g_RegionCacheEnd;
    *dumpable = g_RegionCacheDumpable;
    *isImage = g_RegionCacheImage;
    return TRUE;
}

void ResetVisitedHash() noexcept
{
    ZeroMemory(IndirectVisitedHash(), static_cast<SIZE_T>(IndirectVisitedHashSlots()) * sizeof(ULONG64));
}

// Open-addressing visited-page set. Returns TRUE if the page was already present; otherwise inserts
// it and returns FALSE. A full table is treated as "present" so collection stops growing.
BOOL VisitedPageSeenOrInsert(ULONG64 page) noexcept
{
    ULONG64* slots = IndirectVisitedHash();
    const ULONG32 mask = IndirectVisitedHashSlots() - 1; // slot count is a power of two
    ULONG32 h = static_cast<ULONG32>((page >> 12) * 0x9E3779B97F4A7C15ULL >> 40) & mask;
    for (ULONG32 probes = 0; probes <= mask; ++probes) {
        ULONG64 cur = slots[h];
        if (cur == 0) { slots[h] = page; return FALSE; }
        if (cur == page) { return TRUE; }
        h = (h + 1) & mask;
    }
    return TRUE;
}
} // namespace


// Validates a candidate pointer (cached VirtualQuery), normalizes it to a 4KB page, dedups via the
// visited-page hash, rejects overlaps with already-planned ranges, and records it at the given BFS
// layer. Returns FALSE only when the per-dump cap is reached (signals callers to stop).

BOOL AddIndirectMemoryRangeFromPointer(ULONG64 value, ULONG64 sourceStart, ULONG64 sourceEnd, ULONG32 layer) noexcept
{
    if (g_IndirectMemoryRangeCount >= g_IndirectMemoryRangeCap) {
        return FALSE;
    }
    if (value < 0x10000ULL || (value >= sourceStart && value < sourceEnd)) {
        return TRUE;
    }

    ULONG64 regionStart = 0, regionEnd = 0;
    BOOL dumpable = FALSE, isImage = FALSE;
    if (!ClassifyRegionCached(value, &regionStart, &regionEnd, &dumpable, &isImage)) {
        return TRUE;
    }
    if (!dumpable || isImage) {
        return TRUE; // cache makes clustered image/reserved rejects O(1)
    }

    ULONG64 page = AlignDown(value, kIndirectMemoryRangeSize);
    if (page < regionStart || page + kIndirectMemoryRangeSize > regionEnd) {
        return TRUE;
    }

    // Dedup first (O(1)); marking the page visited also prevents re-running the known-overlap
    // check for every pointer that lands on the same page.
    if (VisitedPageSeenOrInsert(page)) {
        return TRUE;
    }
    if (KnownMemoryRangeOverlaps(page, kIndirectMemoryRangeSize)) {
        return TRUE;
    }

    INPROC_MEMORY_RANGE* ranges = IndirectMemoryRanges();
    ranges[g_IndirectMemoryRangeCount].Start = page;
    ranges[g_IndirectMemoryRangeCount].Size = kIndirectMemoryRangeSize;
    ranges[g_IndirectMemoryRangeCount].Layer = layer;
    ++g_IndirectMemoryRangeCount;
    return g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap;
}


// Scans a span pointer-width at a time, feeding plausible values into the collector at the given layer.

BOOL ScanStackSpanForIndirectMemory(ULONG64 scanStart, ULONG64 scanEnd,
                                    ULONG64 sourceStart, ULONG64 sourceEnd, ULONG32 layer) noexcept
{
    for (ULONG64 cursor = scanStart;
         cursor + sizeof(ULONG_PTR) <= scanEnd && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap;
         cursor += sizeof(ULONG_PTR)) {
        ULONG_PTR value = 0;
        if (SafeCopyBytes(&value, reinterpret_cast<const void*>(static_cast<ULONG_PTR>(cursor)), sizeof(value))) {
            if (!AddIndirectMemoryRangeFromPointer(static_cast<ULONG64>(value), sourceStart, sourceEnd, layer)) {
                break;
            }
        }
    }
    return TRUE;
}


// Copies one already-collected 4KB page and scans it for pointers, enqueuing referenced pages at the
// next BFS layer. Reading the whole page once (instead of probing each slot) keeps SEH overhead low.

namespace {
BOOL ScanPageForIndirectMemory(ULONG64 pageStart, ULONG32 layer) noexcept
{
    BYTE buffer[kIndirectMemoryRangeSize];
    if (!SafeCopyBytes(buffer, reinterpret_cast<const void*>(static_cast<ULONG_PTR>(pageStart)), sizeof(buffer))) {
        return TRUE;
    }
    for (ULONG32 offset = 0;
         offset + sizeof(ULONG_PTR) <= sizeof(buffer) && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap;
         offset += sizeof(ULONG_PTR)) {
        ULONG_PTR value = 0;
        CopyMemory(&value, buffer + offset, sizeof(value));
        if (!AddIndirectMemoryRangeFromPointer(static_cast<ULONG64>(value),
                                               pageStart, pageStart + kIndirectMemoryRangeSize, layer)) {
            break;
        }
    }
    return TRUE;
}

// Expands the indirect-range queue breadth-first: every entry from headIndex onward whose layer is
// below kIndirectMaxScanLayers is scanned, appending its referenced pages at layer+1. Returns the new
// head so the caller can expand the crash thread's subtree fully before seeding other threads.
ULONG32 ExpandIndirectBfs(ULONG32 headIndex) noexcept
{
    const INPROC_MEMORY_RANGE* ranges = IndirectMemoryRanges();
    while (headIndex < g_IndirectMemoryRangeCount && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap) {
        ULONG64 pageStart = ranges[headIndex].Start;
        ULONG32 layer = ranges[headIndex].Layer;
        ++headIndex;
        if (layer < kIndirectMaxScanLayers) {
            (void)ScanPageForIndirectMemory(pageStart, layer + 1);
        }
    }
    return headIndex;
}
} // namespace


// Scans a thread stack for layer-1 indirect references, prioritizing SP-to-stack-base for the
// exception thread (live frames) before scanning the lower, already-unwound part.

BOOL ScanStackForIndirectMemory(ULONG64 stackStart,
                                ULONG32 stackSize,
                                const CONTEXT* preferredContext) noexcept
{
    ULONG64 stackEnd = stackStart + stackSize;
    ULONG64 sp = ContextStackPointer(preferredContext);
    if (sp >= stackStart && sp < stackEnd) {
        (void)ScanStackSpanForIndirectMemory(sp, stackEnd, stackStart, stackEnd, 1);
        if (g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap) {
            (void)ScanStackSpanForIndirectMemory(stackStart, sp, stackStart, stackEnd, 1);
        }
        return TRUE;
    }

    return ScanStackSpanForIndirectMemory(stackStart, stackEnd, stackStart, stackEnd, 1);
}


// Precomputes stack and data-segment MemoryList ranges so indirect pages can be checked against all known ranges.

void CollectKnownSelectedMemoryRanges(ULONG32 threadCount, BOOL includeDataSegs) noexcept
{
    ResetKnownMemoryRanges();

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].StackSize != 0) {
            AddKnownMemoryRange(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize);
        }
    }

    if (!includeDataSegs) {
        return;
    }

    SYSTEM_INFO sys = {};
    MEMORY_BASIC_INFORMATION mbi = {};
    GetNativeSystemInfo(&sys);
    BYTE* address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    BYTE* maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);
    while (address < maximum && g_KnownMemoryRangeCount < kMaxKnownMemoryRanges) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }
        if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
            AddKnownMemoryRange(reinterpret_cast<ULONG64>(mbi.BaseAddress), static_cast<ULONG64>(mbi.RegionSize));
        }
        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }
}


// Collects indirect 4KB pages via multi-layer BFS, bounded by g_IndirectMemoryRangeCap (file-size
// budget) and kIndirectMaxScanLayers (depth). Priority order, filled until the cap is hit:
//   1. the faulting thread's entire reference subtree (layer 1 -> 2 -> 3),
//   2. then every other thread's subtree (also layer 1 -> 2 -> 3).
// This keeps the data most relevant to the crash even when the budget is tight.

BOOL CollectIndirectMemoryRanges(ULONG32 threadCount,
                                 DWORD preferredThreadId,
                                 const CONTEXT* preferredContext,
                                 ULONG64* rangeCount,
                                 ULONG64* bytesCount) noexcept

{
    (void)threadCount;
    g_IndirectMemoryRangeCount = 0;
    ResetRegionCache();
    ResetVisitedHash();

    ULONG32 bfsHead = 0;

    // Phase 1: the faulting thread's stack (layer 1) and its full transitive subtree.
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].ThreadId == preferredThreadId && g_ThreadPlan[i].StackSize != 0) {
            (void)ScanStackForIndirectMemory(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize, preferredContext);
            break;
        }
    }
    bfsHead = ExpandIndirectBfs(bfsHead);

    // Phase 2: remaining threads' stacks (layer 1), then expand their subtrees.
    for (ULONG32 i = 0; i < g_ThreadPlanCount && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap; ++i) {
        if (g_ThreadPlan[i].ThreadId == preferredThreadId || g_ThreadPlan[i].StackSize == 0) {
            continue;
        }
        (void)ScanStackForIndirectMemory(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize, nullptr);
    }
    (void)ExpandIndirectBfs(bfsHead);

    *rangeCount = g_IndirectMemoryRangeCount;
    *bytesCount = static_cast<ULONG64>(g_IndirectMemoryRangeCount) * kIndirectMemoryRangeSize;
    return TRUE;
}


// Counts optional selected memory ranges such as writable image data segments.

BOOL CountExtraMemoryRanges(BOOL includeDataSegs,
                            ULONG64* rangeCount,
                            ULONG64* bytesCount) noexcept

{
    SYSTEM_INFO sys = {};
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG64 count = 0;
    ULONG64 bytes = 0;

    GetNativeSystemInfo(&sys);
    address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);

    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }

        if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
            ++count;
            bytes += static_cast<ULONG64>(mbi.RegionSize);
        }


        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    *rangeCount = count;
    *bytesCount = bytes;
    return TRUE;
}


// Writes a memory region page-by-page and can zero-fill unreadable chunks when the dump type allows it.

BOOL WriteRegionBytes(HANDLE hFile, BYTE* base, SIZE_T size, BOOL ignoreInaccessible) noexcept
{
    SYSTEM_INFO sys = {};
    DWORD pageSize = 4096;
    BYTE* cursor = base;
    SIZE_T remaining = size;

    GetNativeSystemInfo(&sys);
    if (sys.dwPageSize != 0) {
        pageSize = sys.dwPageSize;
    }

    while (remaining != 0) {
        SIZE_T chunk = remaining > pageSize ? pageSize : remaining;
        if (SafeReadBytes(cursor, chunk)) {
            if (!WriteAll(hFile, cursor, chunk)) {
                return FALSE;
            }
        } else if (ignoreInaccessible) {
            if (!WriteZeros(hFile, chunk)) {
                return FALSE;
            }
        } else {
            SetLastError(ERROR_PARTIAL_COPY);
            return FALSE;
        }
        cursor += chunk;
        remaining -= chunk;
    }
    return TRUE;
}


// Writes MemoryList descriptors for stacks, selected data segments, and indirect pages in the same order as their bytes.

BOOL WriteSelectedMemoryDescriptors(HANDLE hFile,
                                    ULONG32 threadCount,
                                    BOOL includeDataSegs,
                                    ULONG64 stackRangeCount,
                                    ULONG64 extraRangeCount,
                                    ULONG64 indirectRangeCount,
                                    ULONG64 memoryBaseRva) noexcept
{
    MINIDUMP_MEMORY_DESCRIPTOR descriptor = {};
    ULONG64 totalCount = stackRangeCount + extraRangeCount + indirectRangeCount;

    ULONG64 currentRva = memoryBaseRva;

    if (totalCount > 0xffffffffULL) {
        SetLastError(ERROR_BAD_LENGTH);
        return FALSE;
    }

    ULONG32 count32 = static_cast<ULONG32>(totalCount);
    if (!WriteAll(hFile, &count32, sizeof(count32))) {
        return FALSE;
    }

    // Stacks come straight from the frozen plan so the descriptor size and the byte stream
    // emitted in WriteSelectedMemoryBytes are guaranteed identical and in the same order.
    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].StackSize == 0) {
            continue;
        }
        descriptor.StartOfMemoryRange = g_ThreadPlan[i].StackStart;
        descriptor.Memory.Rva = static_cast<RVA>(currentRva);
        descriptor.Memory.DataSize = g_ThreadPlan[i].StackSize;
        if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
            return FALSE;
        }
        currentRva += g_ThreadPlan[i].StackSize;
    }

    SYSTEM_INFO sys = {};
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    GetNativeSystemInfo(&sys);
    address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);
    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }
        if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
            descriptor.StartOfMemoryRange = reinterpret_cast<ULONG64>(mbi.BaseAddress);
            descriptor.Memory.Rva = static_cast<RVA>(currentRva);
            descriptor.Memory.DataSize = static_cast<ULONG32>(mbi.RegionSize);
            if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
                return FALSE;
            }
            currentRva += descriptor.Memory.DataSize;
        }

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    const INPROC_MEMORY_RANGE* indirectRanges = IndirectMemoryRanges();
    for (ULONG32 i = 0; i < g_IndirectMemoryRangeCount && i < indirectRangeCount; ++i) {
        descriptor.StartOfMemoryRange = indirectRanges[i].Start;
        descriptor.Memory.Rva = static_cast<RVA>(currentRva);
        descriptor.Memory.DataSize = indirectRanges[i].Size;
        if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
            return FALSE;
        }
        currentRva += descriptor.Memory.DataSize;
    }

    return TRUE;
}


// Writes the backing bytes for selected MemoryList descriptors in descriptor order.

BOOL WriteSelectedMemoryBytes(HANDLE hFile,
                              ULONG32 threadCount,
                              BOOL includeDataSegs,
                              ULONG64 indirectRangeCount,
                              BOOL ignoreInaccessible) noexcept

{
    // Emit stack bytes in the same plan order as WriteSelectedMemoryDescriptors. Each stack is
    // written at its exact captured size (zero-filling unreadable pages) so descriptor.DataSize
    // always matches the bytes on disk.
    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].StackSize == 0) {
            continue;
        }
        if (!WriteRegionBytes(
                hFile,
                reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(g_ThreadPlan[i].StackStart)),
                g_ThreadPlan[i].StackSize,
                TRUE)) {
            return FALSE;
        }
    }

    SYSTEM_INFO sys = {};
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    GetNativeSystemInfo(&sys);
    address = static_cast<BYTE*>(sys.lpMinimumApplicationAddress);
    maximum = static_cast<BYTE*>(sys.lpMaximumApplicationAddress);
    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }
        if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
            if (!WriteRegionBytes(hFile, static_cast<BYTE*>(mbi.BaseAddress), mbi.RegionSize, ignoreInaccessible)) {
                return FALSE;
            }
        }

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    const INPROC_MEMORY_RANGE* indirectRanges = IndirectMemoryRanges();
    for (ULONG32 i = 0; i < g_IndirectMemoryRangeCount && i < indirectRangeCount; ++i) {
        if (!WriteRegionBytes(
                hFile,
                reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(indirectRanges[i].Start)),
                indirectRanges[i].Size,
                TRUE)) {
            return FALSE;
        }
    }
    return TRUE;
}


// Writes Memory64List descriptors for MiniDumpWithFullMemory.

BOOL WriteMemoryDescriptors(HANDLE hFile, ULONG64 rangeCount, ULONG64 memoryBaseRva) noexcept
{
    MINIDUMP_MEMORY_DESCRIPTOR64 descriptor = {};

    if (!WriteAll(hFile, &rangeCount, sizeof(rangeCount))) {
        return FALSE;
    }
    if (!WriteAll(hFile, &memoryBaseRva, sizeof(memoryBaseRva))) {
        return FALSE;
    }

    const INPROC_MEMORY_RANGE64* fullRanges = FullMemoryRanges();
    for (ULONG32 i = 0; i < g_FullMemoryRangeCount && i < rangeCount; ++i) {
        descriptor.StartOfMemoryRange = fullRanges[i].Start;
        descriptor.DataSize = fullRanges[i].Size;
        if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
            return FALSE;
        }
    }

    return TRUE;
}


// Writes Memory64List backing bytes from the captured plan, zero-filling pages that fault.
// Each range writes exactly DataSize bytes so the stream stays consistent with the descriptors.

BOOL WriteMemoryBytes(HANDLE hFile, ULONG64 rangeCount) noexcept
{
    SYSTEM_INFO sys = {};
    DWORD pageSize = 0;

    GetNativeSystemInfo(&sys);
    pageSize = sys.dwPageSize != 0 ? sys.dwPageSize : 4096;

    const INPROC_MEMORY_RANGE64* fullRanges = FullMemoryRanges();
    for (ULONG32 i = 0; i < g_FullMemoryRangeCount && i < rangeCount; ++i) {
        BYTE* cursor = reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(fullRanges[i].Start));
        ULONG64 remaining = fullRanges[i].Size;

        while (remaining != 0) {
            SIZE_T chunk = remaining > pageSize ? pageSize : static_cast<SIZE_T>(remaining);
            if (SafeReadBytes(cursor, chunk)) {
                if (!WriteAll(hFile, cursor, chunk)) {
                    return FALSE;
                }
            } else if (!WriteZeros(hFile, chunk)) {
                return FALSE;
            }
            cursor += chunk;
            remaining -= chunk;
        }
    }

    return TRUE;
}


} // namespace minidump_inproc::internal
