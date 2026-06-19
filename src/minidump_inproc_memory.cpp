#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Captures committed, dumpable regions for MiniDumpWithFullMemory into the shared scratch buffer
// in a single VirtualQuery walk. Both the descriptor pass and the byte pass replay this fixed
// plan, so they can never disagree on count or size even if the live address space changes.

BOOL CaptureFullMemoryRanges() noexcept
{
    MEMORY_BASIC_INFORMATION mbi = {};
    INPROC_MEMORY_RANGE64* ranges = FullMemoryRanges();
    const ULONG32 capacity = FullMemoryRangesCapacity();

    g_FullMemoryRangeCount = 0;
    g_FullMemoryBytes = 0;
    BYTE* address = MinimumApplicationAddress();
    BYTE* maximum = MaximumApplicationAddress();

    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }

        if (mbi.State == MEM_COMMIT && IsDumpableProtect(mbi.Protect)) {
            if (g_FullMemoryRangeCount >= capacity) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            ranges[g_FullMemoryRangeCount].Start = reinterpret_cast<ULONG64>(mbi.BaseAddress);
            ranges[g_FullMemoryRangeCount].Size = static_cast<ULONG64>(mbi.RegionSize);
            g_FullMemoryBytes += static_cast<ULONG64>(mbi.RegionSize);
            ++g_FullMemoryRangeCount;
        }

        BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }
    return TRUE;
}



// Counts VirtualQuery regions for MiniDumpWithFullMemoryInfo.

BOOL CountMemoryInfoRanges(ULONG64* rangeCount) noexcept
{
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG64 count = 0;

    address = MinimumApplicationAddress();
    maximum = MaximumApplicationAddress();

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

    address = MinimumApplicationAddress();
    maximum = MaximumApplicationAddress();

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
BOOL g_RegionCacheWritable = FALSE;

void ResetRegionCache() noexcept
{
    g_RegionCacheValid = FALSE;
}

// Returns the committed/dumpable/image/writable classification and bounds of the region containing value.
BOOL ClassifyRegionCached(ULONG64 value, ULONG64* regionStart, ULONG64* regionEnd,
                          BOOL* dumpable, BOOL* isImage, BOOL* writable) noexcept
{
    if (g_RegionCacheValid && value >= g_RegionCacheStart && value < g_RegionCacheEnd) {
        *regionStart = g_RegionCacheStart;
        *regionEnd = g_RegionCacheEnd;
        *dumpable = g_RegionCacheDumpable;
        *isImage = g_RegionCacheImage;
        *writable = g_RegionCacheWritable;
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
    g_RegionCacheWritable = IsWritableProtect(mbi.Protect);
    g_RegionCacheValid = TRUE;

    *regionStart = g_RegionCacheStart;
    *regionEnd = g_RegionCacheEnd;
    *dumpable = g_RegionCacheDumpable;
    *isImage = g_RegionCacheImage;
    *writable = g_RegionCacheWritable;
    return TRUE;
}

void ResetVisitedHash() noexcept
{
    ZeroMemory(IndirectVisitedHash(), static_cast<SIZE_T>(IndirectVisitedHashSlots()) * sizeof(ULONG64));
}

// Open-addressing visited-page set. Returns TRUE if the page was already present; otherwise inserts
// it and returns FALSE. A full table is treated as "present" so collection stops growing.
//
// Why a hash set at all: multi-layer BFS revisits the same pages constantly; a linear scan of the
// collected list would make dedup O(n^2). This gives O(1) average dedup using the upper half of the
// shared scratch buffer (page address 0 is impossible for a valid 4KB page, so 0 marks an empty slot).
BOOL VisitedPageSeenOrInsert(ULONG64 page) noexcept
{
    ULONG64* slots = IndirectVisitedHash();
    const ULONG32 mask = IndirectVisitedHashSlots() - 1; // slot count is a power of two -> & mask wraps
    // Fibonacci hashing: page>>12 drops the constant in-page bits, then multiply by 2^64/golden-ratio
    // to spread the page index across all bits, and take the top bits (>>40) as the bucket. This
    // scatters sequential/clustered page numbers well, keeping probe chains short.
    ULONG32 h = static_cast<ULONG32>((page >> 12) * 0x9E3779B97F4A7C15ULL >> 40) & mask;
    for (ULONG32 probes = 0; probes <= mask; ++probes) {
        ULONG64 cur = slots[h];
        if (cur == 0) { slots[h] = page; return FALSE; }
        if (cur == page) { return TRUE; }
        h = (h + 1) & mask; // linear probe to the next slot on collision
    }
    return TRUE;
}
} // namespace


// Validates one already-page-aligned address, dedups via the visited-page hash, rejects overlaps
// with already-planned ranges, and records it at the given BFS layer. Each page is classified
// against its OWN VirtualQuery region (a straddle-neighbor page may live in a different, possibly
// guard/uncommitted, region than the page that produced it). Returns FALSE only when the per-dump
// cap is reached (signals callers to stop); a page that fails any gate is skipped with TRUE so
// scanning continues.

static BOOL CollectIndirectPage(ULONG64 page, ULONG32 layer) noexcept
{
    if (g_IndirectMemoryRangeCount >= g_IndirectMemoryRangeCap) {
        return FALSE;
    }

    ULONG64 regionStart = 0, regionEnd = 0;
    BOOL dumpable = FALSE, isImage = FALSE, writable = FALSE;
    if (!ClassifyRegionCached(page, &regionStart, &regionEnd, &dumpable, &isImage, &writable)) {
        return TRUE;
    }
    if (!dumpable) {
        return TRUE;
    }
    // Read-only image pages (code .text / const .rdata) are recoverable from the module files,
    // so they are never collected as indirect references. Writable image pages, however, are the
    // module data segments (globals/statics): when MiniDumpWithDataSegs is NOT set they are not
    // captured wholesale, so we let the reference scan pull in only the pages actually pointed to
    // (treating large global blocks like heap). When MiniDumpWithDataSegs IS set, those same pages
    // are already in the known-range plan below and get deduplicated, avoiding double capture.
    if (isImage && !writable) {
        return TRUE; // cache makes clustered code/reserved rejects O(1)
    }

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


// Validates a candidate pointer, then collects the 4KB page it lands in -- plus the next higher page
// when the pointer sits within kPointerStraddleWindow of the page end. Pointers reference object
// starts and object bodies grow toward higher addresses, so an edge pointer usually targets a struct
// that straddles into the next page; collecting that neighbor recovers both the truncated tail bytes
// and the outgoing pointers inside it (keeping the BFS chain intact). Returns FALSE only when the
// per-dump cap is reached (signals callers to stop).

BOOL AddIndirectMemoryRangeFromPointer(ULONG64 value, ULONG64 sourceStart, ULONG64 sourceEnd, ULONG32 layer) noexcept
{
    if (g_IndirectMemoryRangeCount >= g_IndirectMemoryRangeCap) {
        return FALSE;
    }
    if (value < 0x10000ULL || (value >= sourceStart && value < sourceEnd)) {
        return TRUE;
    }

    // Window spans [value, value + kPointerStraddleWindow). Its end page equals the start page unless
    // value is within the window of the page boundary, in which case exactly one extra (higher) page
    // is added (kPointerStraddleWindow <= page size). Guard the (theoretical) address-space wraparound
    // so an overflowing high pointer collapses to just its own page instead of skipping the loop.
    ULONG64 firstPage = AlignDown(value, kIndirectMemoryRangeSize);
    ULONG64 windowEnd = value + (kPointerStraddleWindow - 1);
    ULONG64 lastPage = (windowEnd < value) ? firstPage : AlignDown(windowEnd, kIndirectMemoryRangeSize);
    for (ULONG64 page = firstPage; page <= lastPage; page += kIndirectMemoryRangeSize) {
        if (!CollectIndirectPage(page, layer)) {
            return FALSE;
        }
    }
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


// Feeds every general-purpose integer register of a thread context into the indirect collector as a
// root at `layer`. Registers routinely hold live object pointers (the faulting `this`, a function
// argument, a freshly returned allocation) that were never spilled to the stack, so without this the
// BFS would miss exactly the pages most relevant to a crash. sourceStart/sourceEnd are 0 because a
// register has no backing range to self-exclude; any value landing in a stack page (RSP/RBP) or code
// page (RIP) is filtered downstream like every other candidate, so RSP/RIP are intentionally omitted
// here (already captured as stack/module). Returns FALSE only when the per-dump cap is reached.

static BOOL ScanContextRegistersForIndirectMemory(const CONTEXT* context, ULONG32 layer) noexcept
{
    if (context == nullptr) {
        return TRUE;
    }
#if defined(_M_X64)
    const ULONG64 regs[] = {
        context->Rax, context->Rcx, context->Rdx, context->Rbx, context->Rbp,
        context->Rsi, context->Rdi, context->R8,  context->R9,  context->R10,
        context->R11, context->R12, context->R13, context->R14, context->R15,
    };
#elif defined(_M_IX86)
    const ULONG64 regs[] = {
        static_cast<ULONG64>(context->Eax), static_cast<ULONG64>(context->Ecx),
        static_cast<ULONG64>(context->Edx), static_cast<ULONG64>(context->Ebx),
        static_cast<ULONG64>(context->Ebp), static_cast<ULONG64>(context->Esi),
        static_cast<ULONG64>(context->Edi),
    };
#else
    const ULONG64 regs[1] = { 0 };
#endif
    for (ULONG32 i = 0; i < ARRAYSIZE(regs) && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap; ++i) {
        if (!AddIndirectMemoryRangeFromPointer(regs[i], 0, 0, layer)) {
            return FALSE;
        }
    }
    return g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap;
}


// Captures a frozen thread's register context (consistent with the captured stack: all non-current
// threads are suspended for the entire dump). Returns FALSE if the context is unavailable.

static BOOL CaptureThreadContextForScan(const INPROC_THREAD_PLAN_ENTRY& entry, CONTEXT* context) noexcept
{
    if (entry.IsCurrent) {
        RtlCaptureContext(context);
        return TRUE;
    }
    if (entry.Handle != nullptr && entry.Suspended) {
        context->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        return GetThreadContext(entry.Handle, context);
    }
    return FALSE;
}


// Precomputes stack and data-segment MemoryList ranges so indirect pages can be checked against all known ranges.

void CollectKnownSelectedMemoryRanges(ULONG32 threadCount, BOOL includeDataSegs) noexcept
{
    ResetKnownMemoryRanges();

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].IncludeStack && g_ThreadPlan[i].StackSize != 0) {
            AddKnownMemoryRange(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize);
        }
        if (g_ThreadPlan[i].AuxStackSize != 0) {
            AddKnownMemoryRange(g_ThreadPlan[i].AuxStackStart, g_ThreadPlan[i].AuxStackSize);
        }
    }

    if (!includeDataSegs) {
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    BYTE* address = MinimumApplicationAddress();
    BYTE* maximum = MaximumApplicationAddress();
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

    // Phase 1: the faulting thread's registers and stack (layer 1) plus its full transitive subtree.
    // Registers are seeded before the stack so a pointer that lives only in a register (never spilled)
    // still anchors its target page first when the budget is tight.
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].ThreadId != preferredThreadId) {
            continue;
        }
        (void)ScanContextRegistersForIndirectMemory(preferredContext, 1);
        if (g_ThreadPlan[i].IncludeStack && g_ThreadPlan[i].StackSize != 0) {
            (void)ScanStackForIndirectMemory(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize, preferredContext);
            if (g_ThreadPlan[i].AuxStackSize != 0 && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap) {
                (void)ScanStackForIndirectMemory(g_ThreadPlan[i].AuxStackStart, g_ThreadPlan[i].AuxStackSize, nullptr);
            }
        }
        break;
    }
    bfsHead = ExpandIndirectBfs(bfsHead);

    // Phase 2: remaining threads' registers and stacks (layer 1), then expand their subtrees. Each
    // thread is frozen for the whole dump, so its live register context is consistent with the stack
    // bytes captured elsewhere.
    CONTEXT threadContext;
    for (ULONG32 i = 0; i < g_ThreadPlanCount && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap; ++i) {
        if (g_ThreadPlan[i].ThreadId == preferredThreadId) {
            continue;
        }
        if (CaptureThreadContextForScan(g_ThreadPlan[i], &threadContext)) {
            (void)ScanContextRegistersForIndirectMemory(&threadContext, 1);
        }
        if (!g_ThreadPlan[i].IncludeStack || g_ThreadPlan[i].StackSize == 0) {
            continue;
        }
        (void)ScanStackForIndirectMemory(g_ThreadPlan[i].StackStart, g_ThreadPlan[i].StackSize, nullptr);
        if (g_ThreadPlan[i].AuxStackSize != 0 && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap) {
            (void)ScanStackForIndirectMemory(g_ThreadPlan[i].AuxStackStart, g_ThreadPlan[i].AuxStackSize, nullptr);
        }
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
    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG64 count = 0;
    ULONG64 bytes = 0;

    address = MinimumApplicationAddress();
    maximum = MaximumApplicationAddress();

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


// Writes a memory region page-by-page, always zero-filling unreadable chunks. Unreadable memory
// never fails the dump: the MiniDumpIgnoreInaccessibleMemory flag is intentionally not honored
// here, so a partially unreadable region degrades to zeros instead of aborting (best-effort dump).

BOOL WriteRegionBytes(HANDLE hFile, BYTE* base, SIZE_T size) noexcept
{
    const DWORD pageSize = NativePageSize();
    BYTE* cursor = base;
    SIZE_T remaining = size;

    while (remaining != 0) {
        SIZE_T block = remaining > kMemoryWriteBlockBytes ? kMemoryWriteBlockBytes : remaining;

        // Fast path: probe the whole block once; if every page is readable, write it in a single
        // call. This is the common case and avoids a WriteFile per 4 KB page.
        if (SafeReadBytes(cursor, block)) {
            if (!WriteAll(hFile, cursor, block)) {
                return FALSE;
            }
        } else {
            // Slow path: some page inside this block faults. Drop to page granularity so only the
            // unreadable pages are zero-filled while the readable ones are still captured.
            BYTE* pageCursor = cursor;
            SIZE_T pageRemaining = block;
            while (pageRemaining != 0) {
                SIZE_T chunk = pageRemaining > pageSize ? pageSize : pageRemaining;
                if (SafeReadBytes(pageCursor, chunk)) {
                    if (!WriteAll(hFile, pageCursor, chunk)) {
                        return FALSE;
                    }
                } else if (!WriteZeros(hFile, chunk)) {
                    return FALSE;
                }
                pageCursor += chunk;
                pageRemaining -= chunk;
            }
        }

        cursor += block;
        remaining -= block;
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
        if (g_ThreadPlan[i].IncludeStack && g_ThreadPlan[i].StackSize != 0) {
            descriptor.StartOfMemoryRange = g_ThreadPlan[i].StackStart;
            descriptor.Memory.Rva = static_cast<RVA>(currentRva);
            descriptor.Memory.DataSize = g_ThreadPlan[i].StackSize;
            if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
                return FALSE;
            }
            currentRva += g_ThreadPlan[i].StackSize;
        }
        if (g_ThreadPlan[i].AuxStackSize != 0) {
            descriptor.StartOfMemoryRange = g_ThreadPlan[i].AuxStackStart;
            descriptor.Memory.Rva = static_cast<RVA>(currentRva);
            descriptor.Memory.DataSize = g_ThreadPlan[i].AuxStackSize;
            if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
                return FALSE;
            }
            currentRva += g_ThreadPlan[i].AuxStackSize;
        }
    }

    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    address = MinimumApplicationAddress();
    maximum = MaximumApplicationAddress();
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
                              ULONG64 indirectRangeCount) noexcept
{
    // Emit stack bytes in the same plan order as WriteSelectedMemoryDescriptors. Each stack is
    // written at its exact captured size (zero-filling unreadable pages) so descriptor.DataSize
    // always matches the bytes on disk.
    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].IncludeStack && g_ThreadPlan[i].StackSize != 0) {
            if (!WriteRegionBytes(
                    hFile,
                    reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(g_ThreadPlan[i].StackStart)),
                    g_ThreadPlan[i].StackSize)) {
                return FALSE;
            }
        }
        if (g_ThreadPlan[i].AuxStackSize != 0) {
            if (!WriteRegionBytes(
                    hFile,
                    reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(g_ThreadPlan[i].AuxStackStart)),
                    g_ThreadPlan[i].AuxStackSize)) {
                return FALSE;
            }
        }
    }

    BYTE* address = nullptr;
    BYTE* maximum = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    address = MinimumApplicationAddress();
    maximum = MaximumApplicationAddress();
    while (address < maximum) {
        SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
        if (queried == 0 || mbi.RegionSize == 0) {
            break;
        }
        if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
            if (!WriteRegionBytes(hFile, static_cast<BYTE*>(mbi.BaseAddress), mbi.RegionSize)) {
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
                indirectRanges[i].Size)) {
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
    const INPROC_MEMORY_RANGE64* fullRanges = FullMemoryRanges();
    for (ULONG32 i = 0; i < g_FullMemoryRangeCount && i < rangeCount; ++i) {
        // Region sizes come from VirtualQuery (SIZE_T), so the ULONG64 plan value fits SIZE_T.
        // WriteRegionBytes handles large-block fast path + per-page fault isolation uniformly.
        if (!WriteRegionBytes(hFile,
                              reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(fullRanges[i].Start)),
                              static_cast<SIZE_T>(fullRanges[i].Size))) {
            return FALSE;
        }
    }

    return TRUE;
}


} // namespace minidump_inproc::internal
