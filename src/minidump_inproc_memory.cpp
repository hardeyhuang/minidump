#include "minidump_inproc_internal.h"

namespace minidump_inproc {
namespace internal {

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
    const ULONG32 idx = g_IndirectMemoryRangeCount;
    ranges[idx].Start = page;
    ranges[idx].Size = kIndirectMemoryRangeSize;
    ranges[idx].Layer = layer;

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
    if (value >= sourceStart && value < sourceEnd) {
        return TRUE;
    }
    // Reject anything outside the live user-mode VA window. lp{Minimum,Maximum}ApplicationAddress come
    // straight from GetNativeSystemInfo (cached pre-crash), so the bounds are exact for this system and
    // architecture -- no hardcoded canonical split -- and naturally honor /3GB, large-address-aware and
    // x86/ARM64 layouts. This rejects poison words (0xFFFF.../0xCCCC...), kernel and non-canonical pointers
    // (keeping the dump clean) AND guarantees the straddle loop below can never start near the top of the
    // address space and wrap. The lower bound also subsumes the old "value < 0x10000" null-page reject.
    const ULONG64 minAppAddr = reinterpret_cast<ULONG64>(MinimumApplicationAddress());
    const ULONG64 maxAppAddr = reinterpret_cast<ULONG64>(MaximumApplicationAddress());
    if (value < minAppAddr || value > maxAppAddr) {
        return TRUE;
    }

    // Window spans [value, value + kPointerStraddleWindow). Its end page equals the start page unless
    // value is within the window of the page boundary, in which case exactly one extra (higher) page
    // is added (kPointerStraddleWindow <= page size). Guard the (theoretical) address-space wraparound
    // so an overflowing high pointer collapses to just its own page instead of skipping the loop.
    ULONG64 firstPage = AlignDown(value, kIndirectMemoryRangeSize);
    ULONG64 windowEnd = value + (kPointerStraddleWindow - 1);
    ULONG64 lastPage = (windowEnd < value) ? firstPage : AlignDown(windowEnd, kIndirectMemoryRangeSize);
    // The "page >= firstPage" guard stops a runaway scan: if page ever wraps past the top of the address
    // space (page += size rolls 0xFFFFFFFFFFFFF000 -> 0), the loop would otherwise restart from 0 and walk
    // the entire address space. With it, the loop covers at most the straddle window's two pages.
    for (ULONG64 page = firstPage; page >= firstPage && page <= lastPage; page += kIndirectMemoryRangeSize) {
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
    // Use the shared static scratch page instead of a 4KB stack buffer: this runs on the crash path
    // (possibly already low on stack) and is invoked in a tight BFS loop, so keeping the page off the
    // stack avoids deep frames. Safe because the dump is single-writer and this is not recursive.
    BYTE* buffer = g_IndirectPageScratch;
    if (!SafeCopyBytes(buffer, reinterpret_cast<const void*>(static_cast<ULONG_PTR>(pageStart)), kIndirectMemoryRangeSize)) {
        return TRUE;
    }
    for (ULONG32 offset = 0;
         offset + sizeof(ULONG_PTR) <= kIndirectMemoryRangeSize && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap;
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


// Precomputes stack, data-segment and process/thread-data MemoryList ranges so indirect pages can be checked against all known ranges.

void CollectKnownSelectedMemoryRanges(ULONG32 threadCount, BOOL includeDataSegs, BOOL includeProcThread) noexcept
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

    // Replay the single process/thread-data capture (CaptureProcessThreadDataRanges) so indirect
    // pages never re-capture the PEB/TEB/params/environment already planned for the MemoryList.
    if (includeProcThread) {
        for (ULONG32 i = 0; i < g_ProcThreadRangeCount && g_KnownMemoryRangeCount < kMaxKnownMemoryRanges; ++i) {
            AddKnownMemoryRange(g_ProcThreadRanges[i].Start, g_ProcThreadRanges[i].Size);
        }
    }

    if (includeDataSegs) {
        // Replay the single data-seg capture (CaptureDataSegRanges) instead of re-walking VirtualQuery,
        // so the known ranges match exactly what the descriptor/byte passes will emit.
        for (ULONG32 i = 0; i < g_DataSegRangeCount && g_KnownMemoryRangeCount < kMaxKnownMemoryRanges; ++i) {
            AddKnownMemoryRange(g_DataSegRanges[i].Start, g_DataSegRanges[i].Size);
        }
    }
}


// Walks a pointer chain DEPTH-FIRST from an already-collected seed page down to kIndirectMaxScanLayers,
// following at most kIndirectChainFanout outgoing pointers per page. This runs BEFORE the breadth pass
// for the faulting thread's seeds: when the file-size budget is tight, a single dense seed page (e.g.
// one full of heap pointers) can exhaust the whole cap on its layer-2 fan-out, leaving no room for the
// breadth pass to ever expand the OTHER seeds -- so a deep but narrow object chain rooted on the crash
// stack (root -> child -> grand) gets truncated at layer 1. Reserving a small, bounded slice to follow
// each seed's chain depth-first first guarantees such chains survive to full depth; the fan-out cap
// keeps the reservation bounded (<= sum_{d<layers} fanout^d pages per seed) so breadth still gets the
// rest. Dedup/known-overlap/cap gates are all enforced via AddIndirectMemoryRangeFromPointer, so pages
// captured here are never double-counted by the subsequent breadth expansion.
//
// seedStopCount is a HARD count-based budget ceiling for the layer-1 seed that started this walk: the
// walk (and all its recursion) stops as soon as g_IndirectMemoryRangeCount reaches it. The fan-out cap
// bounds a well-behaved chain, but a pathological dense seed could otherwise chain into enough live
// pages to swallow most of the cap before the other seeds (including the narrow root->child->grand
// chain) are reached. Checking the count directly bounds each seed's reservation no matter what the
// fan-out/recursion shape ends up being, so every layer-1 seed is guaranteed its turn.

static void FollowIndirectChainDepthFirst(ULONG64 pageStart, ULONG32 layer, ULONG32 seedStopCount) noexcept
{
    if (layer >= kIndirectMaxScanLayers
        || g_IndirectMemoryRangeCount >= g_IndirectMemoryRangeCap
        || g_IndirectMemoryRangeCount >= seedStopCount) {
        return;
    }
    // layer is in [1, kIndirectMaxScanLayers - 1] here, so (layer - 1) indexes a distinct per-depth
    // buffer and the recursion never clobbers a parent frame's page copy.
    BYTE* buffer = g_IndirectChainScratch[layer - 1];
    if (!SafeCopyBytes(buffer, reinterpret_cast<const void*>(static_cast<ULONG_PTR>(pageStart)),
                       kIndirectMemoryRangeSize)) {
        return;
    }
    ULONG32 followed = 0;
    for (ULONG32 offset = 0;
         offset + sizeof(ULONG_PTR) <= kIndirectMemoryRangeSize
             && followed < kIndirectChainFanout
             && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap
             && g_IndirectMemoryRangeCount < seedStopCount;
         offset += sizeof(ULONG_PTR)) {
        ULONG_PTR value = 0;
        CopyMemory(&value, buffer + offset, sizeof(value));
        ULONG64 target = static_cast<ULONG64>(value);
        if (target < reinterpret_cast<ULONG64>(MinimumApplicationAddress())
            || target > reinterpret_cast<ULONG64>(MaximumApplicationAddress())
            || (target >= pageStart && target < pageStart + kIndirectMemoryRangeSize)) {
            continue;
        }
        
        ULONG32 before = g_IndirectMemoryRangeCount;
        (void)AddIndirectMemoryRangeFromPointer(target, pageStart, pageStart + kIndirectMemoryRangeSize, layer + 1);
        if (g_IndirectMemoryRangeCount > before) {
            // A new page was just captured for this pointer: descend into it so the chain is followed
            // to full depth before we move on to this page's next sibling pointer.
            ++followed;
            FollowIndirectChainDepthFirst(AlignDown(target, kIndirectMemoryRangeSize), layer + 1, seedStopCount);
        }
    }
}


// Collects indirect 4KB pages via multi-layer BFS, bounded by g_IndirectMemoryRangeCap (file-size
// budget) and kIndirectMaxScanLayers (depth). Priority order, filled until the cap is hit:
//   1. the faulting thread's chains followed depth-first (so deep narrow object graphs survive),
//   2. the faulting thread's remaining reference subtree breadth-first (layer 1 -> 2 -> 3),
//   3. then every other thread's subtree (also layer 1 -> 2 -> 3).
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

    // Depth-first reservation: follow each layer-1 seed's pointer chain to full depth BEFORE the breadth
    // pass, so a deep narrow object graph rooted on the crash stack survives even when one dense seed's
    // breadth fan-out would otherwise consume the entire budget (see FollowIndirectChainDepthFirst).
    // Each seed is given a hard kIndirectPerSeedReserve-page slice (relative to the current count) so no
    // single seed can monopolize the cap and starve the later seeds' chains.
    {
        const ULONG32 seedCount = g_IndirectMemoryRangeCount; // appended pages stay >= seedCount; never re-walked
        const INPROC_MEMORY_RANGE* seeds = IndirectMemoryRanges();
        for (ULONG32 i = 0; i < seedCount && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap; ++i) {
            const ULONG32 seedStop = g_IndirectMemoryRangeCount + kIndirectPerSeedReserve;
            FollowIndirectChainDepthFirst(seeds[i].Start, seeds[i].Layer, seedStop);
        }
    }

    bfsHead = ExpandIndirectBfs(bfsHead);

    // Phase 2: remaining threads' registers and stacks (layer 1), then expand their subtrees. Each
    // thread is frozen for the whole dump, so its live register context is consistent with the stack
    // bytes captured elsewhere. Reuse the shared g_ContextScratch (this layout phase never overlaps
    // WriteThreadContexts, the only other user) to keep a full CONTEXT off the crash-path stack.
    CONTEXT* threadContext = &g_ContextScratch;
    for (ULONG32 i = 0; i < g_ThreadPlanCount && g_IndirectMemoryRangeCount < g_IndirectMemoryRangeCap; ++i) {
        if (g_ThreadPlan[i].ThreadId == preferredThreadId) {
            continue;
        }
        if (CaptureThreadContextForScan(g_ThreadPlan[i], threadContext)) {
            (void)ScanContextRegistersForIndirectMemory(threadContext, 1);
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


// Validates one process/thread-data candidate (start + requested size), clamps it to the committed,
// dumpable VirtualQuery region that contains it, caps it, de-duplicates it against the ranges already
// captured, and records it in g_ProcThreadRanges. Clamping to the region means an over-estimated
// requested size can never read past the real allocation, and the dedup keeps the descriptor/byte
// passes free of overlapping entries. Silently no-ops on any failure (best-effort, crash-path safe).

static void AddProcThreadRange(ULONG64 start, ULONG64 requestedSize) noexcept
{
    if (start == 0 || requestedSize == 0 || g_ProcThreadRangeCount >= kMaxProcThreadRanges) {
        return;
    }
    if (requestedSize > kProcThreadRangeMaxBytes) {
        requestedSize = kProcThreadRangeMaxBytes;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(start)), &mbi, sizeof(mbi)) == 0) {
        return;
    }
    if (mbi.State != MEM_COMMIT || !IsDumpableProtect(mbi.Protect)) {
        return;
    }
    const ULONG64 regionStart = reinterpret_cast<ULONG64>(mbi.BaseAddress);
    const ULONG64 regionEnd = regionStart + static_cast<ULONG64>(mbi.RegionSize);
    if (start < regionStart || start >= regionEnd) {
        return;
    }
    const ULONG64 avail = regionEnd - start;
    if (requestedSize > avail) {
        requestedSize = avail;
    }

    // Skip anything that overlaps a range already captured (e.g. a UNICODE_STRING buffer that lives
    // inside the process-parameters block, which was added first). This keeps MemoryList descriptors
    // non-overlapping, matching how AddKnownMemoryRange coalesces the stack/data-seg plan.
    for (ULONG32 i = 0; i < g_ProcThreadRangeCount; ++i) {
        if (RangesOverlap(start, requestedSize, g_ProcThreadRanges[i].Start, g_ProcThreadRanges[i].Size)) {
            return;
        }
    }

    g_ProcThreadRanges[g_ProcThreadRangeCount].Start = start;
    g_ProcThreadRanges[g_ProcThreadRangeCount].Size = requestedSize;
    g_ProcThreadBytes += requestedSize;
    ++g_ProcThreadRangeCount;
}


// Adds the buffer backing one UNICODE_STRING (from a local copy of the process parameters) as a
// process/thread-data range. MaximumLength is preferred over Length so the full allocation is kept;
// AddProcThreadRange validates and clamps the buffer pointer, so a stale/garbage descriptor is safe.

static void AddProcThreadUnicodeString(const INPROC_UNICODE_STRING* us) noexcept
{
    if (us == nullptr || us->Buffer == nullptr) {
        return;
    }
    ULONG64 size = us->MaximumLength != 0 ? us->MaximumLength : us->Length;
    if (size == 0) {
        return;
    }
    AddProcThreadRange(reinterpret_cast<ULONG64>(us->Buffer), size);
}


// Captures the MiniDumpWithProcessThreadData memory set once into g_ProcThreadRanges. Mirrors the
// semantics of dbghelp's MiniDumpWithProcessThreadData: the PEB, every frozen thread's TEB, the
// RTL_USER_PROCESS_PARAMETERS block, the environment block, and the UNICODE_STRING buffers the
// parameters reference. Every read goes through SafeCopyBytes/VirtualQuery and every range is region
// clamped + capped + de-duplicated, so the whole capture is best-effort and crash-path safe.
//
// Intentional differences from dbghelp (documented, acceptable per the library's design): the full
// environment block is captured (EnvironmentSize) rather than a fixed 0x2000 window, and the internal
// per-thread runtime blocks dbghelp reaches through TEB pointers (e.g. the FLS context) are not
// chased -- the documented PEB/TEB/parameters/environment set is what makes !peb/!teb, the command
// line, the current directory and the environment resolve in WinDbg.

BOOL CaptureProcessThreadDataRanges(BOOL includeProcThread,
                                    ULONG32 threadCount,
                                    ULONG64* rangeCount,
                                    ULONG64* bytesCount) noexcept
{
    g_ProcThreadRangeCount = 0;
    g_ProcThreadBytes = 0;

    if (includeProcThread) {
        INPROC_PEB* peb = GetCurrentPeb();

        // PEB first so anything that happens to alias it is de-duplicated against it.
        if (peb != nullptr) {
            AddProcThreadRange(reinterpret_cast<ULONG64>(peb), kProcThreadPebBytes);
        }

        // Every frozen thread's TEB (the "thread data"). The plan already froze these pointers.
        for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
            if (g_ThreadPlan[i].Teb != nullptr) {
                AddProcThreadRange(reinterpret_cast<ULONG64>(g_ThreadPlan[i].Teb), kProcThreadTebBytes);
            }
        }

        // RTL_USER_PROCESS_PARAMETERS + environment + the strings it references (the "process data").
        if (peb != nullptr) {
            void* paramsPtr = nullptr;
            if (SafeCopyBytes(&paramsPtr, &peb->ProcessParameters, sizeof(paramsPtr)) && paramsPtr != nullptr) {
                // Copy only the leading core (up to CurrentDirectores) so older OSes that lack the
                // trailing fields are tolerated; EnvironmentSize is probed separately below.
                INPROC_RTL_USER_PROCESS_PARAMETERS params = {};
                const SIZE_T coreSize = offsetof(INPROC_RTL_USER_PROCESS_PARAMETERS, CurrentDirectores);
                if (SafeCopyBytes(&params, paramsPtr, coreSize)) {
                    // The parameters block itself. MaximumLength is the allocated size of the block
                    // (it usually carries the inline image-path/command-line strings), so capturing it
                    // also absorbs those buffers; the per-string adds below then cover any that live
                    // outside the block (e.g. the current directory).
                    ULONG64 paramsSize = params.MaximumLength;
                    if (paramsSize < kProcThreadParamsMinBytes) {
                        paramsSize = kProcThreadParamsMinBytes;
                    }
                    AddProcThreadRange(reinterpret_cast<ULONG64>(paramsPtr), paramsSize);

                    // Environment block. EnvironmentSize sits past the core copy, so probe it with its
                    // own guarded read and fall back to a default window when it is unavailable/zero.
                    if (params.Environment != nullptr) {
                        SIZE_T envSizeField = 0;
                        ULONG64 envSize = kProcThreadEnvDefaultBytes;
                        const BYTE* envSizeAddr = reinterpret_cast<const BYTE*>(paramsPtr) +
                            offsetof(INPROC_RTL_USER_PROCESS_PARAMETERS, EnvironmentSize);
                        if (SafeCopyBytes(&envSizeField, envSizeAddr, sizeof(envSizeField))
                            && envSizeField != 0 && envSizeField <= kProcThreadEnvMaxBytes) {
                            envSize = static_cast<ULONG64>(envSizeField);
                        }
                        AddProcThreadRange(reinterpret_cast<ULONG64>(params.Environment), envSize);
                    }

                    // Referenced UNICODE_STRING buffers. Those that fall inside the parameters block
                    // are de-duplicated away; the rest (typically the current directory) get their own
                    // range, matching dbghelp.
                    AddProcThreadUnicodeString(&params.CurrentDirectory.DosPath);
                    AddProcThreadUnicodeString(&params.DllPath);
                    AddProcThreadUnicodeString(&params.ImagePathName);
                    AddProcThreadUnicodeString(&params.CommandLine);
                    AddProcThreadUnicodeString(&params.WindowTitle);
                    AddProcThreadUnicodeString(&params.DesktopInfo);
                    AddProcThreadUnicodeString(&params.ShellInfo);
                    AddProcThreadUnicodeString(&params.RuntimeData);
                }
            }
        }
    }

    *rangeCount = g_ProcThreadRangeCount;
    *bytesCount = g_ProcThreadBytes;
    return TRUE;
}


// Captures optional selected memory ranges (writable image data segments) once into the fixed
// g_DataSegRanges list in a single VirtualQuery walk. The known-range, descriptor and byte passes all
// replay this list, so they can never disagree on count or size even if the live address space shifts
// (it was previously re-walked in each of those passes). Regions beyond kMaxDataSegRanges are dropped,
// degrading gracefully while staying internally consistent.

BOOL CaptureDataSegRanges(BOOL includeDataSegs,
                          ULONG64* rangeCount,
                          ULONG64* bytesCount) noexcept
{
    g_DataSegRangeCount = 0;
    g_DataSegBytes = 0;

    if (includeDataSegs) {
        MEMORY_BASIC_INFORMATION mbi = {};
        BYTE* address = MinimumApplicationAddress();
        BYTE* maximum = MaximumApplicationAddress();

        while (address < maximum && g_DataSegRangeCount < kMaxDataSegRanges) {
            SIZE_T queried = VirtualQuery(address, &mbi, sizeof(mbi));
            if (queried == 0 || mbi.RegionSize == 0) {
                break;
            }

            if (ShouldIncludeExtraMemoryRange(mbi, includeDataSegs)) {
                g_DataSegRanges[g_DataSegRangeCount].Start = reinterpret_cast<ULONG64>(mbi.BaseAddress);
                g_DataSegRanges[g_DataSegRangeCount].Size = static_cast<ULONG64>(mbi.RegionSize);
                g_DataSegBytes += static_cast<ULONG64>(mbi.RegionSize);
                ++g_DataSegRangeCount;
            }

            BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= address) {
                break;
            }
            address = next;
        }
    }

    *rangeCount = g_DataSegRangeCount;
    *bytesCount = g_DataSegBytes;
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
                                    ULONG64 procThreadRangeCount,
                                    ULONG64 extraRangeCount,
                                    ULONG64 indirectRangeCount,
                                    ULONG64 memoryBaseRva) noexcept
{
    MINIDUMP_MEMORY_DESCRIPTOR descriptor = {};
    ULONG64 totalCount = stackRangeCount + procThreadRangeCount + extraRangeCount + indirectRangeCount;

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

    // Process/thread data (PEB, TEBs, parameters, environment, referenced strings) replays the single
    // CaptureProcessThreadDataRanges plan, so these descriptors stay byte-for-byte consistent with
    // WriteSelectedMemoryBytes. procThreadRangeCount is 0 when the set was dropped by budget.
    for (ULONG32 i = 0; i < g_ProcThreadRangeCount && i < procThreadRangeCount; ++i) {
        descriptor.StartOfMemoryRange = g_ProcThreadRanges[i].Start;
        descriptor.Memory.Rva = static_cast<RVA>(currentRva);
        descriptor.Memory.DataSize = static_cast<ULONG32>(g_ProcThreadRanges[i].Size);
        if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
            return FALSE;
        }
        currentRva += descriptor.Memory.DataSize;
    }

    // Data segments replay the single CaptureDataSegRanges plan (not a live VirtualQuery re-walk), so
    // these descriptors are byte-for-byte consistent with WriteSelectedMemoryBytes. includeDataSegs is
    // implied by extraRangeCount (0 when data segs were dropped); g_DataSegRangeCount bounds the list.
    (void)includeDataSegs;
    for (ULONG32 i = 0; i < g_DataSegRangeCount && i < extraRangeCount; ++i) {
        descriptor.StartOfMemoryRange = g_DataSegRanges[i].Start;
        descriptor.Memory.Rva = static_cast<RVA>(currentRva);
        descriptor.Memory.DataSize = static_cast<ULONG32>(g_DataSegRanges[i].Size);
        if (!WriteAll(hFile, &descriptor, sizeof(descriptor))) {
            return FALSE;
        }
        currentRva += descriptor.Memory.DataSize;
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
                              ULONG64 procThreadRangeCount,
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

    // Process/thread-data bytes replay the same CaptureProcessThreadDataRanges plan as the descriptor
    // pass (same order), so descriptor.DataSize always matches the bytes on disk. procThreadRangeCount
    // is 0 (set dropped by budget) writes nothing here, mirroring the zero descriptors emitted there.
    for (ULONG32 i = 0; i < g_ProcThreadRangeCount && i < procThreadRangeCount; ++i) {
        if (!WriteRegionBytes(
                hFile,
                reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(g_ProcThreadRanges[i].Start)),
                static_cast<SIZE_T>(g_ProcThreadRanges[i].Size))) {
            return FALSE;
        }
    }

    // Data-seg bytes replay the same CaptureDataSegRanges plan as the descriptor pass (in the same
    // order), so descriptor.DataSize always matches the bytes on disk. includeDataSegs being FALSE
    // (data segs dropped by budget) writes nothing here, mirroring the zero descriptors emitted there.
    if (includeDataSegs) {
        for (ULONG32 i = 0; i < g_DataSegRangeCount; ++i) {
            if (!WriteRegionBytes(
                    hFile,
                    reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(g_DataSegRanges[i].Start)),
                    static_cast<SIZE_T>(g_DataSegRanges[i].Size))) {
                return FALSE;
            }
        }
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

} // namespace internal
} // namespace minidump_inproc
