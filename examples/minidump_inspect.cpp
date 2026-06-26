#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>
#include <unordered_set>

namespace {

const wchar_t* StreamName(ULONG32 type) noexcept
{
    switch (type) {
    case UnusedStream: return L"UnusedStream";
    case ReservedStream0: return L"ReservedStream0";
    case ReservedStream1: return L"ReservedStream1";
    case ThreadListStream: return L"ThreadListStream";
    case ModuleListStream: return L"ModuleListStream";
    case MemoryListStream: return L"MemoryListStream";
    case ExceptionStream: return L"ExceptionStream";
    case SystemInfoStream: return L"SystemInfoStream";
    case ThreadExListStream: return L"ThreadExListStream";
    case Memory64ListStream: return L"Memory64ListStream";
    case CommentStreamA: return L"CommentStreamA";
    case CommentStreamW: return L"CommentStreamW";
    case HandleDataStream: return L"HandleDataStream";
    case FunctionTableStream: return L"FunctionTableStream";
    case UnloadedModuleListStream: return L"UnloadedModuleListStream";
    case MiscInfoStream: return L"MiscInfoStream";
    case MemoryInfoListStream: return L"MemoryInfoListStream";
    case ThreadInfoListStream: return L"ThreadInfoListStream";
    case HandleOperationListStream: return L"HandleOperationListStream";
    case TokenStream: return L"TokenStream";
    case JavaScriptDataStream: return L"JavaScriptDataStream";
    case SystemMemoryInfoStream: return L"SystemMemoryInfoStream";
    case ProcessVmCountersStream: return L"ProcessVmCountersStream";
    case IptTraceStream: return L"IptTraceStream";
    case ThreadNamesStream: return L"ThreadNamesStream";
    default: return L"UnknownStream";
    }
}

BOOL ReadAt(HANDLE file, ULONG64 offset, void* buffer, DWORD size) noexcept
{
    LARGE_INTEGER pos = {};
    pos.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN)) {
        return FALSE;
    }
    DWORD read = 0;
    return ReadFile(file, buffer, size, &read, nullptr) && read == size;
}

void PrintStreamDetails(HANDLE file, const MINIDUMP_DIRECTORY& dir) noexcept
{
    switch (dir.StreamType) {
    case ThreadListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            wprintf(L"    threads=%lu\n", count);
        }
        break;
    }
    case ModuleListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            wprintf(L"    modules=%lu\n", count);
        }
        break;
    }
    case MemoryListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            ULONG64 bytes = 0;
            for (ULONG32 i = 0; i < count; ++i) {
                MINIDUMP_MEMORY_DESCRIPTOR desc = {};
                if (!ReadAt(file, dir.Location.Rva + sizeof(count) + static_cast<ULONG64>(i) * sizeof(desc), &desc, sizeof(desc))) {
                    break;
                }
                bytes += desc.Memory.DataSize;
            }
            wprintf(L"    ranges=%lu bytes=%llu\n", count, bytes);
        }
        break;
    }
    case Memory64ListStream: {
        ULONG64 count = 0;
        ULONG64 baseRva = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count)) &&
            ReadAt(file, dir.Location.Rva + sizeof(count), &baseRva, sizeof(baseRva))) {
            ULONG64 bytes = 0;
            for (ULONG64 i = 0; i < count; ++i) {
                MINIDUMP_MEMORY_DESCRIPTOR64 desc = {};
                if (!ReadAt(file, dir.Location.Rva + sizeof(count) + sizeof(baseRva) + i * sizeof(desc), &desc, sizeof(desc))) {
                    break;
                }
                bytes += desc.DataSize;
            }
            wprintf(L"    ranges=%llu bytes=%llu baseRva=0x%llx\n", count, bytes, baseRva);
        }
        break;
    }
    case ExceptionStream: {
        MINIDUMP_EXCEPTION_STREAM ex = {};
        CONTEXT context = {};
        if (ReadAt(file, dir.Location.Rva, &ex, sizeof(ex))) {
            wprintf(L"    thread=%lu code=0x%08lx address=0x%llx contextRva=0x%lx contextSize=%lu\n",
                    ex.ThreadId,
                    ex.ExceptionRecord.ExceptionCode,
                    ex.ExceptionRecord.ExceptionAddress,
                    ex.ThreadContext.Rva,
                    ex.ThreadContext.DataSize);
            if (ReadAt(file, ex.ThreadContext.Rva, &context, ex.ThreadContext.DataSize)) {
                wprintf(L"    flags=%lu Rip=0x%llx\n",
                    context.ContextFlags,
                    context.Rip);
            }
        }
        break;
    }
    case SystemInfoStream: {
        MINIDUMP_SYSTEM_INFO info = {};
        if (ReadAt(file, dir.Location.Rva, &info, sizeof(info))) {
            wprintf(L"    arch=%u processors=%u os=%lu.%lu build=%lu\n",
                    info.ProcessorArchitecture,
                    info.NumberOfProcessors,
                    info.MajorVersion,
                    info.MinorVersion,
                    info.BuildNumber);
        }
        break;
    }
    case MiscInfoStream: {
        // Read SizeOfInfo first so we know the struct version, then read up to
        // that size (capped by the stream's DataSize) to tolerate newer fields.
        ULONG32 sizeOfInfo = 0;
        if (!ReadAt(file, dir.Location.Rva, &sizeOfInfo, sizeof(sizeOfInfo))) {
            break;
        }
        ULONG32 readSize = sizeOfInfo;
        if (readSize > sizeof(MINIDUMP_MISC_INFO)) {
            readSize = sizeof(MINIDUMP_MISC_INFO);
        }
        if (readSize > dir.Location.DataSize) {
            readSize = dir.Location.DataSize;
        }
        MINIDUMP_MISC_INFO info = {};
        if (!ReadAt(file, dir.Location.Rva, &info, readSize)) {
            break;
        }
        wprintf(L"    sizeOfInfo=%lu sizeof(MINIDUMP_MISC_INFO)=%zu dataSize=%lu\n",
                sizeOfInfo, sizeof(MINIDUMP_MISC_INFO), dir.Location.DataSize);
        wprintf(L"    pid=%lu flags=0x%08lx\n", info.ProcessId, info.Flags1);

        if (info.Flags1 & MINIDUMP_MISC1_PROCESS_TIMES) {
            // ProcessCreateTime is time_t （seconds since 1970-01-01 UTC）.
            __time64_t createTime = static_cast<__time64_t>(info.ProcessCreateTime);
            wprintf(L"    ProcessCreateTime=%lu (0x%lx)\n", info.ProcessCreateTime, info.ProcessCreateTime);
            if (info.ProcessCreateTime != 0) {
                struct tm utcTm = {};
                if (_gmtime64_s(&utcTm, &createTime) == 0) {
                    wprintf(L"      => %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                            1900 + utcTm.tm_year, 1 + utcTm.tm_mon, utcTm.tm_mday,
                            utcTm.tm_hour, utcTm.tm_min, utcTm.tm_sec);
                }
            } else {
                wprintf(L"      => (zero / epoch)\n");
            }
            wprintf(L"    ProcessUserTime=%lu sec (%lu days %lu:%02lu:%02lu)\n",
                    info.ProcessUserTime,
                    info.ProcessUserTime / 86400,
                    (info.ProcessUserTime % 86400) / 3600,
                    (info.ProcessUserTime % 3600) / 60,
                    info.ProcessUserTime % 60);
            wprintf(L"    ProcessKernelTime=%lu sec (%lu days %lu:%02lu:%02lu)\n",
                    info.ProcessKernelTime,
                    info.ProcessKernelTime / 86400,
                    (info.ProcessKernelTime % 86400) / 3600,
                    (info.ProcessKernelTime % 60) / 60,
                    info.ProcessKernelTime % 60);
        } else {
            wprintf(L"    (MINIDUMP_MISC1_PROCESS_TIMES not set -- GetProcessTimes likely failed)\n");
        }
        break;
    }
    case MemoryInfoListStream: {
        MINIDUMP_MEMORY_INFO_LIST list = {};
        if (ReadAt(file, dir.Location.Rva, &list, sizeof(list))) {
            wprintf(L"    entries=%llu entrySize=%lu\n", list.NumberOfEntries, list.SizeOfEntry);
        }
        break;
    }
    case CommentStreamA: {
        // ANSI memory-summary comment. Print it as text (WinDbg shows it automatically on load).
        char text[1024] = {};
        DWORD size = dir.Location.DataSize;
        if (size >= sizeof(text)) {
            size = sizeof(text) - 1;
        }
        if (size != 0 && ReadAt(file, dir.Location.Rva, text, size)) {
            text[size] = '\0';
            wprintf(L"    %hs\n", text);
        }
        break;
    }
    case ThreadInfoListStream: {
        MINIDUMP_THREAD_INFO_LIST list = {};
        if (ReadAt(file, dir.Location.Rva, &list, sizeof(list))) {
            wprintf(L"    entries=%lu entrySize=%lu\n", list.NumberOfEntries, list.SizeOfEntry);
        }
        break;
    }
    default:
        break;
    }
}


// ---- Indirect-memory provenance reconstruction (post-hoc, from the captured dump) ---------------
//
// The library used to track provenance live, recording for every indirectly-referenced 4KB page the
// exact edge (CPU register / stack slot / source page slot) that pulled it in, plus the parent chain.
// To keep the crash-path writer lean that tracking was removed; instead this tool re-runs the same
// reference BFS *after* the fact, over the memory actually present in the dump (the MemoryListStream
// ranges plus each thread's register context and stack), and emits <dump>.prov.csv in the identical
// column layout the in-library tracker used -- so examples/prov_csv_to_tree.py renders it unchanged.
//
// Faithful but not bit-identical to the original live scan: page *index* order can differ (we seed
// all roots then expand breadth-first, with no file-size budget), and DataSegs pages -- if the dump
// happens to contain them -- are indistinguishable from genuinely indirect pages. Thread stacks are
// excluded as collectible pages via the known-range set, matching the library's behavior.

namespace prov {

constexpr ULONG64 kPageSize = 4096;
constexpr ULONG64 kStraddleWindow = 512;   // pointer within this of a page end also pulls the next page
constexpr ULONG32 kMaxLayers = 3;          // layer 1 = register/stack roots; 2/3 = transitive pages

enum { SrcRegister = 0, SrcStack = 1, SrcPage = 2 };

#if defined(_M_X64)
const char* const kRegNames[] = {
    "RAX", "RCX", "RDX", "RBX", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
};
#elif defined(_M_IX86)
const char* const kRegNames[] = { "EAX", "ECX", "EDX", "EBX", "EBP", "ESI", "EDI" };
#else
const char* const kRegNames[] = { "?" };
#endif

const char* SourceName(int source) noexcept
{
    switch (source) {
    case SrcRegister: return "register";
    case SrcStack:    return "stack";
    case SrcPage:     return "page";
    default:          return "none";
    }
}

const char* RegName(int idx) noexcept
{
    return (idx >= 0 && idx < static_cast<int>(ARRAYSIZE(kRegNames))) ? kRegNames[idx] : "?";
}

ULONG64 AlignDown(ULONG64 v, ULONG64 a) noexcept { return v & ~(a - 1); }

struct MemRange { ULONG64 Va; ULONG64 Size; ULONG64 FileRva; };
struct StackRange { ULONG64 Va; ULONG64 Size; };

struct ThreadInfo {
    ULONG32 ThreadId;
    ULONG64 StackVa;
    ULONG64 StackSize;
    ULONG64 Sp;
    bool HasContext;
    int RegCount;
    ULONG64 Regs[16];
};

struct Entry {
    ULONG64 Page;
    ULONG32 Layer;
    int Source;
    ULONG32 ThreadId;
    int RegIndex;        // valid only for register roots
    ULONG64 SourceAddr;  // stack slot / parent-page slot (0 for register roots)
    ULONG64 PointerValue;
    int ParentIndex;     // -1 for layer-1 roots
};

// Reconstructs the indirect-reference graph by reading memory out of the dump file.
struct Builder {
    HANDLE File = nullptr;
    std::vector<MemRange> Ranges;         // sorted by Va
    std::vector<StackRange> Stacks;       // thread stacks (excluded from collection)
    std::vector<Entry> Entries;
    std::unordered_set<ULONG64> Visited;

    // Largest range whose Va <= va, if it also covers va.
    int FindRange(ULONG64 va) const noexcept
    {
        int lo = 0, hi = static_cast<int>(Ranges.size()) - 1, ans = -1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (Ranges[mid].Va <= va) { ans = mid; lo = mid + 1; }
            else { hi = mid - 1; }
        }
        if (ans >= 0 && va < Ranges[ans].Va + Ranges[ans].Size) {
            return ans;
        }
        return -1;
    }

    bool ReadVa(ULONG64 va, void* buf, ULONG32 len) const noexcept
    {
        int idx = FindRange(va);
        if (idx < 0) {
            return false;
        }
        const MemRange& r = Ranges[idx];
        if (va + len > r.Va + r.Size) {
            return false;
        }
        return ReadAt(File, r.FileRva + (va - r.Va), buf, len) != FALSE;
    }

    bool PageCaptured(ULONG64 page) const noexcept
    {
        int idx = FindRange(page);
        if (idx < 0) {
            return false;
        }
        const MemRange& r = Ranges[idx];
        return page + kPageSize <= r.Va + r.Size;
    }

    bool StackOverlaps(ULONG64 page) const noexcept
    {
        for (const StackRange& s : Stacks) {
            if (page < s.Va + s.Size && s.Va < page + kPageSize) {
                return true;
            }
        }
        return false;
    }

    void CollectPage(ULONG64 page, ULONG32 layer, int source, ULONG32 tid, int regIndex,
                     ULONG64 sourceAddr, ULONG64 ptrValue, int parentIndex)
    {
        if (!PageCaptured(page) || StackOverlaps(page) || Visited.count(page) != 0) {
            return;
        }
        Visited.insert(page);
        Entry e = {};
        e.Page = page;
        e.Layer = layer;
        e.Source = source;
        e.ThreadId = tid;
        e.RegIndex = regIndex;
        e.SourceAddr = sourceAddr;
        e.PointerValue = ptrValue;
        e.ParentIndex = parentIndex;
        Entries.push_back(e);
    }

    // Mirrors the library's AddIndirectMemoryRangeFromPointer: skip self-range/null pointers, then
    // collect the landing page plus a straddle neighbor when the pointer sits near the page end.
    void AddFromPointer(ULONG64 value, ULONG64 srcStart, ULONG64 srcEnd, ULONG32 layer,
                        int source, ULONG32 tid, int regIndex, ULONG64 sourceAddr, int parentIndex)
    {
        if ((value >= srcStart && value < srcEnd) || value < 0x10000ULL || value >= 0x000007FFFFFFFFFF) {
            return;
        }
        ULONG64 firstPage = AlignDown(value, kPageSize);
        ULONG64 windowEnd = value + (kStraddleWindow - 1);
        ULONG64 lastPage = (windowEnd < value) ? firstPage : AlignDown(windowEnd, kPageSize);
        for (ULONG64 page = firstPage; page >= firstPage && page <= lastPage; page += kPageSize) {
            CollectPage(page, layer, source, tid, regIndex, sourceAddr, value, parentIndex);
        }
    }

    void ScanStackSpan(ULONG64 start, ULONG64 end, ULONG64 srcStart, ULONG64 srcEnd, ULONG32 tid)
    {
        for (ULONG64 cursor = start; cursor + sizeof(ULONG64) <= end; cursor += sizeof(ULONG64)) {
            ULONG64 value = 0;
            if (ReadVa(cursor, &value, sizeof(value))) {
                AddFromPointer(value, srcStart, srcEnd, 1, SrcStack, tid, -1, cursor, -1);
            }
        }
    }

    // For the exception thread, scan the live window (SP -> stack base) first, like the library.
    void ScanStack(const ThreadInfo& t, ULONG64 sp)
    {
        ULONG64 start = t.StackVa;
        ULONG64 end = t.StackVa + t.StackSize;
        if (t.StackSize == 0) {
            return;
        }
        if (sp >= start && sp < end) {
            ScanStackSpan(sp, end, start, end, t.ThreadId);
            ScanStackSpan(start, sp, start, end, t.ThreadId);
        } else {
            ScanStackSpan(start, end, start, end, t.ThreadId);
        }
    }

    void ScanRegisters(const ThreadInfo& t)
    {
        if (!t.HasContext) {
            return;
        }
        for (int i = 0; i < t.RegCount; ++i) {
            AddFromPointer(t.Regs[i], 0, 0, 1, SrcRegister, t.ThreadId, i, 0, -1);
        }
    }

    // Breadth-first expansion over the growing entry list: each collected page below the layer cap is
    // read once and scanned pointer-width at a time, enqueuing referenced pages at the next layer.
    void ExpandBfs()
    {
        BYTE page[kPageSize];
        for (size_t head = 0; head < Entries.size(); ++head) {
            ULONG32 layer = Entries[head].Layer;
            if (layer >= kMaxLayers) {
                continue;
            }
            ULONG64 pageStart = Entries[head].Page;
            ULONG32 tid = Entries[head].ThreadId;
            int parentIndex = static_cast<int>(head);
            if (!ReadVa(pageStart, page, kPageSize)) {
                continue;
            }
            for (ULONG32 off = 0; off + sizeof(ULONG64) <= kPageSize; off += sizeof(ULONG64)) {
                ULONG64 value = 0;
                memcpy(&value, page + off, sizeof(value));
                AddFromPointer(value, pageStart, pageStart + kPageSize, layer + 1, SrcPage,
                               tid, -1, pageStart + off, parentIndex);
            }
        }
    }

    // Builds the "origin -> page -> ..." chain by walking ParentIndex up to the layer-1 root, then
    // emitting pages root-first (so a layer-3 page reads root -> child -> grand), mirroring the library.
    std::string BuildChain(int idx) const
    {
        int path[kMaxLayers + 2];
        int depth = 0;
        int cur = idx;
        while (depth < static_cast<int>(ARRAYSIZE(path))) {
            path[depth++] = cur;
            int parent = Entries[cur].ParentIndex;
            if (parent < 0 || parent >= static_cast<int>(Entries.size()) || parent == cur) {
                break;
            }
            cur = parent;
        }
        const Entry& root = Entries[path[depth - 1]];
        char buf[128];
        std::string s;
        if (root.Source == SrcRegister) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "REG %s@T%lu", RegName(root.RegIndex),
                        static_cast<unsigned long>(root.ThreadId));
            s += buf;
        } else if (root.Source == SrcStack) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "STACK[0x%llX]@T%lu", root.SourceAddr,
                        static_cast<unsigned long>(root.ThreadId));
            s += buf;
        } else {
            s += "PAGE";
        }
        for (int k = depth - 1; k >= 0; --k) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, " -> 0x%llX", Entries[path[k]].Page);
            s += buf;
        }
        return s;
    }
};

// Prints the indirect-memory reference graph as a human-readable provenance tree to stdout,
// grouped by thread with register/stack roots and page-slot children.
// Returns the number of collected pages, or -1 if not generated.
int PrintProvenanceTree(HANDLE file, const MINIDUMP_HEADER& header, const wchar_t* dumpPath)
{
    ULONG64 threadListRva = 0;
    ULONG64 memListRva = 0;
    bool haveThreads = false;
    bool haveMem = false;
    ULONG32 exceptionTid = 0;
    bool haveException = false;

    for (ULONG32 i = 0; i < header.NumberOfStreams; ++i) {
        MINIDUMP_DIRECTORY dir = {};
        ULONG64 dirOffset = header.StreamDirectoryRva + static_cast<ULONG64>(i) * sizeof(dir);
        if (!ReadAt(file, dirOffset, &dir, sizeof(dir))) {
            break;
        }
        if (dir.StreamType == ThreadListStream) {
            threadListRva = dir.Location.Rva;
            haveThreads = true;
        } else if (dir.StreamType == MemoryListStream) {
            memListRva = dir.Location.Rva;
            haveMem = true;
        } else if (dir.StreamType == ExceptionStream) {
            MINIDUMP_EXCEPTION_STREAM ex = {};
            if (ReadAt(file, dir.Location.Rva, &ex, sizeof(ex))) {
                exceptionTid = ex.ThreadId;
                haveException = true;
            }
        }
    }

    // Default condition: only generate when the dump carries both selected memory and threads.
    if (!haveThreads || !haveMem) {
        return -1;
    }

    Builder b;
    b.File = file;

    // Load the captured memory ranges (VA -> file offset map) and sort by VA for binary search.
    ULONG32 memCount = 0;
    if (!ReadAt(file, memListRva, &memCount, sizeof(memCount))) {
        return -1;
    }
    for (ULONG32 i = 0; i < memCount; ++i) {
        MINIDUMP_MEMORY_DESCRIPTOR desc = {};
        ULONG64 off = memListRva + sizeof(memCount) + static_cast<ULONG64>(i) * sizeof(desc);
        if (!ReadAt(file, off, &desc, sizeof(desc))) {
            break;
        }
        MemRange r = {};
        r.Va = desc.StartOfMemoryRange;
        r.Size = desc.Memory.DataSize;
        r.FileRva = desc.Memory.Rva;
        if (r.Size != 0) {
            b.Ranges.push_back(r);
        }
    }
    std::sort(b.Ranges.begin(), b.Ranges.end(),
              [](const MemRange& a, const MemRange& c) { return a.Va < c.Va; });

    // Load threads: stack ranges (excluded from collection) and register contexts (layer-1 roots).
    std::vector<ThreadInfo> threads;
    ULONG32 threadCount = 0;
    if (ReadAt(file, threadListRva, &threadCount, sizeof(threadCount))) {
        for (ULONG32 i = 0; i < threadCount; ++i) {
            MINIDUMP_THREAD t = {};
            ULONG64 off = threadListRva + sizeof(threadCount) + static_cast<ULONG64>(i) * sizeof(t);
            if (!ReadAt(file, off, &t, sizeof(t))) {
                break;
            }
            ThreadInfo ti = {};
            ti.ThreadId = t.ThreadId;
            ti.StackVa = t.Stack.StartOfMemoryRange;
            ti.StackSize = t.Stack.Memory.DataSize;
            if (ti.StackSize != 0) {
                StackRange sr = { ti.StackVa, ti.StackSize };
                b.Stacks.push_back(sr);
            }
            CONTEXT ctx = {};
            ULONG32 csize = t.ThreadContext.DataSize;
            if (csize > sizeof(ctx)) {
                csize = sizeof(ctx);
            }
            if (csize != 0 && ReadAt(file, t.ThreadContext.Rva, &ctx, csize)) {
                ti.HasContext = true;
#if defined(_M_X64)
                const ULONG64 regs[] = {
                    ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rbp, ctx.Rsi, ctx.Rdi,
                    ctx.R8,  ctx.R9,  ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15,
                };
                ti.Sp = ctx.Rsp;
#elif defined(_M_IX86)
                const ULONG64 regs[] = {
                    ctx.Eax, ctx.Ecx, ctx.Edx, ctx.Ebx, ctx.Ebp, ctx.Esi, ctx.Edi,
                };
                ti.Sp = ctx.Esp;
#else
                const ULONG64 regs[1] = { 0 };
#endif
                ti.RegCount = static_cast<int>(ARRAYSIZE(regs));
                for (int r = 0; r < ti.RegCount && r < static_cast<int>(ARRAYSIZE(ti.Regs)); ++r) {
                    ti.Regs[r] = regs[r];
                }
            }
            threads.push_back(ti);
        }
    }

    // Seed layer-1 roots: the exception thread first (registers, then stack live-window first), then
    // every other thread (registers, then a linear stack scan). Then expand the whole graph.
    auto seedThread = [&](const ThreadInfo& t, bool isException) {
        b.ScanRegisters(t);
        b.ScanStack(t, isException ? t.Sp : 0);
    };
    if (haveException) {
        for (const ThreadInfo& t : threads) {
            if (t.ThreadId == exceptionTid) {
                seedThread(t, true);
                break;
            }
        }
    }
    for (const ThreadInfo& t : threads) {
        if (haveException && t.ThreadId == exceptionTid) {
            continue;
        }
        seedThread(t, false);
    }
    b.ExpandBfs();

    // ---- Build the tree: compute parent -> children mapping from the flat entry list. ----
    std::vector<std::vector<int>> children(b.Entries.size());
    std::vector<int> roots;
    for (size_t i = 0; i < b.Entries.size(); ++i) {
        if (b.Entries[i].ParentIndex < 0) {
            roots.push_back(static_cast<int>(i));
        } else if (static_cast<size_t>(b.Entries[i].ParentIndex) < b.Entries.size()) {
            children[static_cast<size_t>(b.Entries[i].ParentIndex)].push_back(static_cast<int>(i));
        }
    }

    // Sort children by page address for deterministic output.
    for (auto& ch : children) {
        std::sort(ch.begin(), ch.end(), [&](int a, int c) { return b.Entries[a].Page < b.Entries[c].Page; });
    }

    // ---- Group roots by thread, keeping the seeding order (exception thread first). ----
    struct RootGroup {
        ULONG32 ThreadId;
        bool IsException;
        std::vector<int> RootIndices;
    };
    std::vector<RootGroup> groups;
    for (int idx : roots) {
        ULONG32 tid = b.Entries[idx].ThreadId;
        bool isEx = haveException && tid == exceptionTid;
        auto it = std::find_if(groups.begin(), groups.end(),
            [tid](const RootGroup& g) { return g.ThreadId == tid; });
        if (it == groups.end()) {
            RootGroup g = {};
            g.ThreadId = tid;
            g.IsException = isEx;
            g.RootIndices.push_back(idx);
            groups.push_back(g);
        } else {
            it->RootIndices.push_back(idx);
        }
    }

    // ---- Print the provenance tree to stdout. ----

    // Compute summary stats.
    ULONG32 maxLayer = 0;
    ULONG32 threadCountInTree = static_cast<ULONG32>(groups.size());
    for (const Entry& e : b.Entries) {
        if (e.Layer > maxLayer) maxLayer = e.Layer;
    }

    // ---- Tree-drawing helpers.  All pure ASCII for maximum portability. ----
    auto PrintNodeLine = [&](const std::wstring& prefix, bool isLast, const Entry& e, int idx) {
        wprintf(L"%ls%ls-- ", prefix.c_str(), isLast ? L"\\" : L"+");

        wchar_t srcLabel[48];
        if (e.Source == SrcRegister) {
            _snwprintf_s(srcLabel, _countof(srcLabel), _TRUNCATE, L"REG %-4hs",
                        RegName(e.RegIndex));
        } else if (e.Source == SrcStack) {
            _snwprintf_s(srcLabel, _countof(srcLabel), _TRUNCATE, L"STACK 0x%llX",
                        e.SourceAddr);
        } else {
            ULONG64 pageBase = b.Entries[e.ParentIndex].Page;
            _snwprintf_s(srcLabel, _countof(srcLabel), _TRUNCATE, L"PAGE +0x%llX",
                        e.SourceAddr - pageBase);
        }

        wprintf(L"%ls = 0x%016llX -> page 0x%016llX [L%lu]",
                srcLabel, e.PointerValue, e.Page,
                static_cast<unsigned long>(e.Layer));

        size_t nChildren = children[idx].size();
        if (nChildren != 0) {
            wprintf(L" (%zu child%s)", nChildren, nChildren == 1 ? L"" : L"ren");
        }
        wprintf(L"\n");
    };

    // Recursive depth-first tree walk.
    std::function<void(const std::wstring&, int)> WalkTree;
    WalkTree = [&](const std::wstring& prefix, int idx) {
        const auto& ch = children[idx];
        for (size_t k = 0; k < ch.size(); ++k) {
            int childIdx = ch[k];
            bool isLastChild = (k + 1 == ch.size());
            PrintNodeLine(prefix, isLastChild, b.Entries[childIdx], childIdx);
            std::wstring childPrefix = prefix + (isLastChild ? L"    " : L" |  ");
            WalkTree(childPrefix, childIdx);
        }
    };

    time_t now = time(nullptr);
    struct tm utcTm = {};
    _gmtime64_s(&utcTm, &now);

    wprintf(L"\n");
    wprintf(L"=== Indirect Memory Provenance (Reference Tree) ===\n");
    wprintf(L"\n");
    wprintf(L"Dump   : %ls\n", dumpPath);
    wprintf(L"Pages  : %zu referenced across %lu layer(s) from %lu thread(s)\n",
            b.Entries.size(), static_cast<unsigned long>(maxLayer),
            static_cast<unsigned long>(threadCountInTree));
    wprintf(L"Time   : %04d-%02d-%02d %02d:%02d:%02d UTC\n",
            1900 + utcTm.tm_year, 1 + utcTm.tm_mon, utcTm.tm_mday,
            utcTm.tm_hour, utcTm.tm_min, utcTm.tm_sec);

    if (!b.Entries.empty()) {
        wprintf(L"\n");
        wprintf(L"Legend : REG=<register>, STACK=<stack_slot>, PAGE=<parent_page_offset>\n");
        wprintf(L"         L1=register/stack root, L2/L3=transitive reference\n");
        wprintf(L"         [CRASH] = exception thread\n");
        wprintf(L"\n");
    } else {
        wprintf(L"(no referenced pages found)\n");
        return static_cast<int>(b.Entries.size());
    }

    // Emit the tree: groups in seed order (exception thread first).
    for (size_t gi = 0; gi < groups.size(); ++gi) {
        const RootGroup& g = groups[gi];
        // Sort roots within a group: register roots first, then stack roots.
        std::vector<int> sorted = g.RootIndices;
        std::sort(sorted.begin(), sorted.end(), [&](int a, int c) {
            if (b.Entries[a].Source != b.Entries[c].Source)
                return b.Entries[a].Source < b.Entries[c].Source;
            if (b.Entries[a].Source == SrcRegister)
                return b.Entries[a].RegIndex < b.Entries[c].RegIndex;
            return b.Entries[a].SourceAddr < b.Entries[c].SourceAddr;
        });

        wprintf(L"%ls Thread %lu\n",
                g.IsException ? L"[CRASH]" : L"       ",
                static_cast<unsigned long>(g.ThreadId));

        for (size_t ri = 0; ri < sorted.size(); ++ri) {
            int idx = sorted[ri];
            bool lastRoot = (ri + 1 == sorted.size());
            PrintNodeLine(std::wstring(), lastRoot, b.Entries[idx], idx);
            std::wstring prefix = lastRoot ? L"    " : L" |  ";
            WalkTree(prefix, idx);
        }
        if (gi + 1 < groups.size()) {
            wprintf(L"\n");
        }
    }
    return static_cast<int>(b.Entries.size());
}

} // namespace prov

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        fwprintf(stderr, L"usage: MiniDumpInspect <dump.dmp>\n");
        return 2;
    }

    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"open failed: %ls (%lu)\n", argv[1], GetLastError());
        return 1;
    }

    LARGE_INTEGER fileSize = {};
    MINIDUMP_HEADER header = {};
    if (!GetFileSizeEx(file, &fileSize) || !ReadAt(file, 0, &header, sizeof(header))) {
        fwprintf(stderr, L"read header failed\n");
        CloseHandle(file);
        return 1;
    }
    if (header.Signature != MINIDUMP_SIGNATURE) {
        fwprintf(stderr, L"not a minidump: signature=0x%lx\n", header.Signature);
        CloseHandle(file);
        return 1;
    }

    wprintf(L"file=%ls\n", argv[1]);
    wprintf(L"size=%llu bytes\n", static_cast<ULONG64>(fileSize.QuadPart));
    wprintf(L"version=0x%lx streams=%lu directoryRva=0x%lx flags=0x%llx\n",
            header.Version,
            header.NumberOfStreams,
            header.StreamDirectoryRva,
            header.Flags);
    wprintf(L"header.TimeDateStamp=%lu (0x%lx)\n",
            header.TimeDateStamp, header.TimeDateStamp);
    if (header.TimeDateStamp != 0) {
        __time64_t stamp = static_cast<__time64_t>(header.TimeDateStamp);
        struct tm utcTm = {};
        if (_gmtime64_s(&utcTm, &stamp) == 0) {
            wprintf(L"  => %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                    1900 + utcTm.tm_year, 1 + utcTm.tm_mon, utcTm.tm_mday,
                    utcTm.tm_hour, utcTm.tm_min, utcTm.tm_sec);
        }
    }

    for (ULONG32 i = 0; i < header.NumberOfStreams; ++i) {
        MINIDUMP_DIRECTORY dir = {};
        ULONG64 dirOffset = header.StreamDirectoryRva + static_cast<ULONG64>(i) * sizeof(dir);
        if (!ReadAt(file, dirOffset, &dir, sizeof(dir))) {
            fwprintf(stderr, L"read directory %lu failed\n", i);
            break;
        }
        wprintf(L"[%02lu] %-28ls type=%lu rva=0x%08lx size=%lu\n",
                i,
                StreamName(dir.StreamType),
                dir.StreamType,
                dir.Location.Rva,
                dir.Location.DataSize);
        PrintStreamDetails(file, dir);
    }

    // Cross-check: if MiscInfo has PROCESS_TIMES, compute ProcessUptime from
    // header.TimeDateStamp - ProcessCreateTime and compare with .time output.
    for (ULONG32 i = 0; i < header.NumberOfStreams; ++i) {
        MINIDUMP_DIRECTORY dir = {};
        ULONG64 dirOffset = header.StreamDirectoryRva + static_cast<ULONG64>(i) * sizeof(dir);
        if (!ReadAt(file, dirOffset, &dir, sizeof(dir)) || dir.StreamType != MiscInfoStream) {
            continue;
        }
        MINIDUMP_MISC_INFO info = {};
        ULONG32 readSize = sizeof(info);
        if (readSize > dir.Location.DataSize) {
            readSize = dir.Location.DataSize;
        }
        if (ReadAt(file, dir.Location.Rva, &info, readSize)) {
            if (info.Flags1 & MINIDUMP_MISC1_PROCESS_TIMES && info.ProcessCreateTime != 0) {
                ULONG32 uptime = header.TimeDateStamp - info.ProcessCreateTime;
                wprintf(L"\n== Process Uptime ==\n");
                wprintf(L"  header.TimeDateStamp   = %lu\n", header.TimeDateStamp);
                wprintf(L"  ProcessCreateTime      = %lu\n", info.ProcessCreateTime);
                wprintf(L"  diff (Process Uptime)  = %lu sec\n", uptime);
                wprintf(L"                        = %lu days %lu:%02lu:%02lu\n",
                        uptime / 86400,
                        (uptime % 86400) / 3600,
                        (uptime % 3600) / 60,
                        uptime % 60);
            } else {
                wprintf(L"\n== Process Uptime (NOT available) ==\n");
                wprintf(L"  MINIDUMP_MISC1_PROCESS_TIMES flag is not set.\n");
                wprintf(L"  header.TimeDateStamp - 0 = %lu sec (~%lu days) -- this IS the bogus uptime Windbg likely shows.\n",
                        header.TimeDateStamp, header.TimeDateStamp / 86400);
            }
        }
        break;
    }

    // Reconstruct the indirect-memory provenance (register/stack/page reference chains) from the
    // captured memory and print the reference tree to stdout. Generated whenever the dump carries
    // both a MemoryListStream and a ThreadListStream.
    prov::PrintProvenanceTree(file, header, argv[1]);

    CloseHandle(file);
    return 0;
}
