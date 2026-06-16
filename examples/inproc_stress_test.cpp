// Stress / robustness harness for WriteMiniDumpInproc.
//
// It runs as a parent that launches itself as a child once per crash scenario. Each child:
//   * spawns 150 worker threads, each parking a 3-level pointer chain on its stack so the
//     multi-layer MiniDumpWithIndirectlyReferencedMemory scanner has real graphs to walk,
//   * installs an unhandled-exception filter that hands the crash to a dedicated dump thread
//     running on its own large stack (so even a stack-overflow crash can still be written),
//   * triggers a real crash (AV, stack overflow, use-after-free, or heap-metadata corruption).
// The parent then parses the produced dump and verifies the header, stream set and that 100+
// threads were captured.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#include "minidump_inproc.h"

namespace {

constexpr DWORD kStressThreads = 150;
constexpr DWORD kChainPages = 3;        // pointer-chain depth parked on each worker stack
constexpr DWORD kDumpWorkerStackBytes = 8 * 1024 * 1024;
constexpr DWORD kDumpWaitMs = 120000;

// ---- data-seg-via-indirect-scan validation -------------------------------------------------
// A large global block lives in the EXE's writable image section (.bss, Type=MEM_IMAGE,
// PAGE_READWRITE). Without MiniDumpWithDataSegs it must NOT be captured wholesale; only the 4KB
// page that a crash-thread stack pointer points at should be pulled in by the indirect-reference
// scan. We plant a magic in the referenced page (expected present in the dump) and a different
// magic in a far, unreferenced page (expected absent) to assert exactly that selectivity.
constexpr ULONG64 kMagicReferenced   = 0xCAFED00DBEEF1234ULL;
constexpr ULONG64 kMagicUnreferenced = 0xFEEDFACE0BADF00DULL;
constexpr ULONG64 kMagicGraphRoot    = 0x1111222233334444ULL;
constexpr ULONG64 kMagicGraphChild   = 0x5555666677778888ULL;
constexpr ULONG64 kMagicGraphGrand   = 0x9999AAAABBBBCCCCULL;
constexpr SIZE_T  kBigGlobalBytes = 8 * 1024 * 1024;
constexpr SIZE_T  kRefGlobalOffset = 1 * 1024 * 1024; // page a stack pointer will reference
constexpr SIZE_T  kFarGlobalOffset = 7 * 1024 * 1024; // page nothing references
volatile unsigned char g_BigGlobal[kBigGlobalBytes];

struct IndirectGraphNode {
    ULONG64 Magic;
    IndirectGraphNode* Child;
    BYTE Padding[4096 - sizeof(ULONG64) - sizeof(void*)];
};

// ---- child: dedicated dump thread state ----------------------------------------------------

HANDLE g_DumpRequest = nullptr;   // signaled by the crashing thread
HANDLE g_DumpDone = nullptr;      // signaled by the dump thread when finished
EXCEPTION_POINTERS* g_ExceptionPointers = nullptr;
DWORD g_ExceptionThreadId = 0;
volatile LONG g_DumpResult = 0;
const wchar_t* g_DumpPath = nullptr;
MINIDUMP_TYPE g_DumpType = MiniDumpNormal;
ULONG64 g_MaxFileSize = 0;

HANDLE g_WorkersReady = nullptr;
volatile LONG g_WorkersLive = 0;
HANDLE g_HoldEvent = nullptr;     // never signaled; keeps worker frames (and their pointers) alive

DWORD WINAPI DumpThreadProc(LPVOID) noexcept
{
    WaitForSingleObject(g_DumpRequest, INFINITE);

    HANDLE file = CreateFileW(g_DumpPath, GENERIC_WRITE | GENERIC_READ, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION info = {};
        info.ThreadId = g_ExceptionThreadId;
        info.ExceptionPointers = g_ExceptionPointers;
        info.ClientPointers = FALSE;
        BOOL ok = WriteMiniDumpInproc(file, g_DumpType, &info, g_MaxFileSize);
        InterlockedExchange(&g_DumpResult, ok ? 1 : 0);
        FlushFileBuffers(file);
        CloseHandle(file);
    }

    SetEvent(g_DumpDone);
    return 0;
}

// Runs on the faulting thread. Keeps its own stack use tiny (just signal + wait) so it survives a
// stack overflow; the heavy dump work happens on the dedicated dump thread.
LONG WINAPI StressExceptionFilter(EXCEPTION_POINTERS* ep) noexcept
{
    g_ExceptionPointers = ep;
    g_ExceptionThreadId = GetCurrentThreadId();
    SetEvent(g_DumpRequest);
    WaitForSingleObject(g_DumpDone, kDumpWaitMs);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ---- child: worker threads ----------------------------------------------------------------

// Builds a kChainPages-deep pointer chain (page[0] -> page[1] -> ... ) and parks the head pointer
// in a stack local, then blocks forever so the frame (and thus the chain) stays referenced.
DWORD WINAPI WorkerThreadProc(LPVOID) noexcept
{
    ULONG stackGuarantee = 64 * 1024; // leave room for the unhandled-exception filter on overflow
    (void)SetThreadStackGuarantee(&stackGuarantee);

    volatile void* chainHead = nullptr;
    void* pages[kChainPages] = {};
    for (DWORD i = 0; i < kChainPages; ++i) {
        pages[i] = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    for (DWORD i = 0; i + 1 < kChainPages; ++i) {
        if (pages[i] != nullptr) {
            *reinterpret_cast<void**>(pages[i]) = pages[i + 1]; // page[i] -> page[i+1]
        }
    }
    chainHead = pages[0];

    if (InterlockedIncrement(&g_WorkersLive) == static_cast<LONG>(kStressThreads)) {
        SetEvent(g_WorkersReady);
    }

    WaitForSingleObject(g_HoldEvent, INFINITE);

    volatile void* keep = chainHead; // prevent the chain pointer from being optimized away
    (void)keep;
    return 0;
}

void SpawnWorkers() noexcept
{
    for (DWORD i = 0; i < kStressThreads; ++i) {
        HANDLE h = CreateThread(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr);
        if (h != nullptr) {
            CloseHandle(h);
        }
    }
    WaitForSingleObject(g_WorkersReady, 10000);
}

BOOL StackOverflowScenarioStackBytes(const wchar_t* scenario, SIZE_T* stackBytes) noexcept
{
    if (lstrcmpiW(scenario, L"stack_overflow") == 0 || lstrcmpiW(scenario, L"stack_overflow_1m") == 0) {
        *stackBytes = 1 * 1024 * 1024;
        return TRUE;
    }
    if (lstrcmpiW(scenario, L"stack_overflow_256k") == 0) {
        *stackBytes = 256 * 1024;
        return TRUE;
    }
    if (lstrcmpiW(scenario, L"stack_overflow_2m") == 0) {
        *stackBytes = 2 * 1024 * 1024;
        return TRUE;
    }
    if (lstrcmpiW(scenario, L"stack_overflow_4m") == 0) {
        *stackBytes = 4 * 1024 * 1024;
        return TRUE;
    }
    return FALSE;
}

// ---- child: crash scenarios ---------------------------------------------------------------

#pragma optimize("", off)
int RecurseUntilStackOverflow(volatile int depth) noexcept
{
    volatile char frame[8192];
    frame[0] = static_cast<char>(depth & 0x7f);
    frame[sizeof(frame) - 1] = static_cast<char>(depth);
    return RecurseUntilStackOverflow(depth + 1) + frame[0] + frame[sizeof(frame) - 1];
}
#pragma optimize("", on)

DWORD WINAPI StackOverflowThreadProc(LPVOID) noexcept
{
    ULONG stackGuarantee = 64 * 1024;
    (void)SetThreadStackGuarantee(&stackGuarantee);
    (void)RecurseUntilStackOverflow(0);
    return 0;
}

// Writes a magic pattern into one page of the large global block. noinline + a parameter-passed
// offset/magic keep the address computation off the caller's frame; the leftover pointer/magic in
// this helper's own (now-stale) frame are scrubbed by ClobberStackRegion below.
__declspec(noinline) void PlantGlobalMagic(SIZE_T offset, ULONG64 magic) noexcept
{
    volatile ULONG64* p = reinterpret_cast<volatile ULONG64*>(&g_BigGlobal[offset]);
    for (int i = 0; i < 64; ++i) {
        p[i] = magic;
    }
}

// Overwrites the stack region used by the PlantGlobalMagic calls so no stale pointer to (or magic
// value of) an unreferenced global page lingers on the crashing thread's stack. Without this, the
// indirect scan would legitimately follow such a stale pointer and capture the "far" page too.
__declspec(noinline) void ClobberStackRegion() noexcept
{
    volatile unsigned char buf[64 * 1024];
    SecureZeroMemory(const_cast<unsigned char*>(buf), sizeof(buf));
}

__declspec(noinline) IndirectGraphNode* BuildIndirectObjectGraph() noexcept
{
    IndirectGraphNode* root = static_cast<IndirectGraphNode*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    IndirectGraphNode* child = static_cast<IndirectGraphNode*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    IndirectGraphNode* grand = static_cast<IndirectGraphNode*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (root != nullptr) {
        root->Magic = kMagicGraphRoot;
        root->Child = child;
    }
    if (child != nullptr) {
        child->Magic = kMagicGraphChild;
        child->Child = grand;
    }
    if (grand != nullptr) {
        grand->Magic = kMagicGraphGrand;
        grand->Child = nullptr;
    }
    return root;
}

void TriggerCrash(const wchar_t* scenario) noexcept
{
    if (lstrcmpiW(scenario, L"av_write") == 0 || lstrcmpiW(scenario, L"av_write_capped") == 0 ||
        wcsncmp(scenario, L"type_", 5) == 0) {
        volatile int* p = nullptr;
        *p = 1;
    } else if (lstrcmpiW(scenario, L"stack_overflow") == 0) {
        (void)RecurseUntilStackOverflow(0);
    } else if (lstrcmpiW(scenario, L"use_after_free") == 0) {
        BYTE* p = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        VirtualFree(p, 0, MEM_RELEASE);
        *p = 0x42; // touch decommitted page -> access violation
    } else if (lstrcmpiW(scenario, L"datasegs_indirect") == 0) {
        // Write a recognizable magic into a far page (must stay UNreferenced) and into the page a
        // stack pointer will reference. Both writes go through a noinline helper; ClobberStackRegion
        // then wipes any stale pointer/magic those calls left on this thread's stack, so the only
        // surviving reference into the global block is the deliberate stackAnchor below.
        PlantGlobalMagic(kFarGlobalOffset, kMagicUnreferenced);
        PlantGlobalMagic(kRefGlobalOffset, kMagicReferenced);
        ClobberStackRegion();

        // Park pointers to the referenced page on this (the crashing) thread's stack so the
        // indirect-reference scanner reaches exactly that 4KB global page (layer 1).
        volatile void* refPtr = const_cast<unsigned char*>(&g_BigGlobal[kRefGlobalOffset]);
        volatile void* stackAnchor[8];
        for (int i = 0; i < 8; ++i) { stackAnchor[i] = refPtr; }
        // Crash; stackAnchor stays live on the stack at dump time.
        volatile int* p = nullptr;
        *p = static_cast<int>(reinterpret_cast<ULONG_PTR>(stackAnchor[0]));
    } else if (lstrcmpiW(scenario, L"indirect_object_graph") == 0) {
        IndirectGraphNode* root = BuildIndirectObjectGraph();
        ClobberStackRegion();
        volatile void* stackAnchor[8];
        for (int i = 0; i < 8; ++i) { stackAnchor[i] = root; }
        volatile int* p = nullptr;
        *p = static_cast<int>(reinterpret_cast<ULONG_PTR>(stackAnchor[0]));
    } else if (lstrcmpiW(scenario, L"heap_corruption") == 0) {
        HANDLE heap = GetProcessHeap();
        BYTE* p = static_cast<BYTE*>(HeapAlloc(heap, 0, 32));
        if (p != nullptr) {
            FillMemory(p, 256, 0xAA);          // overflow the block, smash heap metadata
            HeapFree(heap, 0, p);              // may trip a fail-fast that bypasses handlers
            void* q = HeapAlloc(heap, 0, 64);  // force a heap walk
            (void)q;
        }
        // If the corruption did not fault, fall back to a guaranteed crash.
        volatile int* z = nullptr;
        *z = 7;
    }
}

int RunChild(const wchar_t* scenario, const wchar_t* dumpPath, ULONG64 maxFileSize) noexcept
{
    g_DumpPath = dumpPath;
    g_MaxFileSize = maxFileSize;
    if (lstrcmpiW(scenario, L"datasegs_indirect") == 0 || lstrcmpiW(scenario, L"indirect_object_graph") == 0 ||
        lstrcmpiW(scenario, L"type_indirect") == 0) {
        // Deliberately omit MiniDumpWithDataSegs and MiniDumpWithFullMemory: referenced memory must
        // be collected purely by the indirect-reference scan.
        g_DumpType = static_cast<MINIDUMP_TYPE>(
            MiniDumpNormal |
            MiniDumpWithIndirectlyReferencedMemory |
            MiniDumpIgnoreInaccessibleMemory);
    } else if (lstrcmpiW(scenario, L"type_normal") == 0) {
        g_DumpType = MiniDumpNormal;
    } else if (lstrcmpiW(scenario, L"type_thread_info") == 0) {
        g_DumpType = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithProcessThreadData);
    } else if (lstrcmpiW(scenario, L"type_memory_info") == 0) {
        g_DumpType = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithFullMemoryInfo);
    } else if (lstrcmpiW(scenario, L"type_data_segs") == 0) {
        g_DumpType = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithDataSegs);
    } else if (lstrcmpiW(scenario, L"type_full_memory") == 0) {
        g_DumpType = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo);
    } else {
        g_DumpType = static_cast<MINIDUMP_TYPE>(
            MiniDumpNormal |
            MiniDumpWithThreadInfo |
            MiniDumpWithFullMemoryInfo |
            MiniDumpWithDataSegs |
            MiniDumpWithIndirectlyReferencedMemory |
            MiniDumpIgnoreInaccessibleMemory);
    }

    g_DumpRequest = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_DumpDone = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_WorkersReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_HoldEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_DumpRequest == nullptr || g_DumpDone == nullptr || g_WorkersReady == nullptr || g_HoldEvent == nullptr) {
        return 100;
    }

    HANDLE dumpThread = CreateThread(nullptr, kDumpWorkerStackBytes, DumpThreadProc, nullptr,
                                     STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (dumpThread != nullptr) {
        CloseHandle(dumpThread);
    }

    ULONG stackGuarantee = 64 * 1024; // ensure the filter has room even on a stack-overflow crash
    (void)SetThreadStackGuarantee(&stackGuarantee);

    SetUnhandledExceptionFilter(StressExceptionFilter);
    SpawnWorkers();

    SIZE_T stackBytes = 0;
    if (StackOverflowScenarioStackBytes(scenario, &stackBytes)) {
        HANDLE crasher = CreateThread(nullptr, stackBytes, StackOverflowThreadProc, nullptr,
                                      STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
        if (crasher == nullptr) {
            return 101;
        }
        WaitForSingleObject(crasher, INFINITE);
        CloseHandle(crasher);
        return 99;
    }

    TriggerCrash(scenario);

    // Should not reach here; if a scenario failed to crash, exit non-zero.
    return 99;
}

// ---- parent: dump validation --------------------------------------------------------------

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

// Streams the whole dump file looking for an 8-byte magic value. The magics are only ever written
// into the large global block, so a hit means that block's page was actually captured in the dump.
// A 7-byte carry between chunks handles a value straddling a read boundary.
BOOL FileContainsQword(const wchar_t* path, ULONG64 magic) noexcept
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BOOL found = FALSE;
    const DWORD kChunk = 1u << 16;
    BYTE* buf = static_cast<BYTE*>(VirtualAlloc(nullptr, kChunk + 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (buf != nullptr) {
        DWORD carry = 0;
        for (;;) {
            DWORD read = 0;
            if (!ReadFile(file, buf + carry, kChunk, &read, nullptr) || read == 0) {
                break;
            }
            DWORD total = carry + read;
            for (DWORD i = 0; i + 8 <= total; ++i) {
                ULONG64 v = 0;
                CopyMemory(&v, buf + i, sizeof(v));
                if (v == magic) { found = TRUE; break; }
            }
            if (found || read < kChunk) {
                break;
            }
            if (total >= 7) { CopyMemory(buf, buf + total - 7, 7); carry = 7; }
            else { carry = 0; }
        }
        VirtualFree(buf, 0, MEM_RELEASE);
    }

    CloseHandle(file);
    return found;
}

BOOL ValidateDump(const wchar_t* path, ULONG32* threadCount, ULONG32* streams,
                  ULONG64* flags, ULONG64* size) noexcept
{
    *threadCount = 0;
    *streams = 0;
    *flags = 0;
    *size = 0;

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BOOL ok = FALSE;
    LARGE_INTEGER fileSize = {};
    MINIDUMP_HEADER header = {};
    if (GetFileSizeEx(file, &fileSize) && ReadAt(file, 0, &header, sizeof(header)) &&
        header.Signature == MINIDUMP_SIGNATURE && header.NumberOfStreams != 0) {
        *streams = header.NumberOfStreams;
        *flags = header.Flags;
        *size = static_cast<ULONG64>(fileSize.QuadPart);
        ok = TRUE;

        for (ULONG32 i = 0; i < header.NumberOfStreams; ++i) {
            MINIDUMP_DIRECTORY dir = {};
            if (!ReadAt(file, header.StreamDirectoryRva + static_cast<ULONG64>(i) * sizeof(dir), &dir, sizeof(dir))) {
                break;
            }
            if (dir.StreamType == ThreadListStream) {
                ULONG32 count = 0;
                if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
                    *threadCount = count;
                }
                break;
            }
        }
    }

    CloseHandle(file);
    return ok;
}

struct Scenario {
    const wchar_t* Name;
    ULONG64 MaxFileSize;
    BOOL Informational;       // crash may bypass in-process handlers (fail-fast); missing dump is not a failure
    BOOL CheckIndirectDataSeg; // additionally assert: referenced global page present, far page absent
};

int RunParent(const wchar_t* exePath) noexcept
{
    const Scenario scenarios[] = {
        { L"av_write",             0,                    FALSE, FALSE },
        { L"av_write_capped",      1ull * 1024 * 1024,   FALSE, FALSE },
        { L"use_after_free",       0,                    FALSE, FALSE },
        { L"stack_overflow_256k",  12ull * 1024 * 1024,  FALSE, FALSE },
        { L"stack_overflow_1m",    12ull * 1024 * 1024,  FALSE, FALSE },
        { L"stack_overflow_2m",    12ull * 1024 * 1024,  FALSE, FALSE },
        { L"stack_overflow_4m",    12ull * 1024 * 1024,  FALSE, FALSE },
        { L"heap_corruption",      0,                    TRUE,  FALSE },
        { L"datasegs_indirect",    0,                    FALSE, TRUE  },
        { L"indirect_object_graph",0,                    FALSE, FALSE },
        { L"type_normal",          0,                    FALSE, FALSE },
        { L"type_thread_info",     0,                    FALSE, FALSE },
        { L"type_memory_info",     0,                    FALSE, FALSE },
        { L"type_data_segs",       0,                    FALSE, FALSE },
        { L"type_indirect",        0,                    FALSE, FALSE },
        { L"type_full_memory",     128ull * 1024 * 1024, FALSE, FALSE },
    };

    unsigned failures = 0;
    for (const Scenario& s : scenarios) {
        wchar_t dumpPath[MAX_PATH] = {};
        StringCchPrintfW(dumpPath, MAX_PATH, L"inproc_stress_%ls.dmp", s.Name);
        DeleteFileW(dumpPath);

        wchar_t cmd[1024] = {};
        StringCchPrintfW(cmd, 1024, L"\"%ls\" --child %ls \"%ls\" %llu",
                         exePath, s.Name, dumpPath, s.MaxFileSize);

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            wprintf(L"[FAIL] %-18ls CreateProcess failed (%lu)\n", s.Name, GetLastError());
            ++failures;
            continue;
        }
        WaitForSingleObject(pi.hProcess, kDumpWaitMs);
        DWORD childExit = 0;
        GetExitCodeProcess(pi.hProcess, &childExit);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        ULONG32 threadCount = 0, streams = 0;
        ULONG64 flags = 0, size = 0;
        BOOL dumpOk = ValidateDump(dumpPath, &threadCount, &streams, &flags, &size);
        BOOL threadsOk = threadCount >= 100;

        if (s.CheckIndirectDataSeg) {
            // Selectivity check: the referenced global page must have been captured by the indirect
            // scan, while the far, unreferenced page of the same global block must NOT be present
            // (proving data segments are pulled in by-reference, not wholesale, without DataSegs).
            BOOL refPage = dumpOk && FileContainsQword(dumpPath, kMagicReferenced);
            BOOL farPage = dumpOk && FileContainsQword(dumpPath, kMagicUnreferenced);
            const wchar_t* verdict;
            if (dumpOk && threadsOk && refPage && !farPage) {
                verdict = L"PASS";
            } else {
                verdict = L"FAIL";
                ++failures;
            }
            wprintf(L"[%ls] %-22ls dump=%d threads=%lu streams=%lu size=%llu refPage=%d farPage=%d (expect ref=1 far=0)\n",
                    verdict, s.Name, dumpOk, threadCount, streams, size, refPage, farPage);
            continue;
        }

        if (lstrcmpiW(s.Name, L"indirect_object_graph") == 0) {
            BOOL root = dumpOk && FileContainsQword(dumpPath, kMagicGraphRoot);
            BOOL child = dumpOk && FileContainsQword(dumpPath, kMagicGraphChild);
            BOOL grand = dumpOk && FileContainsQword(dumpPath, kMagicGraphGrand);
            const wchar_t* verdict;
            if (dumpOk && threadsOk && root && child && grand) {
                verdict = L"PASS";
            } else {
                verdict = L"FAIL";
                ++failures;
            }
            wprintf(L"[%ls] %-22ls dump=%d threads=%lu streams=%lu size=%llu root=%d child=%d grand=%d (expect all=1)\n",
                    verdict, s.Name, dumpOk, threadCount, streams, size, root, child, grand);
            continue;
        }

        const wchar_t* verdict;
        if (dumpOk && threadsOk) {
            verdict = L"PASS";
        } else if (!dumpOk && s.Informational) {
            verdict = L"INFO"; // expected: fail-fast bypassed the in-process handler, no dump produced
        } else {
            verdict = L"FAIL";
            ++failures;
        }

        wprintf(L"[%ls] %-22ls dump=%d threads=%lu streams=%lu size=%llu flags=0x%llx childExit=0x%lx\n",
                verdict, s.Name, dumpOk, threadCount, streams, size, flags, childExit);
    }

    wprintf(L"\nsummary: %u hard failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 4 && lstrcmpiW(argv[1], L"--child") == 0) {
        ULONG64 maxFileSize = (argc >= 5) ? _wcstoui64(argv[4], nullptr, 10) : 0;
        return RunChild(argv[2], argv[3], maxFileSize);
    }

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    return RunParent(exePath);
}
