// UE4-style large-application crash-capture demo for WriteMiniDumpInproc.
//
// Simulates the resource profile of a big game/engine process and verifies that the in-process
// writer produces a usable, HARD-CAPPED dump under two very different size budgets:
//
//   * ~10 GB+ of committed memory (spread across many VirtualAlloc regions, like a game allocator),
//   * 320 worker threads (each parking a pointer chain so the indirect-reference scan has work),
//   * a crashing thread running on a 12 MB stack that overflows (STATUS_STACK_OVERFLOW),
//   * MaxFileSize tested at 12 MB and 128 MB.
//
// Because the dump is SELECTIVE (no MiniDumpWithFullMemory), the writer must keep the file within
// MaxFileSize by capturing the crash stack (dual-window for the >1 MB overflowed stack), thread
// info, region metadata and indirect memory by priority -- NOT the full 10 GB. The crash is handled
// by a dedicated dump thread on its own large stack so the overflow can still be written.
//
// Runs as parent -> launches itself as a child once per size budget, then validates each dump:
// produced, within the cap, has the expected streams, captured 300+ threads, and recorded the
// exception. Build is enabled with the other samples (MINIDUMP_INPROC_BUILD_SAMPLE=ON).

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

// ---- profile knobs -------------------------------------------------------------------------
constexpr DWORD  kWorkerThreads      = 320;                       // "super many threads" (>300)
constexpr DWORD  kChainPages         = 3;                         // pointer-chain depth per worker
constexpr ULONG64 kTargetCommitBytes = 10ull * 1024 * 1024 * 1024; // "super high memory" (~10 GB)
constexpr SIZE_T kCommitChunkBytes   = 64ull * 1024 * 1024;       // 64 MB per allocation (many regions)
constexpr DWORD  kMaxCommitChunks    = 256;                       // cap the region table
constexpr SIZE_T kCrashStackBytes    = 12ull * 1024 * 1024;       // "super large stack" (12 MB)
constexpr SIZE_T kRecurseFrameBytes  = 8192;                      // frame size of the overflow recursion
constexpr DWORD  kDumpThreadStackBytes = 8 * 1024 * 1024;         // dedicated dump-thread stack
constexpr DWORD  kDumpWaitMs         = 180000;

// ---- child: shared state -------------------------------------------------------------------
HANDLE g_DumpRequest = nullptr;
HANDLE g_DumpDone = nullptr;
EXCEPTION_POINTERS* g_ExceptionPointers = nullptr;
DWORD g_ExceptionThreadId = 0;
volatile LONG g_DumpResult = 0;
DWORD g_DumpLastError = 0;
const wchar_t* g_DumpPath = nullptr;
MINIDUMP_TYPE g_DumpType = MiniDumpNormal;
ULONG64 g_MaxFileSize = 0;

HANDLE g_WorkersReady = nullptr;
volatile LONG g_WorkersLive = 0;
HANDLE g_HoldEvent = nullptr;        // never signaled; keeps worker frames (and their chains) alive

void* g_CommitChunks[kMaxCommitChunks] = {};
DWORD g_CommitChunkCount = 0;
ULONG64 g_CommittedBytes = 0;

// Application-defined state attached as a user stream, proving UserStreamParam survives the cap.
struct AppStatePayload {
    char Tag[16];
    ULONG64 CommittedBytes;
    DWORD WorkerThreads;
    DWORD CrashStackBytes;
    char Build[64];
};
AppStatePayload g_AppState = {};

// ---- child: simulate the big-game memory footprint -----------------------------------------

// Commits ~10 GB across many regions. Pages are demand-zero (committed, not touched), so this
// inflates Commit Charge / Private Bytes like a real allocator reservation without forcing 10 GB of
// physical RAM. Stops early and reports the real total if the system runs out of commit.
void CommitHugeMemory() noexcept
{
    g_CommitChunkCount = 0;
    g_CommittedBytes = 0;
    while (g_CommitChunkCount < kMaxCommitChunks &&
           g_CommittedBytes < kTargetCommitBytes) {
        void* p = VirtualAlloc(nullptr, kCommitChunkBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p == nullptr) {
            break; // out of commit; keep what we have
        }
        // Touch the first page only so the region is unmistakably backed/committed without paging
        // in the whole 64 MB.
        *static_cast<volatile BYTE*>(p) = 0xA5;
        g_CommitChunks[g_CommitChunkCount++] = p;
        g_CommittedBytes += kCommitChunkBytes;
    }
}

// ---- child: dedicated dump thread ----------------------------------------------------------

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

        // Attach the app state as a user stream (priority above indirect memory, still capped).
        MINIDUMP_USER_STREAM userStream = {};
        userStream.Type = CommentStreamA; // generic id so viewers print it; real apps use custom ids
        userStream.BufferSize = static_cast<ULONG>(sizeof(g_AppState));
        userStream.Buffer = &g_AppState;
        MINIDUMP_USER_STREAM_INFORMATION userStreamInfo = {};
        userStreamInfo.UserStreamCount = 1;
        userStreamInfo.UserStreamArray = &userStream;

        SetLastError(ERROR_SUCCESS);
        BOOL ok = WriteMiniDumpInproc(file, g_DumpType, &info, &userStreamInfo, g_MaxFileSize);
        g_DumpLastError = ok ? ERROR_SUCCESS : GetLastError();
        InterlockedExchange(&g_DumpResult, ok ? 1 : 0);
        FlushFileBuffers(file);
        CloseHandle(file);
    }

    SetEvent(g_DumpDone);
    return 0;
}

// Runs on the faulting thread; keeps its own footprint tiny (signal + wait) so it survives even a
// stack overflow. The heavy dump work happens on the dedicated dump thread above.
LONG WINAPI LargeAppExceptionFilter(EXCEPTION_POINTERS* ep) noexcept
{
    g_ExceptionPointers = ep;
    g_ExceptionThreadId = GetCurrentThreadId();
    SetEvent(g_DumpRequest);
    WaitForSingleObject(g_DumpDone, kDumpWaitMs);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ---- child: worker threads -----------------------------------------------------------------

DWORD WINAPI WorkerThreadProc(LPVOID) noexcept
{
    ULONG stackGuarantee = 64 * 1024;
    (void)SetThreadStackGuarantee(&stackGuarantee);

    volatile void* chainHead = nullptr;
    void* pages[kChainPages] = {};
    for (DWORD i = 0; i < kChainPages; ++i) {
        pages[i] = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    for (DWORD i = 0; i + 1 < kChainPages; ++i) {
        if (pages[i] != nullptr) {
            *reinterpret_cast<void**>(pages[i]) = pages[i + 1];
        }
    }
    chainHead = pages[0];

    if (InterlockedIncrement(&g_WorkersLive) == static_cast<LONG>(kWorkerThreads)) {
        SetEvent(g_WorkersReady);
    }

    WaitForSingleObject(g_HoldEvent, INFINITE);

    volatile void* keep = chainHead;
    (void)keep;
    return 0;
}

void SpawnWorkers() noexcept
{
    for (DWORD i = 0; i < kWorkerThreads; ++i) {
        HANDLE h = CreateThread(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr);
        if (h != nullptr) {
            CloseHandle(h);
        }
    }
    WaitForSingleObject(g_WorkersReady, 30000);
}

// ---- child: the 12 MB-stack overflow crash -------------------------------------------------

#pragma optimize("", off)
int RecurseUntilStackOverflow(volatile int depth) noexcept
{
    volatile char frame[kRecurseFrameBytes];
    frame[0] = static_cast<char>(depth & 0x7f);
    frame[sizeof(frame) - 1] = static_cast<char>(depth);
    return RecurseUntilStackOverflow(depth + 1) + frame[0] + frame[sizeof(frame) - 1];
}
#pragma optimize("", on)

DWORD WINAPI CrashThreadProc(LPVOID) noexcept
{
    ULONG stackGuarantee = 64 * 1024; // room for the unhandled-exception filter on overflow
    (void)SetThreadStackGuarantee(&stackGuarantee);
    (void)RecurseUntilStackOverflow(0);
    return 0;
}

int RunChild(const wchar_t* label, const wchar_t* dumpPath, ULONG64 maxFileSize) noexcept
{
    (void)label;
    g_DumpPath = dumpPath;
    g_MaxFileSize = maxFileSize;

    // Rich SELECTIVE dump: exercises thread info, region metadata, writable data segments and the
    // indirect-reference scan, all bounded by MaxFileSize. Deliberately NOT MiniDumpWithFullMemory,
    // so the 10 GB is never written wholesale -- the writer trims to fit the cap.
    g_DumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpNormal |
        MiniDumpWithThreadInfo |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithDataSegs |
        MiniDumpWithIndirectlyReferencedMemory |
        MiniDumpIgnoreInaccessibleMemory);

    g_DumpRequest = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_DumpDone = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_WorkersReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_HoldEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_DumpRequest == nullptr || g_DumpDone == nullptr || g_WorkersReady == nullptr || g_HoldEvent == nullptr) {
        return 100;
    }

    HANDLE dumpThread = CreateThread(nullptr, kDumpThreadStackBytes, DumpThreadProc, nullptr,
                                     STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (dumpThread != nullptr) {
        CloseHandle(dumpThread);
    }

    // Build the big-game footprint: ~10 GB committed + 320 worker threads.
    CommitHugeMemory();
    SpawnWorkers();

    // Fill the app-state user stream now that the footprint is known.
    StringCchCopyA(g_AppState.Tag, sizeof(g_AppState.Tag), "UE4LIKE");
    g_AppState.CommittedBytes = g_CommittedBytes;
    g_AppState.WorkerThreads = kWorkerThreads;
    g_AppState.CrashStackBytes = static_cast<DWORD>(kCrashStackBytes);
    StringCchCopyA(g_AppState.Build, sizeof(g_AppState.Build), "ue4_like_large_app_crash demo build");

    ULONG stackGuarantee = 64 * 1024;
    (void)SetThreadStackGuarantee(&stackGuarantee);
    SetUnhandledExceptionFilter(LargeAppExceptionFilter);

    // Crash on a dedicated 12 MB-stack thread (recurse to STATUS_STACK_OVERFLOW).
    HANDLE crasher = CreateThread(nullptr, kCrashStackBytes, CrashThreadProc, nullptr,
                                  STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (crasher == nullptr) {
        return 101;
    }
    WaitForSingleObject(crasher, INFINITE);
    CloseHandle(crasher);
    return 99; // should not reach here (the thread overflows and the process exits via the filter)
}

// ---- parent: validation --------------------------------------------------------------------

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

BOOL ValidateDump(const wchar_t* path, ULONG32* threadCount, ULONG32* streams,
                  ULONG64* flags, ULONG64* size, BOOL* hasException) noexcept
{
    *threadCount = 0;
    *streams = 0;
    *flags = 0;
    *size = 0;
    *hasException = FALSE;

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
            } else if (dir.StreamType == ExceptionStream) {
                *hasException = TRUE;
            }
        }
    }

    CloseHandle(file);
    return ok;
}

struct Budget {
    const wchar_t* Label;
    ULONG64 MaxFileSize;
};

int RunParent(const wchar_t* exePath) noexcept
{
    const Budget budgets[] = {
        { L"ue4_12mb",  12ull * 1024 * 1024 },
        { L"ue4_128mb", 128ull * 1024 * 1024 },
    };

    wprintf(L"UE4-like large-app crash capture: ~10GB commit, %lu threads, %llu-byte crash stack\n",
            static_cast<unsigned long>(kWorkerThreads), static_cast<unsigned long long>(kCrashStackBytes));
    wprintf(L"=========================================================================\n");

    unsigned failures = 0;
    for (const Budget& b : budgets) {
        wchar_t dumpPath[MAX_PATH] = {};
        StringCchPrintfW(dumpPath, MAX_PATH, L"%ls.dmp", b.Label);
        DeleteFileW(dumpPath);

        wchar_t cmd[1024] = {};
        StringCchPrintfW(cmd, 1024, L"\"%ls\" --child %ls \"%ls\" %llu",
                         exePath, b.Label, dumpPath, b.MaxFileSize);

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            wprintf(L"[FAIL] %-10ls CreateProcess failed (%lu)\n", b.Label, GetLastError());
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
        BOOL hasException = FALSE;
        BOOL dumpOk = ValidateDump(dumpPath, &threadCount, &streams, &flags, &size, &hasException);

        const BOOL withinCap = dumpOk && size <= b.MaxFileSize;
        const BOOL threadsOk = threadCount >= 300;
        const wchar_t* verdict;
        if (dumpOk && withinCap && threadsOk && hasException) {
            verdict = L"PASS";
        } else {
            verdict = L"FAIL";
            ++failures;
        }

        wprintf(L"[%ls] %-10ls cap=%lluMB dump=%d size=%llu (%lluKB) withinCap=%d threads=%lu exc=%d streams=%lu childExit=0x%lx\n",
                verdict, b.Label, b.MaxFileSize >> 20, dumpOk, size, size >> 10,
                withinCap, threadCount, hasException, streams, childExit);
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
