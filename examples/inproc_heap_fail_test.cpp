#ifndef _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#define _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "minidump_inproc.h"

#include <windows.h>
#include <dbghelp.h>
#include <intrin.h>
#include <stdio.h>
#include <strsafe.h>

#include "../third_party/Detours/src/detours.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wmicrosoft-cast"
#endif

namespace {

enum FailMode : ULONG {
    FailHeapAlloc = 0x0001,
    FailHeapReAlloc = 0x0002,
    FailRtlAllocateHeap = 0x0004,
    FailRtlReAllocateHeap = 0x0008,
    FailHeapCreate = 0x0010,
    FailRtlCreateHeap = 0x0020,
    FailVirtualAlloc = 0x0040,
};

struct Scenario {
    const wchar_t* Name;
    ULONG FailMask;
    MINIDUMP_TYPE DumpType;
    BOOL InitBeforeWrite;
};

constexpr ULONG kIndirectTestPointers = 2100;
constexpr SIZE_T kIndirectTestBytes = static_cast<SIZE_T>(kIndirectTestPointers) * 4096;


using HeapCreateFn = HANDLE (WINAPI*)(DWORD, SIZE_T, SIZE_T);
using HeapAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, SIZE_T);
using HeapReAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
using HeapFreeFn = BOOL (WINAPI*)(HANDLE, DWORD, LPVOID);
using RtlCreateHeapFn = PVOID (NTAPI*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
using RtlAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlReAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);
using RtlFreeHeapFn = BOOLEAN (NTAPI*)(PVOID, ULONG, PVOID);
using VirtualAllocFn = LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFreeFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD);

HeapCreateFn RealHeapCreate = nullptr;
HeapAllocFn RealHeapAlloc = nullptr;
HeapReAllocFn RealHeapReAlloc = nullptr;
HeapFreeFn RealHeapFree = nullptr;
RtlCreateHeapFn RealRtlCreateHeap = nullptr;
RtlAllocateHeapFn RealRtlAllocateHeap = nullptr;
RtlReAllocateHeapFn RealRtlReAllocateHeap = nullptr;
RtlFreeHeapFn RealRtlFreeHeap = nullptr;
VirtualAllocFn RealVirtualAlloc = nullptr;
VirtualFreeFn RealVirtualFree = nullptr;

volatile LONG g_HooksActive = 0;
volatile LONG g_FailMask = 0;
volatile LONG g_HeapCreateCalls = 0;
volatile LONG g_HeapAllocCalls = 0;
volatile LONG g_HeapReAllocCalls = 0;
volatile LONG g_RtlCreateHeapCalls = 0;
volatile LONG g_RtlAllocateHeapCalls = 0;
volatile LONG g_RtlReAllocateHeapCalls = 0;
volatile LONG g_VirtualAllocCalls = 0;

BOOL ShouldFail(ULONG bit) noexcept
{
    return InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0 &&
           (static_cast<ULONG>(InterlockedCompareExchange(&g_FailMask, 0, 0)) & bit) != 0;
}

HANDLE WINAPI HookHeapCreate(DWORD options, SIZE_T initialSize, SIZE_T maximumSize)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_HeapCreateCalls);
    }
    if (ShouldFail(FailHeapCreate)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    return RealHeapCreate(options, initialSize, maximumSize);
}

LPVOID WINAPI HookHeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes)
{
    UNREFERENCED_PARAMETER(heap);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(bytes);
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_HeapAllocCalls);
    }
    if (ShouldFail(FailHeapAlloc)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    return RealHeapAlloc(heap, flags, bytes);
}

LPVOID WINAPI HookHeapReAlloc(HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_HeapReAllocCalls);
    }
    if (ShouldFail(FailHeapReAlloc)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    return RealHeapReAlloc(heap, flags, mem, bytes);
}

BOOL WINAPI HookHeapFree(HANDLE heap, DWORD flags, LPVOID mem)
{
    return RealHeapFree(heap, flags, mem);
}

PVOID NTAPI HookRtlCreateHeap(ULONG flags, PVOID heapBase, SIZE_T reserveSize, SIZE_T commitSize,
                              PVOID lock, PVOID parameters)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_RtlCreateHeapCalls);
    }
    if (ShouldFail(FailRtlCreateHeap)) {
        return nullptr;
    }
    return RealRtlCreateHeap(flags, heapBase, reserveSize, commitSize, lock, parameters);
}

PVOID NTAPI HookRtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_RtlAllocateHeapCalls);
    }
    if (ShouldFail(FailRtlAllocateHeap)) {
        return nullptr;
    }
    return RealRtlAllocateHeap(heap, flags, size);
}

PVOID NTAPI HookRtlReAllocateHeap(PVOID heap, ULONG flags, PVOID mem, SIZE_T size)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_RtlReAllocateHeapCalls);
    }
    if (ShouldFail(FailRtlReAllocateHeap)) {
        return nullptr;
    }
    return RealRtlReAllocateHeap(heap, flags, mem, size);
}

BOOLEAN NTAPI HookRtlFreeHeap(PVOID heap, ULONG flags, PVOID mem)
{
    return RealRtlFreeHeap(heap, flags, mem);
}

LPVOID WINAPI HookVirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect)
{
    if (InterlockedCompareExchange(&g_HooksActive, 0, 0) != 0) {
        InterlockedIncrement(&g_VirtualAllocCalls);
    }
    if (ShouldFail(FailVirtualAlloc)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    return RealVirtualAlloc(address, size, allocationType, protect);
}

BOOL WINAPI HookVirtualFree(LPVOID address, SIZE_T size, DWORD freeType)
{
    return RealVirtualFree(address, size, freeType);
}

FARPROC ResolveProc(const wchar_t* moduleName, const char* procName)
{
    HMODULE module = GetModuleHandleW(moduleName);
    if (module == nullptr) {
        module = LoadLibraryW(moduleName);
    }
    return module != nullptr ? GetProcAddress(module, procName) : nullptr;
}

BOOL ResolveTargets()
{
    RealHeapCreate = reinterpret_cast<HeapCreateFn>(ResolveProc(L"kernelbase.dll", "HeapCreate"));
    RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernelbase.dll", "HeapAlloc"));
    RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernelbase.dll", "HeapReAlloc"));
    RealHeapFree = reinterpret_cast<HeapFreeFn>(ResolveProc(L"kernelbase.dll", "HeapFree"));
    RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernelbase.dll", "VirtualAlloc"));
    RealVirtualFree = reinterpret_cast<VirtualFreeFn>(ResolveProc(L"kernelbase.dll", "VirtualFree"));

    if (RealHeapCreate == nullptr) RealHeapCreate = reinterpret_cast<HeapCreateFn>(ResolveProc(L"kernel32.dll", "HeapCreate"));
    if (RealHeapAlloc == nullptr) RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernel32.dll", "HeapAlloc"));
    if (RealHeapReAlloc == nullptr) RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernel32.dll", "HeapReAlloc"));
    if (RealHeapFree == nullptr) RealHeapFree = reinterpret_cast<HeapFreeFn>(ResolveProc(L"kernel32.dll", "HeapFree"));
    if (RealVirtualAlloc == nullptr) RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernel32.dll", "VirtualAlloc"));
    if (RealVirtualFree == nullptr) RealVirtualFree = reinterpret_cast<VirtualFreeFn>(ResolveProc(L"kernel32.dll", "VirtualFree"));

    RealRtlCreateHeap = reinterpret_cast<RtlCreateHeapFn>(ResolveProc(L"ntdll.dll", "RtlCreateHeap"));
    RealRtlAllocateHeap = reinterpret_cast<RtlAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlAllocateHeap"));
    RealRtlReAllocateHeap = reinterpret_cast<RtlReAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlReAllocateHeap"));
    RealRtlFreeHeap = reinterpret_cast<RtlFreeHeapFn>(ResolveProc(L"ntdll.dll", "RtlFreeHeap"));

    return RealHeapCreate != nullptr && RealHeapAlloc != nullptr && RealHeapReAlloc != nullptr &&
           RealHeapFree != nullptr && RealRtlCreateHeap != nullptr && RealRtlAllocateHeap != nullptr &&
           RealRtlReAllocateHeap != nullptr && RealRtlFreeHeap != nullptr &&
           RealVirtualAlloc != nullptr && RealVirtualFree != nullptr;
}

LONG AttachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapCreate), HookHeapCreate);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapFree), HookHeapFree);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlCreateHeap), HookRtlCreateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlAllocateHeap), HookRtlAllocateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlReAllocateHeap), HookRtlReAllocateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlFreeHeap), HookRtlFreeHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealVirtualAlloc), HookVirtualAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealVirtualFree), HookVirtualFree);
    return DetourTransactionCommit();
}

LONG DetachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapCreate), HookHeapCreate);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapFree), HookHeapFree);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlCreateHeap), HookRtlCreateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlAllocateHeap), HookRtlAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlReAllocateHeap), HookRtlReAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlFreeHeap), HookRtlFreeHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealVirtualAlloc), HookVirtualAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealVirtualFree), HookVirtualFree);
    return DetourTransactionCommit();
}

void ResetCounters() noexcept
{
    InterlockedExchange(&g_HeapCreateCalls, 0);
    InterlockedExchange(&g_HeapAllocCalls, 0);
    InterlockedExchange(&g_HeapReAllocCalls, 0);
    InterlockedExchange(&g_RtlCreateHeapCalls, 0);
    InterlockedExchange(&g_RtlAllocateHeapCalls, 0);
    InterlockedExchange(&g_RtlReAllocateHeapCalls, 0);
    InterlockedExchange(&g_VirtualAllocCalls, 0);
}

BOOL ReadHeaderOk(const wchar_t* path, ULONG32* streams, ULONG64* flags, LARGE_INTEGER* size) noexcept
{
    *streams = 0;
    *flags = 0;
    size->QuadPart = 0;

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    MINIDUMP_HEADER header = {};
    DWORD read = 0;
    BOOL ok = GetFileSizeEx(file, size) &&
              ReadFile(file, &header, sizeof(header), &read, nullptr) &&
              read == sizeof(header) &&
              header.Signature == MINIDUMP_SIGNATURE &&
              header.NumberOfStreams != 0 &&
              header.StreamDirectoryRva >= sizeof(MINIDUMP_HEADER);
    if (ok) {
        *streams = header.NumberOfStreams;
        *flags = header.Flags;
    }
    CloseHandle(file);
    return ok;
}

void BuildDumpPath(const wchar_t* scenarioName, wchar_t* path, DWORD chars) noexcept
{
    if (chars == 0) {
        return;
    }
    path[0] = L'\0';
    (void)StringCchPrintfW(path, chars, L"inproc_heap_fail_%ls.dmp", scenarioName);
}

BOOL RunScenario(const Scenario& scenario) noexcept
{
    wchar_t path[MAX_PATH] = {};
    BuildDumpPath(scenario.Name, path, MAX_PATH);
    DeleteFileW(path);

    // Initialization is automatic at module load; InitBeforeWrite is retained only for
    // scenario labeling and no longer triggers an explicit init call.
    UNREFERENCED_PARAMETER(scenario.InitBeforeWrite);

    HANDLE file = CreateFileW(path, GENERIC_WRITE | GENERIC_READ, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        wprintf(L"[FAIL] %-36ls CreateFile failed, LastError=%lu\n", scenario.Name, GetLastError());
        return FALSE;
    }

    BYTE* indirectBlock = nullptr;
    volatile PVOID indirectRefs[kIndirectTestPointers] = {};
    if ((static_cast<ULONG>(scenario.DumpType) & MiniDumpWithIndirectlyReferencedMemory) != 0) {
        indirectBlock = static_cast<BYTE*>(RealVirtualAlloc(
            nullptr,
            kIndirectTestBytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE));
        if (indirectBlock != nullptr) {
            for (ULONG i = 0; i < kIndirectTestPointers; ++i) {
                indirectBlock[static_cast<SIZE_T>(i) * 4096] = static_cast<BYTE>(i);
                indirectRefs[i] = indirectBlock + static_cast<SIZE_T>(i) * 4096;
            }
        }
    }

    CONTEXT context = {};
    RtlCaptureContext(&context);
    if (indirectBlock != nullptr) {
#if defined(_M_X64)
        context.Rsp = reinterpret_cast<DWORD64>(&indirectRefs[0]);
#elif defined(_M_IX86)
        context.Esp = reinterpret_cast<DWORD>(&indirectRefs[0]);
#endif
    }
    EXCEPTION_RECORD record = {};


    record.ExceptionCode = 0xE0424244;
    record.ExceptionAddress = _ReturnAddress();
    EXCEPTION_POINTERS pointers = {};
    pointers.ExceptionRecord = &record;
    pointers.ContextRecord = &context;
    MINIDUMP_EXCEPTION_INFORMATION exceptionInfo = {};
    exceptionInfo.ThreadId = GetCurrentThreadId();
    exceptionInfo.ExceptionPointers = &pointers;
    exceptionInfo.ClientPointers = FALSE;

    ResetCounters();
    InterlockedExchange(&g_FailMask, static_cast<LONG>(scenario.FailMask));
    InterlockedExchange(&g_HooksActive, 1);
    SetLastError(ERROR_SUCCESS);
    BOOL writeOk = WriteMiniDumpInproc(file, scenario.DumpType, &exceptionInfo, 0);
    DWORD writeError = writeOk ? ERROR_SUCCESS : GetLastError();
    InterlockedExchange(&g_HooksActive, 0);
    InterlockedExchange(&g_FailMask, 0);

    FlushFileBuffers(file);
    CloseHandle(file);

    volatile PVOID keepIndirectRefs = indirectRefs[0];
    UNREFERENCED_PARAMETER(keepIndirectRefs);
    if (indirectBlock != nullptr) {
        (void)RealVirtualFree(indirectBlock, 0, MEM_RELEASE);
    }

    ULONG32 streams = 0;

    ULONG64 flags = 0;
    LARGE_INTEGER size = {};
    BOOL headerOk = writeOk && ReadHeaderOk(path, &streams, &flags, &size);

    wprintf(L"[%ls] %-36ls write=%d err=%lu header=%d size=%lld streams=%lu flags=0x%llx\n",
            headerOk ? L"PASS" : L"FAIL",
            scenario.Name,
            writeOk,
            writeError,
            headerOk,
            size.QuadPart,
            streams,
            flags);
    wprintf(L"       calls: HeapCreate=%ld HeapAlloc=%ld HeapReAlloc=%ld RtlCreateHeap=%ld RtlAllocateHeap=%ld RtlReAllocateHeap=%ld VirtualAlloc=%ld\n",
            g_HeapCreateCalls,
            g_HeapAllocCalls,
            g_HeapReAllocCalls,
            g_RtlCreateHeapCalls,
            g_RtlAllocateHeapCalls,
            g_RtlReAllocateHeapCalls,
            g_VirtualAllocCalls);
    return headerOk;
}

} // namespace

int wmain()
{
    if (!ResolveTargets()) {
        fwprintf(stderr, L"ResolveTargets failed. LastError=%lu\n", GetLastError());
        return 2;
    }

    LONG attach = AttachHooks();
    if (attach != NO_ERROR) {
        fwprintf(stderr, L"AttachHooks failed: %ld\n", attach);
        return 3;
    }

    const MINIDUMP_TYPE normalDump = static_cast<MINIDUMP_TYPE>(
        MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpIgnoreInaccessibleMemory);
    const MINIDUMP_TYPE richDump = static_cast<MINIDUMP_TYPE>(
        MiniDumpNormal |
        MiniDumpWithThreadInfo |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithDataSegs |
        MiniDumpWithIndirectlyReferencedMemory |
        MiniDumpWithUnloadedModules |
        MiniDumpIgnoreInaccessibleMemory);


    const Scenario scenarios[] = {
        { L"noinit_heapalloc_null", FailHeapAlloc, normalDump, FALSE },
        { L"init_heapalloc_null", FailHeapAlloc, normalDump, TRUE },
        { L"init_heap_realloc_null", FailHeapAlloc | FailHeapReAlloc, normalDump, TRUE },
        { L"init_rtl_alloc_null", FailHeapAlloc | FailHeapReAlloc | FailRtlAllocateHeap | FailRtlReAllocateHeap, normalDump, TRUE },
        { L"init_heapcreate_alloc_null", FailHeapCreate | FailHeapAlloc | FailHeapReAlloc | FailRtlCreateHeap | FailRtlAllocateHeap | FailRtlReAllocateHeap, normalDump, TRUE },
        { L"init_virtualalloc_null", FailHeapAlloc | FailHeapReAlloc | FailRtlAllocateHeap | FailRtlReAllocateHeap | FailVirtualAlloc, normalDump, TRUE },
        { L"rich_all_heap_null", FailHeapCreate | FailHeapAlloc | FailHeapReAlloc | FailRtlCreateHeap | FailRtlAllocateHeap | FailRtlReAllocateHeap, richDump, TRUE },
        { L"rich_heap_virtual_null", FailHeapCreate | FailHeapAlloc | FailHeapReAlloc | FailRtlCreateHeap | FailRtlAllocateHeap | FailRtlReAllocateHeap | FailVirtualAlloc, richDump, TRUE },
    };

    ULONG failed = 0;
    for (ULONG i = 0; i < ARRAYSIZE(scenarios); ++i) {
        if (!RunScenario(scenarios[i])) {
            ++failed;
        }
    }

    InterlockedExchange(&g_HooksActive, 0);
    InterlockedExchange(&g_FailMask, 0);
    LONG detach = DetachHooks();
    if (detach != NO_ERROR) {
        fwprintf(stderr, L"DetachHooks failed: %ld\n", detach);
        return 4;
    }

    wprintf(L"\nsummary: %lu/%lu scenarios failed\n", failed, static_cast<ULONG>(ARRAYSIZE(scenarios)));
    return failed == 0 ? 0 : 1;
}
