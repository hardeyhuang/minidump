#ifndef _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#define _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <intrin.h>

#include "../third_party/Detours/src/detours.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wmicrosoft-cast"
#endif

namespace {


constexpr ULONG kMaxHeapRecords = 64;
constexpr ULONG kMaxOtherHeapRecords = 128;
constexpr ULONG kMaxPreExistingHeaps = 512;
constexpr ULONG kMaxAllocEvents = 8192;

struct HeapRecord {
    HANDLE Heap;
    DWORD CreateFlags;
    SIZE_T InitialSize;
    SIZE_T MaximumSize;
    DWORD ThreadId;
};

struct AllocEvent {
    char Op;
    HANDLE Heap;
    PVOID Ptr;
    PVOID OldPtr;
    SIZE_T Size;
    DWORD Flags;
    DWORD ThreadId;
    PVOID ReturnAddress;
    BOOL IsPrivateHeap;
};

struct OtherHeapRecord {
    HANDLE Heap;
    BOOL IsProcessHeap;
    BOOL ExistedBeforeTrace;
    DWORD FirstThreadId;
    PVOID FirstReturnAddress;
    SIZE_T FirstSize;
    DWORD FirstFlags;
    char FirstOp;
};

using HeapCreateFn = HANDLE (WINAPI*)(DWORD, SIZE_T, SIZE_T);
using HeapDestroyFn = BOOL (WINAPI*)(HANDLE);
using HeapAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, SIZE_T);
using HeapReAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
using HeapFreeFn = BOOL (WINAPI*)(HANDLE, DWORD, LPVOID);
using RtlCreateHeapFn = PVOID (NTAPI*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
using RtlDestroyHeapFn = PVOID (NTAPI*)(PVOID);
using RtlAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlReAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);
using RtlFreeHeapFn = BOOLEAN (NTAPI*)(PVOID, ULONG, PVOID);
using VirtualAllocFn = LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFreeFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD);
using MiniDumpWriteDumpFn = BOOL (WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                           PMINIDUMP_EXCEPTION_INFORMATION,
                                           PMINIDUMP_USER_STREAM_INFORMATION,
                                           PMINIDUMP_CALLBACK_INFORMATION);

HeapCreateFn RealHeapCreate = nullptr;
HeapDestroyFn RealHeapDestroy = nullptr;
HeapAllocFn RealHeapAlloc = nullptr;
HeapReAllocFn RealHeapReAlloc = nullptr;
HeapFreeFn RealHeapFree = nullptr;
RtlCreateHeapFn RealRtlCreateHeap = nullptr;
RtlDestroyHeapFn RealRtlDestroyHeap = nullptr;
RtlAllocateHeapFn RealRtlAllocateHeap = nullptr;
RtlReAllocateHeapFn RealRtlReAllocateHeap = nullptr;
RtlFreeHeapFn RealRtlFreeHeap = nullptr;
VirtualAllocFn RealVirtualAlloc = nullptr;
VirtualFreeFn RealVirtualFree = nullptr;
MiniDumpWriteDumpFn RealMiniDumpWriteDump = nullptr;

volatile LONG g_TraceEnabled = 0;
volatile LONG g_InHook = 0;
volatile LONG g_HeapRecordCount = 0;
volatile LONG g_OtherHeapRecordCount = 0;
volatile LONG g_PreExistingHeapCount = 0;
volatile LONG g_AllocEventCount = 0;
volatile LONG g_VirtualAllocCount = 0;
volatile LONG g_VirtualFreeCount = 0;

HeapRecord g_HeapRecords[kMaxHeapRecords] = {};
OtherHeapRecord g_OtherHeapRecords[kMaxOtherHeapRecords] = {};
HANDLE g_PreExistingHeaps[kMaxPreExistingHeaps] = {};
AllocEvent g_AllocEvents[kMaxAllocEvents] = {};

bool EnterHook() noexcept
{
    if (InterlockedCompareExchange(&g_InHook, 1, 0) != 0) {
        return false;
    }
    return true;
}

void LeaveHook() noexcept
{
    InterlockedExchange(&g_InHook, 0);
}

BOOL IsRecordedHeap(HANDLE heap) noexcept
{
    LONG count = g_HeapRecordCount;
    if (count < 0) {
        count = 0;
    }
    if (count > static_cast<LONG>(kMaxHeapRecords)) {
        count = kMaxHeapRecords;
    }
    for (LONG i = 0; i < count; ++i) {
        if (g_HeapRecords[i].Heap == heap) {
            return TRUE;
        }
    }
    return FALSE;
}


BOOL IsPreExistingHeap(HANDLE heap) noexcept
{
    LONG count = g_PreExistingHeapCount;
    if (count < 0) {
        count = 0;
    }
    if (count > static_cast<LONG>(kMaxPreExistingHeaps)) {
        count = kMaxPreExistingHeaps;
    }
    for (LONG i = 0; i < count; ++i) {
        if (g_PreExistingHeaps[i] == heap) {
            return TRUE;
        }
    }
    return FALSE;
}

void SnapshotPreExistingHeaps() noexcept
{
    DWORD count = GetProcessHeaps(kMaxPreExistingHeaps, g_PreExistingHeaps);
    if (count > kMaxPreExistingHeaps) {
        count = kMaxPreExistingHeaps;
    }
    InterlockedExchange(&g_PreExistingHeapCount, static_cast<LONG>(count));
}

void RecordOtherHeap(HANDLE heap, char op, SIZE_T size, DWORD flags, PVOID ret) noexcept
{
    if (heap == nullptr || IsRecordedHeap(heap)) {
        return;
    }

    LONG count = g_OtherHeapRecordCount;
    if (count < 0) {
        count = 0;
    }
    if (count > static_cast<LONG>(kMaxOtherHeapRecords)) {
        count = kMaxOtherHeapRecords;
    }
    for (LONG i = 0; i < count; ++i) {
        if (g_OtherHeapRecords[i].Heap == heap) {
            return;
        }
    }

    LONG index = InterlockedIncrement(&g_OtherHeapRecordCount) - 1;
    if (index >= 0 && index < static_cast<LONG>(kMaxOtherHeapRecords)) {
        g_OtherHeapRecords[index].Heap = heap;
        g_OtherHeapRecords[index].IsProcessHeap = (heap == GetProcessHeap());
        g_OtherHeapRecords[index].ExistedBeforeTrace = IsPreExistingHeap(heap);
        g_OtherHeapRecords[index].FirstThreadId = GetCurrentThreadId();
        g_OtherHeapRecords[index].FirstReturnAddress = ret;
        g_OtherHeapRecords[index].FirstSize = size;
        g_OtherHeapRecords[index].FirstFlags = flags;
        g_OtherHeapRecords[index].FirstOp = op;
    }
}

void RecordHeap(HANDLE heap, DWORD flags, SIZE_T initialSize, SIZE_T maximumSize) noexcept
{
    if (heap == nullptr || InterlockedCompareExchange(&g_TraceEnabled, 0, 0) == 0) {
        return;
    }
    if (IsRecordedHeap(heap)) {
        return;
    }
    LONG index = InterlockedIncrement(&g_HeapRecordCount) - 1;
    if (index >= 0 && index < static_cast<LONG>(kMaxHeapRecords)) {
        g_HeapRecords[index].Heap = heap;
        g_HeapRecords[index].CreateFlags = flags;
        g_HeapRecords[index].InitialSize = initialSize;
        g_HeapRecords[index].MaximumSize = maximumSize;
        g_HeapRecords[index].ThreadId = GetCurrentThreadId();
    }
}

void RecordAllocEvent(char op, HANDLE heap, PVOID ptr, PVOID oldPtr, SIZE_T size, DWORD flags, PVOID ret) noexcept
{
    if (InterlockedCompareExchange(&g_TraceEnabled, 0, 0) == 0) {
        return;
    }
    LONG index = InterlockedIncrement(&g_AllocEventCount) - 1;
    if (index >= 0 && index < static_cast<LONG>(kMaxAllocEvents)) {
        g_AllocEvents[index].Op = op;
        g_AllocEvents[index].Heap = heap;
        g_AllocEvents[index].Ptr = ptr;
        g_AllocEvents[index].OldPtr = oldPtr;
        g_AllocEvents[index].Size = size;
        g_AllocEvents[index].Flags = flags;
        g_AllocEvents[index].ThreadId = GetCurrentThreadId();
        g_AllocEvents[index].ReturnAddress = ret;
        g_AllocEvents[index].IsPrivateHeap = IsRecordedHeap(heap);
        if (!g_AllocEvents[index].IsPrivateHeap) {
            RecordOtherHeap(heap, op, size, flags, ret);
        }
    } else if (!IsRecordedHeap(heap)) {
        RecordOtherHeap(heap, op, size, flags, ret);
    }
}

HANDLE WINAPI HookHeapCreate(DWORD options, SIZE_T initialSize, SIZE_T maximumSize)
{
    HANDLE heap = RealHeapCreate(options, initialSize, maximumSize);
    if (EnterHook()) {
        RecordHeap(heap, options, initialSize, maximumSize);
        LeaveHook();
    }
    return heap;
}

BOOL WINAPI HookHeapDestroy(HANDLE heap)
{
    if (EnterHook()) {
        RecordAllocEvent('D', heap, nullptr, nullptr, 0, 0, _ReturnAddress());
        LeaveHook();
    }
    return RealHeapDestroy(heap);
}

LPVOID WINAPI HookHeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes)
{
    LPVOID ptr = RealHeapAlloc(heap, flags, bytes);
    if (EnterHook()) {
        RecordAllocEvent('A', heap, ptr, nullptr, bytes, flags, _ReturnAddress());
        LeaveHook();
    }
    return ptr;
}

LPVOID WINAPI HookHeapReAlloc(HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes)
{
    LPVOID ptr = RealHeapReAlloc(heap, flags, mem, bytes);
    if (EnterHook()) {
        RecordAllocEvent('R', heap, ptr, mem, bytes, flags, _ReturnAddress());
        LeaveHook();
    }
    return ptr;
}

BOOL WINAPI HookHeapFree(HANDLE heap, DWORD flags, LPVOID mem)
{
    return RealHeapFree(heap, flags, mem);
}

PVOID NTAPI HookRtlCreateHeap(ULONG flags, PVOID heapBase, SIZE_T reserveSize, SIZE_T commitSize,
                              PVOID lock, PVOID parameters)
{
    PVOID heap = RealRtlCreateHeap(flags, heapBase, reserveSize, commitSize, lock, parameters);
    if (EnterHook()) {
        RecordHeap(static_cast<HANDLE>(heap), flags, commitSize, reserveSize);
        LeaveHook();
    }
    return heap;
}

PVOID NTAPI HookRtlDestroyHeap(PVOID heap)
{
    if (EnterHook()) {
        RecordAllocEvent('d', static_cast<HANDLE>(heap), nullptr, nullptr, 0, 0, _ReturnAddress());
        LeaveHook();
    }
    return RealRtlDestroyHeap(heap);
}

PVOID NTAPI HookRtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size)
{
    PVOID ptr = RealRtlAllocateHeap(heap, flags, size);
    if (EnterHook()) {
        RecordAllocEvent('a', static_cast<HANDLE>(heap), ptr, nullptr, size, flags, _ReturnAddress());
        LeaveHook();
    }
    return ptr;
}

PVOID NTAPI HookRtlReAllocateHeap(PVOID heap, ULONG flags, PVOID mem, SIZE_T size)
{
    PVOID ptr = RealRtlReAllocateHeap(heap, flags, mem, size);
    if (EnterHook()) {
        RecordAllocEvent('r', static_cast<HANDLE>(heap), ptr, mem, size, flags, _ReturnAddress());
        LeaveHook();
    }
    return ptr;
}

BOOLEAN NTAPI HookRtlFreeHeap(PVOID heap, ULONG flags, PVOID mem)
{
    return RealRtlFreeHeap(heap, flags, mem);
}

LPVOID WINAPI HookVirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect)
{
    LPVOID ptr = RealVirtualAlloc(address, size, allocationType, protect);
    if (InterlockedCompareExchange(&g_TraceEnabled, 0, 0) != 0) {
        InterlockedIncrement(&g_VirtualAllocCount);
    }
    return ptr;
}

BOOL WINAPI HookVirtualFree(LPVOID address, SIZE_T size, DWORD freeType)
{
    if (InterlockedCompareExchange(&g_TraceEnabled, 0, 0) != 0) {
        InterlockedIncrement(&g_VirtualFreeCount);
    }
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

bool ResolveTargets()
{
    RealHeapCreate = reinterpret_cast<HeapCreateFn>(ResolveProc(L"kernelbase.dll", "HeapCreate"));
    RealHeapDestroy = reinterpret_cast<HeapDestroyFn>(ResolveProc(L"kernelbase.dll", "HeapDestroy"));
    RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernelbase.dll", "HeapAlloc"));
    RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernelbase.dll", "HeapReAlloc"));
    RealHeapFree = reinterpret_cast<HeapFreeFn>(ResolveProc(L"kernelbase.dll", "HeapFree"));
    RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernelbase.dll", "VirtualAlloc"));
    RealVirtualFree = reinterpret_cast<VirtualFreeFn>(ResolveProc(L"kernelbase.dll", "VirtualFree"));

    if (RealHeapCreate == nullptr) RealHeapCreate = reinterpret_cast<HeapCreateFn>(ResolveProc(L"kernel32.dll", "HeapCreate"));
    if (RealHeapDestroy == nullptr) RealHeapDestroy = reinterpret_cast<HeapDestroyFn>(ResolveProc(L"kernel32.dll", "HeapDestroy"));
    if (RealHeapAlloc == nullptr) RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernel32.dll", "HeapAlloc"));
    if (RealHeapReAlloc == nullptr) RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernel32.dll", "HeapReAlloc"));
    if (RealHeapFree == nullptr) RealHeapFree = reinterpret_cast<HeapFreeFn>(ResolveProc(L"kernel32.dll", "HeapFree"));
    if (RealVirtualAlloc == nullptr) RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernel32.dll", "VirtualAlloc"));
    if (RealVirtualFree == nullptr) RealVirtualFree = reinterpret_cast<VirtualFreeFn>(ResolveProc(L"kernel32.dll", "VirtualFree"));

    RealRtlCreateHeap = reinterpret_cast<RtlCreateHeapFn>(ResolveProc(L"ntdll.dll", "RtlCreateHeap"));
    RealRtlDestroyHeap = reinterpret_cast<RtlDestroyHeapFn>(ResolveProc(L"ntdll.dll", "RtlDestroyHeap"));
    RealRtlAllocateHeap = reinterpret_cast<RtlAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlAllocateHeap"));
    RealRtlReAllocateHeap = reinterpret_cast<RtlReAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlReAllocateHeap"));
    RealRtlFreeHeap = reinterpret_cast<RtlFreeHeapFn>(ResolveProc(L"ntdll.dll", "RtlFreeHeap"));

    HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
    if (dbghelp != nullptr) {
        RealMiniDumpWriteDump = reinterpret_cast<MiniDumpWriteDumpFn>(GetProcAddress(dbghelp, "MiniDumpWriteDump"));
    }

    return RealHeapCreate != nullptr && RealHeapDestroy != nullptr &&
           RealHeapAlloc != nullptr && RealHeapReAlloc != nullptr && RealHeapFree != nullptr &&
           RealRtlCreateHeap != nullptr && RealRtlDestroyHeap != nullptr &&
           RealRtlAllocateHeap != nullptr && RealRtlReAllocateHeap != nullptr && RealRtlFreeHeap != nullptr &&
           RealVirtualAlloc != nullptr && RealVirtualFree != nullptr && RealMiniDumpWriteDump != nullptr;
}

LONG AttachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapCreate), HookHeapCreate);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapDestroy), HookHeapDestroy);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapFree), HookHeapFree);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlCreateHeap), HookRtlCreateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlDestroyHeap), HookRtlDestroyHeap);
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
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapDestroy), HookHeapDestroy);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapFree), HookHeapFree);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlCreateHeap), HookRtlCreateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlDestroyHeap), HookRtlDestroyHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlAllocateHeap), HookRtlAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlReAllocateHeap), HookRtlReAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlFreeHeap), HookRtlFreeHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealVirtualAlloc), HookVirtualAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealVirtualFree), HookVirtualFree);
    return DetourTransactionCommit();
}

void ResetTrace()
{
    ZeroMemory(g_HeapRecords, sizeof(g_HeapRecords));
    ZeroMemory(g_OtherHeapRecords, sizeof(g_OtherHeapRecords));
    ZeroMemory(g_AllocEvents, sizeof(g_AllocEvents));
    InterlockedExchange(&g_HeapRecordCount, 0);
    InterlockedExchange(&g_OtherHeapRecordCount, 0);
    InterlockedExchange(&g_AllocEventCount, 0);
    InterlockedExchange(&g_VirtualAllocCount, 0);
    InterlockedExchange(&g_VirtualFreeCount, 0);
}

BOOL RunMiniDumpWriteDumpOnce(const wchar_t* dumpPath, MINIDUMP_TYPE dumpType, DWORD* dumpError) noexcept
{
    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (dumpError != nullptr) {
            *dumpError = GetLastError();
        }
        return FALSE;
    }

    BOOL ok = RealMiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        nullptr,
        nullptr,
        nullptr);
    if (dumpError != nullptr) {
        *dumpError = ok ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(hFile);
    return ok;
}

void PrintSummary()
{

    LONG heapRecords = g_HeapRecordCount;
    LONG allocEvents = g_AllocEventCount;
    if (heapRecords > static_cast<LONG>(kMaxHeapRecords)) heapRecords = kMaxHeapRecords;
    if (allocEvents > static_cast<LONG>(kMaxAllocEvents)) allocEvents = kMaxAllocEvents;

    LONG otherHeapRecords = g_OtherHeapRecordCount;
    if (otherHeapRecords > static_cast<LONG>(kMaxOtherHeapRecords)) otherHeapRecords = kMaxOtherHeapRecords;

    LONG privateHeapEvents = 0;
    LONG otherHeapEvents = 0;
    LONG allocCount = 0;
    LONG reallocCount = 0;
    LONG destroyCount = 0;

    for (LONG i = 0; i < allocEvents; ++i) {
        if (IsRecordedHeap(g_AllocEvents[i].Heap)) {
            ++privateHeapEvents;
        } else {
            ++otherHeapEvents;
        }
        switch (g_AllocEvents[i].Op) {
        case 'A':
        case 'a': ++allocCount; break;
        case 'R':
        case 'r': ++reallocCount; break;
        case 'D':
        case 'd': ++destroyCount; break;
        default: break;
        }
    }

    wprintf(L"\n=== MiniDumpWriteDump allocation trace ===\n");
    wprintf(L"created heaps recorded: %ld\n", heapRecords);
    for (LONG i = 0; i < heapRecords; ++i) {
        wprintf(L"  heap[%ld]=0x%p flags=0x%lx initial=0x%Ix max=0x%Ix tid=%lu\n",
                i,
                g_HeapRecords[i].Heap,
                g_HeapRecords[i].CreateFlags,
                g_HeapRecords[i].InitialSize,
                g_HeapRecords[i].MaximumSize,
                g_HeapRecords[i].ThreadId);
    }

    wprintf(L"heap allocation/reallocation/destroy events recorded: %ld (buffer cap %lu)\n", g_AllocEventCount, kMaxAllocEvents);
    wprintf(L"  HeapAlloc/RtlAllocateHeap=%ld HeapReAlloc/RtlReAllocateHeap=%ld HeapDestroy/RtlDestroyHeap=%ld\n",
            allocCount, reallocCount, destroyCount);
    wprintf(L"  events on MiniDumpWriteDump-created heaps=%ld\n", privateHeapEvents);
    wprintf(L"  events on other heaps=%ld\n", otherHeapEvents);
    wprintf(L"  VirtualAlloc calls=%ld VirtualFree calls=%ld\n", g_VirtualAllocCount, g_VirtualFreeCount);

    LONG printedOtherHeaps = 0;
    for (LONG i = 0; i < otherHeapRecords; ++i) {
        if (!IsRecordedHeap(g_OtherHeapRecords[i].Heap)) {
            ++printedOtherHeaps;
        }
    }
    wprintf(L"\nother heaps observed: %ld (raw %ld, cap %lu)\n", printedOtherHeaps, g_OtherHeapRecordCount, kMaxOtherHeapRecords);
    for (LONG i = 0; i < otherHeapRecords; ++i) {
        if (IsRecordedHeap(g_OtherHeapRecords[i].Heap)) {
            continue;
        }
        ULONG compatibility = 0xffffffffUL;
        SIZE_T returned = 0;
        BOOL queryOk = HeapQueryInformation(
            g_OtherHeapRecords[i].Heap,
            HeapCompatibilityInformation,
            &compatibility,
            sizeof(compatibility),
            &returned);
        wprintf(L"  other[%ld]=0x%p processHeap=%d preExisting=%d compat=%ls(0x%lx) firstOp=%c firstSize=0x%Ix firstFlags=0x%lx firstRet=0x%p firstTid=%lu\n",
                i,
                g_OtherHeapRecords[i].Heap,
                g_OtherHeapRecords[i].IsProcessHeap,
                g_OtherHeapRecords[i].ExistedBeforeTrace,
                queryOk ? L"ok" : L"fail",
                compatibility,
                g_OtherHeapRecords[i].FirstOp,
                g_OtherHeapRecords[i].FirstSize,
                g_OtherHeapRecords[i].FirstFlags,
                g_OtherHeapRecords[i].FirstReturnAddress,
                g_OtherHeapRecords[i].FirstThreadId);
    }

    wprintf(L"\nfirst allocation/reallocation/destroy events:\n");

    LONG shown = allocEvents < 64 ? allocEvents : 64;
    for (LONG i = 0; i < shown; ++i) {
        const AllocEvent& e = g_AllocEvents[i];
        wprintf(L"  #%03ld %c heap=0x%p ptr=0x%p old=0x%p size=0x%Ix flags=0x%lx private=%d ret=0x%p tid=%lu\n",
                i, e.Op, e.Heap, e.Ptr, e.OldPtr, e.Size, e.Flags, IsRecordedHeap(e.Heap),
                e.ReturnAddress, e.ThreadId);
    }
}

} // namespace

int wmain(int argc, wchar_t** argv)
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

    const wchar_t* dumpPath = argc > 1 ? argv[1] : L"minidumpwritedump_alloc_trace.dmp";

    MINIDUMP_TYPE dumpType = MiniDumpNormal;


    DWORD warmupError = ERROR_SUCCESS;
    BOOL warmupOk = RunMiniDumpWriteDumpOnce(L"minidumpwritedump_warmup.dmp", MiniDumpNormal, &warmupError);
    DeleteFileW(L"minidumpwritedump_warmup.dmp");
    wprintf(L"warm-up MiniDumpWriteDump returned %d, LastError=%lu\n", warmupOk, warmupError);

    SnapshotPreExistingHeaps();
    ResetTrace();
    InterlockedExchange(&g_TraceEnabled, 1);

    DWORD dumpError = ERROR_SUCCESS;
    BOOL ok = RunMiniDumpWriteDumpOnce(dumpPath, dumpType, &dumpError);
    InterlockedExchange(&g_TraceEnabled, 0);
    DetachHooks();

    wprintf(L"traced MiniDumpWriteDump returned %d, LastError=%lu, output=%ls\n", ok, dumpError, dumpPath);

    PrintSummary();
    return ok ? 0 : 1;
}
