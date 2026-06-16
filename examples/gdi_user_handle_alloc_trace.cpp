// gdi_user_handle_alloc_trace.cpp
//
// A small Win32 demo with two purposes:
//
//   1. Demonstrate how the GDI / USER object counts are *acquired* for the current process via
//      user32!GetGuiResources (GR_GDIOBJECTS / GR_USEROBJECTS and their *_PEAK variants). This is
//      exactly the call the minidump library uses to populate the GDI/USER line of its comment
//      stream. The demo creates a batch of real GDI objects (DC, pen, brush, font, bitmap, region)
//      and USER objects (a hidden window, a couple of menus, an icon) so the counts visibly move.
//
//   2. Trace whether GetGuiResources *itself* allocates from the heap. The crash-path writer must
//      not perform heap allocation, so before relying on GetGuiResources we want empirical proof of
//      how it behaves. We use Microsoft Detours to hook the user-mode allocators
//      (HeapAlloc / HeapReAlloc / RtlAllocateHeap / RtlReAllocateHeap / VirtualAlloc), then count
//      only the allocations made *on the calling thread while the single GetGuiResources call is in
//      flight*. The per-thread + windowed filtering keeps unrelated background-thread noise out of
//      the measurement.
//
// Build: enabled together with the Detours demos (MINIDUMP_INPROC_BUILD_DETOURS_DEMO=ON).

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
#include <stdio.h>
#include <strsafe.h>

#include "../third_party/Detours/src/detours.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wmicrosoft-cast"
#endif

namespace {

// ---------------------------------------------------------------------------------------------
// Real allocator entry points and their Detours trampolines.
// ---------------------------------------------------------------------------------------------
using HeapAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, SIZE_T);
using HeapReAllocFn = LPVOID (WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
using RtlAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlReAllocateHeapFn = PVOID (NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);
using VirtualAllocFn = LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using GetGuiResourcesFn = DWORD (WINAPI*)(HANDLE, DWORD);

HeapAllocFn RealHeapAlloc = nullptr;
HeapReAllocFn RealHeapReAlloc = nullptr;
RtlAllocateHeapFn RealRtlAllocateHeap = nullptr;
RtlReAllocateHeapFn RealRtlReAllocateHeap = nullptr;
VirtualAllocFn RealVirtualAlloc = nullptr;

// ---------------------------------------------------------------------------------------------
// Trace window state. We only count allocations when the trace is "armed" AND they come from the
// thread that armed it, so the measurement reflects exactly the GetGuiResources call we wrapped.
// ---------------------------------------------------------------------------------------------
volatile LONG g_TraceActive = 0;
volatile LONG g_TraceThreadId = 0;

volatile LONG g_HeapAllocCalls = 0;
volatile LONG g_HeapReAllocCalls = 0;
volatile LONG g_RtlAllocateHeapCalls = 0;
volatile LONG g_RtlReAllocateHeapCalls = 0;
volatile LONG g_VirtualAllocCalls = 0;

bool TracingThisThread() noexcept
{
    return InterlockedCompareExchange(&g_TraceActive, 0, 0) != 0 &&
           InterlockedCompareExchange(&g_TraceThreadId, 0, 0) ==
               static_cast<LONG>(GetCurrentThreadId());
}

LPVOID WINAPI HookHeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes)
{
    if (TracingThisThread()) {
        InterlockedIncrement(&g_HeapAllocCalls);
    }
    return RealHeapAlloc(heap, flags, bytes);
}

LPVOID WINAPI HookHeapReAlloc(HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes)
{
    if (TracingThisThread()) {
        InterlockedIncrement(&g_HeapReAllocCalls);
    }
    return RealHeapReAlloc(heap, flags, mem, bytes);
}

PVOID NTAPI HookRtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size)
{
    if (TracingThisThread()) {
        InterlockedIncrement(&g_RtlAllocateHeapCalls);
    }
    return RealRtlAllocateHeap(heap, flags, size);
}

PVOID NTAPI HookRtlReAllocateHeap(PVOID heap, ULONG flags, PVOID mem, SIZE_T size)
{
    if (TracingThisThread()) {
        InterlockedIncrement(&g_RtlReAllocateHeapCalls);
    }
    return RealRtlReAllocateHeap(heap, flags, mem, size);
}

LPVOID WINAPI HookVirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect)
{
    if (TracingThisThread()) {
        InterlockedIncrement(&g_VirtualAllocCalls);
    }
    return RealVirtualAlloc(address, size, allocationType, protect);
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
    RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernelbase.dll", "HeapAlloc"));
    RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernelbase.dll", "HeapReAlloc"));
    RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernelbase.dll", "VirtualAlloc"));

    if (RealHeapAlloc == nullptr) RealHeapAlloc = reinterpret_cast<HeapAllocFn>(ResolveProc(L"kernel32.dll", "HeapAlloc"));
    if (RealHeapReAlloc == nullptr) RealHeapReAlloc = reinterpret_cast<HeapReAllocFn>(ResolveProc(L"kernel32.dll", "HeapReAlloc"));
    if (RealVirtualAlloc == nullptr) RealVirtualAlloc = reinterpret_cast<VirtualAllocFn>(ResolveProc(L"kernel32.dll", "VirtualAlloc"));

    RealRtlAllocateHeap = reinterpret_cast<RtlAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlAllocateHeap"));
    RealRtlReAllocateHeap = reinterpret_cast<RtlReAllocateHeapFn>(ResolveProc(L"ntdll.dll", "RtlReAllocateHeap"));

    return RealHeapAlloc != nullptr && RealHeapReAlloc != nullptr &&
           RealRtlAllocateHeap != nullptr && RealRtlReAllocateHeap != nullptr &&
           RealVirtualAlloc != nullptr;
}

LONG AttachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlAllocateHeap), HookRtlAllocateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealRtlReAllocateHeap), HookRtlReAllocateHeap);
    DetourAttach(reinterpret_cast<PVOID*>(&RealVirtualAlloc), HookVirtualAlloc);
    return DetourTransactionCommit();
}

LONG DetachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapAlloc), HookHeapAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealHeapReAlloc), HookHeapReAlloc);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlAllocateHeap), HookRtlAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealRtlReAllocateHeap), HookRtlReAllocateHeap);
    DetourDetach(reinterpret_cast<PVOID*>(&RealVirtualAlloc), HookVirtualAlloc);
    return DetourTransactionCommit();
}

void ResetCounters() noexcept
{
    InterlockedExchange(&g_HeapAllocCalls, 0);
    InterlockedExchange(&g_HeapReAllocCalls, 0);
    InterlockedExchange(&g_RtlAllocateHeapCalls, 0);
    InterlockedExchange(&g_RtlReAllocateHeapCalls, 0);
    InterlockedExchange(&g_VirtualAllocCalls, 0);
}

LONG TotalAllocCalls() noexcept
{
    return g_HeapAllocCalls + g_HeapReAllocCalls + g_RtlAllocateHeapCalls +
           g_RtlReAllocateHeapCalls + g_VirtualAllocCalls;
}

// Calls GetGuiResources once with the allocation trace armed around exactly that call, prints the
// returned count and the per-thread allocation deltas observed during the call.
DWORD MeasureGuiResources(const wchar_t* label, DWORD flags)
{
    ResetCounters();
    InterlockedExchange(&g_TraceThreadId, static_cast<LONG>(GetCurrentThreadId()));
    InterlockedExchange(&g_TraceActive, 1);

    // Called directly (not through a hook): GetGuiResources is the API under test; the hooks above
    // observe any allocator calls it makes internally on this thread.
    DWORD count = GetGuiResources(GetCurrentProcess(), flags);

    InterlockedExchange(&g_TraceActive, 0);

    const LONG total = TotalAllocCalls();
    wprintf(L"  %-22ls = %-6lu | allocs during call: total=%ld "
            L"(HeapAlloc=%ld HeapReAlloc=%ld RtlAllocateHeap=%ld RtlReAllocateHeap=%ld VirtualAlloc=%ld)%ls\n",
            label,
            count,
            total,
            g_HeapAllocCalls,
            g_HeapReAllocCalls,
            g_RtlAllocateHeapCalls,
            g_RtlReAllocateHeapCalls,
            g_VirtualAllocCalls,
            total == 0 ? L"  <- no heap allocation" : L"");
    return count;
}

void DumpAllGuiCounts(const wchar_t* phase)
{
    wprintf(L"[%ls]\n", phase);
    MeasureGuiResources(L"GR_GDIOBJECTS", GR_GDIOBJECTS);
    MeasureGuiResources(L"GR_GDIOBJECTS_PEAK", GR_GDIOBJECTS_PEAK);
    MeasureGuiResources(L"GR_USEROBJECTS", GR_USEROBJECTS);
    MeasureGuiResources(L"GR_USEROBJECTS_PEAK", GR_USEROBJECTS_PEAK);
}

// ---------------------------------------------------------------------------------------------
// A bundle of real GDI + USER objects, created to push GetGuiResources counts up and torn down at
// the end. These are genuine per-process handles that GetGuiResources accounts for.
// ---------------------------------------------------------------------------------------------
struct GuiObjectBundle {
    // GDI
    HDC memDC = nullptr;
    HPEN pen = nullptr;
    HBRUSH brush = nullptr;
    HFONT font = nullptr;
    HBITMAP bitmap = nullptr;
    HRGN region = nullptr;
    // USER
    ATOM classAtom = 0;
    HWND window = nullptr;
    HMENU menu = nullptr;
    HMENU popup = nullptr;
    HICON icon = nullptr;
};

const wchar_t* const kWindowClassName = L"MiniDumpGuiTraceHiddenWindow";

LRESULT CALLBACK DemoWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void CreateGuiObjects(GuiObjectBundle& b)
{
    HINSTANCE instance = GetModuleHandleW(nullptr);

    // --- GDI objects ---
    b.memDC = CreateCompatibleDC(nullptr);
    b.pen = CreatePen(PS_SOLID, 1, RGB(10, 20, 30));
    b.brush = CreateSolidBrush(RGB(40, 50, 60));
    b.font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                         DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    b.bitmap = CreateBitmap(8, 8, 1, 32, nullptr);
    b.region = CreateRectRgn(0, 0, 8, 8);

    // --- USER objects ---
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DemoWndProc;
    wc.hInstance = instance;
    wc.lpszClassName = kWindowClassName;
    b.classAtom = RegisterClassExW(&wc);
    if (b.classAtom != 0) {
        // A real top-level window (kept hidden: WS_OVERLAPPEDWINDOW without WS_VISIBLE).
        b.window = CreateWindowExW(0, kWindowClassName, L"hidden", WS_OVERLAPPEDWINDOW,
                                   CW_USEDEFAULT, CW_USEDEFAULT, 200, 100,
                                   nullptr, nullptr, instance, nullptr);
    }
    b.menu = CreateMenu();
    b.popup = CreatePopupMenu();
    if (b.popup != nullptr) {
        AppendMenuW(b.popup, MF_STRING, 1, L"Item");
    }
    // CreateIcon dereferences the AND/XOR mask buffers, so they must be real arrays (passing NULL
    // crashes inside user32). 16x16, 1 plane, 1 bpp => 32 bytes per mask.
    static const BYTE andMask[32] = {};   // all-zero AND mask
    static const BYTE xorMask[32] = {};   // all-zero XOR mask
    b.icon = CreateIcon(instance, 16, 16, 1, 1, andMask, xorMask);
}

void DestroyGuiObjects(GuiObjectBundle& b)
{
    // GDI
    if (b.memDC) DeleteDC(b.memDC);
    if (b.pen) DeleteObject(b.pen);
    if (b.brush) DeleteObject(b.brush);
    if (b.font) DeleteObject(b.font);
    if (b.bitmap) DeleteObject(b.bitmap);
    if (b.region) DeleteObject(b.region);
    // USER
    if (b.window) DestroyWindow(b.window);
    if (b.menu) DestroyMenu(b.menu);
    if (b.popup) DestroyMenu(b.popup);
    if (b.icon) DestroyIcon(b.icon);
    if (b.classAtom != 0) UnregisterClassW(kWindowClassName, GetModuleHandleW(nullptr));

    b = GuiObjectBundle{};
}

} // namespace

int wmain()
{
    // Unbuffered stdout so each line is visible immediately even if a later call faults; with full
    // buffering a crash would discard everything emitted so far.
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (!ResolveTargets()) {
        fwprintf(stderr, L"ResolveTargets failed. LastError=%lu\n", GetLastError());
        return 2;
    }

    LONG attach = AttachHooks();
    if (attach != NO_ERROR) {
        fwprintf(stderr, L"AttachHooks failed: %ld\n", attach);
        return 3;
    }

    wprintf(L"GDI / USER handle acquisition + heap-allocation trace\n");
    wprintf(L"=====================================================\n");
    wprintf(L"GetGuiResources is called once per metric with per-thread heap/Virtual allocation\n");
    wprintf(L"hooks armed around exactly that call. 'total=0' means the call did not allocate.\n\n");

    // Baseline: counts before we create anything.
    DumpAllGuiCounts(L"baseline (before creating objects)");

    GuiObjectBundle bundle;
    CreateGuiObjects(bundle);
    wprintf(L"\nCreated GDI objects: DC=%d pen=%d brush=%d font=%d bitmap=%d region=%d\n",
            bundle.memDC != nullptr, bundle.pen != nullptr, bundle.brush != nullptr,
            bundle.font != nullptr, bundle.bitmap != nullptr, bundle.region != nullptr);
    wprintf(L"Created USER objects: class=%d window=%d menu=%d popup=%d icon=%d\n\n",
            bundle.classAtom != 0, bundle.window != nullptr, bundle.menu != nullptr,
            bundle.popup != nullptr, bundle.icon != nullptr);

    // After creating objects: counts should have risen (GDI noticeably; USER by the window/menus).
    DumpAllGuiCounts(L"after creating objects");

    DestroyGuiObjects(bundle);
    wprintf(L"\nDestroyed all created GDI/USER objects.\n\n");

    // After cleanup: live counts drop back; the PEAK metrics retain the high-water mark.
    DumpAllGuiCounts(L"after destroying objects");

    InterlockedExchange(&g_TraceActive, 0);
    LONG detach = DetachHooks();
    if (detach != NO_ERROR) {
        fwprintf(stderr, L"DetachHooks failed: %ld\n", detach);
        return 4;
    }

    wprintf(L"\nConclusion: if every 'total' above is 0, GetGuiResources performs no user-mode heap\n"
            L"allocation, which is why it is safe for the crash-path comment stream.\n");
    return 0;
}
