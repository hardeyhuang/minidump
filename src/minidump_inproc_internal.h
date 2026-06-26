#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>
#include <intrin.h>
#include <cstddef> // offsetof

#include "../include/minidump_inproc.h"


#pragma intrinsic(memset)
#if defined(_M_X64)
#pragma intrinsic(__readgsqword)
#elif defined(_M_IX86)
#pragma intrinsic(__readfsdword)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif
#ifndef STATUS_STACK_OVERFLOW
#define STATUS_STACK_OVERFLOW ((DWORD)0xC00000FD)
#endif

namespace minidump_inproc {
namespace internal {

constexpr ULONG32 kMaxModules = 4096;
constexpr ULONG32 kMaxThreads = 1024;
// Upper bound on writable image data-segment regions captured once for MiniDumpWithDataSegs. The
// selected-dump count/known-range/descriptor/byte passes all replay this single capture, so they can
// never disagree on count or size even if the live address space shifts. 8192 x 16 B = 128 KB
// (demand-zero .bss). Regions beyond this are dropped, degrading gracefully without inconsistency.
constexpr ULONG32 kMaxDataSegRanges = 8192;
// Process/thread-data memory ranges captured for MiniDumpWithProcessThreadData: the PEB, every
// thread's TEB, the RTL_USER_PROCESS_PARAMETERS block, the environment block, and the UNICODE_STRING
// buffers it references (image path / command line / current directory / window / desktop strings).
// One slot per TEB plus a fixed margin for the process-wide structures. Captured once into
// g_ProcThreadRanges so the count/known-range/descriptor/byte passes always agree.
constexpr ULONG32 kMaxProcThreadRanges = kMaxThreads + 16;
// Per-range capture sizes (bytes). Each is clamped down to the committed VirtualQuery region that
// contains it, so an over-estimate can never read past the real allocation. The PEB and TEB sizes
// comfortably cover the documented x64 structures; params/env use the sizes reported by the block
// itself, falling back to these defaults when those fields are unavailable.
constexpr ULONG64 kProcThreadPebBytes = 0x1000;
constexpr ULONG64 kProcThreadTebBytes = 0x2000;
constexpr ULONG64 kProcThreadParamsMinBytes = 0x460; // >= sizeof(RTL_USER_PROCESS_PARAMETERS) x64
constexpr ULONG64 kProcThreadEnvDefaultBytes = 0x2000;
constexpr ULONG64 kProcThreadEnvMaxBytes = 0x8000;
// Hard per-range ceiling so a corrupt MaximumLength/EnvironmentSize cannot blow up the dump.
constexpr ULONG64 kProcThreadRangeMaxBytes = 0x10000;
// Per-thread captured name (WCHARs, excluding NUL) for ThreadNamesStream. Stored inline in the
// immutable thread plan so the crash path needs no heap. Names longer than this are dropped (the
// kernel query reports buffer-too-small) rather than partially captured.
constexpr ULONG32 kMaxThreadNameChars = 64;
// NtQueryInformationThread class for the kernel-stored thread name (ThreadNameInformation).
constexpr ULONG kThreadNameInformation = 38;
// MINIDUMP_STREAM_TYPE::ThreadNamesStream. Hardcoded so the build does not depend on the SDK
// dbghelp.h being recent enough to define the enumerator.
constexpr ULONG32 kThreadNamesStreamType = 24;
// MINIDUMP_STREAM_TYPE::UnloadedModuleListStream. Hardcoded for the same reason as the thread-names
// type, so the build never depends on the SDK dbghelp.h version.
constexpr ULONG32 kUnloadedModuleListStreamType = 14;
// Upper bound on unloaded-module trace entries captured. The ntdll ring buffer holds at most ~64;
// this cap merely guards against an implausibly large/garbage ElementCount and bounds the directory.
constexpr ULONG32 kMaxUnloadedModules = 256;
// Maximum caller-provided user streams (MiniDumpWriteDump-style UserStreamParam) honored per dump.
// Bounds the static plan array and the stream-directory slack so no heap is needed.
constexpr ULONG32 kMaxUserStreams = 16;
constexpr ULONG32 kMaxModuleNameBytes = 32766;
constexpr ULONG32 kMaxCodeViewRecordBytes = 4096;
constexpr ULONG32 kCodeViewSignatureRsds = 0x53445352;
constexpr ULONG32 kIndirectMemoryRangeSize = 4096;
// Pointers reference object *starts*, and object bodies grow toward higher addresses, so a pointer
// landing near the top of its 4KB page usually points to a struct that straddles into the next page.
// Capturing only AlignDown(value) would then truncate the object AND drop the outgoing pointers in
// its tail half (breaking the BFS chain). When the pointer is within this many bytes of the page end
// we also collect the next higher page. Kept small (one extra page at most, since it is <= the page
// size) so the file-size budget is not doubled: only the ~window/4096 fraction of edge pointers pay.
constexpr ULONG32 kPointerStraddleWindow = 512;
static_assert(kPointerStraddleWindow <= kIndirectMemoryRangeSize,
              "straddle window must stay within one page so at most one neighbor page is added");
// Memory byte-streaming block size. WriteRegionBytes probes and writes a whole block in one
// WriteFile on the common all-readable path (instead of one WriteFile per 4 KB page), only dropping
// to page granularity to isolate and zero-fill faulting pages. This cuts syscalls by ~256x for large
// committed regions (the dominant cost of MiniDumpWithFullMemory) without changing the output bytes.
constexpr ULONG32 kMemoryWriteBlockBytes = 1024 * 1024;

// Deepest indirect-reference layer collected for MiniDumpWithIndirectlyReferencedMemory.
// Layer 1 = pages referenced from thread stacks; 2/3 = transitively referenced pages. Relevance
// decays with depth, so this is capped; the file-size budget is the real limiter underneath it.
constexpr ULONG32 kIndirectMaxScanLayers = 3;

// Max outgoing pointers followed per page during the depth-first chain reservation (see
// FollowIndirectChainDepthFirst). Under a tight file-size budget the breadth-first pass can spend the
// whole cap on a single dense seed's layer-2 fan-out (a page full of heap pointers), starving deep but
// narrow object chains -- exactly the data a debugger needs to walk a linked structure from a crash
// local. The depth-first pre-pass reserves a small, bounded slice (<= sum_{d<layers} fanout^d pages per
// seed) to follow such chains to full depth first. Kept small so the reservation stays bounded across
// many seeds while still capturing branchy-but-shallow graphs; deep narrow chains (fan-out 1) always fit.
constexpr ULONG32 kIndirectChainFanout = 4;

// Hard upper bound on the number of indirect pages a SINGLE layer-1 seed may reserve during the
// depth-first pre-pass. The fan-out cap alone bounds a well-behaved chain, but a pathological seed
// page (e.g. one densely packed with valid heap pointers that themselves chain into more dense pages)
// could otherwise let one seed's depth walk consume most of the cap before the remaining seeds -- and
// the narrow root->child->grand chain we actually care about -- are ever reached. This count-based cap
// is checked directly against g_IndirectMemoryRangeCount in the walk's guards, so it bounds a seed's
// reservation regardless of fan-out/recursion shape, guaranteeing every layer-1 seed gets its turn.
constexpr ULONG32 kIndirectPerSeedReserve = 16;


constexpr ULONG32 kMaxKnownMemoryRanges = kMaxThreads + 4096;
constexpr ULONG64 kWriteChunk = 0x40000000ULL;
constexpr ULONG64 kFileTimeUnixEpoch = 116444736000000000ULL;
constexpr ULONG64 kFileTimeTicksPerSecond = 10000000ULL;
constexpr ULONG kSystemProcessInformation = 5;
constexpr ULONG kSystemExtendedProcessInformation = 57;
// NtQueryInformationProcess class for VM_COUNTERS_EX (working set / private commit / pagefile usage).
constexpr ULONG kProcessVmCounters = 3;
// NtQueryInformationProcess class for the open-handle count (+ high watermark / peak).
constexpr ULONG kProcessHandleCount = 20;
// ANSI comment-stream buffer: system + process memory summary text shown by WinDbg on load.
constexpr ULONG32 kCommentBufferBytes = 1024;
// Fixed-width, space-padded digit field reserved inside CommentStreamA for the total dump elapsed
// time (milliseconds). Because the comment's DataSize is fixed at layout time but the elapsed time
// is only known after every other stream is written, BuildMemoryCommentText reserves this field and
// PatchCommentElapsed fills it in right before the comment is written last. 10 digits covers far more
// milliseconds than any real dump would ever take.
constexpr ULONG32 kCommentElapsedWidth = 10;
// Sentinel meaning "no elapsed field was reserved" (e.g. the buffer was too full to fit it).
constexpr ULONG32 kCommentElapsedUnset = 0xFFFFFFFFu;
// Wide CommentStreamW buffer capacity (in WCHARs, including the terminating NUL). Holds the
// user-supplied INI-style (section/key/value) comment text accumulated by SetMiniDumpInprocComment*.
constexpr ULONG32 kCommentBufferWChars = 4096;
// Maximum characters accepted for a SetMiniDumpInprocComment* section or key. A longer section/key
// fails the call (returns FALSE) rather than being silently truncated.
constexpr ULONG32 kCommentMaxSectionKeyChars = 64;
// Maximum source characters kept from a SetMiniDumpInprocComment* value; anything beyond this is
// truncated. After truncation the kept characters are escaped for INI safety: each newline becomes a
// single '↵' (U+21B5, a visible return arrow) and each ';' becomes the full-width '；' (U+FF1B). Both
// substitutions are 1:1, so the stored value is at most kCommentMaxValueChars WCHARs.
constexpr ULONG32 kCommentMaxValueChars = 256;
// Worst-case stored (escaped) value length in WCHARs. Every escape is 1:1, so this equals the source
// cap; kept as a named alias so buffer sizing reads clearly and survives future escape-rule changes.
constexpr ULONG32 kCommentMaxStoredValueWChars = kCommentMaxValueChars;
// Upper bound (in WCHARs) on the largest INI fragment CommentIniApply ever assembles before handing
// it to CommentSplice. The biggest case is the "section absent" append: '[' + section + ']' + '\n' +
// key + '=' + value + '\n'. Bounding the scratch buffer by this instead of kCommentBufferWChars keeps
// the function's stack frame small.
constexpr ULONG32 kCommentMaxFragmentWChars =
    1 + kCommentMaxSectionKeyChars + 1 + 1 + kCommentMaxSectionKeyChars + 1 + kCommentMaxStoredValueWChars + 1;

// One shared scratch buffer is reused across non-overlapping phases to keep the static
// footprint small: first as the NtQuerySystemInformation process snapshot (consumed entirely
// while building the thread plan), then as the full-memory range plan (full-memory dumps) or
// the indirect-memory range plan (selected-memory dumps). These uses never overlap in time.
constexpr ULONG kScratchBufferSize = 4 * 1024 * 1024;

// Production size policy: MaxFileSize is a hard cap. Values below 4 MB (including 0)
// are clamped to 4 MB.
constexpr ULONG64 kMinHardMaxFileSize = 4ULL * 1024 * 1024;
constexpr ULONG32 kMaxCapturedStackBytes = 1024 * 1024;
// STATUS_STACK_OVERFLOW stack capture policy:
//   - If the crashing thread's original stack is <= kStackOverflowFullStackThreshold (1MB), the
//     whole stack is recorded as-is.
//   - Otherwise a deterministic two-window capture is used: kStackOverflowLiveStackBytes (512 KB) of
//     the live unwind window from SP/RSP, plus kStackOverflowHighStackBytes (512 KB) near StackBase
//     so the recursion entry / call origin is still observable.
constexpr ULONG32 kStackOverflowFullStackThreshold = 1 * 1024 * 1024;
constexpr ULONG32 kStackOverflowLiveStackBytes = 512 * 1024;
constexpr ULONG32 kStackOverflowHighStackBytes = 512 * 1024;

enum INIT_STATUS : LONG {
    NOT_INITIALIZED = 0,
    INITIALIZING = 1,
    INITIALIZED = 2,
};

struct INPROC_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct INPROC_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    BYTE Reserved1[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct INPROC_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    INPROC_PEB_LDR_DATA* Ldr;
    // ProcessParameters follows Ldr in the real PEB (x64 offset 0x20, x86 offset 0x10). Declared
    // here so MiniDumpWithProcessThreadData can reach the RTL_USER_PROCESS_PARAMETERS block; module
    // enumeration only reads Ldr, so appending this field leaves the existing layout untouched.
    PVOID ProcessParameters;
};

struct INPROC_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    INPROC_UNICODE_STRING FullDllName;
    INPROC_UNICODE_STRING BaseDllName;
};

// CURDIR / RTL_DRIVE_LETTER_CURDIR mirror the ntdll layout so the field offsets in
// INPROC_RTL_USER_PROCESS_PARAMETERS line up with the OS structure on both x86 and x64 (pointer-sized
// fields shift the offsets automatically, exactly as the real struct does).
struct INPROC_CURDIR {
    INPROC_UNICODE_STRING DosPath;
    PVOID Handle;
};

struct INPROC_RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    INPROC_UNICODE_STRING DosPath; // ntdll uses ANSI STRING here; same on-disk size, contents unused
};

// Subset of RTL_USER_PROCESS_PARAMETERS captured for MiniDumpWithProcessThreadData. Only fields up to
// EnvironmentSize are declared; that covers everything the dump needs (image path, command line,
// current directory, window/desktop strings, the environment block and its size). The struct is read
// best-effort under SEH, and older OSes that lack the trailing fields are tolerated because the reader
// only copies the leading "core" up to CurrentDirectores and probes EnvironmentSize separately.
struct INPROC_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    INPROC_CURDIR CurrentDirectory;
    INPROC_UNICODE_STRING DllPath;
    INPROC_UNICODE_STRING ImagePathName;
    INPROC_UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    INPROC_UNICODE_STRING WindowTitle;
    INPROC_UNICODE_STRING DesktopInfo;
    INPROC_UNICODE_STRING ShellInfo;
    INPROC_UNICODE_STRING RuntimeData;
    INPROC_RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    SIZE_T EnvironmentSize;
    SIZE_T EnvironmentVersion;
};

#if defined(_M_X64)
static_assert(offsetof(INPROC_RTL_USER_PROCESS_PARAMETERS, ImagePathName) == 0x60,
              "RTL_USER_PROCESS_PARAMETERS.ImagePathName must sit at x64 offset 0x60");
static_assert(offsetof(INPROC_RTL_USER_PROCESS_PARAMETERS, Environment) == 0x80,
              "RTL_USER_PROCESS_PARAMETERS.Environment must sit at x64 offset 0x80");
static_assert(offsetof(INPROC_RTL_USER_PROCESS_PARAMETERS, EnvironmentSize) == 0x3f0,
              "RTL_USER_PROCESS_PARAMETERS.EnvironmentSize must sit at x64 offset 0x3f0");
#endif

struct INPROC_NT_TIB {
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    PVOID Self;
};

struct INPROC_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct INPROC_THREAD_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    INPROC_CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct INPROC_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    INPROC_CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION {
    INPROC_SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase;
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
};

struct INPROC_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    INPROC_UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    INPROC_SYSTEM_THREAD_INFORMATION Threads[1];
};

struct INPROC_THREAD_SNAPSHOT {
    INPROC_SYSTEM_PROCESS_INFORMATION* Process;
    BOOL Extended;
};

// Subset of VM_COUNTERS_EX returned by NtQueryInformationProcess(ProcessVmCounters). PrivateUsage
// is the process private commit charge; PagefileUsage is the classic commit-charge counter.
struct INPROC_VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
};

// Returned by NtQueryInformationProcess(ProcessHandleCount). The high watermark is the peak number
// of open handles the process has held, which is the key signal for handle-leak diagnosis.
struct INPROC_PROCESS_HANDLE_INFORMATION {
    ULONG HandleCount;
    ULONG HandleCountHighWatermark;
};

struct INPROC_MEMORY_RANGE {
    ULONG64 Start;
    ULONG32 Size;
    ULONG32 Layer;   // indirect-scan BFS depth (1 = referenced by a stack, 2/3 = transitive); 0 otherwise. Free: fills existing padding.
};

// One caller-provided user stream (snapshot of a MINIDUMP_USER_STREAM entry). Buffer points into the
// caller's memory and is read at write time; Rva is assigned during file layout.
struct INPROC_USER_STREAM {
    ULONG32 Type;
    ULONG32 BufferSize;
    const void* Buffer;
    ULONG32 Rva;
};

// A 64-bit memory range used to capture the full-memory plan once so the descriptor
// pass and the byte pass always agree on count and size (no live re-walk).
struct INPROC_MEMORY_RANGE64 {
    ULONG64 Start;
    ULONG64 Size;
};

// NtQueryInformationThread(ThreadNameInformation) result: a UNICODE_STRING whose Buffer points just
// past this header inside the caller-provided buffer. No heap is involved; the kernel fills our
// buffer directly, so it is safe to query on the crash path even for suspended threads.
struct INPROC_THREAD_NAME_INFORMATION {
    INPROC_UNICODE_STRING ThreadName;
};

// On-disk ThreadNamesStream layout. These mirror MINIDUMP_THREAD_NAME / MINIDUMP_THREAD_NAME_LIST
// with their natural 8-byte alignment (RvaOfThreadName is a 64-bit absolute file offset to a
// MINIDUMP_STRING). Defined locally so the build never depends on the SDK dbghelp.h version.
struct INPROC_MINIDUMP_THREAD_NAME {
    ULONG32 ThreadId;
    ULONG32 Padding;
    ULONG64 RvaOfThreadName;
};
struct INPROC_MINIDUMP_THREAD_NAME_LIST {
    ULONG32 NumberOfThreadNames;
    ULONG32 Padding;
};
static_assert(sizeof(INPROC_MINIDUMP_THREAD_NAME) == 16, "MINIDUMP_THREAD_NAME on-disk size must be 16");
static_assert(sizeof(INPROC_MINIDUMP_THREAD_NAME_LIST) == 8, "MINIDUMP_THREAD_NAME_LIST header on-disk size must be 8");

// In-process view of ntdll's RTL_UNLOAD_EVENT_TRACE entry. Only the leading documented fields are
// declared; RtlGetUnloadEventTraceEx reports the real per-entry stride (which may carry a trailing
// Version field plus padding), so iteration uses that reported stride and reads just these fields.
struct INPROC_RTL_UNLOAD_EVENT_TRACE {
    PVOID BaseAddress;
    SIZE_T SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
};

// On-disk UnloadedModuleListStream layout, mirroring MINIDUMP_UNLOADED_MODULE_LIST /
// MINIDUMP_UNLOADED_MODULE. Defined locally so the build never depends on the SDK dbghelp.h version.
// The stream DataSize is header + entries only; the trailing MINIDUMP_STRING name blobs referenced by
// ModuleNameRva are stored after the stream (like ModuleListStream) and not counted in DataSize.
struct INPROC_MINIDUMP_UNLOADED_MODULE {
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
};
struct INPROC_MINIDUMP_UNLOADED_MODULE_LIST {
    ULONG32 SizeOfHeader;
    ULONG32 SizeOfEntry;
    ULONG32 NumberOfEntries;
};
static_assert(sizeof(INPROC_MINIDUMP_UNLOADED_MODULE) == 24, "MINIDUMP_UNLOADED_MODULE on-disk size must be 24");
static_assert(sizeof(INPROC_MINIDUMP_UNLOADED_MODULE_LIST) == 12, "MINIDUMP_UNLOADED_MODULE_LIST header on-disk size must be 12");

enum INPROC_STREAM_WRITE_RESULT {
    InprocStreamOk,
    InprocStreamSkip,
    InprocStreamIoFailed,
};

inline INPROC_STREAM_WRITE_RESULT StreamResultFromBool(BOOL ok) noexcept {
    return ok ? InprocStreamOk : InprocStreamIoFailed;
}

// One immutable per-thread record captured under freeze. Every later stream (ThreadList,
// thread contexts, ThreadInfoList, stack MemoryList ranges, indirect-memory scan) reads
// this plan instead of re-querying the live system, which keeps all passes consistent.
struct INPROC_THREAD_PLAN_ENTRY {
    DWORD ThreadId;
    DWORD ThreadState;
    DWORD Priority;
    BOOL Suspended;       // TRUE if SuspendThread succeeded on Handle
    BOOL IsCurrent;       // TRUE for the dump-writing thread
    HANDLE Handle;        // pre-opened handle for non-current threads (already suspended); NULL for current/failed
    PVOID Teb;
    ULONG64 StartAddress;
    ULONG64 StackStart;               // captured primary stack window start
    ULONG64 OriginalStackStart;       // original TIB StackLimit before production clipping
    ULONG64 AuxStackStart;            // optional extra window, used for large stack-overflow high-address stack top
    ULONG32 StackSize;                // captured primary stack window size
    ULONG32 OriginalStackSize;        // original StackBase - StackLimit before production clipping
    ULONG32 AuxStackSize;
    BOOL IncludeStack;                // TRUE if the primary stack window fits the hard dump budget
    ULONG64 CreateTime;
    ULONG64 KernelTime;
    ULONG64 UserTime;
    ULONG32 WaitTime;
    USHORT NameLength;                // captured thread name length in WCHARs (excluding NUL); 0 if no name
    WCHAR Name[kMaxThreadNameChars];  // captured under freeze; written to ThreadNamesStream
};

struct RTL_OSVERSIONINFOEXW_INPROC {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR wProductType;
    UCHAR wReserved;
};

using RtlGetVersionFn = LONG (WINAPI*)(RTL_OSVERSIONINFOEXW_INPROC*);
using NtQueryInformationThreadFn = LONG (WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQuerySystemInformationFn = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn = LONG (WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
// user32!GetGuiResources, used for GDI/USER object counts. Resolved at load time ONLY if user32 is
// already mapped (we never LoadLibrary it), so the library never forces a user32 dependency.
using GetGuiResourcesFn = DWORD (WINAPI*)(HANDLE, DWORD);
// ntdll!RtlGetUnloadEventTraceEx: returns pointers to the process-wide unloaded-module ring buffer
// (per-entry size, entry count, array base). A pure read of an ntdll global -- no heap, no loader
// lock -- so it is safe to query on the crash path.
using RtlGetUnloadEventTraceExFn = void (WINAPI*)(PULONG*, PULONG*, PVOID*);

struct INPROC_API_TABLE {
    RtlGetVersionFn RtlGetVersion;
    NtQueryInformationThreadFn NtQueryInformationThread;
    NtQuerySystemInformationFn NtQuerySystemInformation;
    NtQueryInformationProcessFn NtQueryInformationProcess;
    GetGuiResourcesFn GetGuiResources;   // may be null when user32 is not loaded
    RtlGetUnloadEventTraceExFn RtlGetUnloadEventTraceEx;  // may be null on very old OS
};

// ---- Protected init-once globals (placed on their own page, VirtualProtect'd after init) ----
// Memory corruption is the most common reason a crash dump fails to write: a wild write that
// zeroes the API table or scrambles the page-size field silently produces a broken (or empty)
// dump instead of a useful one.  By placing every global that is written exactly once (during
// ResolveInprocApis) and never again into a dedicated 4KB page that is set PAGE_READONLY after
// init, any later corruption attempt triggers an immediate access violation instead of silent
// data loss -- the AV is then caught by the crash-handler SEH guard and the process still gets
// a dump (possibly of a different crash, but better than a corrupted one).
//
// The Crc field covers every preceding byte in the struct (CRC-32/ISO-HDLC, computed without a
// lookup table so it needs no static data).  It is written AFTER all real fields are populated
// and checked FIRST on the crash path, so any single- or multi-byte corruption anywhere in the
// struct is detected with P(undetected) ≈ 2⁻³².

#pragma warning(push)
// structure was padded due to alignment specifier (intentional: must occupy exactly one page)
#pragma warning(disable: 4324)
struct __declspec(align(4096)) PROTECTED_GLOBALS {
    INPROC_API_TABLE Apis;
    SYSTEM_INFO     NativeSystemInfo;
    volatile LONG   InitStatus = 0;   // INIT_STATUS enum, atomic
    HANDLE          CommentMutex;     // kernel mutex for g_CommentBufferW
    HANDLE          DumpMutex;        // kernel mutex for write serialization
    ULONG32         Crc = 0xffffffff; // CRC-32 of all preceding bytes (stored last, checked first)
};
#pragma warning(pop)

// CRC-32/ISO-HDLC (polynomial 0xEDB88320 reflected).  No lookup table — for ~150 bytes the
// per-byte inner loop runs ~1200 simple ops, negligible even on the crash path, and it keeps
// the library free of a 1 KB static table that itself could be a corruption target.
inline ULONG32 ComputeCrc32(const void* data, size_t len) noexcept {
    const BYTE* p = static_cast<const BYTE*>(data);
    ULONG32 crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= p[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc & 1u) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
    }
    return ~crc;
}

extern PROTECTED_GLOBALS g_Protected;

// Backward-compatible reference aliases: every existing user of g_Apis / g_NativeSystemInfo /
// g_ApisInitializeStatus continues to compile unchanged, but the storage now lives inside the
// protected page.  Taking the address of any alias yields the address inside g_Protected.
extern INPROC_API_TABLE& g_Apis;
extern SYSTEM_INFO& g_NativeSystemInfo;
extern volatile LONG& g_ApisInitializeStatus;

// Called at the end of ResolveInprocApis after all fields are populated.  Makes the page
// PAGE_READONLY so any wild write triggers an AV instead of silently corrupting the globals.
void ProtectInitGlobals() noexcept;

// Computes and stores the CRC over all fields preceding the Crc member.
inline void SetProtectedGlobalsCrc() noexcept {
    g_Protected.Crc = ComputeCrc32(&g_Protected, offsetof(PROTECTED_GLOBALS, Crc));
}

// Returns TRUE when the CRC-32 over the protected globals matches the stored value.
inline BOOL IsProtectedGlobalsIntact() noexcept {
    return ComputeCrc32(&g_Protected, offsetof(PROTECTED_GLOBALS, Crc)) == g_Protected.Crc;
}

extern CONTEXT g_ContextScratch;

// Single 4KB scratch page reused by ScanPageForIndirectMemory to copy and scan one page at a time.
// The indirect scan runs serially under the single-writer lock and is not recursive (BFS via an
// explicit queue), so one shared static page is sufficient and keeps it off the crash-path stack.
extern BYTE g_IndirectPageScratch[kIndirectMemoryRangeSize];

// Per-depth scratch pages for the recursive depth-first chain walk (FollowIndirectChainDepthFirst).
// One page per BFS layer so the recursion (bounded by kIndirectMaxScanLayers) never reuses a parent
// frame's buffer; kept static to stay off the (possibly exhausted) crash-path stack like the page
// scratch above. Indexed by (layer - 1).
extern BYTE g_IndirectChainScratch[kIndirectMaxScanLayers][kIndirectMemoryRangeSize];

// ANSI comment-stream text (system + process memory summary) and its byte length, built once per
// dump. Static so it persists from layout computation to the write pass; dumps are serialized.
extern char g_CommentBufferA[kCommentBufferBytes];
// Byte offset of the reserved elapsed-time digit field inside g_CommentBufferA, or kCommentElapsedUnset.
extern ULONG32 g_CommentElapsedOffset;
// User-supplied CommentStreamW text (INI-style sections/keys) and its current length in WCHARs
// (excluding the terminating NUL). Populated incrementally by SetMiniDumpInprocComment* and persists
// for the process lifetime so every dump includes it. Serialized by g_Protected.CommentMutex.
extern WCHAR g_CommentBufferW[kCommentBufferWChars];
extern ULONG32 g_CommentBufferWCrc;     // CRC-32 over the full g_CommentBufferW (recomputed after every mutation)
// Serialized by g_Protected.CommentMutex (kernel mutex, handle lives in PAGE_READONLY).

extern ULONG32 g_IndirectMemoryRangeCount;
extern INPROC_MEMORY_RANGE g_KnownMemoryRanges[kMaxKnownMemoryRanges];
extern ULONG32 g_KnownMemoryRangeCount;

// Shared scratch buffer (see kScratchBufferSize). Reinterpreted per phase via the helpers below.
// Use __declspec(align) rather than alignas here: clang/clang-cl reject `extern alignas(N) T arr[]`
// (it parses alignas as a type attribute in that position), while __declspec(align) is accepted by
// both MSVC and clang-cl on the declaration.
extern __declspec(align(16)) BYTE g_ScratchBuffer[kScratchBufferSize];

// Write serialization: g_Protected.DumpMutex (kernel mutex, stored in PAGE_READONLY).

// Immutable thread plan captured once under freeze; shared by all thread/stack streams.
extern INPROC_THREAD_PLAN_ENTRY g_ThreadPlan[kMaxThreads];
extern ULONG32 g_ThreadPlanCount;

// Number of committed full-memory ranges captured in the scratch buffer.
extern ULONG32 g_FullMemoryRangeCount;
extern ULONG64 g_FullMemoryBytes;

// Writable image data-segment ranges captured once per selected dump (MiniDumpWithDataSegs). Lives in
// its own fixed array (not the shared scratch, which the indirect scan occupies concurrently) so the
// count, known-range, descriptor and byte passes all replay the exact same list. g_DataSegBytes is
// the summed RegionSize of the captured ranges.
extern INPROC_MEMORY_RANGE64 g_DataSegRanges[kMaxDataSegRanges];
extern ULONG32 g_DataSegRangeCount;
extern ULONG64 g_DataSegBytes;

// Process/thread-data ranges (PEB, TEBs, process parameters, environment, referenced strings)
// captured once per selected dump for MiniDumpWithProcessThreadData. Like g_DataSegRanges, every
// later pass (known-range, descriptor, byte) replays this fixed list so they can never disagree on
// count or size. g_ProcThreadBytes is the summed (region-clamped) size of the captured ranges.
extern INPROC_MEMORY_RANGE64 g_ProcThreadRanges[kMaxProcThreadRanges];
extern ULONG32 g_ProcThreadRangeCount;
extern ULONG64 g_ProcThreadBytes;

// Snapshot of the caller-provided user streams (UserStreamParam) and its count, built once per dump.
extern INPROC_USER_STREAM g_UserStreams[kMaxUserStreams];
extern ULONG32 g_UserStreamCount;

// Effective per-dump cap on indirect-memory ranges (derived from MaxFileSize and buffer capacity).
extern ULONG32 g_IndirectMemoryRangeCap;

// Full-memory range plan overlaid on the shared scratch buffer.
inline INPROC_MEMORY_RANGE64* FullMemoryRanges() noexcept {
    return reinterpret_cast<INPROC_MEMORY_RANGE64*>(g_ScratchBuffer);
}
inline ULONG32 FullMemoryRangesCapacity() noexcept {
    return static_cast<ULONG32>(kScratchBufferSize / sizeof(INPROC_MEMORY_RANGE64));
}

// Indirect-memory plan overlaid on the shared scratch buffer. To keep multi-layer dedup O(1),
// the buffer is split: the lower half holds the collected ranges, the upper half is an
// open-addressing hash set of visited 4KB page addresses (0 = empty slot; page addresses are
// always >= 0x10000 so 0 is a safe sentinel). Both halves are powers of two in element count.
constexpr ULONG kIndirectRangesBytes = kScratchBufferSize / 2;

inline INPROC_MEMORY_RANGE* IndirectMemoryRanges() noexcept {
    return reinterpret_cast<INPROC_MEMORY_RANGE*>(g_ScratchBuffer);
}
inline ULONG32 IndirectMemoryRangesCapacity() noexcept {
    return static_cast<ULONG32>(kIndirectRangesBytes / sizeof(INPROC_MEMORY_RANGE));
}
inline ULONG64* IndirectVisitedHash() noexcept {
    return reinterpret_cast<ULONG64*>(g_ScratchBuffer + kIndirectRangesBytes);
}
inline ULONG32 IndirectVisitedHashSlots() noexcept {
    return static_cast<ULONG32>((kScratchBufferSize - kIndirectRangesBytes) / sizeof(ULONG64));
}

// Rounds a file RVA or stream size up to the 4-byte alignment required by the minidump format.
ULONG64 Align4(ULONG64 value) noexcept;

// Rounds an address down to an alignment boundary. The indirect-memory scanner uses this to normalize pointers to page starts.
ULONG64 AlignDown(ULONG64 value, ULONG64 alignment) noexcept;

// Reads the current thread segment register to obtain the PEB without calling loader APIs or allocating memory.
INPROC_PEB* GetCurrentPeb() noexcept;

// Reads the TEB pointer directly from the architecture-specific segment register.
PVOID GetCurrentTebPointer() noexcept;

// Accesses process-invariant system information cached during load-time initialization.
DWORD NativePageSize() noexcept;
BYTE* MinimumApplicationAddress() noexcept;
BYTE* MaximumApplicationAddress() noexcept;

// Normalizes the caller's MaxFileSize into the production hard cap.
ULONG64 NormalizeHardMaxFileSize(ULONG64 maxFileSize) noexcept;

// Caches system information and pre-resolves low-level NTDLL entry points during load-time initialization.
void ResolveInprocApis() noexcept;

// Converts a FILETIME timestamp to the seconds-since-1970 format used by MINIDUMP_MISC_INFO.
ULONG32 FileTimeToUnixSeconds(const FILETIME& ft) noexcept;

// Converts a FILETIME duration to seconds for process user/kernel time fields.
ULONG32 FileTimeDurationSeconds(const FILETIME& ft) noexcept;

// Probes every touched page of a range under SEH so corrupt middle pages do not tear down dump generation.
BOOL SafeReadBytes(const void* address, SIZE_T size) noexcept;

// Copies memory under SEH; this is used when reading potentially damaged process structures such as PEB/LDR or exception records.
BOOL SafeCopyBytes(void* dst, const void* src, SIZE_T size) noexcept;

// Safely validates and clamps an LDR Unicode module path before it is serialized as a MINIDUMP_STRING.
ULONG32 SafeModuleNameLength(const INPROC_UNICODE_STRING* name) noexcept;

// Computes the on-disk size of a MINIDUMP_STRING including the terminating WCHAR and 4-byte padding.
ULONG32 MinidumpStringSize(ULONG32 bytes) noexcept;

// Writes a byte range to the caller-provided file handle, splitting very large writes into DWORD-sized WriteFile calls.
BOOL WriteAll(HANDLE hFile, const void* data, ULONG64 size) noexcept;

// Writes zero-filled padding without heap allocation by reusing a static zero page.
BOOL WriteZeros(HANDLE hFile, ULONG64 size) noexcept;

// Serializes a Windows UNICODE_STRING as a MINIDUMP_STRING while tolerating invalid string buffers.
BOOL WriteMinidumpString(HANDLE hFile, const INPROC_UNICODE_STRING* name) noexcept;

// Returns whether a virtual memory protection value is readable enough to safely include in a dump.
BOOL IsDumpableProtect(DWORD protect) noexcept;

// Returns whether a protection value represents writable image data for MiniDumpWithDataSegs.
BOOL IsWritableProtect(DWORD protect) noexcept;

// Decides whether a VirtualQuery region should be included as optional selected memory, currently writable MEM_IMAGE data segments.
BOOL ShouldIncludeExtraMemoryRange(const MEMORY_BASIC_INFORMATION& mbi,
                                   BOOL includeDataSegs) noexcept;

// Counts modules by walking PEB_LDR_DATA directly instead of using ToolHelp or loader enumeration APIs.
// It also precomputes trailing MINIDUMP_STRING and CodeView RSDS storage sizes.
BOOL CountModules(ULONG32* moduleCount, ULONG32* nameBytes, ULONG32* codeViewBytes) noexcept;

// Reads PE timestamp and checksum from an image base under SEH so damaged module headers do not fail the dump.
BOOL ReadPeImageInfo(PVOID moduleBase, ULONG32* timeDateStamp, ULONG32* checkSum) noexcept;

// Returns the raw RSDS CodeView record size from a module debug directory, capped for crash-path safety.
BOOL QueryModuleCodeViewRecord(PVOID moduleBase, const BYTE** record, ULONG32* recordSize) noexcept;

// Writes one module RSDS CodeView record and pads it to the minidump 4-byte alignment.
BOOL WriteModuleCodeViewRecord(HANDLE hFile, PVOID moduleBase, ULONG32* writtenSize) noexcept;

// Writes ModuleListStream descriptors and their trailing strings/CodeView records; stream size excludes trailing storage per minidump rules.
BOOL WriteModuleList(HANDLE hFile, ULONG32 moduleCount, ULONG32 moduleListRva) noexcept;

// Counts entries in ntdll's unloaded-module ring (RtlGetUnloadEventTraceEx) and the trailing
// MINIDUMP_STRING name storage they need. A pure read of an ntdll global: no heap, no loader lock.
// Degrades to an empty stream (count 0) when the routine is unavailable or the table looks invalid.
BOOL CountUnloadedModules(ULONG32* count, ULONG32* nameBytes) noexcept;

// Writes UnloadedModuleListStream (header + fixed-size entries) plus the trailing MINIDUMP_STRING
// name blobs referenced by each entry's ModuleNameRva. streamRva is the stream's own RVA. Re-reads
// the same frozen ntdll ring as CountUnloadedModules so descriptor count and name storage stay
// consistent. The stream DataSize excludes the trailing name storage, per minidump rules.
BOOL WriteUnloadedModuleList(HANDLE hFile, ULONG32 count, ULONG32 streamRva) noexcept;


// Copies the caller-provided exception record and context pointers into minidump exception-stream form.
BOOL CaptureExceptionStreamInfo(
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    MINIDUMP_EXCEPTION_STREAM* stream,
    const CONTEXT** contextRecord) noexcept;

// Returns the basic thread record at an index from a SystemProcessInformation buffer.
const INPROC_SYSTEM_THREAD_INFORMATION* SnapshotThreadInfo(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept;

// Returns the extended thread record when SystemExtendedProcessInformation is available.
const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION* SnapshotExtendedThreadInfo(
    const INPROC_THREAD_SNAPSHOT& snapshot,
    ULONG32 index) noexcept;

// Captures the current process entry from NtQuerySystemInformation into a static buffer, avoiding ToolHelp heap paths.
BOOL QueryCurrentProcessThreadSnapshot(INPROC_THREAD_SNAPSHOT* snapshot) noexcept;

// Clamps the number of snapshot threads to the fixed writer capacity.
ULONG32 SnapshotThreadCount(const INPROC_THREAD_SNAPSHOT& snapshot) noexcept;

// Extracts a DWORD thread id from an NT CLIENT_ID record.
DWORD SnapshotThreadId(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept;

// Returns a TEB from the extended thread snapshot, falling back to the current TEB for the writing thread.
PVOID SnapshotThreadTeb(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept;

// Takes a single thread snapshot, opens+suspends every other thread, and records an immutable
// per-thread plan (TEB, frozen stack range, times) so all later passes stay mutually consistent.
// Always succeeds for at least the current thread.
BOOL BuildThreadPlanAndFreeze(DWORD preferredThreadId) noexcept;

// Resumes and closes all threads frozen by BuildThreadPlanAndFreeze. Idempotent: safe to call twice.
void ResumeThreadPlan() noexcept;

// Captures committed, dumpable regions for MiniDumpWithFullMemory into g_FullMemoryRanges in a single
// VirtualQuery walk so the descriptor and byte passes can never disagree on count or size.
BOOL CaptureFullMemoryRanges() noexcept;

// Queries a non-current thread TEB through pre-resolved NtQueryInformationThread.
PVOID QueryThreadTeb(HANDLE hThread, DWORD threadId) noexcept;

// Writes ThreadListStream from the frozen thread plan; for selected-memory dumps it points each
// thread's stack descriptor at the stack bytes emitted by the MemoryList stream.
BOOL WriteThreadList(HANDLE hFile,
                     ULONG32 threadCount,
                     ULONG32 contextBaseRva,
                     ULONG64 stackBytesBaseRva,
                     BOOL stacksInMemoryList) noexcept;

// Writes the contiguous context-record backing store referenced by ThreadListStream and ExceptionStream.
BOOL WriteThreadContexts(HANDLE hFile, ULONG32 threadCount, PMINIDUMP_EXCEPTION_INFORMATION exceptionParam) noexcept;

// Writes ThreadInfoListStream from the NT thread snapshot instead of opening every thread for GetThreadTimes.
BOOL WriteThreadInfoList(HANDLE hFile, ULONG32 threadCount) noexcept;

// Counts threads that have a kernel-stored name and the total MINIDUMP_STRING storage their names
// need, from the immutable thread plan captured under freeze.
BOOL CountThreadNames(ULONG32 threadCount, ULONG32* nameCount, ULONG32* nameStorageBytes) noexcept;

// Writes ThreadNamesStream (MINIDUMP_THREAD_NAME_LIST + entries) plus the trailing MINIDUMP_STRING
// name blobs they reference. namesBaseRva is the stream's own RVA (each entry's RvaOfThreadName is
// an absolute file offset into the trailing blobs). All data comes from the frozen thread plan.
BOOL WriteThreadNames(HANDLE hFile, ULONG32 threadCount, ULONG64 namesBaseRva) noexcept;

// Applies production stack clipping and hard-budget priority: crash stack, main thread stack, then best-effort others.
BOOL ApplyThreadStackCapturePolicy(DWORD preferredThreadId,
                                   ULONG32 exceptionCode,
                                   const CONTEXT* exceptionContext,
                                   ULONG64 fixedDumpBytes,
                                   ULONG64 hardMaxFileSize) noexcept;

// Counts stack ranges that will be included in the selected MemoryList stream.
BOOL CountStackMemoryRanges(ULONG32 threadCount, ULONG64* rangeCount, ULONG64* bytesCount) noexcept;

// Extracts RSP/ESP from a CONTEXT for prioritizing indirect-memory scans near the crash frame.
ULONG64 ContextStackPointer(const CONTEXT* context) noexcept;

// Counts VirtualQuery regions for MiniDumpWithFullMemoryInfo.
BOOL CountMemoryInfoRanges(ULONG64* rangeCount) noexcept;

// Writes MemoryInfoListStream and pads missing entries with zeroes if the address map changes between count and write passes.
BOOL WriteMemoryInfoList(HANDLE hFile, ULONG64 rangeCount) noexcept;

// Checks half-open range intersection with overflow guards.
BOOL RangesOverlap(ULONG64 leftStart, ULONG64 leftSize, ULONG64 rightStart, ULONG64 rightSize) noexcept;

// Clears the fixed table of already-planned MemoryList ranges.
void ResetKnownMemoryRanges() noexcept;

// Adds a stack or data-segment range to the known MemoryList table, coalescing by overlap to keep lookups bounded.
void AddKnownMemoryRange(ULONG64 start, ULONG64 size) noexcept;

// Tests whether a candidate indirect page overlaps memory already planned for MemoryList.
BOOL KnownMemoryRangeOverlaps(ULONG64 start, ULONG64 size) noexcept;

// Validates a candidate pointer with a cached VirtualQuery, normalizes it to a 4KB page, dedups it
// via the visited-page hash, rejects overlaps, and records it at the given BFS layer if room remains.
BOOL AddIndirectMemoryRangeFromPointer(ULONG64 value, ULONG64 sourceStart, ULONG64 sourceEnd, ULONG32 layer) noexcept;

// Scans a span pointer-width at a time and feeds plausible values into the indirect-memory collector at the given layer.
BOOL ScanStackSpanForIndirectMemory(ULONG64 scanStart, ULONG64 scanEnd,
                                    ULONG64 sourceStart, ULONG64 sourceEnd, ULONG32 layer) noexcept;

// Scans a thread stack for layer-1 indirect references, prioritizing SP-to-stack-base for the exception thread.
BOOL ScanStackForIndirectMemory(ULONG64 stackStart,
                                ULONG32 stackSize,
                                const CONTEXT* preferredContext) noexcept;

// Precomputes stack, data-segment and process/thread-data MemoryList ranges so indirect pages can be checked against all known ranges.
void CollectKnownSelectedMemoryRanges(ULONG32 threadCount, BOOL includeDataSegs, BOOL includeProcThread) noexcept;

// Collects indirect 4KB pages via multi-layer BFS (bounded by g_IndirectMemoryRangeCap and
// kIndirectMaxScanLayers), expanding the crash thread's whole reference subtree before other threads.
BOOL CollectIndirectMemoryRanges(ULONG32 threadCount,
                                 DWORD preferredThreadId,
                                 const CONTEXT* preferredContext,
                                 ULONG64* rangeCount,
                                 ULONG64* bytesCount) noexcept;

// Captures optional selected memory ranges (writable image data segments) once into g_DataSegRanges
// in a single VirtualQuery walk, then reports the captured count and total bytes. The known-range,
// descriptor and byte passes all replay g_DataSegRanges, so they can never disagree on count or size
// even if the live address space shifts. When includeDataSegs is FALSE the capture is empty.
BOOL CaptureDataSegRanges(BOOL includeDataSegs,
                          ULONG64* rangeCount,
                          ULONG64* bytesCount) noexcept;

// Captures the MiniDumpWithProcessThreadData memory set once into g_ProcThreadRanges: the PEB, every
// frozen thread's TEB, the RTL_USER_PROCESS_PARAMETERS block, the environment block, and the
// UNICODE_STRING buffers the parameters reference (image path / command line / current directory /
// window / desktop strings). Every range is validated and clamped to its committed VirtualQuery
// region, capped, and de-duplicated, so the read is crash-path safe and the count/known-range/
// descriptor/byte passes can never disagree. When includeProcThread is FALSE the capture is empty.
BOOL CaptureProcessThreadDataRanges(BOOL includeProcThread,
                                    ULONG32 threadCount,
                                    ULONG64* rangeCount,
                                    ULONG64* bytesCount) noexcept;

// Writes a memory region page-by-page, always zero-filling unreadable chunks (never fails on
// inaccessible memory; MiniDumpIgnoreInaccessibleMemory is intentionally not honored).
BOOL WriteRegionBytes(HANDLE hFile, BYTE* base, SIZE_T size) noexcept;

// Writes MemoryList descriptors for stacks, process/thread data, selected data segments, and indirect
// pages in the same order as their bytes.
BOOL WriteSelectedMemoryDescriptors(HANDLE hFile,
                                    ULONG32 threadCount,
                                    BOOL includeDataSegs,
                                    ULONG64 stackRangeCount,
                                    ULONG64 procThreadRangeCount,
                                    ULONG64 extraRangeCount,
                                    ULONG64 indirectRangeCount,
                                    ULONG64 memoryBaseRva) noexcept;

// Writes the backing bytes for selected MemoryList descriptors in descriptor order.
BOOL WriteSelectedMemoryBytes(HANDLE hFile,
                              ULONG32 threadCount,
                              BOOL includeDataSegs,
                              ULONG64 procThreadRangeCount,
                              ULONG64 indirectRangeCount) noexcept;

// Writes Memory64List descriptors for MiniDumpWithFullMemory.
BOOL WriteMemoryDescriptors(HANDLE hFile, ULONG64 rangeCount, ULONG64 memoryBaseRva) noexcept;

// Writes Memory64List backing bytes while zero-filling pages that fault during reads.
BOOL WriteMemoryBytes(HANDLE hFile, ULONG64 rangeCount) noexcept;

// Writes SystemInfoStream using kernel system information and pre-resolved RtlGetVersion when available.
BOOL WriteSystemInfo(HANDLE hFile) noexcept;

// Writes MiscInfoStream with process id and process timing information.
BOOL WriteMiscInfo(HANDLE hFile) noexcept;

// Builds the ANSI comment text (system + process memory summary) into g_CommentBufferA and returns
// its 4-byte-aligned byte length (including NUL + padding). Always produces a valid, NUL-terminated
// string even if the underlying queries fail. Safe to call before file layout.
ULONG32 BuildMemoryCommentText() noexcept;

// Patches the reserved fixed-width elapsed-time field in g_CommentBufferA (reserved by
// BuildMemoryCommentText) with the measured total dump duration in milliseconds, right-justified
// and space-padded. Safe no-op if no field was reserved (g_CommentElapsedOffset == sentinel).
void PatchCommentElapsed(ULONG64 elapsedMillis) noexcept;

// Snapshots the caller-provided user streams (MiniDumpWriteDump-style UserStreamParam) into the
// fixed g_UserStreams plan, validating the caller structure/array under SEH. Caps to kMaxUserStreams
// and skips NULL/empty entries. Buffer pointers are stored and read later at write time.
void SnapshotUserStreams(PMINIDUMP_USER_STREAM_INFORMATION userStreamParam) noexcept;

// Writes the first `count` admitted user-stream byte blobs contiguously at their laid-out RVAs, each
// padded to a 4-byte boundary. Unreadable caller buffers are zero-filled (best-effort, never aborts).
BOOL WriteUserStreams(HANDLE hFile, ULONG32 count) noexcept;

// Writes CommentStreamA from g_CommentBufferA. byteLen must equal the value returned by
// BuildMemoryCommentText (the size reserved in the stream directory).
INPROC_STREAM_WRITE_RESULT WriteCommentStream(HANDLE hFile, ULONG32 byteLen) noexcept;

// Applies one user (section, key, value) operation to the persistent CommentStreamW INI buffer
// (g_CommentBufferW). Validates inputs, takes g_Protected.CommentMutex, and is SEH-guarded against
// bad caller pointers. Returns FALSE on invalid input or when the result would not fit the buffer.
// the shared worker behind the exported SetMiniDumpInprocCommentA/W wrappers.
BOOL SetCommentIniW(const wchar_t* section, const wchar_t* key, const wchar_t* value,
                    COMMENT_STRING_OPER_TYPE oper) noexcept;

// Returns the 4-byte-aligned on-disk byte size of CommentStreamW (the wide INI text in
// g_CommentBufferW including its terminating NUL), or 0 when no user comment has been set.
ULONG32 CommentStreamWBytes() noexcept;

// Writes CommentStreamW from g_CommentBufferW. byteLen must equal the value returned by
// CommentStreamWBytes (the size reserved in the stream directory); any alignment slack is zero-filled.
INPROC_STREAM_WRITE_RESULT WriteCommentStreamW(HANDLE hFile, ULONG32 byteLen) noexcept;



// Writes the captured exception stream (CONTEXT + MINIDUMP_EXCEPTION_STREAM).
INPROC_STREAM_WRITE_RESULT WriteExceptionStream(HANDLE hFile, const CONTEXT* context, const MINIDUMP_EXCEPTION_STREAM* capturedException) noexcept;

// Lays out the complete minidump file, computes stream RVAs, writes directories, and serializes each enabled stream.
// maxFileSize is a soft size budget (0 = unlimited) applied to truncatable memory in priority order.
BOOL WriteMiniDumpInprocImpl(
    HANDLE hFile,
    MINIDUMP_TYPE dumpType,
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION userStreamParam,
    ULONG64 maxFileSize) noexcept;

// Truncates the input multi-byte string to the maximum allowed length to convert to wide string.
// Returns the number of bytes to convert.
int TruncateMultiByteString(LPCSTR lpMultiByteStr, int maxWideChars) noexcept;

} // namespace internal
} // namespace minidump_inproc
