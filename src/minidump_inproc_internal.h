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

namespace minidump_inproc::internal {

inline constexpr ULONG32 kMaxModules = 4096;
inline constexpr ULONG32 kMaxThreads = 1024;
// Maximum caller-provided user streams (MiniDumpWriteDump-style UserStreamParam) honored per dump.
// Bounds the static plan array and the stream-directory slack so no heap is needed.
inline constexpr ULONG32 kMaxUserStreams = 16;
inline constexpr ULONG32 kMaxModuleNameBytes = 32766;
inline constexpr ULONG32 kMaxCodeViewRecordBytes = 4096;
inline constexpr ULONG32 kCodeViewSignatureRsds = 0x53445352;
inline constexpr ULONG32 kIndirectMemoryRangeSize = 4096;
// Pointers reference object *starts*, and object bodies grow toward higher addresses, so a pointer
// landing near the top of its 4KB page usually points to a struct that straddles into the next page.
// Capturing only AlignDown(value) would then truncate the object AND drop the outgoing pointers in
// its tail half (breaking the BFS chain). When the pointer is within this many bytes of the page end
// we also collect the next higher page. Kept small (one extra page at most, since it is <= the page
// size) so the file-size budget is not doubled: only the ~window/4096 fraction of edge pointers pay.
inline constexpr ULONG32 kPointerStraddleWindow = 512;
static_assert(kPointerStraddleWindow <= kIndirectMemoryRangeSize,
              "straddle window must stay within one page so at most one neighbor page is added");
// Memory byte-streaming block size. WriteRegionBytes probes and writes a whole block in one
// WriteFile on the common all-readable path (instead of one WriteFile per 4 KB page), only dropping
// to page granularity to isolate and zero-fill faulting pages. This cuts syscalls by ~256x for large
// committed regions (the dominant cost of MiniDumpWithFullMemory) without changing the output bytes.
inline constexpr ULONG32 kMemoryWriteBlockBytes = 1024 * 1024;

// Deepest indirect-reference layer collected for MiniDumpWithIndirectlyReferencedMemory.
// Layer 1 = pages referenced from thread stacks; 2/3 = transitively referenced pages. Relevance
// decays with depth, so this is capped; the file-size budget is the real limiter underneath it.
inline constexpr ULONG32 kIndirectMaxScanLayers = 3;

inline constexpr ULONG32 kMaxKnownMemoryRanges = kMaxThreads + 4096;
inline constexpr ULONG64 kWriteChunk = 0x40000000ULL;
inline constexpr ULONG64 kFileTimeUnixEpoch = 116444736000000000ULL;
inline constexpr ULONG64 kFileTimeTicksPerSecond = 10000000ULL;
inline constexpr ULONG kSystemProcessInformation = 5;
inline constexpr ULONG kSystemExtendedProcessInformation = 57;
// NtQueryInformationProcess class for VM_COUNTERS_EX (working set / private commit / pagefile usage).
inline constexpr ULONG kProcessVmCounters = 3;
// NtQueryInformationProcess class for the open-handle count (+ high watermark / peak).
inline constexpr ULONG kProcessHandleCount = 20;
// ANSI comment-stream buffer: system + process memory summary text shown by WinDbg on load.
inline constexpr ULONG32 kCommentBufferBytes = 1024;
// Fixed-width, space-padded digit field reserved inside CommentStreamA for the total dump elapsed
// time (microseconds). Because the comment's DataSize is fixed at layout time but the elapsed time
// is only known after every other stream is written, BuildMemoryCommentText reserves this field and
// PatchCommentElapsed fills it in right before the comment is written last. 10 digits covers up to
// ~2.7 hours of microseconds, far more than any real dump.
inline constexpr ULONG32 kCommentElapsedWidth = 10;
// Sentinel meaning "no elapsed field was reserved" (e.g. the buffer was too full to fit it).
inline constexpr ULONG32 kCommentElapsedUnset = 0xFFFFFFFFu;

// One shared scratch buffer is reused across non-overlapping phases to keep the static
// footprint small: first as the NtQuerySystemInformation process snapshot (consumed entirely
// while building the thread plan), then as the full-memory range plan (full-memory dumps) or
// the indirect-memory range plan (selected-memory dumps). These uses never overlap in time.
inline constexpr ULONG kScratchBufferSize = 4 * 1024 * 1024;

// Production size policy: MaxFileSize is a hard cap. Values below 4 MB (including 0)
// are clamped to 4 MB.
inline constexpr ULONG64 kMinHardMaxFileSize = 4ULL * 1024 * 1024;
inline constexpr ULONG32 kMaxCapturedStackBytes = 1024 * 1024;
// STATUS_STACK_OVERFLOW stack capture policy:
//   - If the crashing thread's original stack is <= kStackOverflowFullStackThreshold (1 MB), the
//     whole stack is recorded as-is.
//   - Otherwise a deterministic two-window capture is used: kStackOverflowLiveStackBytes (512 KB) of
//     the live unwind window from SP/RSP, plus kStackOverflowHighStackBytes (512 KB) near StackBase
//     so the recursion entry / call origin is still observable.
inline constexpr ULONG32 kStackOverflowFullStackThreshold = 1 * 1024 * 1024;
inline constexpr ULONG32 kStackOverflowLiveStackBytes = 512 * 1024;
inline constexpr ULONG32 kStackOverflowHighStackBytes = 512 * 1024;


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
    HANDLE Handle;        // pre-opened handle for non-current threads (already suspended); NULL for current/failed
    BOOL Suspended;       // TRUE if SuspendThread succeeded on Handle
    BOOL IsCurrent;       // TRUE for the dump-writing thread
    PVOID Teb;
    ULONG64 StackStart;   // captured primary stack window start
    ULONG32 StackSize;    // captured primary stack window size
    ULONG64 OriginalStackStart; // original TIB StackLimit before production clipping
    ULONG32 OriginalStackSize;  // original StackBase - StackLimit before production clipping
    BOOL IncludeStack;          // TRUE if the primary stack window fits the hard dump budget
    ULONG64 AuxStackStart;      // optional extra window, used for large stack-overflow high-address stack top
    ULONG32 AuxStackSize;
    ULONG64 CreateTime;
    ULONG64 KernelTime;
    ULONG64 UserTime;
    ULONG64 StartAddress;
    LONG Priority;
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

struct INPROC_API_TABLE {
    RtlGetVersionFn RtlGetVersion;
    NtQueryInformationThreadFn NtQueryInformationThread;
    NtQuerySystemInformationFn NtQuerySystemInformation;
    NtQueryInformationProcessFn NtQueryInformationProcess;
    GetGuiResourcesFn GetGuiResources;   // may be null when user32 is not loaded
};

extern CONTEXT g_ContextScratch;

extern volatile LONG g_ApisInitialized;
extern INPROC_API_TABLE g_Apis;
extern SYSTEM_INFO g_NativeSystemInfo;

// ANSI comment-stream text (system + process memory summary) and its byte length, built once per
// dump. Static so it persists from layout computation to the write pass; dumps are serialized.
extern char g_CommentBuffer[kCommentBufferBytes];
extern ULONG32 g_CommentBytes;
// Byte offset of the reserved elapsed-time digit field inside g_CommentBuffer, or kCommentElapsedUnset.
extern ULONG32 g_CommentElapsedOffset;
extern ULONG32 g_IndirectMemoryRangeCount;
extern INPROC_MEMORY_RANGE g_KnownMemoryRanges[kMaxKnownMemoryRanges];
extern ULONG32 g_KnownMemoryRangeCount;

// Shared scratch buffer (see kScratchBufferSize). Reinterpreted per phase via the helpers below.
// Use __declspec(align) rather than alignas here: clang/clang-cl reject `extern alignas(N) T arr[]`
// (it parses alignas as a type attribute in that position), while __declspec(align) is accepted by
// both MSVC and clang-cl on the declaration.
extern __declspec(align(16)) BYTE g_ScratchBuffer[kScratchBufferSize];

// Serializes concurrent crashes: only one thread may run the writer at a time.
extern volatile LONG g_DumpInProgress;

// Immutable thread plan captured once under freeze; shared by all thread/stack streams.
extern INPROC_THREAD_PLAN_ENTRY g_ThreadPlan[kMaxThreads];
extern ULONG32 g_ThreadPlanCount;
extern ULONG32 g_ExceptionThreadIndex;

// Number of committed full-memory ranges captured in the scratch buffer.
extern ULONG32 g_FullMemoryRangeCount;
extern ULONG64 g_FullMemoryBytes;

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
inline constexpr ULONG kIndirectRangesBytes = kScratchBufferSize / 2;

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

// Extracts stack limits from an extended thread snapshot when available.
BOOL SnapshotThreadStackRange(const INPROC_THREAD_SNAPSHOT& snapshot,
                              ULONG32 index,
                              ULONG64* stackStart,
                              ULONG32* stackSize) noexcept;

// Counts process threads and finds the preferred exception-thread index used to place the exception context RVA.
BOOL CountProcessThreads(DWORD preferredThreadId, ULONG32* threadCount, ULONG32* preferredIndex) noexcept;

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

// Builds the stack memory descriptor for a thread from its TEB stack limits.
void FillThreadStackDescriptor(PVOID teb, MINIDUMP_MEMORY_DESCRIPTOR* stack) noexcept;

// Builds a MINIDUMP_THREAD record without allocating, using snapshot data where possible.
void FillThreadDescriptor(DWORD threadId,
                          ULONG32 index,
                          ULONG32 contextBaseRva,
                          PVOID knownTeb,
                          MINIDUMP_THREAD* thread) noexcept;

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

// Reads a thread stack range from its TEB, opening the thread only when it is not the current thread.
BOOL QueryThreadStackRange(DWORD threadId, ULONG64* stackStart, ULONG32* stackSize) noexcept;

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

// Returns the best stack range for a thread, preferring the live TEB for the current thread to avoid stale snapshot limits.
BOOL QuerySnapshotOrThreadStackRange(const INPROC_THREAD_SNAPSHOT& snapshot,
                                     ULONG32 index,
                                     ULONG64* stackStart,
                                     ULONG32* stackSize) noexcept;

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

// Precomputes stack and data-segment MemoryList ranges so indirect pages can be checked against all known ranges.
void CollectKnownSelectedMemoryRanges(ULONG32 threadCount, BOOL includeDataSegs) noexcept;

// Collects indirect 4KB pages via multi-layer BFS (bounded by g_IndirectMemoryRangeCap and
// kIndirectMaxScanLayers), expanding the crash thread's whole reference subtree before other threads.
BOOL CollectIndirectMemoryRanges(ULONG32 threadCount,
                                 DWORD preferredThreadId,
                                 const CONTEXT* preferredContext,
                                 ULONG64* rangeCount,
                                 ULONG64* bytesCount) noexcept;

// Counts optional selected memory ranges such as writable image data segments.
BOOL CountExtraMemoryRanges(BOOL includeDataSegs,
                            ULONG64* rangeCount,
                            ULONG64* bytesCount) noexcept;

// Writes a memory region page-by-page, always zero-filling unreadable chunks (never fails on
// inaccessible memory; MiniDumpIgnoreInaccessibleMemory is intentionally not honored).
BOOL WriteRegionBytes(HANDLE hFile, BYTE* base, SIZE_T size) noexcept;

// Writes MemoryList descriptors for stacks, selected data segments, and indirect pages in the same order as their bytes.
BOOL WriteSelectedMemoryDescriptors(HANDLE hFile,
                                    ULONG32 threadCount,
                                    BOOL includeDataSegs,
                                    ULONG64 stackRangeCount,
                                    ULONG64 extraRangeCount,
                                    ULONG64 indirectRangeCount,
                                    ULONG64 memoryBaseRva) noexcept;

// Writes the backing bytes for selected MemoryList descriptors in descriptor order.
BOOL WriteSelectedMemoryBytes(HANDLE hFile,
                              ULONG32 threadCount,
                              BOOL includeDataSegs,
                              ULONG64 indirectRangeCount) noexcept;

// Writes Memory64List descriptors for MiniDumpWithFullMemory.
BOOL WriteMemoryDescriptors(HANDLE hFile, ULONG64 rangeCount, ULONG64 memoryBaseRva) noexcept;

// Writes Memory64List backing bytes while zero-filling pages that fault during reads.
BOOL WriteMemoryBytes(HANDLE hFile, ULONG64 rangeCount) noexcept;

// Writes SystemInfoStream using kernel system information and pre-resolved RtlGetVersion when available.
BOOL WriteSystemInfo(HANDLE hFile) noexcept;

// Writes MiscInfoStream with process id and process timing information.
BOOL WriteMiscInfo(HANDLE hFile) noexcept;

// Builds the ANSI comment text (system + process memory summary) into g_CommentBuffer and returns
// its 4-byte-aligned byte length (including NUL + padding). Always produces a valid, NUL-terminated
// string even if the underlying queries fail. Safe to call before file layout.
ULONG32 BuildMemoryCommentText() noexcept;

// Patches the reserved fixed-width elapsed-time field in g_CommentBuffer (reserved by
// BuildMemoryCommentText) with the measured total dump duration in microseconds, right-justified
// and space-padded. Safe no-op if no field was reserved (g_CommentElapsedOffset == sentinel).
void PatchCommentElapsed(ULONG64 elapsedMicros) noexcept;

// Snapshots the caller-provided user streams (MiniDumpWriteDump-style UserStreamParam) into the
// fixed g_UserStreams plan, validating the caller structure/array under SEH. Caps to kMaxUserStreams
// and skips NULL/empty entries. Buffer pointers are stored and read later at write time.
void SnapshotUserStreams(PMINIDUMP_USER_STREAM_INFORMATION userStreamParam) noexcept;

// Writes the first `count` admitted user-stream byte blobs contiguously at their laid-out RVAs, each
// padded to a 4-byte boundary. Unreadable caller buffers are zero-filled (best-effort, never aborts).
BOOL WriteUserStreams(HANDLE hFile, ULONG32 count) noexcept;

// Writes CommentStreamA from g_CommentBuffer. byteLen must equal the value returned by
// BuildMemoryCommentText (the size reserved in the stream directory).
INPROC_STREAM_WRITE_RESULT WriteCommentStream(HANDLE hFile, ULONG32 byteLen) noexcept;



// Writes ExceptionStream and points it at the already-laid-out exception thread context record.
INPROC_STREAM_WRITE_RESULT WriteExceptionStream(HANDLE hFile, ULONG32 contextRva, const MINIDUMP_EXCEPTION_STREAM* capturedException) noexcept;

// Lays out the complete minidump file, computes stream RVAs, writes directories, and serializes each enabled stream.
// maxFileSize is a soft size budget (0 = unlimited) applied to truncatable memory in priority order.
BOOL WriteMiniDumpInprocImpl(
    HANDLE hFile,
    MINIDUMP_TYPE dumpType,
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION userStreamParam,
    ULONG64 maxFileSize) noexcept;

} // namespace minidump_inproc::internal
