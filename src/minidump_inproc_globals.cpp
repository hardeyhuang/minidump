#include "minidump_inproc_internal.h"

namespace minidump_inproc {
namespace internal {

// ---- Protected init-once globals (own 4KB page, VirtualProtect'd after init) ----
__declspec(align(4096)) PROTECTED_GLOBALS g_Protected = {};

INPROC_API_TABLE& g_Apis = g_Protected.Apis;
SYSTEM_INFO& g_NativeSystemInfo = g_Protected.NativeSystemInfo;
volatile LONG& g_ApisInitializeStatus = g_Protected.InitStatus;

// ---- Unprotected init-once globals (no VirtualProtect) ----
CONTEXT g_ContextScratch = {};
BYTE g_IndirectPageScratch[kIndirectMemoryRangeSize] = {};
BYTE g_IndirectChainScratch[kIndirectMaxScanLayers][kIndirectMemoryRangeSize] = {};

char g_CommentBufferA[kCommentBufferBytes] = {};
ULONG32 g_CommentElapsedOffset = kCommentElapsedUnset;

WCHAR g_CommentBufferW[kCommentBufferWChars] = {};
ULONG32 g_CommentBufferWCrc = 0;

ULONG32 g_IndirectMemoryRangeCount = 0;
INPROC_MEMORY_RANGE g_KnownMemoryRanges[kMaxKnownMemoryRanges] = {};
ULONG32 g_KnownMemoryRangeCount = 0;
__declspec(align(16)) BYTE g_ScratchBuffer[kScratchBufferSize] = {};

INPROC_THREAD_PLAN_ENTRY g_ThreadPlan[kMaxThreads] = {};
ULONG32 g_ThreadPlanCount = 0;

ULONG32 g_FullMemoryRangeCount = 0;
ULONG64 g_FullMemoryBytes = 0;
ULONG32 g_IndirectMemoryRangeCap = 0;

INPROC_MEMORY_RANGE64 g_DataSegRanges[kMaxDataSegRanges] = {};
ULONG32 g_DataSegRangeCount = 0;
ULONG64 g_DataSegBytes = 0;

INPROC_MEMORY_RANGE64 g_ProcThreadRanges[kMaxProcThreadRanges] = {};
ULONG32 g_ProcThreadRangeCount = 0;
ULONG64 g_ProcThreadBytes = 0;

INPROC_USER_STREAM g_UserStreams[kMaxUserStreams] = {};
ULONG32 g_UserStreamCount = 0;

namespace {
// Resolves the required NTDLL routines automatically at module load so the crash path never
// needs a separate initialization call and never resolves exports lazily while crashing.
struct AutoInitInprocApis {
    AutoInitInprocApis() noexcept
    {
        ResolveInprocApis();
    }
};
AutoInitInprocApis g_autoInitInprocApis;
} // namespace
} // namespace internal
} // namespace minidump_inproc
