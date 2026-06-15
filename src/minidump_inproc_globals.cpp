#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

CONTEXT g_ContextScratch = {};
volatile LONG g_ApisInitialized = 0;
INPROC_API_TABLE g_Apis = {};
ULONG32 g_IndirectMemoryRangeCount = 0;
INPROC_MEMORY_RANGE g_KnownMemoryRanges[kMaxKnownMemoryRanges] = {};
ULONG32 g_KnownMemoryRangeCount = 0;
__declspec(align(16)) BYTE g_ScratchBuffer[kScratchBufferSize] = {};

volatile LONG g_DumpInProgress = 0;

INPROC_THREAD_PLAN_ENTRY g_ThreadPlan[kMaxThreads] = {};
ULONG32 g_ThreadPlanCount = 0;
ULONG32 g_ExceptionThreadIndex = 0;

ULONG32 g_FullMemoryRangeCount = 0;
ULONG32 g_IndirectMemoryRangeCap = 0;

namespace {
// Resolves the required NTDLL routines automatically at module load so the crash path never
// needs a separate initialization call and never resolves exports lazily while crashing.
struct AutoInitInprocApis {
    AutoInitInprocApis() noexcept { ResolveInprocApis(); }
};
AutoInitInprocApis g_autoInitInprocApis;
} // namespace

} // namespace minidump_inproc::internal
