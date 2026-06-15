#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>

#if defined(MINIDUMP_INPROC_STATIC)
#define MINIDUMP_INPROC_API
#elif defined(MINIDUMP_INPROC_EXPORTS)
#define MINIDUMP_INPROC_API __declspec(dllexport)
#else
#define MINIDUMP_INPROC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
#define MINIDUMP_INPROC_NOEXCEPT noexcept
extern "C" {
#else
#define MINIDUMP_INPROC_NOEXCEPT
#endif

// Writes a best-effort minidump for the current process to an already-open file handle.
// The implementation does not call MiniDumpWriteDump and avoids explicit heap allocation.
//
// The required NTDLL routines are resolved automatically at module load, so no explicit
// initialization call is needed before using this function.
//
// MaxFileSize: optional soft cap (in bytes) on the produced dump. Pass 0 for "no limit".
// When set, mandatory data (header, system/misc info, modules, threads, thread contexts,
// the exception record and every thread stack) is always written even if it exceeds the
// cap, because a dump without it is useless. Optional/truncatable data is then added in
// priority order until the budget is consumed: writable data segments
// (MiniDumpWithDataSegs) first, and indirectly-referenced memory
// (MiniDumpWithIndirectlyReferencedMemory) last as the lowest priority.
MINIDUMP_INPROC_API BOOL WINAPI WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    ULONG64 MaxFileSize) MINIDUMP_INPROC_NOEXCEPT;


#ifdef __cplusplus
}
#endif
