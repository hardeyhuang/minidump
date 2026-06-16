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
// The required NTDLL routines are resolved automatically at module load (a global constructor),
// and the crash path NEVER resolves exports lazily (it must not touch the loader lock). If that
// load-time initialization did not run, this function fails with ERROR_NOT_READY rather than
// calling into the loader. No explicit init call is provided or needed.
//
// ExceptionParam->ClientPointers MUST be FALSE: this is an in-process self-dump that reads the
// exception record / context / scanned memory directly from this process's own address space.
// Passing TRUE (a claim that the pointers belong to another process) is rejected with
// ERROR_INVALID_PARAMETER.
//
// MaxFileSize: production hard cap (in bytes) on the produced dump. Values below 4 MB (including 0)
// are clamped to 4 MB. Selected-memory dumps fit the cap by
// prioritizing fixed metadata, the crashing thread stack, the main thread stack, then best-effort
// remaining thread stacks and optional memory. Individual stack windows are capped to keep large
// reserved stacks from dominating the dump; STATUS_STACK_OVERFLOW keeps the whole crashing stack
// when it is <= 2 MB (or fails if it cannot fit), otherwise it keeps live-unwind and
// high-address stack-top windows.
//
// MiniDumpWithFullMemory keeps its full-memory semantics: if all captured committed/readable ranges
// cannot fit under the hard cap, the function fails with ERROR_FILE_TOO_LARGE rather than silently
// truncating. For selected-memory dumps the 32-bit MemoryList RVAs also impose a hard ~4 GB limit; if
// the final layout would exceed either limit, the function fails with ERROR_FILE_TOO_LARGE.
MINIDUMP_INPROC_API BOOL WINAPI WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    ULONG64 MaxFileSize) MINIDUMP_INPROC_NOEXCEPT;

// Optionally pre-resolves the low-level system/NTDLL routines this library needs (cached native
// SYSTEM_INFO plus the NtQuery* entry points, and user32!GetGuiResources only when user32 is
// already mapped -- it never LoadLibrary's anything).
//
// This same resolution also runs automatically from a load-time global constructor, so calling it
// is NOT required. It is exported only so callers can force the work to happen at a well-defined
// point: the relative order of global constructors across different translation units / DLLs is
// unspecified, so if your own static/global initializers (in another .cpp) rely on this library
// being ready, call ResolveInprocApis() yourself first to remove that ordering dependency.
//
// Idempotent and thread-safe to call repeatedly: it checks an internal "already initialized" flag
// and the actual export/proc resolution runs only once; later calls return immediately. Never
// throws and never touches the loader beyond GetModuleHandle/GetProcAddress.
MINIDUMP_INPROC_API void WINAPI ResolveInprocApis(void) MINIDUMP_INPROC_NOEXCEPT;


#ifdef __cplusplus
}
#endif
