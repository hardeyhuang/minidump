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
//
// UserStreamParam (optional, may be NULL): MiniDumpWriteDump-style user-defined streams. Each entry's
// Buffer/BufferSize is written verbatim as a stream whose StreamType is the caller-supplied Type. Up
// to 16 streams are honored. User streams are admitted with HIGHER priority than
// MiniDumpWithIndirectlyReferencedMemory but are still subject to MaxFileSize: they are included in
// array order until one would exceed the cap, after which it and the rest are dropped. The caller
// owns the buffers (read at write time); an unreadable buffer is zero-filled rather than failing.
MINIDUMP_INPROC_API BOOL WINAPI WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
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


// Operation applied by SetMiniDumpInprocComment* to a single (section, key) entry.
typedef enum _COMMENT_STRING_OPER_TYPE {
    // Upsert overwrite: if the key already exists in the section its value is replaced, otherwise the
    // key is added. As a special case, a NULL value DELETES the key (its whole line is removed); a
    // missing key with a NULL value is a no-op. This is the default operation.
    CommentStringReplace = 0,
    // Deduplicating append: the existing value is treated as a ';'-separated token list. If the new
    // value is not already one of those tokens it is appended after a ';', otherwise the value is left
    // unchanged. A missing key is added. A NULL value is a no-op.
    CommentStringMerge = 1,
    // Unconditional append: the new value is appended to the existing value after a ';' even if it is
    // already present (duplicates are allowed). A missing key is added. A NULL value is a no-op.
    CommentStringAppend = 2,
} COMMENT_STRING_OPER_TYPE;

// Records a user-defined (section, key, value) entry into the dump's CommentStreamW (a WinDbg-visible
// wide-character comment). Both the ANSI (A) and wide (W) variants ultimately store their data in the
// SAME CommentStreamW: the A variant converts its inputs from the active ANSI code page (CP_ACP) to
// UTF-16 first. This is independent of the automatic system/process memory summary, which continues to
// be written to CommentStreamA.
//
// The accumulated comment is kept in a fixed internal INI-style buffer that persists for the process
// lifetime, so entries can be set incrementally well before a crash and are included in every later
// dump. `section` and `key` must be non-NULL and non-empty (otherwise the call fails). `value` may be
// NULL; see COMMENT_STRING_OPER_TYPE for the per-operation NULL semantics. Returns FALSE if the inputs
// are invalid or the internal buffer cannot fit the result.
//
// Input size limits and value normalization:
//   - `section` and `key` accept at most 64 characters each; a longer section/key fails the call
//     (returns FALSE) and is never truncated.
//   - `value` accepts at most 256 characters; anything beyond that is silently TRUNCATED.
//   - Within the (truncated) value, each '\n' to U+21B5 (a visible return arrow) and 
//     each ';' to the full-width '；' (U+FF1B). This keeps the value on a single INI line and
//     prevents it from colliding with the ';' token separator used by MERGE/APPEND.
//
// Calls are serialized against each other with a lightweight internal lock. Like the rest of this
// library these setters are intended to be called BEFORE a crash (to attach diagnostic context); they
// are not guaranteed to be safe to call concurrently with an in-progress WriteMiniDumpInproc.
MINIDUMP_INPROC_API BOOL WINAPI SetMiniDumpInprocCommentA(
    const char* section,
    const char* key,
    const char* value,
    COMMENT_STRING_OPER_TYPE oper) MINIDUMP_INPROC_NOEXCEPT;

MINIDUMP_INPROC_API BOOL WINAPI SetMiniDumpInprocCommentW(
    const wchar_t* section,
    const wchar_t* key,
    const wchar_t* value,
    COMMENT_STRING_OPER_TYPE oper) MINIDUMP_INPROC_NOEXCEPT;


#ifdef __cplusplus
}
#endif
