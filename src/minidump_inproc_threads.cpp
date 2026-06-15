#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Copies the caller-provided exception record and context pointers into minidump exception-stream form.

BOOL CaptureExceptionStreamInfo(
    PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
    MINIDUMP_EXCEPTION_STREAM* stream,
    const CONTEXT** contextRecord) noexcept
{
    EXCEPTION_POINTERS* pointers = nullptr;
    EXCEPTION_RECORD record = {};
    CONTEXT* context = nullptr;

    *contextRecord = nullptr;
    ZeroMemory(stream, sizeof(*stream));

    if (exceptionParam == nullptr) {
        return FALSE;
    }
    if (!SafeCopyBytes(&pointers, &exceptionParam->ExceptionPointers, sizeof(pointers)) || pointers == nullptr) {
        return FALSE;
    }
    if (!SafeCopyBytes(&context, &pointers->ContextRecord, sizeof(context)) || context == nullptr) {
        return FALSE;
    }
    if (!SafeCopyBytes(&record, pointers->ExceptionRecord, sizeof(record))) {
        return FALSE;
    }

    stream->ThreadId = exceptionParam->ThreadId;
    stream->ExceptionRecord.ExceptionCode = record.ExceptionCode;
    stream->ExceptionRecord.ExceptionFlags = record.ExceptionFlags;
    stream->ExceptionRecord.ExceptionRecord = reinterpret_cast<ULONG64>(record.ExceptionRecord);
    stream->ExceptionRecord.ExceptionAddress = reinterpret_cast<ULONG64>(record.ExceptionAddress);
    stream->ExceptionRecord.NumberParameters = record.NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS
        ? EXCEPTION_MAXIMUM_PARAMETERS
        : record.NumberParameters;

    for (ULONG i = 0; i < stream->ExceptionRecord.NumberParameters; ++i) {
        stream->ExceptionRecord.ExceptionInformation[i] = static_cast<ULONG64>(record.ExceptionInformation[i]);
    }

    *contextRecord = context;
    return TRUE;
}


// Returns the basic thread record at an index from a SystemProcessInformation buffer.

const INPROC_SYSTEM_THREAD_INFORMATION* SnapshotThreadInfo(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept
{
    if (snapshot.Process == nullptr || index >= snapshot.Process->NumberOfThreads) {
        return nullptr;
    }

    const BYTE* first = reinterpret_cast<const BYTE*>(&snapshot.Process->Threads[0]);
    const BYTE* entry = first + static_cast<SIZE_T>(index) *
        (snapshot.Extended ? sizeof(INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION) : sizeof(INPROC_SYSTEM_THREAD_INFORMATION));
    return snapshot.Extended
        ? &reinterpret_cast<const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION*>(entry)->ThreadInfo
        : reinterpret_cast<const INPROC_SYSTEM_THREAD_INFORMATION*>(entry);
}


// Returns the extended thread record when SystemExtendedProcessInformation is available.

const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION* SnapshotExtendedThreadInfo(
    const INPROC_THREAD_SNAPSHOT& snapshot,
    ULONG32 index) noexcept
{
    if (!snapshot.Extended || snapshot.Process == nullptr || index >= snapshot.Process->NumberOfThreads) {
        return nullptr;
    }

    const BYTE* first = reinterpret_cast<const BYTE*>(&snapshot.Process->Threads[0]);
    return reinterpret_cast<const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION*>(
        first + static_cast<SIZE_T>(index) * sizeof(INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION));
}


// Captures the current process entry from NtQuerySystemInformation into a static buffer, avoiding ToolHelp heap paths.

BOOL QueryCurrentProcessThreadSnapshot(INPROC_THREAD_SNAPSHOT* snapshot) noexcept
{
    ZeroMemory(snapshot, sizeof(*snapshot));

    NtQuerySystemInformationFn querySystem = g_Apis.NtQuerySystemInformation;
    if (querySystem == nullptr) {
        return FALSE;
    }

    ULONG returnLength = 0;
    LONG status = querySystem(
        kSystemExtendedProcessInformation,
        g_ScratchBuffer,
        kScratchBufferSize,
        &returnLength);
    BOOL extended = NT_SUCCESS(status);
    if (!extended) {
        status = querySystem(
            kSystemProcessInformation,
            g_ScratchBuffer,
            kScratchBufferSize,
            &returnLength);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }
    }

    BYTE* cursor = g_ScratchBuffer;
    BYTE* end = g_ScratchBuffer + kScratchBufferSize;
    HANDLE currentPid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
    while (cursor + sizeof(INPROC_SYSTEM_PROCESS_INFORMATION) <= end) {
        INPROC_SYSTEM_PROCESS_INFORMATION* process = reinterpret_cast<INPROC_SYSTEM_PROCESS_INFORMATION*>(cursor);
        if (process->UniqueProcessId == currentPid) {
            snapshot->Process = process;
            snapshot->Extended = extended;
            return TRUE;
        }
        if (process->NextEntryOffset == 0) {
            break;
        }
        cursor += process->NextEntryOffset;
    }

    return FALSE;
}


// Clamps the number of snapshot threads to the fixed writer capacity.

ULONG32 SnapshotThreadCount(const INPROC_THREAD_SNAPSHOT& snapshot) noexcept
{
    if (snapshot.Process == nullptr) {
        return 0;
    }
    return snapshot.Process->NumberOfThreads > kMaxThreads
        ? kMaxThreads
        : snapshot.Process->NumberOfThreads;
}


// Extracts a DWORD thread id from an NT CLIENT_ID record.

DWORD SnapshotThreadId(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept
{
    const INPROC_SYSTEM_THREAD_INFORMATION* info = SnapshotThreadInfo(snapshot, index);
    return info != nullptr ? static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info->ClientId.UniqueThread)) : 0;
}


// Returns a TEB from the extended thread snapshot, falling back to the current TEB for the writing thread.

PVOID SnapshotThreadTeb(const INPROC_THREAD_SNAPSHOT& snapshot, ULONG32 index) noexcept
{
    const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION* info = SnapshotExtendedThreadInfo(snapshot, index);
    if (info != nullptr && info->TebBase != nullptr) {
        return info->TebBase;
    }
    return SnapshotThreadId(snapshot, index) == GetCurrentThreadId() ? GetCurrentTebPointer() : nullptr;
}


// Extracts stack limits from an extended thread snapshot when available.

BOOL SnapshotThreadStackRange(const INPROC_THREAD_SNAPSHOT& snapshot,
                              ULONG32 index,
                              ULONG64* stackStart,
                              ULONG32* stackSize) noexcept
{
    *stackStart = 0;
    *stackSize = 0;

    const INPROC_SYSTEM_EXTENDED_THREAD_INFORMATION* info = SnapshotExtendedThreadInfo(snapshot, index);
    if (info != nullptr) {
        ULONG64 base = reinterpret_cast<ULONG64>(info->StackBase);
        ULONG64 limit = reinterpret_cast<ULONG64>(info->StackLimit);
        if (base > limit && (base - limit) <= 0xffffffffULL) {

            *stackStart = limit;
            *stackSize = static_cast<ULONG32>(base - limit);
            return TRUE;
        }
    }

    return FALSE;
}


// Counts process threads and finds the preferred exception-thread index used to place the exception context RVA.

BOOL CountProcessThreads(DWORD preferredThreadId, ULONG32* threadCount, ULONG32* preferredIndex) noexcept
{
    INPROC_THREAD_SNAPSHOT snapshot = {};
    ULONG32 count = 0;
    ULONG32 foundIndex = 0;
    BOOL foundPreferred = FALSE;

    if (QueryCurrentProcessThreadSnapshot(&snapshot)) {
        count = SnapshotThreadCount(snapshot);
        for (ULONG32 i = 0; i < count; ++i) {
            if (SnapshotThreadId(snapshot, i) == preferredThreadId) {
                foundIndex = i;
                foundPreferred = TRUE;
                break;
            }
        }
    }

    if (count == 0) {
        count = 1;
    }
    *threadCount = count;
    *preferredIndex = foundPreferred ? foundIndex : 0;
    return TRUE;
}


// Takes a single thread snapshot, opens+suspends every other thread, and records an immutable
// per-thread plan so all later passes operate on identical, frozen data. Threads are opened
// BEFORE any suspension to avoid needing the handle table lock while threads are frozen.
BOOL BuildThreadPlanAndFreeze(DWORD preferredThreadId) noexcept
{
    g_ThreadPlanCount = 0;
    g_ExceptionThreadIndex = 0;
    DWORD currentTid = GetCurrentThreadId();

    INPROC_THREAD_SNAPSHOT snapshot = {};
    BOOL haveSnapshot = QueryCurrentProcessThreadSnapshot(&snapshot);

    // Phase 1: enumerate and open handles while every thread is still running.
    if (haveSnapshot) {
        ULONG32 snapshotCount = SnapshotThreadCount(snapshot);
        for (ULONG32 i = 0; i < snapshotCount && g_ThreadPlanCount < kMaxThreads; ++i) {
            DWORD tid = SnapshotThreadId(snapshot, i);
            if (tid == 0) {
                continue;
            }

            INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[g_ThreadPlanCount];
            ZeroMemory(&entry, sizeof(entry));
            entry.ThreadId = tid;
            entry.IsCurrent = (tid == currentTid);
            entry.Teb = SnapshotThreadTeb(snapshot, i);

            const INPROC_SYSTEM_THREAD_INFORMATION* threadInfo = SnapshotThreadInfo(snapshot, i);
            if (threadInfo != nullptr) {
                entry.CreateTime = static_cast<ULONG64>(threadInfo->CreateTime.QuadPart);
                entry.KernelTime = static_cast<ULONG64>(threadInfo->KernelTime.QuadPart);
                entry.UserTime = static_cast<ULONG64>(threadInfo->UserTime.QuadPart);
                entry.StartAddress = reinterpret_cast<ULONG64>(threadInfo->StartAddress);
            }

            if (!entry.IsCurrent) {
                entry.Handle = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE,
                    tid);
            }
            ++g_ThreadPlanCount;
        }
    }

    // Guarantee the writing thread is always represented.
    BOOL haveCurrent = FALSE;
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].IsCurrent) {
            haveCurrent = TRUE;
            break;
        }
    }
    if (!haveCurrent) {
        ULONG32 slot;
        if (g_ThreadPlanCount < kMaxThreads) {
            slot = g_ThreadPlanCount;
            ++g_ThreadPlanCount;
        } else {
            slot = kMaxThreads - 1;
            if (g_ThreadPlan[slot].Handle != nullptr) {
                CloseHandle(g_ThreadPlan[slot].Handle);
            }
        }
        ZeroMemory(&g_ThreadPlan[slot], sizeof(g_ThreadPlan[slot]));
        g_ThreadPlan[slot].ThreadId = currentTid;
        g_ThreadPlan[slot].IsCurrent = TRUE;
    }

    // Guarantee the exception (preferred) thread is always represented. ExceptionStream.ThreadContext
    // aliases a slot inside the contiguous CONTEXT array via g_ExceptionThreadIndex; if the faulting
    // thread were missing from the plan, that index would stay 0 and the exception context RVA would
    // silently point at some OTHER thread's context -- producing an openable but MISLEADING dump.
    // The snapshot can miss it (snapshot failure, or more threads than kMaxThreads), so if it is not
    // present we add it explicitly here, opening its handle now (before any suspension) just like the
    // snapshot threads. preferredThreadId == currentTid is already covered above.
    if (preferredThreadId != 0 && preferredThreadId != currentTid) {
        BOOL havePreferred = FALSE;
        for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
            if (g_ThreadPlan[i].ThreadId == preferredThreadId) {
                havePreferred = TRUE;
                break;
            }
        }
        if (!havePreferred) {
            ULONG32 slot;
            if (g_ThreadPlanCount < kMaxThreads) {
                slot = g_ThreadPlanCount;
                ++g_ThreadPlanCount;
            } else {
                // Plan is full: evict a non-current, non-preferred slot so the exception thread fits.
                // Prefer the last slot; never evict the writing thread (its context is mandatory too).
                slot = kMaxThreads - 1;
                if (g_ThreadPlan[slot].IsCurrent && kMaxThreads >= 2) {
                    slot = kMaxThreads - 2;
                }
                if (g_ThreadPlan[slot].Handle != nullptr) {
                    CloseHandle(g_ThreadPlan[slot].Handle);
                }
            }
            ZeroMemory(&g_ThreadPlan[slot], sizeof(g_ThreadPlan[slot]));
            g_ThreadPlan[slot].ThreadId = preferredThreadId;
            g_ThreadPlan[slot].IsCurrent = FALSE;
            g_ThreadPlan[slot].Handle = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE,
                preferredThreadId);
        }
    }

    // Phase 2: freeze every other thread now that all handles are open.
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];
        if (!entry.IsCurrent && entry.Handle != nullptr) {
            if (SuspendThread(entry.Handle) != static_cast<DWORD>(-1)) {
                entry.Suspended = TRUE;
            }
        }
    }

    // Phase 3: with other threads frozen, capture TEB, stack range and priority consistently.
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];
        PVOID teb = entry.Teb;

        if (entry.IsCurrent) {
            teb = GetCurrentTebPointer();
            entry.Priority = GetThreadPriority(GetCurrentThread());
        } else {
            if (teb == nullptr && entry.Handle != nullptr) {
                teb = QueryThreadTeb(entry.Handle, entry.ThreadId);
            }
            if (entry.Handle != nullptr) {
                entry.Priority = GetThreadPriority(entry.Handle);
            }
        }
        entry.Teb = teb;

        INPROC_NT_TIB tib = {};
        if (teb != nullptr && SafeCopyBytes(&tib, teb, sizeof(tib))) {
            ULONG64 base = reinterpret_cast<ULONG64>(tib.StackBase);
            ULONG64 limit = reinterpret_cast<ULONG64>(tib.StackLimit);
            if (base > limit && (base - limit) <= 0xffffffffULL) {
                entry.StackStart = limit;
                entry.StackSize = static_cast<ULONG32>(base - limit);
            }
        }

        if (entry.ThreadId == preferredThreadId) {
            g_ExceptionThreadIndex = i;
        }
    }

    return TRUE;
}


// Resumes and closes all threads frozen by BuildThreadPlanAndFreeze. Idempotent.
void ResumeThreadPlan() noexcept
{
    for (ULONG32 i = 0; i < g_ThreadPlanCount; ++i) {
        INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];
        if (entry.Handle != nullptr) {
            if (entry.Suspended) {
                ResumeThread(entry.Handle);
                entry.Suspended = FALSE;
            }
            CloseHandle(entry.Handle);
            entry.Handle = nullptr;
        }
    }
    g_ThreadPlanCount = 0;
}


// Queries a non-current thread TEB through pre-resolved NtQueryInformationThread.

PVOID QueryThreadTeb(HANDLE hThread, DWORD threadId) noexcept
{
    if (threadId == GetCurrentThreadId()) {
        return GetCurrentTebPointer();
    }

    NtQueryInformationThreadFn queryThread = g_Apis.NtQueryInformationThread;
    if (queryThread == nullptr || hThread == nullptr) {
        return nullptr;
    }

    INPROC_THREAD_BASIC_INFORMATION basic = {};
    if (!NT_SUCCESS(queryThread(hThread, 0, &basic, sizeof(basic), nullptr))) {
        return nullptr;
    }
    return basic.TebBaseAddress;
}


// Builds the stack memory descriptor for a thread from its TEB stack limits.

void FillThreadStackDescriptor(PVOID teb, MINIDUMP_MEMORY_DESCRIPTOR* stack) noexcept
{
    INPROC_NT_TIB tib = {};
    ZeroMemory(stack, sizeof(*stack));

    if (teb == nullptr || !SafeCopyBytes(&tib, teb, sizeof(tib))) {
        return;
    }

    ULONG64 stackBase = reinterpret_cast<ULONG64>(tib.StackBase);
    ULONG64 stackLimit = reinterpret_cast<ULONG64>(tib.StackLimit);
    if (stackBase > stackLimit) {
        stack->StartOfMemoryRange = stackLimit;
        stack->Memory.DataSize = static_cast<ULONG32>(stackBase - stackLimit);
        stack->Memory.Rva = 0;
    }
}


// Builds a MINIDUMP_THREAD record without allocating, using snapshot data where possible.

void FillThreadDescriptor(DWORD threadId,
                          ULONG32 index,
                          ULONG32 contextBaseRva,
                          PVOID knownTeb,
                          MINIDUMP_THREAD* thread) noexcept
{
    HANDLE hThread = nullptr;
    PVOID teb = knownTeb;

    ZeroMemory(thread, sizeof(*thread));
    thread->ThreadId = threadId;
    thread->PriorityClass = GetPriorityClass(GetCurrentProcess());
    thread->ThreadContext.Rva = contextBaseRva + index * sizeof(CONTEXT);
    thread->ThreadContext.DataSize = sizeof(CONTEXT);

    if (threadId == GetCurrentThreadId()) {
        teb = GetCurrentTebPointer();
        thread->Priority = GetThreadPriority(GetCurrentThread());
    } else if (teb == nullptr) {
        hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);

        if (hThread != nullptr) {
            teb = QueryThreadTeb(hThread, threadId);
            CloseHandle(hThread);
        }
    }

    thread->Teb = reinterpret_cast<ULONG64>(teb);
    FillThreadStackDescriptor(teb, &thread->Stack);
}


// Writes ThreadListStream from the immutable thread plan. Each thread's CONTEXT slot is at a
// fixed RVA, and (for selected-memory dumps) the stack descriptor RVA is computed in the same
// order the stack bytes are emitted so debuggers can reconstruct call stacks.

BOOL WriteThreadList(HANDLE hFile,
                     ULONG32 threadCount,
                     ULONG32 contextBaseRva,
                     ULONG64 stackBytesBaseRva,
                     BOOL stacksInMemoryList) noexcept
{
    MINIDUMP_THREAD thread = {};
    DWORD priorityClass = GetPriorityClass(GetCurrentProcess());
    ULONG64 stackRva = stackBytesBaseRva;

    if (!WriteAll(hFile, &threadCount, sizeof(threadCount))) {
        return FALSE;
    }

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        const INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];
        ZeroMemory(&thread, sizeof(thread));
        thread.ThreadId = entry.ThreadId;
        thread.PriorityClass = priorityClass;
        thread.Priority = entry.Priority;
        thread.Teb = reinterpret_cast<ULONG64>(entry.Teb);
        thread.ThreadContext.Rva = contextBaseRva + i * sizeof(CONTEXT);
        thread.ThreadContext.DataSize = sizeof(CONTEXT);

        if (entry.StackSize != 0) {
            thread.Stack.StartOfMemoryRange = entry.StackStart;
            thread.Stack.Memory.DataSize = entry.StackSize;
            if (stacksInMemoryList) {
                thread.Stack.Memory.Rva = static_cast<RVA>(stackRva);
                stackRva += entry.StackSize;
            }
        }

        if (!WriteAll(hFile, &thread, sizeof(thread))) {
            return FALSE;
        }
    }

    return TRUE;
}


// Writes the contiguous context-record backing store referenced by ThreadListStream and
// ExceptionStream, in the exact order of the frozen thread plan. The faulting thread uses the
// caller-provided exception context; other threads are already suspended, so GetThreadContext
// is consistent with the stack bytes captured elsewhere in this dump.

BOOL WriteThreadContexts(HANDLE hFile, ULONG32 threadCount, PMINIDUMP_EXCEPTION_INFORMATION exceptionParam) noexcept
{
    MINIDUMP_EXCEPTION_STREAM exceptionStream = {};
    const CONTEXT* exceptionContext = nullptr;
    BOOL hasExceptionContext = CaptureExceptionStreamInfo(exceptionParam, &exceptionStream, &exceptionContext);

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        const INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];

        if (hasExceptionContext && exceptionContext != nullptr && entry.ThreadId == exceptionStream.ThreadId) {
            if (!WriteAll(hFile, exceptionContext, sizeof(CONTEXT))) {
                return FALSE;
            }
            continue;
        }

        ZeroMemory(&g_ContextScratch, sizeof(g_ContextScratch));
        BOOL captured = FALSE;

        if (entry.IsCurrent) {
            RtlCaptureContext(&g_ContextScratch);
            captured = TRUE;
        } else if (entry.Handle != nullptr && entry.Suspended) {
            g_ContextScratch.ContextFlags = CONTEXT_ALL;
            captured = GetThreadContext(entry.Handle, &g_ContextScratch);
        }

        if (captured) {
            if (!WriteAll(hFile, &g_ContextScratch, sizeof(g_ContextScratch))) {
                return FALSE;
            }
        } else if (!WriteZeros(hFile, sizeof(CONTEXT))) {
            return FALSE;
        }
    }

    return TRUE;
}


// Writes ThreadInfoListStream from the NT thread snapshot instead of opening every thread for GetThreadTimes.

BOOL WriteThreadInfoList(HANDLE hFile, ULONG32 threadCount) noexcept
{
    MINIDUMP_THREAD_INFO_LIST header = {};
    MINIDUMP_THREAD_INFO info = {};

    header.SizeOfHeader = sizeof(header);
    header.SizeOfEntry = sizeof(info);
    header.NumberOfEntries = threadCount;
    if (!WriteAll(hFile, &header, sizeof(header))) {
        return FALSE;
    }

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        const INPROC_THREAD_PLAN_ENTRY& entry = g_ThreadPlan[i];
        ZeroMemory(&info, sizeof(info));
        info.ThreadId = entry.ThreadId;
        if (entry.IsCurrent) {
            info.DumpFlags = MINIDUMP_THREAD_INFO_WRITING_THREAD;
        }
        info.CreateTime = entry.CreateTime;
        info.KernelTime = entry.KernelTime;
        info.UserTime = entry.UserTime;
        info.StartAddress = entry.StartAddress;

        if (!WriteAll(hFile, &info, sizeof(info))) {
            return FALSE;
        }
    }

    return TRUE;
}


// Reads a thread stack range from its TEB, opening the thread only when it is not the current thread.

BOOL QueryThreadStackRange(DWORD threadId, ULONG64* stackStart, ULONG32* stackSize) noexcept
{
    HANDLE hThread = nullptr;
    PVOID teb = nullptr;
    INPROC_NT_TIB tib = {};

    *stackStart = 0;
    *stackSize = 0;

    if (threadId == GetCurrentThreadId()) {
        teb = GetCurrentTebPointer();
    } else {
        hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (hThread != nullptr) {
            teb = QueryThreadTeb(hThread, threadId);
            CloseHandle(hThread);
        }
    }

    if (teb == nullptr || !SafeCopyBytes(&tib, teb, sizeof(tib))) {
        return FALSE;
    }

    ULONG64 base = reinterpret_cast<ULONG64>(tib.StackBase);
    ULONG64 limit = reinterpret_cast<ULONG64>(tib.StackLimit);
    if (base <= limit || (base - limit) > 0xffffffffULL) {
        return FALSE;
    }

    *stackStart = limit;
    *stackSize = static_cast<ULONG32>(base - limit);
    return TRUE;
}


// Counts stack ranges that will be included in the selected MemoryList stream.

BOOL CountStackMemoryRanges(ULONG32 threadCount, ULONG64* rangeCount, ULONG64* bytesCount) noexcept
{
    ULONG64 count = 0;
    ULONG64 bytes = 0;

    for (ULONG32 i = 0; i < threadCount && i < g_ThreadPlanCount; ++i) {
        if (g_ThreadPlan[i].StackSize != 0) {
            ++count;
            bytes += g_ThreadPlan[i].StackSize;
        }
    }

    *rangeCount = count;
    *bytesCount = bytes;
    return TRUE;
}


// Extracts RSP/ESP from a CONTEXT for prioritizing indirect-memory scans near the crash frame.

ULONG64 ContextStackPointer(const CONTEXT* context) noexcept
{
    if (context == nullptr) {
        return 0;
    }
#if defined(_M_X64)
    return context->Rsp;
#elif defined(_M_IX86)
    return context->Esp;
#else
    return 0;
#endif
}


// Returns the best stack range for a thread, preferring the live TEB for the current thread to avoid stale snapshot limits.

BOOL QuerySnapshotOrThreadStackRange(const INPROC_THREAD_SNAPSHOT& snapshot,
                                     ULONG32 index,
                                     ULONG64* stackStart,
                                     ULONG32* stackSize) noexcept
{
    DWORD threadId = SnapshotThreadId(snapshot, index);
    if (threadId == GetCurrentThreadId() && QueryThreadStackRange(threadId, stackStart, stackSize)) {
        return TRUE;
    }
    if (SnapshotThreadStackRange(snapshot, index, stackStart, stackSize)) {
        return TRUE;
    }
    return QueryThreadStackRange(threadId, stackStart, stackSize);
}


} // namespace minidump_inproc::internal
