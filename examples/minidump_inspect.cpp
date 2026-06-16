#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <wchar.h>

namespace {

const wchar_t* StreamName(ULONG32 type) noexcept
{
    switch (type) {
    case UnusedStream: return L"UnusedStream";
    case ReservedStream0: return L"ReservedStream0";
    case ReservedStream1: return L"ReservedStream1";
    case ThreadListStream: return L"ThreadListStream";
    case ModuleListStream: return L"ModuleListStream";
    case MemoryListStream: return L"MemoryListStream";
    case ExceptionStream: return L"ExceptionStream";
    case SystemInfoStream: return L"SystemInfoStream";
    case ThreadExListStream: return L"ThreadExListStream";
    case Memory64ListStream: return L"Memory64ListStream";
    case CommentStreamA: return L"CommentStreamA";
    case CommentStreamW: return L"CommentStreamW";
    case HandleDataStream: return L"HandleDataStream";
    case FunctionTableStream: return L"FunctionTableStream";
    case UnloadedModuleListStream: return L"UnloadedModuleListStream";
    case MiscInfoStream: return L"MiscInfoStream";
    case MemoryInfoListStream: return L"MemoryInfoListStream";
    case ThreadInfoListStream: return L"ThreadInfoListStream";
    case HandleOperationListStream: return L"HandleOperationListStream";
    case TokenStream: return L"TokenStream";
    case JavaScriptDataStream: return L"JavaScriptDataStream";
    case SystemMemoryInfoStream: return L"SystemMemoryInfoStream";
    case ProcessVmCountersStream: return L"ProcessVmCountersStream";
    case IptTraceStream: return L"IptTraceStream";
    case ThreadNamesStream: return L"ThreadNamesStream";
    default: return L"UnknownStream";
    }
}

BOOL ReadAt(HANDLE file, ULONG64 offset, void* buffer, DWORD size) noexcept
{
    LARGE_INTEGER pos = {};
    pos.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN)) {
        return FALSE;
    }
    DWORD read = 0;
    return ReadFile(file, buffer, size, &read, nullptr) && read == size;
}

void PrintStreamDetails(HANDLE file, const MINIDUMP_DIRECTORY& dir) noexcept
{
    switch (dir.StreamType) {
    case ThreadListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            wprintf(L"    threads=%lu\n", count);
        }
        break;
    }
    case ModuleListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            wprintf(L"    modules=%lu\n", count);
        }
        break;
    }
    case MemoryListStream: {
        ULONG32 count = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count))) {
            ULONG64 bytes = 0;
            for (ULONG32 i = 0; i < count; ++i) {
                MINIDUMP_MEMORY_DESCRIPTOR desc = {};
                if (!ReadAt(file, dir.Location.Rva + sizeof(count) + static_cast<ULONG64>(i) * sizeof(desc), &desc, sizeof(desc))) {
                    break;
                }
                bytes += desc.Memory.DataSize;
            }
            wprintf(L"    ranges=%lu bytes=%llu\n", count, bytes);
        }
        break;
    }
    case Memory64ListStream: {
        ULONG64 count = 0;
        ULONG64 baseRva = 0;
        if (ReadAt(file, dir.Location.Rva, &count, sizeof(count)) &&
            ReadAt(file, dir.Location.Rva + sizeof(count), &baseRva, sizeof(baseRva))) {
            ULONG64 bytes = 0;
            for (ULONG64 i = 0; i < count; ++i) {
                MINIDUMP_MEMORY_DESCRIPTOR64 desc = {};
                if (!ReadAt(file, dir.Location.Rva + sizeof(count) + sizeof(baseRva) + i * sizeof(desc), &desc, sizeof(desc))) {
                    break;
                }
                bytes += desc.DataSize;
            }
            wprintf(L"    ranges=%llu bytes=%llu baseRva=0x%llx\n", count, bytes, baseRva);
        }
        break;
    }
    case ExceptionStream: {
        MINIDUMP_EXCEPTION_STREAM ex = {};
        if (ReadAt(file, dir.Location.Rva, &ex, sizeof(ex))) {
            wprintf(L"    thread=%lu code=0x%08lx address=0x%llx contextRva=0x%lx contextSize=%lu\n",
                    ex.ThreadId,
                    ex.ExceptionRecord.ExceptionCode,
                    ex.ExceptionRecord.ExceptionAddress,
                    ex.ThreadContext.Rva,
                    ex.ThreadContext.DataSize);
        }
        break;
    }
    case SystemInfoStream: {
        MINIDUMP_SYSTEM_INFO info = {};
        if (ReadAt(file, dir.Location.Rva, &info, sizeof(info))) {
            wprintf(L"    arch=%u processors=%u os=%lu.%lu build=%lu\n",
                    info.ProcessorArchitecture,
                    info.NumberOfProcessors,
                    info.MajorVersion,
                    info.MinorVersion,
                    info.BuildNumber);
        }
        break;
    }
    case MiscInfoStream: {
        MINIDUMP_MISC_INFO info = {};
        if (ReadAt(file, dir.Location.Rva, &info, sizeof(info))) {
            wprintf(L"    pid=%lu flags=0x%lx\n", info.ProcessId, info.Flags1);
        }
        break;
    }
    case MemoryInfoListStream: {
        MINIDUMP_MEMORY_INFO_LIST list = {};
        if (ReadAt(file, dir.Location.Rva, &list, sizeof(list))) {
            wprintf(L"    entries=%llu entrySize=%lu\n", list.NumberOfEntries, list.SizeOfEntry);
        }
        break;
    }
    case CommentStreamA: {
        // ANSI memory-summary comment. Print it as text (WinDbg shows it automatically on load).
        char text[1024] = {};
        DWORD size = dir.Location.DataSize;
        if (size >= sizeof(text)) {
            size = sizeof(text) - 1;
        }
        if (size != 0 && ReadAt(file, dir.Location.Rva, text, size)) {
            text[size] = '\0';
            wprintf(L"    %hs\n", text);
        }
        break;
    }
    case ThreadInfoListStream: {
        MINIDUMP_THREAD_INFO_LIST list = {};
        if (ReadAt(file, dir.Location.Rva, &list, sizeof(list))) {
            wprintf(L"    entries=%lu entrySize=%lu\n", list.NumberOfEntries, list.SizeOfEntry);
        }
        break;
    }
    default:
        break;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        fwprintf(stderr, L"usage: MiniDumpInspect <dump.dmp>\n");
        return 2;
    }

    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"open failed: %ls (%lu)\n", argv[1], GetLastError());
        return 1;
    }

    LARGE_INTEGER fileSize = {};
    MINIDUMP_HEADER header = {};
    if (!GetFileSizeEx(file, &fileSize) || !ReadAt(file, 0, &header, sizeof(header))) {
        fwprintf(stderr, L"read header failed\n");
        CloseHandle(file);
        return 1;
    }
    if (header.Signature != MINIDUMP_SIGNATURE) {
        fwprintf(stderr, L"not a minidump: signature=0x%lx\n", header.Signature);
        CloseHandle(file);
        return 1;
    }

    wprintf(L"file=%ls\n", argv[1]);
    wprintf(L"size=%llu bytes\n", static_cast<ULONG64>(fileSize.QuadPart));
    wprintf(L"version=0x%lx streams=%lu directoryRva=0x%lx flags=0x%llx\n",
            header.Version,
            header.NumberOfStreams,
            header.StreamDirectoryRva,
            header.Flags);

    for (ULONG32 i = 0; i < header.NumberOfStreams; ++i) {
        MINIDUMP_DIRECTORY dir = {};
        ULONG64 dirOffset = header.StreamDirectoryRva + static_cast<ULONG64>(i) * sizeof(dir);
        if (!ReadAt(file, dirOffset, &dir, sizeof(dir))) {
            fwprintf(stderr, L"read directory %lu failed\n", i);
            break;
        }
        wprintf(L"[%02lu] %-28ls type=%lu rva=0x%08lx size=%lu\n",
                i,
                StreamName(dir.StreamType),
                dir.StreamType,
                dir.Location.Rva,
                dir.Location.DataSize);
        PrintStreamDetails(file, dir);
    }

    CloseHandle(file);
    return 0;
}
