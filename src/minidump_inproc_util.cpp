#include "minidump_inproc_internal.h"

namespace minidump_inproc {
namespace internal {

// Rounds a file RVA or stream size up to the 4-byte alignment required by the minidump format.

ULONG64 Align4(ULONG64 value) noexcept
{
    return (value + 3ULL) & ~3ULL;
}


// Rounds an address down to an alignment boundary. The indirect-memory scanner uses this to normalize pointers to page starts.

ULONG64 AlignDown(ULONG64 value, ULONG64 alignment) noexcept
{
    return value & ~(alignment - 1ULL);
}


// Reads the current thread segment register to obtain the PEB without calling loader APIs or allocating memory.

INPROC_PEB* GetCurrentPeb() noexcept
{
#if defined(_M_X64)
    return reinterpret_cast<INPROC_PEB*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<INPROC_PEB*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}


// Reads the TEB pointer directly from the architecture-specific segment register.

PVOID GetCurrentTebPointer() noexcept
{
#if defined(_M_X64)
    return reinterpret_cast<PVOID>(__readgsqword(0x30));
#elif defined(_M_IX86)
    return reinterpret_cast<PVOID>(__readfsdword(0x18));
#else
    return nullptr;
#endif
}

// Caches process-invariant system information and pre-resolves low-level NTDLL entry points during
// normal execution so the crash path does not call GetNativeSystemInfo/GetProcAddress lazily.

void ResolveInprocApis() noexcept
{
    // Idempotent: the load-time auto-initializer and any explicit caller(s) may all reach here,
    // possibly from different threads. Resolving the same routines again would be harmless (the
    // values are identical), but once a previous call has finished we skip the repeat work. The
    // flag is published with InterlockedExchange below, so a non-zero read here means a prior call
    // already populated g_Apis / g_NativeSystemInfo.
    while (auto init_value = 
        _InterlockedCompareExchange(&g_ApisInitializeStatus, INITIALIZING, NOT_INITIALIZED)) {
        if (init_value != INITIALIZING) {
			return;
		}
		YieldProcessor(); // another thread is initializing; wait for it to finish
    }

    GetNativeSystemInfo(&g_NativeSystemInfo);
    if (g_NativeSystemInfo.dwPageSize == 0) {
        g_NativeSystemInfo.dwPageSize = 4096;
    }
#pragma warning(push)
#pragma warning(disable: 4191) // 局部关闭 C4191 警告
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll != nullptr) {
		g_Apis.RtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
			GetProcAddress(ntdll, "RtlGetVersion"));
		g_Apis.NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(
			GetProcAddress(ntdll, "NtQueryInformationThread"));
		g_Apis.NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
			GetProcAddress(ntdll, "NtQuerySystemInformation"));
		g_Apis.NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
			GetProcAddress(ntdll, "NtQueryInformationProcess"));
		// Unloaded-module ring accessor (Windows Vista+). When absent (very old OS), the
		// UnloadedModuleListStream is simply omitted.
		g_Apis.RtlGetUnloadEventTraceEx = reinterpret_cast<RtlGetUnloadEventTraceExFn>(
			GetProcAddress(ntdll, "RtlGetUnloadEventTraceEx"));
	}

    // GDI/USER object counts come from user32!GetGuiResources. Resolve it ONLY if user32 is already
    // mapped (GetModuleHandleW, never LoadLibraryW) so this library never forces a user32 dependency
    // on console/service processes. Non-GUI processes simply leave the pointer null and the comment
    // stream reports GDI/USER as n/a.
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        g_Apis.GetGuiResources = reinterpret_cast<GetGuiResourcesFn>(
            GetProcAddress(user32, "GetGuiResources"));
    }
#pragma warning(pop)

	// Create unnamed kernel mutexes.  Their handles are stored inside g_Protected (which
	// becomes PAGE_READONLY after this function), so they cannot be overwritten by wild
	// writes.  The mutex objects themselves live in kernel space, immune to user-mode
	// corruption, and are auto-released if the owning thread terminates abnormally.
	g_Protected.CommentMutex = CreateMutexW(nullptr, FALSE, nullptr);
	g_Protected.DumpMutex    = CreateMutexW(nullptr, FALSE, nullptr);

	// Compute and store the CRC over all populated fields (last, so a partial init can never
	// match).  Then publish INITIALIZED so concurrent init callers can proceed.
	SetProtectedGlobalsCrc();
	_InterlockedExchange(&g_ApisInitializeStatus, INITIALIZED);

	// Lock the page: all init-once data is now populated, so any wild write from this point
	// forward will trigger an access violation instead of silently corrupting the globals.
	ProtectInitGlobals();
}

// Sets the g_Protected page to PAGE_READONLY.  Safe to call multiple times (VirtualProtect
// on an already-readonly page is a fast no-op).  We use the kernel32 wrapper (not the NTDLL
// syscall) because this runs during normal init, not on the crash path.
void ProtectInitGlobals() noexcept
{
	DWORD oldProtect = 0;
	VirtualProtect(&g_Protected, sizeof(g_Protected), PAGE_READONLY, &oldProtect);
}

DWORD NativePageSize() noexcept
{
    return g_NativeSystemInfo.dwPageSize != 0 ? g_NativeSystemInfo.dwPageSize : 4096;
}

BYTE* MinimumApplicationAddress() noexcept
{
    return static_cast<BYTE*>(g_NativeSystemInfo.lpMinimumApplicationAddress);
}

BYTE* MaximumApplicationAddress() noexcept
{
    return static_cast<BYTE*>(g_NativeSystemInfo.lpMaximumApplicationAddress);
}


// Normalizes caller input into a production hard cap. Values below 4 MB are clamped to 4 MB.

ULONG64 NormalizeHardMaxFileSize(ULONG64 maxFileSize) noexcept
{
    return maxFileSize >= kMinHardMaxFileSize ? maxFileSize : kMinHardMaxFileSize;
}

// Converts a FILETIME timestamp to the seconds-since-1970 format used by MINIDUMP_MISC_INFO.

ULONG32 FileTimeToUnixSeconds(const FILETIME& ft) noexcept
{
    ULARGE_INTEGER value = {};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    if (value.QuadPart <= kFileTimeUnixEpoch) {
        return 0;
    }
    return static_cast<ULONG32>((value.QuadPart - kFileTimeUnixEpoch) / kFileTimeTicksPerSecond);
}


// Converts a FILETIME duration to seconds for process user/kernel time fields.

ULONG32 FileTimeDurationSeconds(const FILETIME& ft) noexcept
{
    ULARGE_INTEGER value = {};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return static_cast<ULONG32>(value.QuadPart / kFileTimeTicksPerSecond);
}


// Probes every page touched by a range under SEH so corrupt middle pages do not tear down dump generation.

BOOL SafeReadBytes(const void* address, SIZE_T size) noexcept
{
    if (address == nullptr || size == 0) {
        return FALSE;
    }

#if defined(_MSC_VER)
    __try {
        ULONG_PTR pageSize = NativePageSize();
        ULONG_PTR start = reinterpret_cast<ULONG_PTR>(address);
        ULONG_PTR end = start + size;
        if (end <= start) {
            return FALSE;
        }

        const volatile BYTE* bytes = static_cast<const volatile BYTE*>(address);
        (void)bytes[0];
        ULONG_PTR cursor = (start & ~(pageSize - 1ULL)) + pageSize;
        while (cursor < end) {
            (void)*reinterpret_cast<const volatile BYTE*>(cursor);
            cursor += pageSize;
        }
        (void)*reinterpret_cast<const volatile BYTE*>(end - 1);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#else
    return TRUE;
#endif
}



// Copies memory under SEH; this is used when reading potentially damaged process structures such as PEB/LDR or exception records.

BOOL SafeCopyBytes(void* dst, const void* src, SIZE_T size) noexcept
{
    if (dst == nullptr || src == nullptr) {
        return FALSE;
    }

#if defined(_MSC_VER)
    __try {
        CopyMemory(dst, src, size);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#else
    CopyMemory(dst, src, size);
    return TRUE;
#endif
}


// Safely validates and clamps an LDR Unicode module path before it is serialized as a MINIDUMP_STRING.

ULONG32 SafeModuleNameLength(const INPROC_UNICODE_STRING* name) noexcept
{
    INPROC_UNICODE_STRING local = {};
    if (!SafeCopyBytes(&local, name, sizeof(local))) {
        return 0;
    }

    ULONG32 length = local.Length;
    if (length > kMaxModuleNameBytes) {
        length = kMaxModuleNameBytes;
    }
    length &= ~1UL;

    if (length != 0 && !SafeReadBytes(local.Buffer, length)) {
        return 0;
    }
    return length;
}


// Computes the on-disk size of a MINIDUMP_STRING including the terminating WCHAR and 4-byte padding.

ULONG32 MinidumpStringSize(ULONG32 bytes) noexcept
{
    return static_cast<ULONG32>(Align4(sizeof(ULONG32) + bytes + sizeof(WCHAR)));
}


// Writes a byte range to the caller-provided file handle, splitting very large writes into DWORD-sized WriteFile calls.

BOOL WriteAll(HANDLE hFile, const void* data, ULONG64 size) noexcept
{
    const BYTE* bytes = static_cast<const BYTE*>(data);
    ULONG64 remaining = size;

    while (remaining != 0) {
        DWORD chunk = remaining > kWriteChunk ? static_cast<DWORD>(kWriteChunk) : static_cast<DWORD>(remaining);
        DWORD written = 0;
        if (!WriteFile(hFile, bytes, chunk, &written, nullptr) || written == 0) {
            return FALSE;
        }
        bytes += written;
        remaining -= written;
    }
    return TRUE;
}


// Writes zero-filled padding without heap allocation by reusing a static zero page.

BOOL WriteZeros(HANDLE hFile, ULONG64 size) noexcept
{
    static const BYTE zeros[4096] = {};
    ULONG64 remaining = size;

    while (remaining != 0) {
        DWORD chunk = remaining > sizeof(zeros) ? static_cast<DWORD>(sizeof(zeros)) : static_cast<DWORD>(remaining);
        if (!WriteAll(hFile, zeros, chunk)) {
            return FALSE;
        }
        remaining -= chunk;
    }
    return TRUE;
}


// Serializes a Windows UNICODE_STRING as a MINIDUMP_STRING while tolerating invalid string buffers.

BOOL WriteMinidumpString(HANDLE hFile, const INPROC_UNICODE_STRING* name) noexcept
{
    INPROC_UNICODE_STRING local = {};
    ULONG32 length = 0;
    WCHAR nul = 0;
    ULONG32 total = 0;

    if (SafeCopyBytes(&local, name, sizeof(local))) {
        length = local.Length;
        if (length > kMaxModuleNameBytes) {
            length = kMaxModuleNameBytes;
        }
        length &= ~1UL;
        if (length != 0 && !SafeReadBytes(local.Buffer, length)) {
            length = 0;
        }
    }

    total = MinidumpStringSize(length);
    if (!WriteAll(hFile, &length, sizeof(length))) {
        return FALSE;
    }
    if (length != 0 && !WriteRegionBytes(hFile, reinterpret_cast<BYTE*>(local.Buffer), length)) {
        return FALSE;
    }
    if (!WriteAll(hFile, &nul, sizeof(nul))) {
        return FALSE;
    }
    return WriteZeros(hFile, total - sizeof(length) - length - sizeof(nul));
}


// Returns whether a virtual memory protection value is readable enough to safely include in a dump.

BOOL IsDumpableProtect(DWORD protect) noexcept
{
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return FALSE;
    }

    protect &= 0xff;
    return protect == PAGE_READONLY ||
           protect == PAGE_READWRITE ||
           protect == PAGE_WRITECOPY ||
           protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE ||
           protect == PAGE_EXECUTE_WRITECOPY;
}


// Returns whether a protection value represents writable image data for MiniDumpWithDataSegs.

BOOL IsWritableProtect(DWORD protect) noexcept
{
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return FALSE;
    }
    protect &= 0xff;
    return protect == PAGE_READWRITE ||
           protect == PAGE_WRITECOPY ||
           protect == PAGE_EXECUTE_READWRITE ||
           protect == PAGE_EXECUTE_WRITECOPY;
}


// Decides whether a VirtualQuery region should be included as optional selected memory, currently writable MEM_IMAGE data segments.

BOOL ShouldIncludeExtraMemoryRange(const MEMORY_BASIC_INFORMATION& mbi,
                                   BOOL includeDataSegs) noexcept
{
    if (mbi.State != MEM_COMMIT || !IsDumpableProtect(mbi.Protect)) {
        return FALSE;
    }
    if (includeDataSegs && mbi.Type == MEM_IMAGE && IsWritableProtect(mbi.Protect)) {
        return TRUE;
    }
    return FALSE;
}

    // Returns a pointer to the next character in a UTF-8 encoded string
	LPCSTR UTF8CharNextA(LPCSTR lpCurrentChar) noexcept
	{
		if (lpCurrentChar == nullptr)
			return nullptr;

		const unsigned char* p = reinterpret_cast<const unsigned char*>(lpCurrentChar);

		unsigned char c = *p;

		if (c == 0)
		{
			// End of string, do not advance
			return lpCurrentChar;
		}
		else if ((c & 0x80) == 0x00) {
			// ASCII, 1 byte, no continuation bytes to check
			p += 1;
		}
		else if ((c & 0xE0) == 0xC0) {
			// 2-byte sequence, expect 1 continuation byte (10xxxxxx)
			if ((p[1] & 0xC0) == 0x80)
				p += 2;
			else
				p += 1; // Truncated or invalid, advance 1 byte to recover
		}
		else if ((c & 0xF0) == 0xE0) {
			// 3-byte sequence, expect 2 continuation bytes (10xxxxxx)
			if ((p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80)
				p += 3;
			else if ((p[1] & 0xC0) == 0x80)
				p += 2; // Only 1 valid continuation byte found
			else
				p += 1; // No valid continuation byte, advance 1 byte to recover
		}
		else if ((c & 0xF8) == 0xF0) {
			// 4-byte sequence, expect 3 continuation bytes (10xxxxxx)
			if ((p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80)
				p += 4;
			else if ((p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80)
				p += 3; // Only 2 valid continuation bytes found
			else if ((p[1] & 0xC0) == 0x80)
				p += 2; // Only 1 valid continuation byte found
			else
				p += 1; // No valid continuation byte, advance 1 byte to recover
		}
		else {
			// Invalid leading byte, advance 1 byte to recover
			p += 1;
		}

		return reinterpret_cast<LPCSTR>(p);
	}

	// Returns a pointer to the next character in a DBCS encoded string.
	// DBCS (Double Byte Character Set):
	// Lead byte     → 2-byte character, advance 2 bytes
	// Non-lead byte → 1-byte character, advance 1 byte
	LPCSTR DBCSCharNextA(LPCSTR lpCurrentChar) noexcept
	{
		if (lpCurrentChar == nullptr)
			return nullptr;

		const unsigned char* p = reinterpret_cast<const unsigned char*>(lpCurrentChar);
		if (*p == 0) {
			// End of string, do not advance
			return lpCurrentChar;
		}

		// IsDBCSLeadByte checks whether the byte is a DBCS lead byte
		// based on the current thread ACP (e.g. GBK: 0x81~0xFE, Shift-JIS: 0x81~0x9F / 0xE0~0xFC)
		if (IsDBCSLeadByte(*p)) {
			// Lead byte found, expect a trail byte to follow
			// Guard against a truncated sequence where trail byte is '\0'
			if (*(p + 1) != 0)
				p += 2;
			else
				p += 1; // Truncated sequence, advance 1 byte to recover
		}
		else {
			// Single-byte character
			p += 1;
		}

		return reinterpret_cast<LPCSTR>(p);
	}

	// Truncates the input multi-byte string to the maximum allowed length to covert to wide string.
	// Returns the number of bytes to convert.
	int TruncateMultiByteString(LPCSTR lpMultiByteStr, int maxWideChars) noexcept
	{
		if (lpMultiByteStr == nullptr) {
			return 0;
		}
		LPCSTR lpEnd = lpMultiByteStr;
		int left = maxWideChars;
		if (GetACP() == CP_UTF8) {
			while (left > 0) {
				--left;
				LPCSTR lpNext = UTF8CharNextA(lpEnd);
				if (lpEnd == lpNext) {
					// Reached the end of the string
					break;
				}
				if (lpNext - lpEnd >= 4) {
					// 4-byte utf-8 character, count as 2 utf-16 characters
					if (left == 0) {
						// No more space for the second utf-16 character, truncate here
						break;
					}
					--left;
				}
				lpEnd = lpNext;
			}
		}
		else {
			while (left > 0) {
				--left;
				LPCSTR lpNext = DBCSCharNextA(lpEnd);
				if (lpEnd == lpNext) {
					// Reached the end of the string
					break;
				}
				lpEnd = lpNext;
			}
		}
		return static_cast<int>(lpEnd - lpMultiByteStr);
	}

} // namespace internal
} // namespace minidump_inproc
