#include "minidump_inproc_internal.h"

namespace minidump_inproc::internal {

// Counts modules by walking PEB_LDR_DATA directly instead of using ToolHelp or loader enumeration APIs.
// The minidump ModuleListStream DataSize must include only count + MINIDUMP_MODULE[];
// strings and CodeView records are stored after that stream and referenced by RVA fields.
BOOL CountModules(ULONG32* moduleCount, ULONG32* nameBytes, ULONG32* codeViewBytes) noexcept
{
    INPROC_PEB* peb = GetCurrentPeb();
    INPROC_PEB_LDR_DATA* ldr = nullptr;
    LIST_ENTRY* head = nullptr;
    LIST_ENTRY* current = nullptr;
    ULONG32 count = 0;
    ULONG64 names = 0;
    ULONG64 codeView = 0;

    if (peb == nullptr || !SafeCopyBytes(&ldr, &peb->Ldr, sizeof(PVOID)) || ldr == nullptr) {
        *moduleCount = 0;
        *nameBytes = 0;
        *codeViewBytes = 0;
        return TRUE;
    }

    head = &ldr->InMemoryOrderModuleList;
    if (!SafeCopyBytes(&current, &head->Flink, sizeof(PVOID))) {
        *moduleCount = 0;
        *nameBytes = 0;
        *codeViewBytes = 0;
        return TRUE;
    }

    while (current != nullptr && current != head && count < kMaxModules) {
        INPROC_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, INPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        INPROC_UNICODE_STRING name = {};
        LIST_ENTRY* next = nullptr;
        PVOID moduleBase = nullptr;
        const BYTE* cvRecord = nullptr;
        ULONG32 cvSize = 0;

        if (!SafeCopyBytes(&name, &entry->FullDllName, sizeof(name))) {
            break;
        }
        (void)SafeCopyBytes(&moduleBase, &entry->DllBase, sizeof(PVOID));
        if (QueryModuleCodeViewRecord(moduleBase, &cvRecord, &cvSize)) {
            codeView += Align4(cvSize);
        }
        names += MinidumpStringSize(SafeModuleNameLength(&entry->FullDllName));
        ++count;

        if (!SafeCopyBytes(&next, &current->Flink, sizeof(PVOID))) {
            break;
        }
        current = next;
    }

    if (names > 0xffffffffULL || codeView > 0xffffffffULL) {
        return FALSE;
    }
    *moduleCount = count;
    *nameBytes = static_cast<ULONG32>(names);
    *codeViewBytes = static_cast<ULONG32>(codeView);
    return TRUE;
}



// Reads PE timestamp and checksum from an image base under SEH so damaged module headers do not fail the dump.

BOOL ReadPeImageInfo(PVOID moduleBase, ULONG32* timeDateStamp, ULONG32* checkSum) noexcept
{
    *timeDateStamp = 0;
    *checkSum = 0;
#if defined(_MSC_VER)
    __try {
#endif
        const BYTE* base = static_cast<const BYTE*>(moduleBase);
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }
        *timeDateStamp = nt->FileHeader.TimeDateStamp;
        *checkSum = nt->OptionalHeader.CheckSum;
        return TRUE;
#if defined(_MSC_VER)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#endif
}


// Finds an in-memory RSDS CodeView record in a loaded PE image. We intentionally read
// the already-mapped image instead of opening the file or calling version/symbol APIs,
// because those APIs may allocate heap memory or take loader/resource locks.
BOOL QueryModuleCodeViewRecord(PVOID moduleBase, const BYTE** record, ULONG32* recordSize) noexcept
{
    *record = nullptr;
    *recordSize = 0;
    if (moduleBase == nullptr) {
        return FALSE;
    }

#if defined(_MSC_VER)
    __try {
#endif
        const BYTE* base = static_cast<const BYTE*>(moduleBase);
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
            return FALSE;
        }

        const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG) {
            return FALSE;
        }

        const IMAGE_DATA_DIRECTORY& debugDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (debugDir.VirtualAddress == 0 || debugDir.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) {
            return FALSE;
        }

        ULONG32 sizeOfImage = nt->OptionalHeader.SizeOfImage;
        if (debugDir.VirtualAddress >= sizeOfImage || debugDir.Size > sizeOfImage - debugDir.VirtualAddress) {
            return FALSE;
        }

        const IMAGE_DEBUG_DIRECTORY* debug = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base + debugDir.VirtualAddress);
        ULONG32 debugCount = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (ULONG32 i = 0; i < debugCount; ++i) {
            IMAGE_DEBUG_DIRECTORY local = {};
            if (!SafeCopyBytes(&local, &debug[i], sizeof(local))) {
                break;
            }
            if (local.Type != IMAGE_DEBUG_TYPE_CODEVIEW || local.AddressOfRawData == 0 ||
                local.SizeOfData < sizeof(ULONG32) || local.SizeOfData > kMaxCodeViewRecordBytes) {
                continue;
            }
            if (local.AddressOfRawData >= sizeOfImage || local.SizeOfData > sizeOfImage - local.AddressOfRawData) {
                continue;
            }

            const BYTE* candidate = base + local.AddressOfRawData;
            ULONG32 signature = 0;
            if (!SafeCopyBytes(&signature, candidate, sizeof(signature)) || signature != kCodeViewSignatureRsds) {
                continue;
            }
            if (!SafeReadBytes(candidate, local.SizeOfData)) {
                continue;
            }

            *record = candidate;
            *recordSize = local.SizeOfData;
            return TRUE;
        }
        return FALSE;
#if defined(_MSC_VER)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
#endif
}

// Writes the raw RSDS record referenced by MINIDUMP_MODULE::CvRecord. The DataSize
// remains the exact CodeView byte count; only the physical trailing storage is padded.
BOOL WriteModuleCodeViewRecord(HANDLE hFile, PVOID moduleBase, ULONG32* writtenSize) noexcept
{
    const BYTE* record = nullptr;
    ULONG32 recordSize = 0;
    *writtenSize = 0;
    if (!QueryModuleCodeViewRecord(moduleBase, &record, &recordSize)) {
        return TRUE;
    }
    if (!WriteRegionBytes(hFile, const_cast<BYTE*>(record), recordSize)) {
        return FALSE;
    }
    ULONG32 paddedSize = static_cast<ULONG32>(Align4(recordSize));
    if (!WriteZeros(hFile, paddedSize - recordSize)) {
        return FALSE;
    }
    *writtenSize = paddedSize;
    return TRUE;
}

// Writes ModuleListStream descriptors and their trailing strings/CodeView records; stream size excludes trailing storage per minidump rules.

BOOL WriteModuleList(HANDLE hFile, ULONG32 moduleCount, ULONG32 moduleListRva) noexcept
{
    INPROC_PEB* peb = GetCurrentPeb();
    INPROC_PEB_LDR_DATA* ldr = nullptr;
    LIST_ENTRY* head = nullptr;
    LIST_ENTRY* current = nullptr;
    ULONG32 writtenModules = 0;
    ULONG32 stringRva = moduleListRva + sizeof(ULONG32) + moduleCount * sizeof(MINIDUMP_MODULE);
    ULONG32 cvRva = stringRva;
    LARGE_INTEGER stringPos = {};


    if (!WriteAll(hFile, &moduleCount, sizeof(moduleCount))) {
        return FALSE;
    }

    if (peb == nullptr || !SafeCopyBytes(&ldr, &peb->Ldr, sizeof(PVOID)) || ldr == nullptr) {
        return TRUE;
    }

    head = &ldr->InMemoryOrderModuleList;
    if (!SafeCopyBytes(&current, &head->Flink, sizeof(PVOID))) {
        return TRUE;
    }

    LIST_ENTRY* rvaScan = current;
    ULONG32 scannedModules = 0;
    while (rvaScan != nullptr && rvaScan != head && scannedModules < moduleCount) {
        INPROC_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(rvaScan, INPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LIST_ENTRY* next = nullptr;
        ULONG32 nameLength = SafeModuleNameLength(&entry->FullDllName);
        cvRva += MinidumpStringSize(nameLength);
        ++scannedModules;
        if (!SafeCopyBytes(&next, &rvaScan->Flink, sizeof(PVOID))) {
            break;
        }
        rvaScan = next;
    }

    while (current != nullptr && current != head && writtenModules < moduleCount) {

        INPROC_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, INPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        MINIDUMP_MODULE module = {};
        INPROC_UNICODE_STRING name = {};
        LIST_ENTRY* next = nullptr;
        ULONG32 nameLength = 0;
        ULONG32 timeDateStamp = 0;
        ULONG32 checkSum = 0;
        PVOID moduleBase = nullptr;
        const BYTE* cvRecord = nullptr;
        ULONG32 cvSize = 0;

        (void)SafeCopyBytes(&moduleBase, &entry->DllBase, sizeof(PVOID));
        (void)SafeCopyBytes(&module.BaseOfImage, &entry->DllBase, sizeof(entry->DllBase));

        (void)SafeCopyBytes(&module.SizeOfImage, &entry->SizeOfImage, sizeof(entry->SizeOfImage));
        (void)SafeCopyBytes(&name, &entry->FullDllName, sizeof(name));
        nameLength = SafeModuleNameLength(&entry->FullDllName);

        (void)ReadPeImageInfo(
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(module.BaseOfImage)),
            &timeDateStamp,
            &checkSum);
        module.TimeDateStamp = timeDateStamp;
        module.CheckSum = checkSum;
        module.ModuleNameRva = stringRva;
        if (QueryModuleCodeViewRecord(moduleBase, &cvRecord, &cvSize)) {
            module.CvRecord.Rva = cvRva;
            module.CvRecord.DataSize = cvSize;
            cvRva += static_cast<ULONG32>(Align4(cvSize));
        }

        if (!WriteAll(hFile, &module, sizeof(module))) {

            return FALSE;
        }

        stringRva += MinidumpStringSize(nameLength);
        ++writtenModules;

        if (!SafeCopyBytes(&next, &current->Flink, sizeof(PVOID))) {
            break;
        }
        current = next;
    }

    if (writtenModules < moduleCount && !WriteZeros(hFile, (moduleCount - writtenModules) * sizeof(MINIDUMP_MODULE))) {
        return FALSE;
    }

    stringPos.QuadPart = moduleListRva + sizeof(ULONG32) + moduleCount * sizeof(MINIDUMP_MODULE);
    if (!SetFilePointerEx(hFile, stringPos, nullptr, FILE_BEGIN)) {
        return FALSE;
    }

    current = nullptr;
    writtenModules = 0;
    if (!SafeCopyBytes(&current, &head->Flink, sizeof(PVOID))) {
        return WriteZeros(hFile, stringRva - stringPos.QuadPart);
    }

    while (current != nullptr && current != head && writtenModules < moduleCount) {
        INPROC_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, INPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LIST_ENTRY* next = nullptr;

        if (!WriteMinidumpString(hFile, &entry->FullDllName)) {
            return FALSE;
        }
        ++writtenModules;

        if (!SafeCopyBytes(&next, &current->Flink, sizeof(PVOID))) {
            break;
        }
        current = next;
    }

    while (writtenModules < moduleCount) {
        INPROC_UNICODE_STRING emptyName = {};
        if (!WriteMinidumpString(hFile, &emptyName)) {
            return FALSE;
        }
        ++writtenModules;
    }

    current = nullptr;
    writtenModules = 0;
    if (!SafeCopyBytes(&current, &head->Flink, sizeof(PVOID))) {
        return TRUE;
    }

    while (current != nullptr && current != head && writtenModules < moduleCount) {
        INPROC_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, INPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LIST_ENTRY* next = nullptr;
        PVOID moduleBase = nullptr;
        ULONG32 writtenSize = 0;

        (void)SafeCopyBytes(&moduleBase, &entry->DllBase, sizeof(PVOID));
        if (!WriteModuleCodeViewRecord(hFile, moduleBase, &writtenSize)) {
            return FALSE;
        }
        ++writtenModules;

        if (!SafeCopyBytes(&next, &current->Flink, sizeof(PVOID))) {
            break;
        }
        current = next;
    }

    return TRUE;
}



} // namespace minidump_inproc::internal
