#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dbgeng.h>
#include <string.h>
#include <stdio.h>

#ifndef DEBUG_OUTCTL_DML
#define DEBUG_OUTCTL_DML 0x20
#endif

namespace {

// These mirror the writer's stack-overflow capture policy (see kStackOverflowFullStackThreshold /
// kStackOverflowLiveStackBytes / kStackOverflowHighStackBytes in the library): full-stack scan for
// stacks <= 1 MB, otherwise a 512 KB live window + 512 KB high-address window.
constexpr ULONG64 kStackOverflowFullThreshold = 1ull * 1024 * 1024;
constexpr ULONG64 kDefaultLiveWindowBytes = 512ull * 1024;
constexpr ULONG64 kDefaultHighWindowBytes = 512ull * 1024;
constexpr ULONG64 kMaxReasonableStackBytes = 64ull * 1024 * 1024;
constexpr ULONG64 kPageSize = 4096;
constexpr ULONG kDefaultShadowBytes = 32;

template <typename T>
void SafeRelease(T*& p) noexcept
{
    if (p != nullptr) {
        p->Release();
        p = nullptr;
    }
}

ULONG64 AlignDown(ULONG64 value, ULONG64 alignment) noexcept
{
    return value & ~(alignment - 1ull);
}

ULONG64 AlignUp(ULONG64 value, ULONG64 alignment) noexcept
{
    return (value + alignment - 1ull) & ~(alignment - 1ull);
}

bool ReadPointer(IDebugDataSpaces* data, ULONG64 address, ULONG pointerSize, ULONG64* value) noexcept
{
    *value = 0;
    ULONG done = 0;
    if (pointerSize == 4) {
        ULONG32 v = 0;
        if (FAILED(data->ReadVirtual(address, &v, sizeof(v), &done)) || done != sizeof(v)) {
            return false;
        }
        *value = v;
        return true;
    }

    ULONG64 v = 0;
    if (FAILED(data->ReadVirtual(address, &v, sizeof(v), &done)) || done != sizeof(v)) {
        return false;
    }
    *value = v;
    return true;
}

bool GetRegisterValue(IDebugRegisters* regs, const char* name, ULONG64* value) noexcept
{
    *value = 0;
    ULONG index = 0;
    DEBUG_VALUE v = {};
    if (FAILED(regs->GetIndexByName(name, &index)) || FAILED(regs->GetValue(index, &v))) {
        return false;
    }

    switch (v.Type) {
    case DEBUG_VALUE_INT8:
        *value = v.I8;
        return true;
    case DEBUG_VALUE_INT16:
        *value = v.I16;
        return true;
    case DEBUG_VALUE_INT32:
        *value = v.I32;
        return true;
    case DEBUG_VALUE_INT64:
        *value = v.I64;
        return true;
    default:
        return false;
    }
}

// Resolves a return address into a "module!symbol+0xNN" string. When callSite is true the lookup
// uses offset-1 (the call instruction), matching how k labels each frame.
bool ResolveCodeSymbol(IDebugSymbols* symbols, ULONG64 offset, bool callSite, char* name, ULONG nameChars) noexcept
{
    if (offset < 0x10000 || name == nullptr || nameChars < 16) {
        return false;
    }

    ULONG64 lookup = (callSite && offset != 0) ? offset - 1 : offset;
    ULONG64 moduleBase = 0;
    if (FAILED(symbols->GetModuleByOffset(lookup, 0, nullptr, &moduleBase)) || moduleBase == 0) {
        return false;
    }

    ULONG size = 0;
    ULONG64 displacement = 0;
    if (FAILED(symbols->GetNameByOffset(lookup, name, nameChars, &size, &displacement)) || size <= 1) {
        return false;
    }

    // Stack scanning sees raw qwords; this cap filters most data pointers that merely happen to sit
    // inside a module mapping but are far from a real symbol.
    if (displacement > 0x10000) {
        return false;
    }

    if (strchr(name, '!') == nullptr) {
        return false;
    }

    size_t len = strlen(name);
    if (displacement != 0 && len + 16 < nameChars) {
        _snprintf_s(name + len, nameChars - len, _TRUNCATE, "+0x%llx", displacement);
    }
    name[nameChars - 1] = '\0';
    return true;
}

void ExtractModulePrefix(const char* symbol, char* prefix, ULONG prefixChars) noexcept
{
    if (prefix == nullptr || prefixChars == 0) {
        return;
    }
    prefix[0] = '\0';
    const char* bang = symbol != nullptr ? strchr(symbol, '!') : nullptr;
    if (bang == nullptr) {
        return;
    }

    size_t len = static_cast<size_t>(bang - symbol + 1);
    if (len >= prefixChars) {
        len = prefixChars - 1;
    }
    memcpy(prefix, symbol, len);
    prefix[len] = '\0';
}

bool StartsWithNoCase(const char* text, const char* prefix) noexcept
{
    if (text == nullptr || prefix == nullptr || prefix[0] == '\0') {
        return false;
    }
    return _strnicmp(text, prefix, strlen(prefix)) == 0;
}

bool IsThreadStartSymbol(const char* symbol) noexcept
{
    return symbol != nullptr &&
           (strstr(symbol, "BaseThreadInitThunk") != nullptr ||
            strstr(symbol, "RtlUserThreadStart") != nullptr);
}

bool AcceptHighStackSymbol(const char* symbol, const char* primaryModulePrefix) noexcept
{
    // The high-address stack window often contains stale loader/CRT pointers from thread startup.
    // Keep the crashing module's frames plus the canonical OS thread-start frames so the output
    // describes the logical overflow stack instead of raw dps noise.
    return StartsWithNoCase(symbol, primaryModulePrefix) || IsThreadStartSymbol(symbol);
}


struct SyntheticFrame {
    ULONG64 ChildSp;     // SP of the called frame == address just above the return-address slot
    ULONG64 SlotAddr;    // stack slot that holds RetAddr (for the shadow-stack dump)
    ULONG64 RetAddr;     // return address recovered from the slot
    ULONG64 OmittedBytes;
    ULONG Line;
    bool Omitted;
    bool HasSource;
    char Symbol[512];
    char Source[520];
};

struct FrameList {
    static constexpr ULONG kMaxFrames = 4096;
    SyntheticFrame Frames[kMaxFrames];
    ULONG Count;

    void Init() noexcept
    {
        Count = 0;
    }

    void AddFrame(ULONG64 slotAddr, ULONG64 childSp, ULONG64 retAddr,
                  const char* symbol, const char* source, ULONG line, bool hasSource) noexcept
    {
        if (Count >= kMaxFrames || symbol == nullptr || symbol[0] == '\0') {
            return;
        }
        SyntheticFrame& frame = Frames[Count++];
        frame.SlotAddr = slotAddr;
        frame.ChildSp = childSp;
        frame.RetAddr = retAddr;
        frame.OmittedBytes = 0;
        frame.Line = line;
        frame.Omitted = false;
        frame.HasSource = hasSource;
        strncpy_s(frame.Symbol, symbol, _TRUNCATE);
        if (source != nullptr) {
            strncpy_s(frame.Source, source, _TRUNCATE);
        } else {
            frame.Source[0] = '\0';
        }
    }

    void AddOmitted(ULONG64 bytes) noexcept
    {
        if (Count >= kMaxFrames || bytes == 0) {
            return;
        }
        SyntheticFrame& frame = Frames[Count++];
        frame = {};
        frame.Omitted = true;
        frame.OmittedBytes = bytes;
    }
};

bool ResolveSourceLine(IDebugSymbols* symbols, ULONG64 addr, bool callSite, char* source, ULONG sourceChars, ULONG* line) noexcept
{
    if (source == nullptr || sourceChars == 0 || line == nullptr) {
        return false;
    }
    source[0] = '\0';
    *line = 0;

    // The line MUST be resolved at the SAME address used to resolve the symbol, otherwise the two
    // disagree (this was the kn mismatch). For a return-address frame (callSite) k attributes the
    // frame to the call instruction, which precedes the return address, so look up addr-1. For the
    // live faulting IP (frame 0, not a return address) use the exact address, matching kn.
    ULONG64 lookup = (callSite && addr != 0) ? addr - 1 : addr;
    ULONG fileSize = 0;
    ULONG64 displacement = 0;
    if (FAILED(symbols->GetLineByOffset(lookup, line, source, sourceChars, &fileSize, &displacement)) ||
        fileSize <= 1) {
        return false;
    }
    source[sourceChars - 1] = '\0';
    return true;
}

bool IsStackOverflowThreadProc(const char* symbol) noexcept
{
    return symbol != nullptr && strstr(symbol, "StackOverflowThreadProc") != nullptr;
}

bool IsBaseThreadInitThunk(const char* symbol) noexcept
{
    return symbol != nullptr && strstr(symbol, "BaseThreadInitThunk") != nullptr;
}

void NormalizeLogicalOverflowStack(FrameList* frames) noexcept
{
    if (frames == nullptr || frames->Count == 0) {
        return;
    }

    LONG lastBaseThread = -1;
    LONG finalStackThreadProc = -1;
    for (ULONG i = 0; i < frames->Count; ++i) {
        if (frames->Frames[i].Omitted) {
            continue;
        }
        if (IsBaseThreadInitThunk(frames->Frames[i].Symbol)) {
            lastBaseThread = static_cast<LONG>(i);
        }
    }
    if (lastBaseThread >= 0) {
        for (LONG i = lastBaseThread - 1; i >= 0; --i) {
            if (!frames->Frames[i].Omitted && IsStackOverflowThreadProc(frames->Frames[i].Symbol)) {
                finalStackThreadProc = i;
                break;
            }
        }
    }

    ULONG out = 0;
    for (ULONG i = 0; i < frames->Count; ++i) {
        SyntheticFrame& frame = frames->Frames[i];
        bool keep = true;
        if (!frame.Omitted && finalStackThreadProc >= 0 && static_cast<LONG>(i) < finalStackThreadProc) {
            // High-stack scans can see stale thread-start records before the real thread-start tail.
            // Drop them so the synthesized stack has one logical ending.
            if (IsStackOverflowThreadProc(frame.Symbol) || IsThreadStartSymbol(frame.Symbol)) {
                keep = false;
            }
        }
        if (!keep) {
            continue;
        }
        if (out != i) {
            frames->Frames[out] = frame;
        }
        ++out;
    }
    frames->Count = out;
}

void FormatHexAddr(char* buffer, ULONG bufferChars, ULONG64 value, ULONG pointerSize) noexcept
{
    // Match WinDbg's `hi`x`lo` address rendering for 64-bit and a plain 8-digit form for 32-bit.
    if (pointerSize == 4) {
        _snprintf_s(buffer, bufferChars, _TRUNCATE, "%08lx", static_cast<ULONG>(value));
    } else {
        _snprintf_s(buffer, bufferChars, _TRUNCATE, "%08lx`%08lx",
                    static_cast<ULONG>(value >> 32), static_cast<ULONG>(value & 0xffffffffull));
    }
}

void PrintFrameRow(IDebugControl* control, const SyntheticFrame& frame, ULONG index,
                   ULONG pointerSize, ULONG shadowBytes) noexcept
{
    char childSpText[32] = {};
    char retAddrText[32] = {};
    char slotText[32] = {};
    FormatHexAddr(childSpText, sizeof(childSpText), frame.ChildSp, pointerSize);
    FormatHexAddr(retAddrText, sizeof(retAddrText), frame.RetAddr, pointerSize);
    FormatHexAddr(slotText, sizeof(slotText), frame.SlotAddr, pointerSize);

    // Addresses inside DML commands MUST use WinDbg's hi`lo backtick form, NOT 0x.... A 0x-prefixed
    // 64-bit address is evaluated as 32-bit by the command parser and triggers a Range error.
    //
    // NOTE on the frame-number link: k's clickable frame number runs ".frame 0n<idx>;dv ...", which
    // relies on WinDbg's own unwind frame table. These rows are SYNTHESIZED by scanning stack memory
    // and are NOT in that table, so .frame cannot select them (and .frame /r <addr> takes a frame
    // index, not an address -> Range error). The closest working frame-scoped action is to dump that
    // frame's stack region with dps, so the frame number links to dps over a window from Child-SP.
    // The Call Site links to disassembly at the call; the source link opens that line.
    const ULONG frameSlots = 16;

    // Emit the row in pieces (DML links are self-contained per chunk) so the optional Shadow column
    // can be placed INLINE between RetAddr and Call Site instead of on a separate line.
    // Frame number (links to dps over the frame's stack window) + Child-SP + RetAddr.
    control->ControlledOutput(DEBUG_OUTCTL_DML, DEBUG_OUTPUT_NORMAL,
        "<link cmd=\"dps %s L%lu\">%02lu</link> %s %s ",
        childSpText, frameSlots, index, childSpText, retAddrText);

    // Shadow column (between RetAddr and Call Site): the slot address as a clickable link that dumps
    // the per-frame shadow-stack window. Same fixed width as an address so Call Site stays aligned.
    if (shadowBytes != 0) {
        const ULONG count = (shadowBytes + pointerSize - 1) / pointerSize;
        control->ControlledOutput(DEBUG_OUTCTL_DML, DEBUG_OUTPUT_NORMAL,
            "<link cmd=\"dps %s L%lu\">%s</link> ",
            slotText, count, slotText);
    }

    // Call Site (links to disassembly at the call).
    control->ControlledOutput(DEBUG_OUTCTL_DML, DEBUG_OUTPUT_NORMAL,
        "<link cmd=\"u %s-0x10 L8\">%s</link>",
        retAddrText, frame.Symbol);

    // Optional source location (links to the source line).
    if (frame.HasSource && frame.Line != 0) {
        control->ControlledOutput(DEBUG_OUTCTL_DML, DEBUG_OUTPUT_NORMAL,
            " [<link cmd=\"lsa %s-1\">%s @ %lu</link>]",
            retAddrText, frame.Source, frame.Line);
    }

    control->ControlledOutput(DEBUG_OUTCTL_DML, DEBUG_OUTPUT_NORMAL, "\n");
}

void PrintFrameList(IDebugControl* control, FrameList* frames, ULONG pointerSize, ULONG shadowBytes) noexcept
{
    NormalizeLogicalOverflowStack(frames);
    const int addrWidth = (pointerSize == 4) ? 8 : 17;
    const char* childLabel = (pointerSize == 4) ? "ChildEBP" : "Child-SP";
    if (shadowBytes != 0) {
        control->Output(DEBUG_OUTPUT_NORMAL, " # %-*s %-*s %-*s Call Site [Source]\n",
                        addrWidth, childLabel, addrWidth, "RetAddr", addrWidth, "Shadow");
    } else {
        control->Output(DEBUG_OUTPUT_NORMAL, " # %-*s %-*s Call Site [Source]\n",
                        addrWidth, childLabel, addrWidth, "RetAddr");
    }

    ULONG shownIndex = 0;
    for (ULONG i = 0; i < frames->Count;) {
        const SyntheticFrame& frame = frames->Frames[i];
        if (frame.Omitted) {
            control->Output(DEBUG_OUTPUT_NORMAL, "... <0x%llx bytes of middle stack intentionally omitted> ...\n", frame.OmittedBytes);
            ++i;
            continue;
        }

        // Detect a repeating cycle of frames. A plain recursion repeats with period 1 (same symbol),
        // but an optimized recursive call commonly alternates between two call sites (e.g. "+0xd" and
        // "+0x60"), giving period 2. Probe small periods and fold the longest repeated run.
        ULONG period = 0;
        ULONG repeats = 0;
        for (ULONG p = 1; p <= 4; ++p) {
            if (i + p >= frames->Count) {
                break;
            }
            ULONG r = 1;
            while (true) {
                ULONG base = i + r * p;
                if (base + p > frames->Count) {
                    break;
                }
                bool match = true;
                for (ULONG k = 0; k < p; ++k) {
                    const SyntheticFrame& a = frames->Frames[i + k];
                    const SyntheticFrame& b = frames->Frames[base + k];
                    if (b.Omitted || strcmp(a.Symbol, b.Symbol) != 0) {
                        match = false;
                        break;
                    }
                }
                if (!match) {
                    break;
                }
                ++r;
            }
            // Prefer the period that folds the most frames (r*p), favoring smaller periods on ties.
            if (r >= 2 && r * p > repeats * period) {
                period = p;
                repeats = r;
            }
        }

        const ULONG totalRepeatedFrames = period * repeats;
        // Only collapse when the repeated block is long enough to be worth folding.
        if (period != 0 && repeats >= 3 && totalRepeatedFrames > period * 2 + 1) {
            // Show the first full cycle, the omission marker, then the last full cycle.
            for (ULONG j = 0; j < period; ++j) {
                PrintFrameRow(control, frames->Frames[i + j], shownIndex++, pointerSize, shadowBytes);
            }
            const ULONG hiddenCycles = repeats - 2;
            const ULONG hiddenFrames = hiddenCycles * period;
            control->Output(DEBUG_OUTPUT_NORMAL, "... (%lu repeated frames in %lu cycles) ...\n",
                            hiddenFrames, hiddenCycles);
            shownIndex += hiddenFrames;
            const ULONG lastCycle = i + (repeats - 1) * period;
            for (ULONG j = 0; j < period; ++j) {
                PrintFrameRow(control, frames->Frames[lastCycle + j], shownIndex++, pointerSize, shadowBytes);
            }
            i += totalRepeatedFrames;
            continue;
        }

        PrintFrameRow(control, frame, shownIndex++, pointerSize, shadowBytes);
        ++i;
    }
}

void AddResolvedFrame(IDebugSymbols* symbols, FrameList* frames, ULONG64 slotAddr,
                      ULONG64 childSp, ULONG64 retAddr, const char* symbol, bool callSite) noexcept
{
    char source[520] = {};
    ULONG line = 0;
    bool hasSource = ResolveSourceLine(symbols, retAddr, callSite, source, sizeof(source), &line);
    frames->AddFrame(slotAddr, childSp, retAddr, symbol, source, line, hasSource);
}

void ScanStackRange(IDebugDataSpaces* data,
                    IDebugSymbols* symbols,
                    ULONG pointerSize,
                    ULONG64 start,
                    ULONG64 end,
                    FrameList* frames,
                    const char* primaryModulePrefix,
                    bool highStackFilter) noexcept
{
    if (end <= start || end - start > kMaxReasonableStackBytes) {
        return;
    }

    ULONG64 cursor = AlignDown(start, pointerSize);
    if (cursor < start) {
        cursor += pointerSize;
    }

    while (cursor + pointerSize <= end) {
        ULONG64 value = 0;
        if (!ReadPointer(data, cursor, pointerSize, &value)) {
            cursor = AlignUp(cursor + 1, kPageSize);
            continue;
        }

        char symbol[512] = {};
        if (ResolveCodeSymbol(symbols, value, true, symbol, sizeof(symbol)) &&
            (!highStackFilter || AcceptHighStackSymbol(symbol, primaryModulePrefix))) {
            // k's Child-SP for a frame is the SP after the call returns, i.e. just above the slot
            // that holds the return address. The slot itself is kept for the shadow-stack dump.
            // callSite=true: this is a return address, so resolve symbol/line at value-1 (the call).
            AddResolvedFrame(symbols, frames, cursor, cursor + pointerSize, value, symbol, true);
        }
        cursor += pointerSize;
    }
}

HRESULT QueryDebugInterfaces(PDEBUG_CLIENT4 client,
                             IDebugControl** control,
                             IDebugDataSpaces** data,
                             IDebugSymbols** symbols,
                             IDebugSystemObjects** system,
                             IDebugRegisters** registers) noexcept
{
    if (FAILED(client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(control))) ||
        FAILED(client->QueryInterface(__uuidof(IDebugDataSpaces), reinterpret_cast<void**>(data))) ||
        FAILED(client->QueryInterface(__uuidof(IDebugSymbols), reinterpret_cast<void**>(symbols))) ||
        FAILED(client->QueryInterface(__uuidof(IDebugSystemObjects), reinterpret_cast<void**>(system))) ||
        FAILED(client->QueryInterface(__uuidof(IDebugRegisters), reinterpret_cast<void**>(registers)))) {
        return E_NOINTERFACE;
    }
    return S_OK;
}

void PrintUsage(IDebugControl* control) noexcept
{
    control->Output(DEBUG_OUTPUT_NORMAL,
        "usage: !show_overflow_stack [live=<bytes>] [high=<bytes>] [shadow[=<bytes>]] [noecxr]\n"
        "  live/high : live-unwind and high-address window sizes for stacks > 1MB (default 512KB / 512KB).\n"
        "  shadow    : also dump a per-frame shadow-stack window (default 32 bytes, e.g. shadow=64).\n"
        "  noecxr    : do not run .ecxr first.\n"
        "  For stacks <= 1MB the command scans the full stack. Sizes accept k/m suffixes.\n");
}

ULONG64 ParseSizeOption(PCSTR args, const char* key, ULONG64 fallback) noexcept
{
    if (args == nullptr || key == nullptr) {
        return fallback;
    }

    const char* p = strstr(args, key);
    if (p == nullptr) {
        return fallback;
    }
    p += strlen(key);
    if (*p != '=') {
        return fallback;
    }
    ++p;

    char* end = nullptr;
    unsigned long long value = _strtoui64(p, &end, 0);
    if (end == p || value == 0) {
        return fallback;
    }
    if (*end == 'k' || *end == 'K') {
        value *= 1024ull;
    } else if (*end == 'm' || *end == 'M') {
        value *= 1024ull * 1024ull;
    }
    return value;
}

} // namespace

extern "C" __declspec(dllexport)
HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags)
{
    if (version != nullptr) {
        *version = DEBUG_EXTENSION_VERSION(1, 0);
    }
    if (flags != nullptr) {
        *flags = 0;
    }
    return S_OK;
}

extern "C" __declspec(dllexport)
void CALLBACK DebugExtensionUninitialize()
{
}

extern "C" __declspec(dllexport)
HRESULT CALLBACK show_overflow_stack(PDEBUG_CLIENT4 client, PCSTR args)
{
    if (client == nullptr) {
        return E_INVALIDARG;
    }

    IDebugControl* control = nullptr;
    IDebugDataSpaces* data = nullptr;
    IDebugSymbols* symbols = nullptr;
    IDebugSystemObjects* system = nullptr;
    IDebugRegisters* registers = nullptr;

    HRESULT hr = QueryDebugInterfaces(client, &control, &data, &symbols, &system, &registers);
    if (FAILED(hr)) {
        SafeRelease(control);
        SafeRelease(data);
        SafeRelease(symbols);
        SafeRelease(system);
        SafeRelease(registers);
        return hr;
    }

    if (args != nullptr && strstr(args, "help") != nullptr) {
        PrintUsage(control);
        SafeRelease(control);
        SafeRelease(data);
        SafeRelease(symbols);
        SafeRelease(system);
        SafeRelease(registers);
        return S_OK;
    }

    if (args == nullptr || strstr(args, "noecxr") == nullptr) {
        (void)control->Execute(DEBUG_OUTCTL_IGNORE, ".ecxr", DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
    }

    ULONG processor = 0;
    (void)control->GetEffectiveProcessorType(&processor);
    const bool isX86 = processor == IMAGE_FILE_MACHINE_I386;
    const ULONG pointerSize = isX86 ? 4u : 8u;

    ULONG64 ip = 0;
    ULONG64 sp = 0;
    (void)GetRegisterValue(registers, isX86 ? "eip" : "rip", &ip);
    if (!GetRegisterValue(registers, isX86 ? "esp" : "rsp", &sp)) {
        control->Output(DEBUG_OUTPUT_ERROR, "show_overflow_stack: cannot read stack pointer register\n");
        SafeRelease(control);
        SafeRelease(data);
        SafeRelease(symbols);
        SafeRelease(system);
        SafeRelease(registers);
        return E_FAIL;
    }

    ULONG64 teb = 0;
    ULONG64 stackBase = 0;
    ULONG64 stackLimit = 0;
    if (FAILED(system->GetCurrentThreadTeb(&teb)) || teb == 0 ||
        !ReadPointer(data, teb + (isX86 ? 4 : 8), pointerSize, &stackBase) ||
        !ReadPointer(data, teb + (isX86 ? 8 : 16), pointerSize, &stackLimit) ||
        stackBase <= stackLimit) {
        control->Output(DEBUG_OUTPUT_ERROR, "show_overflow_stack: cannot read TEB stack bounds\n");
        SafeRelease(control);
        SafeRelease(data);
        SafeRelease(symbols);
        SafeRelease(system);
        SafeRelease(registers);
        return E_FAIL;
    }

    ULONG64 liveBytes = ParseSizeOption(args, "live", kDefaultLiveWindowBytes);
    ULONG64 highBytes = ParseSizeOption(args, "high", kDefaultHighWindowBytes);
    if (liveBytes > kMaxReasonableStackBytes) {
        liveBytes = kDefaultLiveWindowBytes;
    }
    if (highBytes > kMaxReasonableStackBytes) {
        highBytes = kDefaultHighWindowBytes;
    }

    // shadow / shadow=<bytes>: print a per-frame shadow-stack window. A bare "shadow" uses 32 bytes.
    ULONG shadowBytes = 0;
    if (args != nullptr) {
        const char* shadowPos = strstr(args, "shadow");
        if (shadowPos != nullptr) {
            ULONG64 parsed = ParseSizeOption(args, "shadow", kDefaultShadowBytes);
            if (parsed == 0 || parsed > 4096) {
                parsed = kDefaultShadowBytes;
            }
            shadowBytes = static_cast<ULONG>(parsed);
        }
    }

    ULONG64 stackBytes = stackBase - stackLimit;
    ULONG64 scanStart = sp;
    if (scanStart < stackLimit || scanStart >= stackBase) {
        scanStart = stackLimit;
    }

    control->Output(DEBUG_OUTPUT_NORMAL,
        "TEB=0x%llx StackLimit=0x%llx StackBase=0x%llx SP=0x%llx stackBytes=%llu\n",
        teb, stackLimit, stackBase, sp, stackBytes);

    static FrameList frames = {};
    frames.Init();

    char primaryModulePrefix[128] = {};
    char ipSymbol[512] = {};
    if (ResolveCodeSymbol(symbols, ip, false, ipSymbol, sizeof(ipSymbol))) {
        ExtractModulePrefix(ipSymbol, primaryModulePrefix, sizeof(primaryModulePrefix));
        // Frame 0 is the live faulting instruction: Child-SP is the current SP and the slot for the
        // shadow dump starts at SP as well. callSite=false: ip is the exact PC (not a return
        // address), so resolve its source line at the exact address to match kn (e.g. chkstk @ 109).
        AddResolvedFrame(symbols, &frames, sp, sp, ip, ipSymbol, false);
    }

    if (stackBytes <= kStackOverflowFullThreshold) {
        control->Output(DEBUG_OUTPUT_NORMAL, "mode=full-stack (<=1MB)\n");
        ScanStackRange(data, symbols, pointerSize, scanStart, stackBase, &frames, primaryModulePrefix, primaryModulePrefix[0] != '\0');
    } else {
        control->Output(DEBUG_OUTPUT_NORMAL, "mode=split-stack (>1MB), live=%llu high=%llu\n", liveBytes, highBytes);
        ULONG64 liveEnd = scanStart + liveBytes;
        if (liveEnd < scanStart || liveEnd > stackBase) {
            liveEnd = stackBase;
        }
        ScanStackRange(data, symbols, pointerSize, scanStart, liveEnd, &frames, primaryModulePrefix, primaryModulePrefix[0] != '\0');

        ULONG64 highStart = stackBase > highBytes ? stackBase - highBytes : stackLimit;
        if (highStart < stackLimit) {
            highStart = stackLimit;
        }
        highStart = AlignDown(highStart, kPageSize);
        if (highStart > liveEnd) {
            frames.AddOmitted(highStart - liveEnd);
        } else {
            highStart = liveEnd;
        }
        ScanStackRange(data, symbols, pointerSize, highStart, stackBase, &frames, primaryModulePrefix, primaryModulePrefix[0] != '\0');
    }

    PrintFrameList(control, &frames, pointerSize, shadowBytes);

    SafeRelease(control);
    SafeRelease(data);
    SafeRelease(symbols);
    SafeRelease(system);
    SafeRelease(registers);
    return S_OK;
}
