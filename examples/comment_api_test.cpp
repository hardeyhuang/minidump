// Behavioral tests for SetMiniDumpInprocCommentA / SetMiniDumpInprocCommentW.
//
// Rather than write a full minidump and parse CommentStreamW back, this test links the static
// library and includes the internal header so it can inspect the persistent comment buffer
// (g_CommentBufferW / g_CommentWChars) directly. That lets each case reset the buffer and assert
// the EXACT stored wide text, which is precisely what both setters ultimately produce.
//
// Only ASCII inputs are used for the A variant so the CP_ACP -> UTF-16 conversion is deterministic
// across locales; wide-only behavior (escaping to U+21B5 / U+FF1B) is asserted via the W variant.

#include <windows.h>

#include <cstdio>
#include <string>

#include "minidump_inproc.h"
#include "minidump_inproc_internal.h"

namespace mi = minidump_inproc::internal;

namespace {

int g_pass = 0;
int g_fail = 0;

// The two characters CommentNormalizeValue substitutes into stored values.
const wchar_t kArrow = static_cast<wchar_t>(0x21B5);   // '\n' -> visible return arrow
const wchar_t kFwSemi = static_cast<wchar_t>(0xFF1B);  // ';'  -> full-width semicolon

void ResetComment() noexcept
{
    mi::g_CommentBufferW[0] = L'\0';
}

std::wstring Stored()
{
    return std::wstring(mi::g_CommentBufferW);
}

std::string HexDump(const std::wstring& s)
{
    std::string out;
    char tmp[16];
    for (wchar_t c : s) {
        std::snprintf(tmp, sizeof(tmp), "%04X ", static_cast<unsigned>(static_cast<unsigned short>(c)));
        out += tmp;
    }
    return out;
}

void CheckBool(const char* name, bool cond)
{
    if (cond) {
        ++g_pass;
        std::printf("[PASS] %s\n", name);
    } else {
        ++g_fail;
        std::printf("[FAIL] %s\n", name);
    }
}

void CheckStored(const char* name, const std::wstring& expected)
{
    const std::wstring actual = Stored();
    if (actual == expected) {
        ++g_pass;
        std::printf("[PASS] %s\n", name);
    } else {
        ++g_fail;
        std::printf("[FAIL] %s\n", name);
        std::printf("       expected (%u): %s\n",
                    static_cast<unsigned>(expected.size()), HexDump(expected).c_str());
        std::printf("       actual   (%u): %s\n",
                    static_cast<unsigned>(actual.size()), HexDump(actual).c_str());
    }
}

void TestInputValidation()
{
    ResetComment();
    CheckBool("W: NULL section rejected",
              SetMiniDumpInprocCommentW(nullptr, L"k", L"v", CommentStringReplace) == FALSE);
    CheckBool("W: NULL key rejected",
              SetMiniDumpInprocCommentW(L"s", nullptr, L"v", CommentStringReplace) == FALSE);
    CheckBool("W: empty section rejected",
              SetMiniDumpInprocCommentW(L"", L"k", L"v", CommentStringReplace) == FALSE);
    CheckBool("W: empty key rejected",
              SetMiniDumpInprocCommentW(L"s", L"", L"v", CommentStringReplace) == FALSE);
    CheckStored("W: rejected inputs leave buffer empty", L"");

    ResetComment();
    CheckBool("W: NULL value on absent key is no-op (returns TRUE)",
              SetMiniDumpInprocCommentW(L"sec", L"k", nullptr, CommentStringReplace) == TRUE);
    CheckStored("W: NULL value no-op leaves buffer empty", L"");
}

void TestInsertAndSections()
{
    ResetComment();
    CheckBool("W: first insert returns TRUE",
              SetMiniDumpInprocCommentW(L"sec", L"k", L"v", CommentStringReplace) == TRUE);
    CheckStored("W: basic insert", L"[sec]\nk=v\n");

    SetMiniDumpInprocCommentW(L"sec", L"k2", L"v2", CommentStringReplace);
    CheckStored("W: second key in same section", L"[sec]\nk=v\nk2=v2\n");

    SetMiniDumpInprocCommentW(L"sec2", L"a", L"1", CommentStringReplace);
    CheckStored("W: new section appended at end", L"[sec]\nk=v\nk2=v2\n[sec2]\na=1\n");
}

void TestReplaceAndDelete()
{
    ResetComment();
    SetMiniDumpInprocCommentW(L"sec", L"k", L"v1", CommentStringReplace);
    SetMiniDumpInprocCommentW(L"sec", L"k", L"v2", CommentStringReplace);
    CheckStored("W: REPLACE overwrites existing value", L"[sec]\nk=v2\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"sec", L"k1", L"a", CommentStringReplace);
    SetMiniDumpInprocCommentW(L"sec", L"k2", L"b", CommentStringReplace);
    CheckBool("W: delete returns TRUE",
              SetMiniDumpInprocCommentW(L"sec", L"k1", nullptr, CommentStringReplace) == TRUE);
    CheckStored("W: REPLACE NULL deletes the whole key line", L"[sec]\nk2=b\n");
}

void TestMerge()
{
    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringReplace);
    SetMiniDumpInprocCommentW(L"s", L"k", L"y", CommentStringMerge);
    CheckStored("W: MERGE appends a new token", L"[s]\nk=x;y\n");
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringMerge);
    CheckStored("W: MERGE dedups an existing token", L"[s]\nk=x;y\n");
    SetMiniDumpInprocCommentW(L"s", L"k", L"y", CommentStringMerge);
    CheckStored("W: MERGE dedups the trailing token", L"[s]\nk=x;y\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"", CommentStringReplace);
    CheckStored("W: REPLACE with empty value", L"[s]\nk=\n");
    SetMiniDumpInprocCommentW(L"s", L"k", L"z", CommentStringMerge);
    CheckStored("W: MERGE into empty value has no leading ';'", L"[s]\nk=z\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringMerge);
    CheckStored("W: MERGE inserts when key absent (no ';')", L"[s]\nk=x\n");
}

void TestAppend()
{
    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringReplace);
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringAppend);
    CheckStored("W: APPEND allows a duplicate token", L"[s]\nk=x;x\n");
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringAppend);
    CheckStored("W: APPEND appends another duplicate", L"[s]\nk=x;x;x\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"x", CommentStringAppend);
    CheckStored("W: APPEND inserts when key absent (no ';')", L"[s]\nk=x\n");
}

void TestEscaping()
{
    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"a\nb", CommentStringReplace);
    CheckStored("W: '\\n' escaped to U+21B5", std::wstring(L"[s]\nk=a") + kArrow + L"b\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"a;b", CommentStringReplace);
    CheckStored("W: ';' escaped to U+FF1B", std::wstring(L"[s]\nk=a") + kFwSemi + L"b\n");

    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"k", L"a\r\nb", CommentStringReplace);
    CheckStored("W: '\\r' dropped and '\\n' escaped", std::wstring(L"[s]\nk=a") + kArrow + L"b\n");
}

void TestTruncationAndLimits()
{
    ResetComment();
    {
        const std::wstring big(300, L'a');
        SetMiniDumpInprocCommentW(L"s", L"k", big.c_str(), CommentStringReplace);
        const std::wstring expect = std::wstring(L"[s]\nk=") + std::wstring(256, L'a') + L"\n";
        CheckStored("W: value truncated to 256 chars", expect);
    }

    ResetComment();
    {
        const std::wstring sec64(64, L's');
        CheckBool("W: 64-char section accepted",
                  SetMiniDumpInprocCommentW(sec64.c_str(), L"k", L"v", CommentStringReplace) == TRUE);
        CheckStored("W: 64-char section stored", std::wstring(L"[") + sec64 + L"]\nk=v\n");
    }

    ResetComment();
    {
        const std::wstring sec65(65, L's');
        CheckBool("W: 65-char section rejected",
                  SetMiniDumpInprocCommentW(sec65.c_str(), L"k", L"v", CommentStringReplace) == FALSE);
        CheckStored("W: rejected long section leaves buffer empty", L"");
        const std::wstring key65(65, L'k');
        CheckBool("W: 65-char key rejected",
                  SetMiniDumpInprocCommentW(L"s", key65.c_str(), L"v", CommentStringReplace) == FALSE);
    }
}

void TestSectionBoundaries()
{
    ResetComment();
    SetMiniDumpInprocCommentW(L"A", L"k", L"1", CommentStringReplace);
    SetMiniDumpInprocCommentW(L"B", L"k", L"2", CommentStringReplace);
    CheckStored("W: two independent sections", L"[A]\nk=1\n[B]\nk=2\n");

    SetMiniDumpInprocCommentW(L"A", L"k", L"9", CommentStringReplace);
    CheckStored("W: REPLACE targets the correct section", L"[A]\nk=9\n[B]\nk=2\n");

    SetMiniDumpInprocCommentW(L"A", L"k2", L"3", CommentStringReplace);
    CheckStored("W: insert respects the section body boundary", L"[A]\nk=9\nk2=3\n[B]\nk=2\n");
}

void TestAnsiVariant()
{
    ResetComment();
    CheckBool("A: insert returns TRUE",
              SetMiniDumpInprocCommentA("sec", "k", "v", CommentStringReplace) == TRUE);
    CheckStored("A: basic insert maps to wide text", L"[sec]\nk=v\n");

    ResetComment();
    SetMiniDumpInprocCommentA("s", "k", "a\nb", CommentStringReplace);
    CheckStored("A: '\\n' escaped to U+21B5", std::wstring(L"[s]\nk=a") + kArrow + L"b\n");

    ResetComment();
    SetMiniDumpInprocCommentA("s", "k", "a;b", CommentStringReplace);
    CheckStored("A: ';' escaped to U+FF1B", std::wstring(L"[s]\nk=a") + kFwSemi + L"b\n");

    ResetComment();
    SetMiniDumpInprocCommentA("s", "k1", "a", CommentStringReplace);
    SetMiniDumpInprocCommentA("s", "k2", "b", CommentStringReplace);
    SetMiniDumpInprocCommentA("s", "k1", nullptr, CommentStringReplace);
    CheckStored("A: NULL value deletes key", L"[s]\nk2=b\n");

    ResetComment();
    CheckBool("A: NULL section rejected",
              SetMiniDumpInprocCommentA(nullptr, "k", "v", CommentStringReplace) == FALSE);
    {
        const std::string sec65(65, 's');
        CheckBool("A: 65-char section rejected",
                  SetMiniDumpInprocCommentA(sec65.c_str(), "k", "v", CommentStringReplace) == FALSE);
    }

    // A and W write into the SAME CommentStreamW buffer.
    ResetComment();
    SetMiniDumpInprocCommentW(L"s", L"wide", L"W", CommentStringReplace);
    SetMiniDumpInprocCommentA("s", "ansi", "A", CommentStringReplace);
    CheckStored("A/W share one CommentStreamW buffer", L"[s]\nwide=W\nansi=A\n");
}

} // namespace

int wmain()
{
    TestInputValidation();
    TestInsertAndSections();
    TestReplaceAndDelete();
    TestMerge();
    TestAppend();
    TestEscaping();
    TestTruncationAndLimits();
    TestSectionBoundaries();
    TestAnsiVariant();

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
