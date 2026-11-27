#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <windows.h>

#include "placeholder_views.h"

using Fn = uint32_t (*)();
static constexpr SIZE_T ViewSize = 0x10000;
static constexpr uint8_t Code[] = {0xb8, 0x7b, 0, 0, 0, 0xc3}; // mov eax, 123; ret

static bool DisableDEP() {
  // Wine's SetProcessDEPPolicy(0) passes no flags, which its NtSetInformationProcess refuses, so set them directly.
  static const bool Disabled = [] {
    using SetInfoFn = LONG(WINAPI*)(HANDLE, ULONG, void*, ULONG);
    auto NtSetInformationProcess = reinterpret_cast<SetInfoFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
    ULONG Flags = 2; // MEM_EXECUTE_OPTION_ENABLE
    return NtSetInformationProcess && !NtSetInformationProcess(GetCurrentProcess(), 34 /* ProcessExecuteFlags */, &Flags, sizeof(Flags));
  }();
  return Disabled;
}

// With DEP off, readable memory is executable, including views of non-image sections mapped afterwards.
TEST_CASE("A readable view runs with DEP disabled") {
  if (!DisableDEP()) {
    SKIP("DEP can't be disabled in this process");
  }
  HANDLE Section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, ViewSize, nullptr);
  REQUIRE(Section);
  auto* RW = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
  auto* R = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
  REQUIRE(RW);
  REQUIRE(R);

  memcpy(RW, Code, sizeof(Code));
  CHECK(reinterpret_cast<Fn>(R)() == 123);

  UnmapViewOfFile(R);
  UnmapViewOfFile(RW);
  CloseHandle(Section);
}

// Executable only because DEP is off, the readable view's range must be forgotten with the view. Otherwise the executable
// view mapped there next is trapped for writes as if it was not executable either, and loses its execute permission.
TEST_CASE("An executable view keeps its protection where a readable view was unmapped") {
  if (!DisableDEP()) {
    SKIP("DEP can't be disabled in this process");
  }
  HANDLE Section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, ViewSize, nullptr);
  REQUIRE(Section);
  auto* X = PlaceholderViews::Reserve(ViewSize);
  REQUIRE(X);

  REQUIRE(PlaceholderViews::Map(Section, X, ViewSize, PAGE_READWRITE));
  memcpy(X, Code, sizeof(Code));
  CHECK(reinterpret_cast<Fn>(X)() == 123);
  PlaceholderViews::Unmap(X);

  // Running code from a writable view traps writes to it, keeping it executable.
  REQUIRE(PlaceholderViews::Map(Section, X, ViewSize, PAGE_EXECUTE_READWRITE));
  CHECK(reinterpret_cast<Fn>(X)() == 123);
  MEMORY_BASIC_INFORMATION Info {};
  REQUIRE(VirtualQuery(X, &Info, sizeof(Info)));
  CHECK(Info.Protect == PAGE_EXECUTE_READ);

  PlaceholderViews::Release(X);
  CloseHandle(Section);
}
