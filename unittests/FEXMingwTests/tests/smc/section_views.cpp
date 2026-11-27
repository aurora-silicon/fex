#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <windows.h>

#include "placeholder_views.h"

// Views of a non-image section raise no protection notification, so FEX learns executable ones from their protection.

using Fn = uint32_t (*)();
static constexpr uint32_t Faulted = UINT32_MAX;
static constexpr SIZE_T ViewSize = 0x10000;
static void* FaultAddress;

// Returns Faulted from a call to FaultAddress that raised an execute fault.
__attribute__((stdcall)) static long ReturnOnExecuteFault(EXCEPTION_POINTERS* Info) {
  auto* Rec = Info->ExceptionRecord;
  if (Rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || Rec->ExceptionInformation[0] != EXCEPTION_EXECUTE_FAULT ||
      Rec->ExceptionInformation[1] != reinterpret_cast<ULONG_PTR>(FaultAddress)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  auto* Ctx = Info->ContextRecord;
#ifdef _WIN64
  Ctx->Rip = *reinterpret_cast<DWORD64*>(Ctx->Rsp);
  Ctx->Rsp += 8;
  Ctx->Rax = Faulted;
#else
  Ctx->Eip = *reinterpret_cast<DWORD*>(Ctx->Esp);
  Ctx->Esp += 4;
  Ctx->Eax = Faulted;
#endif
  return EXCEPTION_CONTINUE_EXECUTION;
}

static void WriteReturn(void* Dst, uint32_t Value) {
  uint8_t Code[] = {0xb8, 0, 0, 0, 0, 0xc3}; // mov eax, Value; ret
  memcpy(Code + 1, &Value, sizeof(Value));
  memcpy(Dst, Code, sizeof(Code));
}

static HANDLE NewSection() {
  return CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, ViewSize, nullptr);
}

TEST_CASE("Code written through a writable view runs from an executable view") {
  HANDLE Section = NewSection();
  REQUIRE(Section);
  auto* RW = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
  auto* RX = MapViewOfFile(Section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
  REQUIRE(RW);
  REQUIRE(RX);

  WriteReturn(RW, 1);
  CHECK(reinterpret_cast<Fn>(RX)() == 1);

  // Writes through the other view are only seen after a flush. Proton's x86 FlushInstructionCache returns without
  // calling ntdll, so call it directly.
  using FlushFn = LONG(WINAPI*)(HANDLE, const void*, SIZE_T);
  auto NtFlushInstructionCache = reinterpret_cast<FlushFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFlushInstructionCache"));
  REQUIRE(NtFlushInstructionCache);
  WriteReturn(RW, 2);
  REQUIRE(NtFlushInstructionCache(GetCurrentProcess(), RX, 6) == 0);
  CHECK(reinterpret_cast<Fn>(RX)() == 2);

  UnmapViewOfFile(RX);
  UnmapViewOfFile(RW);
  CloseHandle(Section);
}

TEST_CASE("An unmapped executable view leaves nothing behind at its address") {
  auto* Handler = AddVectoredExceptionHandler(1, ReturnOnExecuteFault);
  HANDLE Section = NewSection();
  REQUIRE(Section);
  auto* RW = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
  REQUIRE(RW);

  auto* X = PlaceholderViews::Reserve(ViewSize);
  REQUIRE(X);
  FaultAddress = X;

  WriteReturn(RW, 1);
  REQUIRE(PlaceholderViews::Map(Section, X, ViewSize, PAGE_EXECUTE_READ));
  CHECK(reinterpret_cast<Fn>(X)() == 1);
  PlaceholderViews::Unmap(X);

  // A non-executable view at the same address must fault, not run the old view's code.
  WriteReturn(RW, 2);
  REQUIRE(PlaceholderViews::Map(Section, X, ViewSize, PAGE_READWRITE));
  CHECK(reinterpret_cast<Fn>(X)() == Faulted);
  PlaceholderViews::Unmap(X);

  // An executable view there again runs, although the address faulted before.
  REQUIRE(PlaceholderViews::Map(Section, X, ViewSize, PAGE_EXECUTE_READ));
  CHECK(reinterpret_cast<Fn>(X)() == 2);
  PlaceholderViews::Release(X);

  UnmapViewOfFile(RW);
  CloseHandle(Section);
  RemoveVectoredExceptionHandler(Handler);
}

TEST_CASE("Unmapping an executable view while another thread runs it") {
  auto* Handler = AddVectoredExceptionHandler(1, ReturnOnExecuteFault);
  HANDLE Section = NewSection();
  REQUIRE(Section);
  auto* RW = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
  REQUIRE(RW);
  auto* X = PlaceholderViews::Reserve(ViewSize);
  REQUIRE(X);
  FaultAddress = X;

  // The runner compiles the view again after each unmap starts, racing the unmap.
  std::atomic<bool> Stop {};
  std::atomic<uint32_t> Calls {};
  std::thread Runner([&] {
    while (!Stop.load(std::memory_order_relaxed)) {
      reinterpret_cast<Fn>(X)();
      Calls.fetch_add(1, std::memory_order_relaxed);
    }
  });

  uint32_t Maps = 0;
  for (uint32_t i = 1; i <= 20000; i++) {
    WriteReturn(RW, i);
    if (PlaceholderViews::Map(Section, X, ViewSize, PAGE_EXECUTE_READ)) {
      Maps++;
      PlaceholderViews::Unmap(X);
    }
  }

  // Code or executable tracking that survived an unmap would run here instead of faulting.
  WriteReturn(RW, 0);
  const bool Mapped = PlaceholderViews::Map(Section, X, ViewSize, PAGE_READWRITE);
  Stop = true;
  Runner.join();
  INFO("maps " << Maps << ", runner calls " << Calls.load());
  CHECK(Maps == 20000);
  REQUIRE(Mapped);
  CHECK(reinterpret_cast<Fn>(X)() == Faulted);
  PlaceholderViews::Release(X);

  UnmapViewOfFile(RW);
  CloseHandle(Section);
  RemoveVectoredExceptionHandler(Handler);
}
