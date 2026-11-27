#include <catch2/catch_test_macros.hpp>

#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <csetjmp>
#include <cstdint>
#include <cstring>

static jmp_buf LongJump {};
static volatile sig_atomic_t CaughtSignal {};
static void* volatile FaultAddress {};

static void SignalHandler(int Signal, siginfo_t* Info, void*) {
  CaughtSignal = Signal;
  FaultAddress = Info->si_addr;
  longjmp(LongJump, 1);
}

// Runs Bytes placed at the end of an executable page whose next page is PROT_NONE.
// The fetch fault must win over any decode error, and be reported at the first byte that can't be fetched.
static void CheckCrossPageFetchFault(const uint8_t* Bytes, size_t Size, size_t BytesInFirstPage) {
  struct sigaction Act {};
  Act.sa_sigaction = SignalHandler;
  Act.sa_flags = SA_SIGINFO;

  REQUIRE(sigaction(SIGILL, &Act, nullptr) == 0);
  REQUIRE(sigaction(SIGSEGV, &Act, nullptr) == 0);

  const auto PageSize = sysconf(_SC_PAGESIZE);
  REQUIRE(PageSize > 0);

  void* Ptr = mmap(nullptr, PageSize * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(Ptr != MAP_FAILED);

  const auto NextPage = static_cast<uint8_t*>(Ptr) + PageSize;
  auto Code = NextPage - BytesInFirstPage;
  memcpy(Code, Bytes, Size);

  REQUIRE(mprotect(NextPage, PageSize, PROT_NONE) == 0);

  using FuncPtr = void (*)();
  auto Func = reinterpret_cast<FuncPtr>(Code);

  CaughtSignal = 0;
  FaultAddress = nullptr;
  if (setjmp(LongJump) == 0) {
    Func();
    FAIL("Cross-page instruction unexpectedly executed");
  }

  CHECK(CaughtSignal == SIGSEGV);
  CHECK(FaultAddress == NextPage);
  REQUIRE(munmap(Ptr, PageSize * 2) == 0);
}

TEST_CASE("Signals: Instruction fetch faults take priority over decode errors") {
  // movzx r8d, byte [rax]; ret
  const uint8_t Bytes[] = {0x44, 0x0f, 0xb6, 0x00, 0xc3};
  CheckCrossPageFetchFault(Bytes, sizeof(Bytes), 2);
}

TEST_CASE("Signals: Instruction fetch fault inside a VEX prefix") {
  // vpshufb xmm0, xmm1, xmm2; ret. With zeros read past the page, the VEX prefix decodes as invalid.
  const uint8_t Bytes[] = {0xc4, 0xe2, 0x71, 0x00, 0xc2, 0xc3};
  CheckCrossPageFetchFault(Bytes, sizeof(Bytes), 2);
}
