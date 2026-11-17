// A guest signal handler returns through rt_sigreturn, a syscall, so the JIT marks the thread as in a syscall. FEX then resumes the
// interrupted code from the signal frame instead of returning from that syscall, so it has to restore whether the interrupted code
// was in a syscall along with the rest of its state. Left marked, the next signal in the JIT skips spilling the live registers and
// builds its frame from the stack pointer saved at the first fault. Here that is Work()'s, so the second frame lands on Inner()'s
// live locals.
//
// The same goes for a signal that arrives while FEX is in a syscall: its guest handler isn't in that syscall, so a fault in the
// handler has to spill like any other.

#include <catch2/catch_test_macros.hpp>

#include <csignal>
#include <cerrno>
#include <cstdint>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t PageSize;
static volatile char* Page1;
static volatile char* Page2;
static volatile int Faults;

static void Handler(int, siginfo_t* Info, void*) {
  auto Page = reinterpret_cast<uintptr_t>(Info->si_addr) & ~(PageSize - 1);
  mprotect(reinterpret_cast<void*>(Page), PageSize, PROT_READ | PROT_WRITE);
  Faults = Faults + 1;
}

// Returns 0 when its locals survive the fault.
__attribute__((noinline)) static uint64_t Inner(uint64_t Seed) {
  volatile uint64_t Local[32];
  for (int i = 0; i < 32; i++) {
    Local[i] = Seed * 31 + i;
  }
  Page2[0] = Seed; // Second fault, after the handler of the first one returned
  uint64_t Bad = 0;
  for (int i = 0; i < 32; i++) {
    Bad += Local[i] ^ (Seed * 31 + i);
  }
  return Bad;
}

// Returns 0 when its locals and Inner()'s survive the faults.
__attribute__((noinline)) static uint64_t Work(uint64_t Seed) {
  uint64_t A = Seed * 3 + 1, B = Seed ^ 0x5555, C = Seed * 7, D = Seed + 11;
  Page1[0] = A; // First fault
  uint64_t Bad = Inner(Seed);
  return Bad + (A + 2 * B + 3 * C + 4 * D) - ((Seed * 3 + 1) + 2 * (Seed ^ 0x5555) + 3 * (Seed * 7) + 4 * (Seed + 11));
}

TEST_CASE("Signals: rt_sigreturn restores the syscall state") {
  PageSize = sysconf(_SC_PAGESIZE);
  struct sigaction act {};
  act.sa_sigaction = Handler;
  act.sa_flags = SA_SIGINFO;
  REQUIRE(sigaction(SIGSEGV, &act, nullptr) == 0);

  Page1 = static_cast<volatile char*>(mmap(nullptr, PageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  Page2 = static_cast<volatile char*>(mmap(nullptr, PageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  REQUIRE(Page1 != MAP_FAILED);
  REQUIRE(Page2 != MAP_FAILED);

  constexpr int Iterations = 200;
  int Bad = 0;
  Faults = 0;
  for (int i = 0; i < Iterations; i++) {
    REQUIRE(mprotect((void*)Page1, PageSize, PROT_READ) == 0);
    REQUIRE(mprotect((void*)Page2, PageSize, PROT_READ) == 0);
    if (Work(i) != 0) {
      Bad++;
    }
  }

  CHECK(Bad == 0);
  CHECK(Faults == 2 * Iterations);
}

static volatile uint64_t AlarmBad;
static volatile uint64_t AlarmSeed;
static void AlarmHandler(int) {
  AlarmBad = AlarmBad + Inner(AlarmSeed);
}

TEST_CASE("Signals: a handler entered from a blocking syscall isn't in that syscall") {
  PageSize = sysconf(_SC_PAGESIZE);
  struct sigaction act {};
  act.sa_sigaction = Handler;
  act.sa_flags = SA_SIGINFO;
  REQUIRE(sigaction(SIGSEGV, &act, nullptr) == 0);
  struct sigaction AlarmAct {};
  AlarmAct.sa_handler = AlarmHandler; // No SA_RESTART: read returns EINTR after the handler
  REQUIRE(sigaction(SIGALRM, &AlarmAct, nullptr) == 0);

  Page2 = static_cast<volatile char*>(mmap(nullptr, PageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  REQUIRE(Page2 != MAP_FAILED);
  int Pipe[2];
  REQUIRE(pipe(Pipe) == 0);

  constexpr int Iterations = 50;
  Faults = 0;
  for (int i = 0; i < Iterations; i++) {
    REQUIRE(mprotect((void*)Page2, PageSize, PROT_READ) == 0);
    AlarmSeed = i;
    itimerval Timer {.it_interval = {}, .it_value = {.tv_sec = 0, .tv_usec = 1000}};
    REQUIRE(setitimer(ITIMER_REAL, &Timer, nullptr) == 0);
    char Byte;
    // Blocks until SIGALRM arrives in the syscall; the handler takes a fault in Inner()
    REQUIRE(read(Pipe[0], &Byte, 1) == -1);
    REQUIRE(errno == EINTR);
  }

  CHECK(AlarmBad == 0);
  CHECK(Faults == Iterations);
}
