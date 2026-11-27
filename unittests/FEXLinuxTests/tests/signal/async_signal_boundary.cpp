// A signal handler that moves the buffer the interrupted code is writing, the way a compacting GC moves an object, and points
// the register that holds it at the new copy. This only works if the signal arrives between two instructions: one that arrives
// after an instruction computed its store address from that register, but before the store, loses the byte to the old copy.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <thread>
#include <unistd.h>

constexpr size_t Size = 65536;
constexpr int Rounds = 500;
// A loaded machine can starve the sender for whole rounds: keep going until enough moves happened, within a bound.
constexpr int MinMoves = 100;
constexpr int MaxRounds = 50000;

alignas(64) static uint8_t Buffers[2][Size + 16];
static volatile int Moves;
static volatile int Filling;

static void Handler(int, siginfo_t*, void* Context) {
  if (!Filling) {
    return;
  }

  auto& MContext = static_cast<ucontext_t*>(Context)->uc_mcontext;
#ifdef __x86_64__
  auto& Reg = MContext.gregs[REG_RAX];
#else
  auto& Reg = MContext.gregs[REG_EAX];
#endif
  auto* From = reinterpret_cast<uint8_t*>(Reg);
  auto* To = From == Buffers[0] ? Buffers[1] : Buffers[0];
  memcpy(To, From, sizeof(Buffers[0]));
  memset(From, 0xEE, sizeof(Buffers[0]));
  Reg = reinterpret_cast<uintptr_t>(To);
  Moves = Moves + 1;
}

// Fills Buffer[16 + k] with k * 31 one byte at a time and returns where the buffer ended up.
static uint8_t* Fill(uint8_t* Buffer) {
  uint8_t* Result;
  uintptr_t Index;
  __asm volatile(R"(
    mov dword ptr [%[Filling]], 1
    xor ecx, ecx
  .LFill:
    imul edx, ecx, 31
    mov byte ptr [%[Buf] + %[Index] + 16], dl
    inc %[Index]
    cmp %[Index], %[Size]
    jb .LFill
    mov dword ptr [%[Filling]], 0
  )"
                 : [Buf] "=a"(Result), [Index] "=&c"(Index)
                 : "0"(Buffer), [Size] "i"(Size), [Filling] "r"(&Filling)
                 : "memory", "cc", "edx");
  return Result;
}

TEST_CASE("Signals: a handler's register changes apply at an instruction boundary") {
  struct sigaction act {};
  act.sa_sigaction = Handler;
  act.sa_flags = SA_SIGINFO | SA_RESTART;
  REQUIRE(sigaction(SIGUSR1, &act, nullptr) == 0);

  const pid_t Tid = ::gettid();
  std::atomic<bool> Done {};
  std::thread Sender([&] {
    while (!Done) {
      tgkill(::getpid(), Tid, SIGUSR1);
      usleep(20);
    }
  });

  int BadRounds = 0;
  for (int Round = 0; Round < Rounds || (Moves < MinMoves && Round < MaxRounds); Round++) {
    memset(Buffers, 0, sizeof(Buffers));
    auto* Buffer = Fill(Buffers[Round & 1]);
    for (size_t k = 0; k < Size; k++) {
      if (Buffer[16 + k] != static_cast<uint8_t>(k * 31)) {
        BadRounds++;
        break;
      }
    }
  }

  Done = true;
  Sender.join();

  // Without moves the test shows nothing.
  CHECK(Moves > 10);
  CHECK(BadRounds == 0);
}
