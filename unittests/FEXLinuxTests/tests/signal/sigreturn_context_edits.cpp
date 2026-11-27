// A signal handler can change the interrupted code's registers and flags in its signal frame and return to the same RIP, as the
// .NET GC does when it moves objects referenced from a thread it suspended. The changes have to take effect, also when the signal
// arrives in JIT code, which holds the guest registers and flags in host registers.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <thread>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wattributes"

enum class Edit { GPR, XMM, CF, ZF, PF, AF };

static volatile Edit Current;
static volatile int InLoop;
static volatile int Signals;
static uintptr_t EscapeIP;

constexpr uint32_t CF = 1U << 0;
constexpr uint32_t PF = 1U << 2;
constexpr uint32_t AF = 1U << 4;
constexpr uint32_t ZF = 1U << 6;

// Applies the edit the loop waits for. A loop the edit never reaches is sent to its escape label instead.
template<typename T>
static void Apply(T& IP, T& BX, T& Flags, uint32_t* XMM1) {
  if (!InLoop) {
    return;
  }

  Signals = Signals + 1;
  if (Signals >= 100) {
    IP = EscapeIP;
    return;
  }

  switch (Current) {
  case Edit::GPR: BX = 1; break;
  case Edit::XMM: XMM1[0] = 1; break;
  case Edit::CF: Flags |= CF; break;
  case Edit::ZF: Flags &= ~ZF; break;
  case Edit::PF: Flags &= ~PF; break;
  case Edit::AF: Flags |= AF; break;
  }
}

static void Handler(int, siginfo_t*, void* Context) {
  auto& MContext = static_cast<ucontext_t*>(Context)->uc_mcontext;
#ifdef __x86_64__
  Apply(MContext.gregs[REG_RIP], MContext.gregs[REG_RBX], MContext.gregs[REG_EFL], MContext.fpregs->_xmm[1].element);
#else
  Apply(MContext.gregs[REG_EIP], MContext.gregs[REG_EBX], MContext.gregs[REG_EFL], static_cast<uint32_t*>(nullptr));
#endif
}

#ifndef __x86_64__
// A handler without SA_SIGINFO gets a sigframe: return address, signal number, then the sigcontext. The compiler may copy an
// address-taken argument, so find it from the frame instead.
static void LegacyHandler(int) {
  auto* SC = reinterpret_cast<sigcontext*>(static_cast<char*>(__builtin_frame_address(0)) + 12);
  Apply(SC->eip, SC->ebx, SC->eflags, static_cast<uint32_t*>(nullptr));
}
#endif

extern "C" void EscapeGPR();
extern "C" void EscapeXMM();
extern "C" void EscapeCF();
extern "C" void EscapeZF();
extern "C" void EscapePF();
extern "C" void EscapeAF();

// Each loop spins until the handler makes the change it waits for, then reports whether it got there and the state that has to
// survive.

__attribute__((noinline)) static bool SpinGPR(uint32_t& Kept) {
  int Ok = 0;
  __asm volatile(R"(
    mov ecx, 0x12345678
    xor ebx, ebx
    mov dword ptr [%[InLoop]], 1
  .LSpinGPR:
    test ebx, ebx
    jz .LSpinGPR
    mov dword ptr [%[Ok]], 1
  .global EscapeGPR
  EscapeGPR:
    mov dword ptr [%[InLoop]], 0
    mov dword ptr [%[Kept]], ecx
  )"
                 :
                 : [Ok] "r"(&Ok), [Kept] "r"(&Kept), [InLoop] "r"(&InLoop)
                 : "memory", "cc", "ebx", "ecx");
  return Ok;
}

#ifdef __x86_64__
__attribute__((noinline)) static bool SpinXMM(uint64_t& Kept) {
  int Ok = 0;
  __asm volatile(R"(
    mov rax, 0x123456789abcdef0
    movq xmm0, rax
    pxor xmm1, xmm1
    mov dword ptr [%[InLoop]], 1
  .LSpinXMM:
    movd eax, xmm1
    test eax, eax
    jz .LSpinXMM
    mov dword ptr [%[Ok]], 1
  .global EscapeXMM
  EscapeXMM:
    mov dword ptr [%[InLoop]], 0
    movq qword ptr [%[Kept]], xmm0
  )"
                 :
                 : [Ok] "r"(&Ok), [Kept] "r"(&Kept), [InLoop] "r"(&InLoop)
                 : "memory", "cc", "rax", "xmm0", "xmm1");
  return Ok;
}
#endif

// ZF and PF have to survive a change to CF, and so on.
__attribute__((noinline)) static bool SpinCF(uint8_t& ZFKept, uint8_t& PFKept) {
  int Ok = 0;
  __asm volatile(R"(
    mov dword ptr [%[InLoop]], 1
    xor eax, eax
  .LSpinCF:
    jnc .LSpinCF
    mov dword ptr [%[Ok]], 1
  .global EscapeCF
  EscapeCF:
    setz byte ptr [%[ZFKept]]
    setp byte ptr [%[PFKept]]
    mov dword ptr [%[InLoop]], 0
  )"
                 :
                 : [Ok] "r"(&Ok), [ZFKept] "r"(&ZFKept), [PFKept] "r"(&PFKept), [InLoop] "r"(&InLoop)
                 : "memory", "cc", "eax");
  return Ok;
}

__attribute__((noinline)) static bool SpinZF(uint8_t& CFKept) {
  int Ok = 0;
  __asm volatile(R"(
    mov dword ptr [%[InLoop]], 1
    xor eax, eax
    stc
  .LSpinZF:
    jz .LSpinZF
    mov dword ptr [%[Ok]], 1
  .global EscapeZF
  EscapeZF:
    setc byte ptr [%[CFKept]]
    mov dword ptr [%[InLoop]], 0
  )"
                 :
                 : [Ok] "r"(&Ok), [CFKept] "r"(&CFKept), [InLoop] "r"(&InLoop)
                 : "memory", "cc", "eax");
  return Ok;
}

__attribute__((noinline)) static bool SpinPF(uint8_t& ZFKept) {
  int Ok = 0;
  __asm volatile(R"(
    mov dword ptr [%[InLoop]], 1
    xor eax, eax
  .LSpinPF:
    jp .LSpinPF
    mov dword ptr [%[Ok]], 1
  .global EscapePF
  EscapePF:
    setz byte ptr [%[ZFKept]]
    mov dword ptr [%[InLoop]], 0
  )"
                 :
                 : [Ok] "r"(&Ok), [ZFKept] "r"(&ZFKept), [InLoop] "r"(&InLoop)
                 : "memory", "cc", "eax");
  return Ok;
}

// AF has no jump: the loop reads it with lahf and looks bit 4 up in this table, so nothing in it writes the flags.
static uint8_t AFBit[256];

__attribute__((noinline)) static bool SpinAF(uint8_t& ZFKept, uint8_t& PFKept) {
  int Ok = 0;
  uintptr_t Index;
  __asm volatile(R"(
    mov dword ptr [%[InLoop]], 1
    xor %k[Index], %k[Index]
    add %k[Index], 0
  .LSpinAF:
    lahf
    movzx %k[Index], ah
    movzx %k[Index], byte ptr [%[Table] + %[Index]]
    jecxz .LSpinAF
    mov dword ptr [%[Ok]], 1
  .global EscapeAF
  EscapeAF:
    setz byte ptr [%[ZFKept]]
    setp byte ptr [%[PFKept]]
    mov dword ptr [%[InLoop]], 0
  )"
                 : [Index] "=&c"(Index)
                 : [Ok] "r"(&Ok), [ZFKept] "r"(&ZFKept), [PFKept] "r"(&PFKept), [InLoop] "r"(&InLoop), [Table] "r"(AFBit)
                 : "memory", "cc", "eax");
  return Ok;
}

static void Start(Edit E, void (*Escape)()) {
  Current = E;
  Signals = 0;
  EscapeIP = reinterpret_cast<uintptr_t>(Escape);
}

static void RunAll() {
  const pid_t Tid = ::gettid();
  std::atomic<bool> Done {};
  // Keep signalling: one that arrives outside the loops does nothing.
  std::thread Sender([&] {
    while (!Done) {
      tgkill(::getpid(), Tid, SIGUSR1);
      usleep(1000);
    }
  });

  uint32_t GPRKept {};
  Start(Edit::GPR, EscapeGPR);
  CHECK(SpinGPR(GPRKept));
  CHECK(GPRKept == 0x12345678);

#ifdef __x86_64__
  uint64_t XMMKept {};
  Start(Edit::XMM, EscapeXMM);
  CHECK(SpinXMM(XMMKept));
  CHECK(XMMKept == 0x123456789abcdef0);
#endif

  uint8_t ZFKept {}, PFKept {}, CFKept {};
  Start(Edit::CF, EscapeCF);
  CHECK(SpinCF(ZFKept, PFKept));
  CHECK(ZFKept == 1);
  CHECK(PFKept == 1);

  Start(Edit::ZF, EscapeZF);
  CHECK(SpinZF(CFKept));
  CHECK(CFKept == 1);

  ZFKept = 0;
  Start(Edit::PF, EscapePF);
  CHECK(SpinPF(ZFKept));
  CHECK(ZFKept == 1);

  for (unsigned i = 0; i < 256; i++) {
    AFBit[i] = (i & AF) != 0;
  }
  ZFKept = 0;
  PFKept = 0;
  Start(Edit::AF, EscapeAF);
  CHECK(SpinAF(ZFKept, PFKept));
  CHECK(ZFKept == 1);
  CHECK(PFKept == 1);

  Done = true;
  Sender.join();
}

TEST_CASE("Signals: rt_sigreturn applies the handler's register changes") {
  struct sigaction act {};
  act.sa_sigaction = Handler;
  act.sa_flags = SA_SIGINFO | SA_RESTART;
  REQUIRE(sigaction(SIGUSR1, &act, nullptr) == 0);
  RunAll();
}

#ifndef __x86_64__
TEST_CASE("Signals: sigreturn applies the handler's register changes") {
  struct sigaction act {};
  act.sa_handler = LegacyHandler;
  act.sa_flags = SA_RESTART;
  REQUIRE(sigaction(SIGUSR1, &act, nullptr) == 0);
  RunAll();
}
#endif
