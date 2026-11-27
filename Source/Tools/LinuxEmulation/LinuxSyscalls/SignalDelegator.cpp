// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|common
desc: Handles host -> host and host -> guest signal routing, emulates procmask & co
$end_info$
*/

#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <functional>
#include <linux/futex.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <utility>

// For older build environments
#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

namespace FEX::HLE {
#ifdef ARCHITECTURE_x86_64
__attribute__((naked)) static void sigrestore() {
  __asm volatile("syscall;" ::"a"(0xF) : "memory");
}
#endif

constexpr static uint32_t X86_MINSIGSTKSZ = 2048;

static FEX::HLE::ThreadStateObject* GetThreadFromAltStack(const stack_t& alt_stack) {
  // The thread object lives just before the alt-stack begin.
  FEX::HLE::ThreadStateObject* ThreadObject {};
  memcpy(&ThreadObject, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(alt_stack.ss_sp) - 8), sizeof(void*));
  return ThreadObject;
}

static void SignalHandlerThunk(int Signal, siginfo_t* Info, void* UContext) {
  ucontext_t* _context = (ucontext_t*)UContext;
  auto ThreadObject = GetThreadFromAltStack(_context->uc_stack);
  FEXCORE_PROFILE_ACCUMULATION(ThreadObject->Thread, AccumulatedSignalTime);
  ThreadObject->SignalInfo.Delegator->HandleSignal(ThreadObject, Signal, Info, UContext);
}

/**
 * @name Signal frame setup
 * @{ */

void SignalDelegator::HandleSignal(FEX::HLE::ThreadStateObject* Thread, int Signal, void* Info, void* UContext) {
  // Let the host take first stab at handling the signal
  if (!Thread) {
    LogMan::Msg::AFmt("Thread {} has received a signal and hasn't registered itself with the delegate! Programming error!",
                      FHU::Syscalls::gettid());
  } else {
    SignalHandler& Handler = HostHandlers[Signal];
    for (auto& HandlerFunc : Handler.Handlers) {
      if (HandlerFunc(Thread->Thread, Signal, Info, UContext)) {
        // If the host handler handled the fault then we can continue now
        return;
      }
    }

    if (Handler.FrontendHandler && Handler.FrontendHandler(Thread->Thread, Signal, Info, UContext)) {
      return;
    }

    // Now let the frontend handle the signal
    // It's clearly a guest signal and this ends up being an OS specific issue
    HandleGuestSignal(Thread, Signal, Info, UContext);
  }
}

void SignalDelegator::RegisterHostSignalHandler(int Signal, HostSignalDelegatorFunction Func, bool Required) {
  SetHostSignalHandler(Signal, std::move(Func));
  FrontendRegisterHostSignalHandler(Signal, Required);
}

void SignalDelegator::SpillSRAFPRs(FEXCore::Core::InternalThreadState* Thread, void* ucontext) {
#ifdef ARCHITECTURE_arm64
  if (SupportsAVX && SupportsSVE256) {
    // TODO: This doesn't save the upper 128-bits of the 256-bit registers.
    // This needs to be implemented still.
    for (size_t i = 0; i < Config.SRAFPRCount; i++) {
      auto FPR = ArchHelpers::Context::GetArmFPR(ucontext, Config.SRAFPRMapping[i]);
      memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &FPR, sizeof(__uint128_t));
    }
  } else {
    for (size_t i = 0; i < Config.SRAFPRCount; i++) {
      auto FPR = ArchHelpers::Context::GetArmFPR(ucontext, Config.SRAFPRMapping[i]);
      memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &FPR, sizeof(__uint128_t));
    }
  }
#endif
}

void SignalDelegator::FillSRAFPRs(FEXCore::Core::InternalThreadState* Thread, void* ucontext) {
#ifdef ARCHITECTURE_arm64
  const auto& State = Thread->CurrentFrame->State;
  // A 32-bit guest frame only has the first eight registers, the frame's copy of the rest predates the spill.
  const size_t GuestRegs = Is64BitMode ? 16 : 8;

  // Like SpillSRAFPRs, this leaves the upper 128-bits of 256-bit registers alone.
  auto* FPRs = ArchHelpers::Context::GetArmFPRs(ucontext);
  for (size_t i = 0; i < std::min<size_t>(Config.SRAFPRCount, GuestRegs); i++) {
    const void* XMM = SupportsAVX && SupportsSVE256 ? &State.xmm.avx.data[i][0] : &State.xmm.sse.data[i][0];
    memcpy(&FPRs[Config.SRAFPRMapping[i]], XMM, sizeof(__uint128_t));
  }
#endif
}

void SignalDelegator::SpillSRA(FEXCore::Core::InternalThreadState* Thread, void* ucontext, uint32_t IgnoreMask) {
#ifdef ARCHITECTURE_arm64
  Thread->CurrentFrame->State.rip = CTX->RestoreRIPFromHostPC(Thread, ArchHelpers::Context::GetPc(ucontext));

  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    const uint8_t SRAIdxMap = Config.SRAGPRMapping[i];
    if (IgnoreMask & (1U << SRAIdxMap)) {
      // Skip this one, it's already spilled
      continue;
    }
    Thread->CurrentFrame->State.gregs[i] = ArchHelpers::Context::GetArmReg(ucontext, SRAIdxMap);
  }

  SpillSRAFPRs(Thread, ucontext);

  uint32_t EFlags =
    CTX->ReconstructCompactedEFLAGS(Thread, true, ArchHelpers::Context::GetArmGPRs(ucontext), ArchHelpers::Context::GetArmPState(ucontext));
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
#endif
}

// The inverse of SpillSRA, for resuming the interrupted JIT code with the guest state in the frame.
void SignalDelegator::FillSRA(FEXCore::Core::InternalThreadState* Thread, void* ucontext, uint32_t IgnoreMask, uint32_t ChangedEFLAGS) {
#ifdef ARCHITECTURE_arm64
  const auto& State = Thread->CurrentFrame->State;
  // A 32-bit guest frame only has the first eight registers, the frame's copy of the rest predates the spill.
  const size_t GuestRegs = Is64BitMode ? 16 : 8;

  for (size_t i = 0; i < std::min<size_t>(Config.SRAGPRCount, GuestRegs); i++) {
    const uint8_t SRAIdxMap = Config.SRAGPRMapping[i];
    if (IgnoreMask & (1U << SRAIdxMap)) {
      // Already spilled, the JIT reloads it from the frame
      continue;
    }
    ArchHelpers::Context::SetArmReg(ucontext, SRAIdxMap, State.gregs[i]);
  }

  FillSRAFPRs(Thread, ucontext);

  ArchHelpers::Context::SetArmPState(
    ucontext, CTX->FlipHostEFLAGS(ChangedEFLAGS, ArchHelpers::Context::GetArmGPRs(ucontext), ArchHelpers::Context::GetArmPState(ucontext)));
#endif
}

ArchHelpers::Context::ContextBackup*
SignalDelegator::StoreThreadState(FEXCore::Core::InternalThreadState* Thread, int Signal, void* ucontext, bool IsGuestSignal) {
  // We can end up getting a signal at any point in our host state
  // Jump to a handler that saves all state so we can safely return
  uint64_t OldSP = ArchHelpers::Context::GetSp(ucontext);
  uintptr_t NewSP = OldSP;

  size_t StackOffset = sizeof(ArchHelpers::Context::ContextBackup);

  // We need to back up behind the host's red zone
  // We do this on the guest side as well
  // (does nothing on arm hosts)
  NewSP -= ArchHelpers::Context::ContextBackup::RedZoneSize;

  NewSP -= StackOffset;
  NewSP = FEXCore::AlignDown(NewSP, 16);

  auto Context = reinterpret_cast<ArchHelpers::Context::ContextBackup*>(NewSP);
  ArchHelpers::Context::BackupContext(ucontext, Context);

  // Retain the action pointer so we can see it when we return
  Context->Signal = Signal;

  // Save guest state
  // We can't guarantee if registers are in context or host GPRs
  // So we need to save everything
  memcpy(&Context->GuestState, &Thread->CurrentFrame->State, sizeof(FEXCore::Core::CPUState));

  // Set the new SP
  ArchHelpers::Context::SetSp(ucontext, NewSP);

  Context->Flags = 0;
  Context->FPStateLocation = 0;
  Context->UContextLocation = 0;
  Context->SigInfoLocation = 0;
  Context->InSyscallInfo = Thread->CurrentFrame->InSyscallInfo;

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  if (IsGuestSignal && ThreadObject->SignalInfo.InSigSuspend) {
    // POSIX/Linux sigsuspend: a signal delivered during sigsuspend saves the pre-suspend mask
    // so rt_sigreturn restores it rather than leaking the temporary suspend mask.
    Context->GuestSigMask = ThreadObject->SignalInfo.PreviousSuspendMask.Val;
    ThreadObject->SignalInfo.InSigSuspend = false;
  } else {
    Context->GuestSigMask = ThreadObject->SignalInfo.CurrentSignalMask.Val;
  }

  // Store fault to top status and then reset it
  Context->FaultToTopAndGeneratedException = Thread->CurrentFrame->SynchronousFaultData.FaultToTopAndGeneratedException;
  Thread->CurrentFrame->SynchronousFaultData.FaultToTopAndGeneratedException = false;

  return Context;
}

void SignalDelegator::RestoreThreadState(FEXCore::Core::InternalThreadState* Thread, void* ucontext, RestoreType Type) {
  uint64_t OldSP {};
  if (Type == RestoreType::TYPE_PAUSE) [[unlikely]] {
    OldSP = ArchHelpers::Context::GetSp(ucontext);
  } else {
    // Some fun introspection here.
    // We store a pointer to our host-stack on the guest stack.
    // We need to inspect the guest state coming in, so we can get our host stack back.
    uint64_t GuestSP = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];

    if (Is64BitMode) {
      // Signal frame layout on stack needs to be as follows
      // void* ReturnPointer
      // ucontext_t
      // siginfo_t
      // FP state
      // Host stack location

      GuestSP += sizeof(FEXCore::x86_64::ucontext_t);
      GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::ucontext_t));

      GuestSP += sizeof(siginfo_t);
      GuestSP = FEXCore::AlignUp(GuestSP, alignof(siginfo_t));

      if (SupportsAVX) {
        GuestSP += sizeof(FEXCore::x86_64::xstate);
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::xstate));
      } else {
        GuestSP += sizeof(FEXCore::x86_64::_libc_fpstate);
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::_libc_fpstate));
      }
    } else {
      if (Type == RestoreType::TYPE_NONREALTIME) {
        // Signal frame layout on stack needs to be as follows
        // SigFrame_i32
        // FPState
        // Host stack location

        // Remove the 4-byte pretcode /AND/ a legacy argument that is ignored.
        GuestSP += sizeof(SigFrame_i32) - 8;
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(SigFrame_i32));

        if (SupportsAVX) {
          GuestSP += sizeof(FEXCore::x86::xstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::xstate));
        } else {
          GuestSP += sizeof(FEXCore::x86::_libc_fpstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::_libc_fpstate));
        }
      } else {
        // Signal frame layout on stack needs to be as follows
        // RTSigFrame_i32
        // FPState
        // Host stack location

        // Remove the 4-byte pretcode.
        GuestSP += sizeof(RTSigFrame_i32) - 4;
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(RTSigFrame_i32));

        if (SupportsAVX) {
          GuestSP += sizeof(FEXCore::x86::xstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::xstate));
        } else {
          GuestSP += sizeof(FEXCore::x86::_libc_fpstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::_libc_fpstate));
        }
      }
    }

    OldSP = *reinterpret_cast<uint64_t*>(GuestSP);
  }

  uintptr_t NewSP = OldSP;
  auto Context = reinterpret_cast<ArchHelpers::Context::ContextBackup*>(NewSP);

  // Restore host state
  ArchHelpers::Context::RestoreContext(ucontext, Context);

  // Reset the guest state
  memcpy(&Thread->CurrentFrame->State, &Context->GuestState, sizeof(FEXCore::Core::CPUState));

  // Also whether the interrupted code was in a syscall. A guest handler returns through rt_sigreturn, a syscall the JIT
  // marks with every register spilled and never unmarks, because this restore resumes the interrupted code instead.
  // Left set, the next signal in the JIT would skip spilling the live registers and build its frame from a stale RSP,
  // over live stack.
  Thread->CurrentFrame->InSyscallInfo = Context->InSyscallInfo;

  uint64_t RestoredGuestMask = Context->GuestSigMask;
  if (Context->UContextLocation) {
    auto Frame = Thread->CurrentFrame;

    // Like the kernel, take the whole guest state (including uc_sigmask) from the signal frame,
    // so changes the handler made to it take effect.
    if (Is64BitMode) {
      RestoredGuestMask = RestoreFrame_x64(Thread, Context, Frame);
    } else {
      if (Type == RestoreType::TYPE_NONREALTIME) {
        RestoredGuestMask = RestoreFrame_ia32(Thread, Context, Frame);
      } else {
        RestoredGuestMask = RestoreRTFrame_ia32(Thread, Context, Frame);
      }
    }

    if (Context->OriginalRIP != Frame->State.rip || Context->FaultToTopAndGeneratedException) {
      // The guest moved RIP, go back to the top of the dispatcher to run from there
      // The dispatcher will run a different guest instruction, so the interrupted syscall won't clear its spill mask.
      Frame->InSyscallInfo = 0;
      ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
      ArchHelpers::Context::SetFillSRASingleInst(ucontext, false);
      // Set our state register to point to our guest thread data
      ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));
    } else if (Context->Flags &
               (ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT | ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INDISPATCHER)) {
      // The interrupted code resumes with the static registers it holds in host registers, put the frame's values there.
      // Flags only get the handler's changes: the JIT may hold them in a different form at this point.
      const uint32_t ChangedEFLAGS = Context->OriginalEFLAGS ^ CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
      FillSRA(Thread, ucontext, Context->InSyscallInfo & 0xFFFF, ChangedEFLAGS);
    } else if (Context->Flags & ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_FPR_IN_UCONTEXT) {
      // The interrupted NoFP leaf thunk resumes without reloading static FPRs from the frame,
      // so propagate any guest handler XMM modifications back into ucontext's static FPRs.
      FillSRAFPRs(Thread, ucontext);
    }
  }

  if (Type != RestoreType::TYPE_PAUSE) {
    constexpr uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    RestoredGuestMask &= IgnoredSignalsMask;
    auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
    ThreadObject->SignalInfo.CurrentSignalMask.Val = RestoredGuestMask;
    const uint64_t RestoredHostMask = MaskToHostSigMask(RestoredGuestMask | GetDeferredSignalsMask(ThreadObject));
    memcpy(&ArchHelpers::Context::GetUContext(ucontext)->uc_sigmask, &RestoredHostMask, sizeof(uint64_t));
  }
}

bool SignalDelegator::HandleDispatcherGuestSignal(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext,
                                                  GuestSigAction* GuestAction, stack_t* GuestStack) {
  auto ContextBackup = StoreThreadState(Thread, Signal, ucontext, true);

  auto Frame = Thread->CurrentFrame;

  // Ref count our faults
  // We use this to track if it is safe to clear cache
  ++Thread->CurrentFrame->SignalHandlerRefCounter;

  uint64_t OldPC = ArchHelpers::Context::GetPc(ucontext);
  const bool WasInJIT = CTX->IsAddressInCodeBuffer(Thread, OldPC);

  // Spill the SRA regardless of signal handler type
  // We are going to be returning to the top of the dispatcher which will fill again
  // Otherwise we might load garbage
  // A thunk call sets IN_THUNK_CALL only once every static register is spilled to the frame, and clears it
  // only once they are filled again. JIT or dispatcher code executing while IN_THUNK_CALL is set (DEF_OP(Thunk),
  // CallbackPtr prologue, CallbackReturn epilogue) may hold clobbered host values in static host registers
  // (notably x8 = guest RSP, which host thunks clobber with Linux syscall numbers). The frame holds the
  // authoritative guest state, so neither spill nor refill SRA here.
  const bool InThunkCall = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::IN_THUNK_CALL) != 0;
  const bool FprsUnspilled = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::SRA_FPR_UNSPILLED) != 0;

  if (WasInJIT && !InThunkCall) {
    uint32_t IgnoreMask {};
#ifdef ARCHITECTURE_arm64
    if (Frame->InSyscallInfo != 0) {
      // We are in a syscall, this means we are in a weird register state
      // We need to spill SRA but only some of it, since some values have already been spilled
      // Lower 16 bits tells us which registers are already spilled to the context
      // So we ignore spilling those ones
      IgnoreMask = Frame->InSyscallInfo & 0xFFFF;
    } else {
      // We must spill everything
      IgnoreMask = 0;
    }
#endif

    // We are in jit, SRA must be spilled
    SpillSRA(Thread, ucontext, IgnoreMask);

    ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT;
  } else if (WasInJIT && InThunkCall) {
    // Reconstruct the thunk instruction RIP without touching the already-spilled static GPRs.
    Frame->State.rip = CTX->RestoreRIPFromHostPC(Thread, OldPC);
    if (FprsUnspilled) {
      SpillSRAFPRs(Thread, ucontext);
      ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_FPR_IN_UCONTEXT;
    }
  } else if (IsAddressInDispatcher(OldPC) && !InThunkCall) {
    if (FprsUnspilled) {
      SpillSRAFPRs(Thread, ucontext);
      ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_FPR_IN_UCONTEXT;
    } else {
      // Signals only arrive at points where the dispatcher holds the guest state in both the frame and the static registers.
      ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INDISPATCHER;
    }
  } else if (FprsUnspilled) {
    // Interrupted inside a NoFP leaf thunk (e.g., host kernel vDSO): static GPRs are already in Frame->State,
    // while static FPRs (v16..v31) remain live in ucontext. Spill FPRs into Frame->State and reconstruct guest RIP
    // from the active thunk JIT block header (NoFP leaf thunks never make re-entrant guest callbacks).
    SpillSRAFPRs(Thread, ucontext);
    if (InThunkCall) {
      if (const uint64_t BlockEntry = CTX->GetGuestBlockEntry(Thread); BlockEntry != 0) {
        Frame->State.rip = BlockEntry;
      }
    }
    ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_FPR_IN_UCONTEXT;
  }

  // The guest handler isn't in a syscall, even when the signal arrived in the syscall handler. StoreThreadState saved the
  // interrupted code's value, and the handler's rt_sigreturn restores it.
  Thread->CurrentFrame->InSyscallInfo = 0;

  uint64_t OldGuestSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
  uint64_t NewGuestSP = OldGuestSP;

  // altstack is only used if the signal handler was setup with SA_ONSTACK
  if (GuestAction->sa_flags & SA_ONSTACK) {
    // Additionally the altstack is only used if the enabled (SS_DISABLE flag is not set)
    if (!(GuestStack->ss_flags & SS_DISABLE)) {
      // If our guest is already inside of the alternative stack
      // Then that means we are hitting recursive signals and we need to walk back the stack correctly
      uint64_t AltStackBase = reinterpret_cast<uint64_t>(GuestStack->ss_sp);
      uint64_t AltStackEnd = AltStackBase + GuestStack->ss_size;
      if (OldGuestSP >= AltStackBase && OldGuestSP <= AltStackEnd) {
        // We are already in the alt stack, the rest of the code will handle adjusting this
      } else {
        NewGuestSP = AltStackEnd;
      }
    }
  }

  // siginfo_t
  siginfo_t* HostSigInfo = reinterpret_cast<siginfo_t*>(info);

  ContextBackup->OriginalRIP = Thread->CurrentFrame->State.rip;
  uint32_t eflags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  ContextBackup->OriginalEFLAGS = eflags;

  if (Is64BitMode) {
    NewGuestSP = SetupFrame_x64(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
  } else {
    const bool SigInfoFrame = (GuestAction->sa_flags & SA_SIGINFO) == SA_SIGINFO;
    if (SigInfoFrame) {
      NewGuestSP = SetupRTFrame_ia32(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
    } else {
      NewGuestSP = SetupFrame_ia32(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
    }
  }

  Frame->State.rip = reinterpret_cast<uint64_t>(GuestAction->sigaction_handler.sigaction);
  Frame->State.gregs[FEXCore::X86State::REG_RSP] = NewGuestSP;

  // Linux clears DF, RF, and TF flags on signal.
  Frame->State.flags[FEXCore::X86State::RFLAG_DF_RAW_LOC] = 1;
  Frame->State.flags[FEXCore::X86State::RFLAG_RF_LOC] = 0;
  Frame->State.flags[FEXCore::X86State::RFLAG_TF_RAW_LOC] = 0;

  // Linux resets the CS and SS registers on signal handler.
  // This way signal handlers always go back to their original operating mode.
  // Doesn't matter for 32-bit processes as they can only be 32-bit, but does
  // matter for 64-bit processes as they could have potentially installed a 32-bit code segment.
  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  Frame->State.ss_idx = 0;
  Frame->State.cs_cached = Frame->State.CalculateGDTBase(*Frame->State.GetSegmentFromIndex(Frame->State, Frame->State.cs_idx));
  Frame->State.ss_cached = Frame->State.CalculateGDTBase(*Frame->State.GetSegmentFromIndex(Frame->State, Frame->State.ss_idx));

  // The guest starts its signal frame with a zero initialized FPU
  // Set that up now. Little bit costly but it's a requirement
  // This state will be restored on rt_sigreturn
  memset(Frame->State.xmm.avx.data, 0, sizeof(Frame->State.xmm));
  memset(Frame->State.mm, 0, sizeof(Frame->State.mm));
  Frame->State.FCW = 0x37F;
  Frame->State.AbridgedFTW = 0;

  // Set the new PC
  ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
  ArchHelpers::Context::SetFillSRASingleInst(ucontext, false);
  // Set our state register to point to our guest thread data
  ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

  if (GuestAction->sa_flags & SA_RESETHAND) {

    {
      // If SA_RESETHAND is set, then the signal handler is immediately reset to SIG_DFL.
      std::lock_guard lk(GuestDelegatorMutex);
      GuestAction->sigaction_handler.handler = SIG_DFL;
    }

    // If this signal is not required by FEX then we can fully uninstall the host handler as well.
    if (HostHandlers[Signal].Required.load(std::memory_order_relaxed) != true) {
      UninstallHostHandler(Signal);
    }
  }

  return true;
}

bool SignalDelegator::HandleSIGILL(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  if (ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddress ||
      ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddressRT) {
    auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
    RestoreThreadState(Thread, ucontext,
                       ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddressRT ? RestoreType::TYPE_REALTIME :
                                                                                                      RestoreType::TYPE_NONREALTIME);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;

    if (ThreadObject->SignalInfo.DeferredSignalFrameCount != 0) {
      // Keep InterruptFaultPage in sync with the restored mask: re-arm to PROT_NONE if any
      // queued deferred signal is now deliverable, or disarm to RW if all remain blocked.
      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage),
               HasDeliverableDeferredSignal(ThreadObject) ? PROT_NONE : (PROT_READ | PROT_WRITE));
    }
    return true;
  }

  if (ArchHelpers::Context::GetPc(ucontext) == Config.PauseReturnInstruction) {
    RestoreThreadState(Thread, ucontext, RestoreType::TYPE_PAUSE);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;
    return true;
  }

  return false;
}

bool SignalDelegator::HandleSignalPause(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  SignalEvent SignalReason = ThreadObject->SignalReason.load();
  auto Frame = Thread->CurrentFrame;

  if (SignalReason == SignalEvent::Pause) {
    // Store our thread state so we can come back to this
    StoreThreadState(Thread, Signal, ucontext, false);

    const bool InThunkCall = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::IN_THUNK_CALL) != 0;
    const bool FprsUnspilled = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::SRA_FPR_UNSPILLED) != 0;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !InThunkCall) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadPauseHandlerAddressSpillSRA);
    } else {
      // We are in non-jit, SRA GPRs are already spilled; sync live FPRs and clear AFP if unspilled.
      // StoreThreadState already saved the original FPCR in ContextBackup so resume restores it.
      if (FprsUnspilled) {
        SpillSRAFPRs(Thread, ucontext);
#ifdef ARCHITECTURE_arm64
        ArchHelpers::Context::ClearArmAFP(ucontext);
#endif
      }
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_THROW_A_FMT(!IsAddressInDispatcher(ArchHelpers::Context::GetPc(ucontext)) || InThunkCall || FprsUnspilled, "Signals in "
                                                                                                                        "dispatcher have "
                                                                                                                        "unsynchronized "
                                                                                                                        "context");
#endif
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadPauseHandlerAddress);
    }

    // Set our state register to point to our guest thread data
    ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    ++Thread->CurrentFrame->SignalHandlerRefCounter;

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == SignalEvent::Stop) {
    // Our thread is stopping
    // We don't care about anything at this point
    // Set the stack to our starting location when we entered the core and get out safely
    ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);

    // Our ref counting doesn't matter anymore
    Thread->CurrentFrame->SignalHandlerRefCounter = 0;

    // Set the new PC
    const bool InThunkCall = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::IN_THUNK_CALL) != 0;
    const bool FprsUnspilled = (Frame->InSyscallInfo & FEXCore::Core::CpuStateFrame::SRA_FPR_UNSPILLED) != 0;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !InThunkCall) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadStopHandlerAddressSpillSRA);
    } else {
      // We are in non-jit, SRA is already spilled; clear AFP before returning to host C++.
      if (FprsUnspilled) {
#ifdef ARCHITECTURE_arm64
        ArchHelpers::Context::ClearArmAFP(ucontext);
#endif
      }
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_THROW_A_FMT(!IsAddressInDispatcher(ArchHelpers::Context::GetPc(ucontext)) || InThunkCall || FprsUnspilled, "Signals in "
                                                                                                                        "dispatcher have "
                                                                                                                        "unsynchronized "
                                                                                                                        "context");
#endif
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadStopHandlerAddress);
    }

    // We need to be a little bit careful here
    // If we were already paused (due to GDB) and we are immediately stopping (due to gdb kill)
    // Then we need to ensure we don't double decrement our idle thread counter
    if (ThreadObject->ThreadSleeping) {
      // If the thread was sleeping then its idle counter was decremented
      // Reincrement it here to not break logic
      FEX::HLE::_SyscallHandler->TM.IncrementIdleRefCount();
    }

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == SignalEvent::Return || SignalReason == SignalEvent::ReturnRT) {
    RestoreThreadState(Thread, ucontext, SignalReason == SignalEvent::ReturnRT ? RestoreType::TYPE_REALTIME : RestoreType::TYPE_NONREALTIME);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;

    if (ThreadObject->SignalInfo.DeferredSignalFrameCount != 0) {
      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage),
               HasDeliverableDeferredSignal(ThreadObject) ? PROT_NONE : (PROT_READ | PROT_WRITE));
    }

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }
  return false;
}

void SignalDelegator::SignalThread(FEXCore::Core::InternalThreadState* Thread, SignalEvent Event) {
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  ThreadObject->SignalReason.store(Event);
  FHU::Syscalls::tgkill(ThreadObject->ThreadInfo.PID, ThreadObject->ThreadInfo.TID, SignalDelegator::SIGNAL_FOR_PAUSE);
}

/**  @} */

static bool IsAsyncSignal(const siginfo_t* Info, int Signal) {
  if (Info->si_code <= SI_USER) {
    // If the signal is not from the kernel then it is always async.
    // This is because synchronous signals can be sent through tgkill,sigqueue and other methods.
    // SI_USER == 0 and all negative si_code values come from the user.
    return true;
  } else {
    // If the signal is from the kernel then it is async only if it isn't an explicit synchronous signal.
    switch (Signal) {
    // These are all synchronous signals.
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
    case SIGSEGV:
    case SIGTRAP: return false;
    default: break;
    }
  }

  // Everything else is async and can be deferred.
  return true;
}

uint64_t SignalDelegator::GetGuestSignalHandlerMask(int Signal, uint64_t ExistingMask) const {
  const SignalHandler& Handler = HostHandlers[Signal];
  // POSIX/Linux signal delivery adds sa_mask (and Signal itself unless SA_NODEFER)
  // to the thread's existing blocked mask rather than replacing it.
  uint64_t NewMask = ExistingMask | Handler.GuestAction.sa_mask.Val;

  // If !SA_NODEFER then the new signal mask includes this signal
  if (!(Handler.GuestAction.sa_flags & SA_NODEFER)) {
    NewMask |= (1ULL << (Signal - 1));
  }

  constexpr uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
  return NewMask & IgnoredSignalsMask;
}

uint64_t SignalDelegator::MaskToHostSigMask(uint64_t GuestMask) const {
  // Walk our required signals and stop masking them if requested
  for (size_t i = 0; i < MAX_SIGNALS; ++i) {
    if (HostHandlers[i + 1].Required.load(std::memory_order_relaxed)) {
      // Never mask our required signals
      GuestMask &= ~(1ULL << i);
    }
  }

  return GuestMask;
}

uint64_t SignalDelegator::GetDeferredSignalsMask(const FEX::HLE::ThreadStateObject* ThreadObject) const {
  uint64_t Mask {};
  for (size_t i = 0; i < ThreadObject->SignalInfo.DeferredSignalFrameCount; ++i) {
    // Each queued frame contributes only its own signal bit so it cannot re-deliver while queued;
    // the handler's sa_mask is applied when that handler is actually dispatched.
    Mask |= (1ULL << (ThreadObject->SignalInfo.DeferredSignalFrames[i].Signal - 1));
  }
  return Mask;
}

bool SignalDelegator::HasDeliverableDeferredSignal(const FEX::HLE::ThreadStateObject* ThreadObject) const {
  const uint64_t BlockedMask = ThreadObject->SignalInfo.CurrentSignalMask.Val;
  for (size_t i = 0; i < ThreadObject->SignalInfo.DeferredSignalFrameCount; ++i) {
    const int DeferredSignal = ThreadObject->SignalInfo.DeferredSignalFrames[i].Signal;
    if ((BlockedMask & (1ULL << (DeferredSignal - 1))) == 0) {
      return true;
    }
  }
  return false;
}

bool SignalDelegator::HandleFrontendSIGSEGV(FEXCore::Core::InternalThreadState* Thread, int Signal, void* Info, void* UContext) {
  auto SigInfo = *static_cast<siginfo_t*>(Info);

  if (FaultSafeUserMemAccess::TryHandleSafeFault(Signal, SigInfo, UContext)) {
    ERROR_AND_DIE_FMT("Received invalid data to syscall. Crashing now!");
  }

#ifdef ARCHITECTURE_arm64
  if (Signal == SIGSEGV && SigInfo.si_code == SEGV_ACCERR && Thread->JITGuardPage &&
      SigInfo.si_addr >= reinterpret_cast<void*>(Thread->JITGuardPage) &&
      SigInfo.si_addr < reinterpret_cast<void*>(Thread->JITGuardPage + FEXCore::Utils::FEX_PAGE_SIZE)) {
    FEXCore::UncheckedLongJump::ManuallyLoadJumpBuf(Thread->RestartJump, Thread->JITGuardOverflowArgument,
                                                    ArchHelpers::Context::GetArmGPRs(UContext), ArchHelpers::Context::GetArmFPRs(UContext),
                                                    ArchHelpers::Context::GetArmPc(UContext));
    return true;
  }
#endif

  // If this fault is in the main thread stack guard region, we should try to grow the main thread stack.
  if (SigInfo.si_code == SEGV_ACCERR && FEXCore::Allocator::TryGrowMainThreadStack(reinterpret_cast<uintptr_t>(SigInfo.si_addr))) {
    return true;
  }

  return false;
}

void SignalDelegator::HandleGuestSignal(FEX::HLE::ThreadStateObject* ThreadObject, int Signal, void* Info, void* UContext) {
  auto Thread = ThreadObject->Thread;
  ucontext_t* _context = (ucontext_t*)UContext;
  auto SigInfo = *static_cast<siginfo_t*>(Info);

  auto MustDeferSignal = (Thread->CurrentFrame->State.DeferredSignalRefCount.Load() != 0);

  // JIT and dispatcher code is only at a guest instruction boundary at its pending interrupt checks, and between them it
  // can hold guest state the frame can't show, like a register mid-update or an address computed from one. Wait for the next
  // check, so the guest handler sees and changes exact state. Not while the thread is marked as in a syscall: that state is
  // exact as well, and a blocking syscall must be interrupted.
  const auto PC = ArchHelpers::Context::GetPc(UContext);
  const bool BetweenChecks = (CTX->IsAddressInCodeBuffer(Thread, PC) || IsAddressInDispatcher(PC)) && Thread->CurrentFrame->InSyscallInfo == 0;
  bool FromDeferredFault = false;
  if (Signal == SIGSEGV && SigInfo.si_code == SEGV_ACCERR && SigInfo.si_addr == reinterpret_cast<void*>(&Thread->InterruptFaultPage)) {
    if (!MustDeferSignal) {
      // We just reached the end of the outermost signal-deferring section and faulted to check for pending signals.
      // Pull the newest deliverable (unblocked) signal frame off the stack.

      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_READ | PROT_WRITE);

      const uint64_t BlockedMask = ThreadObject->SignalInfo.CurrentSignalMask.Val;
      size_t SelectedIdx = ThreadObject->SignalInfo.DeferredSignalFrameCount;
      for (size_t i = ThreadObject->SignalInfo.DeferredSignalFrameCount; i > 0; --i) {
        const int DeferredSignal = ThreadObject->SignalInfo.DeferredSignalFrames[i - 1].Signal;
        if ((BlockedMask & (1ULL << (DeferredSignal - 1))) == 0) {
          SelectedIdx = i - 1;
          break;
        }
      }

      if (SelectedIdx == ThreadObject->SignalInfo.DeferredSignalFrameCount) {
        // Either no deferred signals remain, or every deferred signal is currently masked by
        // CurrentSignalMask (e.g. inside a synchronous SIGSEGV handler whose sa_mask blocks SIGUSR1).
        // Leave InterruptFaultPage RW and preserve uc_sigmask; rt_sigreturn or rt_sigprocmask will
        // re-arm InterruptFaultPage once a deferred signal becomes unblocked.
        return;
      }

      const auto Selected = ThreadObject->SignalInfo.DeferredSignalFrames[SelectedIdx];
      for (size_t i = SelectedIdx; i + 1 < ThreadObject->SignalInfo.DeferredSignalFrameCount; ++i) {
        ThreadObject->SignalInfo.DeferredSignalFrames[i] = ThreadObject->SignalInfo.DeferredSignalFrames[i + 1];
      }
      --ThreadObject->SignalInfo.DeferredSignalFrameCount;

      Signal = Selected.Signal;
      SigInfo = Selected.Info;
      // Remove only the popped signal's temporary defer mask while preserving CurrentSignalMask
      // (including any enclosing synchronous signal handler's sa_mask) and remaining deferred masks.
      const uint64_t RestoredHostMask = MaskToHostSigMask(ThreadObject->SignalInfo.CurrentSignalMask.Val | GetDeferredSignalsMask(ThreadObject));
      memcpy(&_context->uc_sigmask, &RestoredHostMask, sizeof(uint64_t));
      FromDeferredFault = true;

      // Until we re-protect the page to PROT_NONE, FEX will now *permanently* defer signals and /not/ check them.
      //
      // In order to return /back/ to a sane state, we wait for the rt_sigreturn to happen.
      // rt_sigreturn will check if there are any more deliverable deferred signals to handle
      // - If there are deliverable deferred signals
      //   - mprotect back to PROT_NONE
      //   - sigreturn will trampoline out to the previous fault address check, SIGSEGV and restart
      // - If there are *no* deliverable deferred signals
      //  - No need to mprotect, it is already RW
      // If this popped signal does NOT invoke a guest handler (SIG_IGN / DEFAULT_IGNORE / OldAction),
      // rt_sigreturn will never run, so we must re-protect InterruptFaultPage before returning if more deliverable frames remain.
    } else {
#ifdef ARCHITECTURE_arm64
      // If RefCount != 0 then that means we hit an access with nested signal-deferring sections.
      // Increment the PC past the 4-byte InterruptFaultPage access (`str`/`ldr zr, [...]`) until we reach the outermost section.
      ArchHelpers::Context::SetPc(UContext, ArchHelpers::Context::GetPc(UContext) + 4);
      return;
#else
      // X86 should always be doing a refcount compare and branch since we can't guarantee instruction size.
      // ARM64 just always does the access to reduce branching overhead.
      ERROR_AND_DIE_FMT("X86 shouldn't hit this InterruptFaultPage");
#endif
    }
  } else if (IsAsyncSignal(&SigInfo, Signal) &&
             ((ThreadObject->SignalInfo.CurrentSignalMask.Val & (1ULL << (Signal - 1))) || MustDeferSignal || BetweenChecks)) {
    const bool SignalIsMasked = (ThreadObject->SignalInfo.CurrentSignalMask.Val & (1ULL << (Signal - 1))) != 0;

    // If the signal is asynchronous (as determined by si_code) and either currently blocked by the
    // guest signal mask (e.g. a Required host signal like SIGSEGV/SIGILL/SIGBUS raised while masked
    // by sigprocmask or an active handler's sa_mask) or FEX must defer it to a safe boundary, queue
    // it in DeferredSignalFrames so siginfo, RT multiplicity, and rt_sigreturn/sigprocmask/sigsuspend
    // delivery are preserved.
    // Standard (non-realtime) signals (1..31) do not queue on Linux: coalesce duplicates
    // (which can arrive with SA_NODEFER or while masked) instead of consuming additional slots.
    constexpr int LINUX_SIGRTMIN = 32;
    if (Signal < LINUX_SIGRTMIN) {
      for (size_t i = 0; i < ThreadObject->SignalInfo.DeferredSignalFrameCount; ++i) {
        if (ThreadObject->SignalInfo.DeferredSignalFrames[i].Signal == Signal) {
          if (!SignalIsMasked) {
            mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_NONE);
          }
          return;
        }
      }
    }

    // Never allocate inside a signal handler. If the fixed queue is full, record as pending
    // without altering uc_sigmask so the signal mask cannot leak.
    if (ThreadObject->SignalInfo.DeferredSignalFrameCount >= ThreadStateObject::MAX_DEFERRED_SIGNALS) {
      ThreadObject->SignalInfo.PendingSignals |= 1ULL << (Signal - 1);
      return;
    }

    // Peek into sigset_t implementation details, extracting the __val member for glibc and __bits for musl
    auto& [sigmask_val] = _context->uc_sigmask;
    static_assert(sizeof(sigmask_val[0]) == sizeof(uint64_t), "Unknown sigset_t layout");

    ThreadObject->SignalInfo.DeferredSignalFrames[ThreadObject->SignalInfo.DeferredSignalFrameCount++] = ThreadStateObject::DeferredSignalState {
      .Info = SigInfo,
      .Signal = Signal,
    };

    // Mask only this queued signal on the host (if not Required) so it cannot re-deliver while
    // queued, while preserving already-blocked signals; the handler's sa_mask applies on dispatch.
    sigmask_val[0] |= MaskToHostSigMask(1ULL << (Signal - 1));

    // Only arm InterruptFaultPage when this signal is currently deliverable. Signals queued
    // because CurrentSignalMask blocks them will arm InterruptFaultPage once unmasked by
    // rt_sigreturn, GuestSigProcMask, or GuestSigSuspend.
    if (!SignalIsMasked) {
      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_NONE);
    }

    // Postpone the remainder of signal handling logic until we process the SIGSEGV triggered by accessing InterruptFaultPage.
    return;
  }

  auto RearmDeferredFaultIfNeeded = [&]() {
    if (FromDeferredFault && HasDeliverableDeferredSignal(ThreadObject)) {
      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_NONE);
    }
  };

  // Let the host take first stab at handling the signal
  SignalHandler& Handler = HostHandlers[Signal];

  // Remove the pending signal
  ThreadObject->SignalInfo.PendingSignals &= ~(1ULL << (Signal - 1));

  // We have an emulation thread pointer, we can now modify its state
  if (Handler.GuestAction.sigaction_handler.handler == SIG_DFL) {
    if (Handler.DefaultBehaviour == DEFAULT_TERM || Handler.DefaultBehaviour == DEFAULT_COREDUMP) {
      // Let the signal fall through to the unhandled path
      // This way the parent process can know it died correctly
    }
  } else if (Handler.GuestAction.sigaction_handler.handler == SIG_IGN) {
    RearmDeferredFaultIfNeeded();
    return;
  } else {
    if (Handler.GuestHandler &&
        Handler.GuestHandler(Thread, Signal, &SigInfo, UContext, &Handler.GuestAction, &ThreadObject->SignalInfo.GuestAltStack)) {
      // POSIX/Linux signal delivery ORs sa_mask (and Signal unless SA_NODEFER) into the existing blocked mask.
      const uint64_t NewGuestMask = GetGuestSignalHandlerMask(Signal, ThreadObject->SignalInfo.CurrentSignalMask.Val);
      ThreadObject->SignalInfo.CurrentSignalMask.Val = NewGuestMask;

      const uint64_t NewHostMask = MaskToHostSigMask(NewGuestMask | GetDeferredSignalsMask(ThreadObject));
      memcpy(&_context->uc_sigmask, &NewHostMask, sizeof(uint64_t));

      // Keep InterruptFaultPage in sync with remaining deferred frames under NewGuestMask:
      // re-arm to PROT_NONE if another unblocked deferred signal remains (so a long-running or
      // non-returning handler cannot starve it), or disarm to RW if NewGuestMask blocks them all.
      if (ThreadObject->SignalInfo.DeferredSignalFrameCount != 0) {
        mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage),
                 HasDeliverableDeferredSignal(ThreadObject) ? PROT_NONE : (PROT_READ | PROT_WRITE));
      }

      // We handled this signal, continue running
      return;
    }
    ERROR_AND_DIE_FMT("Unhandled guest exception");
  }

  // Unhandled crash
  // Call back in to the previous handler
  if (Handler.OldAction.sa_flags & SA_SIGINFO) {
    Handler.OldAction.sigaction(Signal, &SigInfo, UContext);
  } else if (Handler.OldAction.handler == SIG_IGN || (Handler.OldAction.handler == SIG_DFL && Handler.DefaultBehaviour == DEFAULT_IGNORE)) {
    // Do nothing
  } else if (Handler.OldAction.handler == SIG_DFL && (Handler.DefaultBehaviour == DEFAULT_COREDUMP || Handler.DefaultBehaviour == DEFAULT_TERM)) {
    CTX->FlushAndCloseCodeMap();

#ifndef FEX_DISABLE_TELEMETRY
    // In the case of signals that cause coredump or terminate, save telemetry early.
    // FEX is hard crashing at this point and won't hit regular shutdown routines.
    // Add the signal to the crash mask.
    FEXCORE_TELEMETRY_OR(TYPE_CRASH_MASK, (1ULL << Signal));
    if (Signal == SIGSEGV && reinterpret_cast<uint64_t>(SigInfo.si_addr) >= SyscallHandler::TASK_MAX_64BIT) {
      // Tried accessing invalid non-canonical x86-64 address.
      FEXCORE_TELEMETRY_SET(TYPE_UNHANDLED_NONCANONICAL_ADDRESS, 1);
    }
    SaveTelemetry();
#endif

    FEX::HLE::_SyscallHandler->TM.CleanupForExit();

    // Reassign back to DFL and crash
    signal(Signal, SIG_DFL);
    if (SigInfo.si_code != SI_KERNEL) {
      // If the signal wasn't sent by the kernel then we need to reraise it.
      // This is necessary since returning from this signal handler now might just continue executing.
      // eg: If sent from tgkill then the signal gets dropped and returns.
      FHU::Syscalls::tgkill(::getpid(), FHU::Syscalls::gettid(), Signal);
    }
  } else {
    Handler.OldAction.handler(Signal);
  }
  RearmDeferredFaultIfNeeded();
}

void SignalDelegator::SaveTelemetry() {
#ifndef FEX_DISABLE_TELEMETRY
  if (!ApplicationName.empty()) {
    FEXCore::Telemetry::Shutdown(ApplicationName);
  }
#endif
}

bool SignalDelegator::InstallHostThunk(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];
  // If the host thunk is already installed for this, just return
  if (SignalHandler.Installed) {
    return false;
  }

  // Default flags for us
  SignalHandler.HostAction.sa_flags = SA_SIGINFO | SA_ONSTACK;

  bool Result = UpdateHostThunk(Signal);

  SignalHandler.Installed = Result;
  return Result;
}

bool SignalDelegator::UpdateHostThunk(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];

  // Now install the thunk handler
  SignalHandler.HostAction.sigaction = SignalHandlerThunk;

  auto CheckAndAddFlags = [](uint64_t HostFlags, uint64_t GuestFlags, uint64_t Flags) {
    // If any of the flags don't match then update to the newest set
    if ((HostFlags ^ GuestFlags) & Flags) {
      // Remove all the flags from the host that we are testing for
      HostFlags &= ~Flags;
      // Copy over the guest flags being set
      HostFlags |= GuestFlags & Flags;
    }

    return HostFlags;
  };

  // Don't allow the guest to override flags for
  // SA_SIGINFO : Host always needs SA_SIGINFO
  // SA_ONSTACK : Host always needs the altstack
  // SA_RESETHAND : We don't support one shot handlers
  // SA_NODEFER : Host thunk must not be re-entered asynchronously while mutating signal state;
  //              guest SA_NODEFER is honored when computing uc_sigmask in HandleGuestSignal.
  // SA_RESTORER : We always need our host side restorer on x86-64, Couldn't use guest restorer anyway
  SignalHandler.HostAction.sa_flags =
    CheckAndAddFlags(SignalHandler.HostAction.sa_flags, SignalHandler.GuestAction.sa_flags, SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART);

#ifdef ARCHITECTURE_x86_64
#define SA_RESTORER 0x04000000
  SignalHandler.HostAction.sa_flags |= SA_RESTORER;
  SignalHandler.HostAction.restorer = sigrestore;
#endif

  // Mask all non-Required signals while the host SignalHandlerThunk executes so another async
  // signal cannot re-enter SignalHandlerThunk mid-SpillSRA, mid-DeferredSignalFrames mutation,
  // mid-RestoreThreadState, or while holding GuestDelegatorMutex (SA_RESETHAND).
  // Required signals (SIGSEGV, SIGBUS, SIGILL, SIGNAL_FOR_PAUSE) stay unmasked; guest masking
  // (sa_mask and SA_NODEFER) is enforced via ucontext->uc_sigmask on return from the thunk.
  SignalHandler.HostAction.sa_mask = MaskToHostSigMask(~0ULL);

  // Check for SIG_IGN
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_IGN && HostHandlers[Signal].Required.load(std::memory_order_relaxed) == false) {
    // We are ignoring this signal on the guest
    // Which means we need to ignore it on the host as well
    SignalHandler.HostAction.handler = SIG_IGN;
  }

  // Check for SIG_DFL
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_DFL && HostHandlers[Signal].Required.load(std::memory_order_relaxed) == false) {
    // Default handler on guest and default handler on host
    // With coredump and terminate then expect fireworks, but that is what the guest wants
    SignalHandler.HostAction.handler = SIG_DFL;
  }

  // Only update the old action if we haven't ever been installed
  const int Result =
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.HostAction, SignalHandler.Installed ? nullptr : &SignalHandler.OldAction, 8);
  if (Result < 0) {
    // Signal 32 and 33 are consumed by glibc. We don't handle this atm
    LogMan::Msg::AFmt("Failed to install host signal thunk for signal {}: {}", Signal, strerror(errno));
    return false;
  }

  return true;
}

void SignalDelegator::UninstallHostHandler(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];

  ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.OldAction, nullptr, 8);
}

void SignalDelegator::QueueSignal(pid_t tgid, pid_t tid, int Signal, siginfo_t* info, bool IgnoreMask) {
  bool WasIgnored {};
  bool WasMasked {};
  SignalHandler& SignalHandler = HostHandlers[Signal];
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_IGN && IgnoreMask) {
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.OldAction, nullptr, 8);
    WasIgnored = true;
  }

  // Get the current host signal mask
  uint64_t ThreadSignalMask {};
  const uint64_t SignalMask = 1ULL << (Signal - 1);
  ::syscall(SYS_rt_sigprocmask, 0, nullptr, &ThreadSignalMask, 8);
  if (ThreadSignalMask & SignalMask) {
    WasMasked = true;

    // Signal currently masked, unmask
    ThreadSignalMask &= ~SignalMask;
    ::syscall(SYS_rt_sigprocmask, 0, &ThreadSignalMask, &ThreadSignalMask, 8);
  }

  ::syscall(SYSCALL_DEF(rt_tgsigqueueinfo), tgid, tid, Signal, info);

  if (WasMasked) {
    // Mask again
    ::syscall(SYS_rt_sigprocmask, 0, &ThreadSignalMask, nullptr, 8);
  }

  if (WasIgnored) {
    // Ignore again
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.HostAction, nullptr, 8);
  }
}

SignalDelegator::SignalDelegator(FEXCore::Context::Context* _CTX, const std::string_view ApplicationName, bool SupportsAVX, bool SupportsSVE256)
  : CTX {_CTX}
  , ApplicationName {ApplicationName}
  , SupportsAVX {SupportsAVX}
  , SupportsSVE256 {SupportsSVE256} {
  // Signal zero isn't real
  HostHandlers[0].Installed = true;

  // We can't capture SIGKILL or SIGSTOP
  HostHandlers[SIGKILL].Installed = true;
  HostHandlers[SIGSTOP].Installed = true;

  if (HalfBarrierTSOEnabled()) {
    UnalignedHandlerType = FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier;
  } else {
    UnalignedHandlerType = FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::NonAtomic;
  }

  // Most signals default to termination
  // These ones are slightly different
  static constexpr std::array<std::pair<int, SignalDelegator::DefaultBehaviourType>, 14> SignalDefaultBehaviours = {{
    {SIGQUIT, DEFAULT_COREDUMP},
    {SIGILL, DEFAULT_COREDUMP},
    {SIGTRAP, DEFAULT_COREDUMP},
    {SIGABRT, DEFAULT_COREDUMP},
    {SIGBUS, DEFAULT_COREDUMP},
    {SIGFPE, DEFAULT_COREDUMP},
    {SIGSEGV, DEFAULT_COREDUMP},
    {SIGCHLD, DEFAULT_IGNORE},
    {SIGCONT, DEFAULT_IGNORE},
    {SIGURG, DEFAULT_IGNORE},
    {SIGXCPU, DEFAULT_COREDUMP},
    {SIGXFSZ, DEFAULT_COREDUMP},
    {SIGSYS, DEFAULT_COREDUMP},
    {SIGWINCH, DEFAULT_IGNORE},
  }};

  for (const auto& [Signal, Behaviour] : SignalDefaultBehaviours) {
    HostHandlers[Signal].DefaultBehaviour = Behaviour;
  }

  // Register frontend SIGILL handler for forced assertion.
  RegisterFrontendHostSignalHandler(
    SIGILL,
    [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
      ucontext_t* _context = (ucontext_t*)ucontext;
      auto& mcontext = _context->uc_mcontext;
      uint64_t PC {};
#ifdef ARCHITECTURE_arm64
      PC = mcontext.pc;
#else
      PC = mcontext.gregs[REG_RIP];
#endif
      if (PC == reinterpret_cast<uint64_t>(&FEXCore::Assert::ForcedAssert)) {
        // This is a host side assert. Don't deliver this to the guest
        // We want to actually break here
        FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->UninstallHostHandler(Signal);
        return true;
      }
      return false;
    },
    true);

  const auto PauseHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleSignalPause(Thread, Signal, info, ucontext);
  };

  const auto GuestSignalHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext,
                                     GuestSigAction* GuestAction, stack_t* GuestStack) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleDispatcherGuestSignal(
      Thread, Signal, info, ucontext, GuestAction, GuestStack);
  };

  const auto SigillHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleSIGILL(Thread, Signal, info, ucontext);
  };

  const auto SigsegvHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleFrontendSIGSEGV(Thread, Signal,
                                                                                                                         info, ucontext);
  };

  // Register SIGILL signal handler.
  RegisterHostSignalHandler(SIGILL, SigillHandler, true);
  RegisterHostSignalHandler(SIGSEGV, SigsegvHandler, true);

#ifdef ARCHITECTURE_arm64
  // Register SIGBUS signal handler.
  const auto SigbusHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* _info, void* ucontext) -> bool {
    const auto PC = ArchHelpers::Context::GetPc(ucontext);
    if (!Thread->CTX->IsAddressInCodeBuffer(Thread, PC)) {
      // Wasn't a sigbus in JIT code
      return false;
    }
    siginfo_t* info = reinterpret_cast<siginfo_t*>(_info);

    if (info->si_code != BUS_ADRALN) {
      // This only handles alignment problems
      return false;
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
    const auto Delegator = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator;
    const auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, Delegator->GetUnalignedHandlerType(), PC,
                                                                           ArchHelpers::Context::GetArmGPRs(ucontext));
    ArchHelpers::Context::SetPc(ucontext, PC + Result.value_or(0));
    return Result.has_value();
  };

  RegisterHostSignalHandler(SIGBUS, SigbusHandler, true);
#endif
  // Register pause signal handler.
  RegisterHostSignalHandler(SignalDelegator::SIGNAL_FOR_PAUSE, PauseHandler, true);

  // Guest signal handlers.
  for (uint32_t Signal = 0; Signal <= SignalDelegator::MAX_SIGNALS; ++Signal) {
    RegisterHostSignalHandlerForGuest(Signal, GuestSignalHandler);
  }
}

SignalDelegator::~SignalDelegator() {
  for (int i = 0; i < MAX_SIGNALS; ++i) {
    if (i == 0 || i == SIGKILL || i == SIGSTOP || !HostHandlers[i].Installed) {
      continue;
    }
    ::syscall(SYS_rt_sigaction, i, &HostHandlers[i].OldAction, nullptr, 8);
    HostHandlers[i].Installed = false;
  }
}

void SignalDelegator::RegisterTLSState(FEX::HLE::ThreadStateObject* Thread) {
  FEXCore::Allocator::RegisterTLSData(Thread->Thread);

  Thread->SignalInfo.Delegator = this;

  // Set up our signal alternative stack
  // This is per thread rather than per signal
  Thread->SignalInfo.AltStackPtr = FEXCore::Allocator::mmap(nullptr, SIGSTKSZ * 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(Thread->SignalInfo.AltStackPtr), SIGSTKSZ * 16);
  stack_t altstack {};
  altstack.ss_sp = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(Thread->SignalInfo.AltStackPtr) + 8);
  altstack.ss_size = SIGSTKSZ * 16 - 8;
  altstack.ss_flags = 0;
  LOGMAN_THROW_A_FMT(!!altstack.ss_sp, "Couldn't allocate stack pointer");

  // Copy the thread object to the start of the alt-stack
  memcpy(Thread->SignalInfo.AltStackPtr, &Thread, sizeof(void*));

  // Protect the first page of the alt-stack for overflow protection.
  mprotect(Thread->SignalInfo.AltStackPtr, FEXCore::Utils::FEX_PAGE_SIZE, PROT_READ);

  // Register the alt stack
  const int Result = sigaltstack(&altstack, nullptr);
  if (Result == -1) {
    LogMan::Msg::EFmt("Failed to install alternative signal stack {}", strerror(errno));
  }

  // Get the current host signal mask
  ::syscall(SYS_rt_sigprocmask, 0, nullptr, &Thread->SignalInfo.CurrentSignalMask.Val, 8);
}

void SignalDelegator::UninstallTLSState(FEX::HLE::ThreadStateObject* Thread) {
  stack_t altstack {};
  altstack.ss_flags = SS_DISABLE;

  // Uninstall the alt stack before unmapping its backing memory.
  const int Result = sigaltstack(&altstack, nullptr);
  if (Result == -1) {
    LogMan::Msg::EFmt("Failed to uninstall alternative signal stack {}", strerror(errno));
  }

  // Clear allocator TLS before munmap so the 64-bit allocator's DeferredSignalRefCountGuard
  // cannot touch InterruptFaultPage while SIGSEGV is raw-masked on thread exit.
  FEXCore::Allocator::UninstallTLSData(Thread->Thread);

  FEXCore::Allocator::munmap(Thread->SignalInfo.AltStackPtr, SIGSTKSZ * 16);

  Thread->SignalInfo.AltStackPtr = nullptr;
}

void SignalDelegator::InstallOrUpdateRequiredHostThunk(int Signal, bool Required) {
  HostHandlers[Signal].Required = Required;
  if (Signal == 0 || Signal == SIGKILL || Signal == SIGSTOP) {
    return;
  }
  if (!InstallHostThunk(Signal) && Required) {
    UpdateHostThunk(Signal);
  }
  if (Required) {
    // Ensure previously-installed host thunks do not mask this newly-required signal.
    const uint64_t Bit = 1ULL << (Signal - 1);
    for (size_t i = 1; i < HostHandlers.size(); ++i) {
      if (i != static_cast<size_t>(Signal) && i != SIGKILL && i != SIGSTOP && HostHandlers[i].Installed &&
          (HostHandlers[i].HostAction.sa_mask & Bit)) {
        UpdateHostThunk(i);
      }
    }
  }
}

void SignalDelegator::FrontendRegisterHostSignalHandler(int Signal, bool Required) {
  // Linux signal handlers are per-process rather than per thread
  // Multiple threads could be calling in to this
  std::lock_guard lk(HostDelegatorMutex);
  InstallOrUpdateRequiredHostThunk(Signal, Required);
}

void SignalDelegator::FrontendRegisterFrontendHostSignalHandler(int Signal, bool Required) {
  // Linux signal handlers are per-process rather than per thread
  // Multiple threads could be calling in to this
  std::lock_guard lk(HostDelegatorMutex);
  InstallOrUpdateRequiredHostThunk(Signal, Required);
}

void SignalDelegator::RegisterHostSignalHandlerForGuest(int Signal, FEX::HLE::HostSignalDelegatorFunctionForGuest Func) {
  std::lock_guard lk(HostDelegatorMutex);
  HostHandlers[Signal].GuestHandler = std::move(Func);
}

void SignalDelegator::RegisterFrontendHostSignalHandler(int Signal, HostSignalDelegatorFunction Func, bool Required) {
  SetFrontendHostSignalHandler(Signal, std::move(Func));
  FrontendRegisterFrontendHostSignalHandler(Signal, Required);
}

uint64_t SignalDelegator::RegisterGuestSignalHandler(int Signal, const GuestSigAction* Action, GuestSigAction* OldAction) {
  // Invalid signal specified
  if (Signal > MAX_SIGNALS) {
    return -EINVAL;
  }

  // These signal dispositions can't be changed on Linux
  if (Action && (Signal == SIGKILL || Signal == SIGSTOP)) {
    return -EINVAL;
  }

  // Copy Action from guest memory before masking SIGSEGV so any MTRACK write-protection fault
  // or bad guest pointer is handled normally instead of killing the process while SIGSEGV is masked.
  GuestSigAction NewAction {};
  if (Action) {
    NewAction = *Action;
  }

  GuestSigAction SavedOldAction {};
  {
    // Mask signals while holding GuestDelegatorMutex so an async signal cannot suspend this thread
    // (or re-enter via SA_RESETHAND in HandleDispatcherGuestSignal) while holding the lock.
    auto lk = FEXCore::MaskSignalsAndLockMutex(GuestDelegatorMutex);

    if (OldAction) {
      SavedOldAction = HostHandlers[Signal].GuestAction;
    }

    // Now assign the new action
    if (Action) {
      HostHandlers[Signal].GuestAction = NewAction;
      // Only attempt to install a new thunk handler if we were installing a new guest action
      if (!InstallHostThunk(Signal)) {
        UpdateHostThunk(Signal);
      }
    }
  }

  // Write OldAction back to guest memory after unmasking SIGSEGV.
  if (OldAction) {
    *OldAction = SavedOldAction;
  }

  return 0;
}

void SignalDelegator::CheckXIDHandler() {
  auto lk = FEXCore::MaskSignalsAndLockMutex(GuestDelegatorMutex);
  std::lock_guard lk2(HostDelegatorMutex);

  constexpr size_t SIGNAL_SETXID = 33;

  kernel_sigaction CurrentAction {};

  // Only update the old action if we haven't ever been installed
  const int Result = ::syscall(SYS_rt_sigaction, SIGNAL_SETXID, nullptr, &CurrentAction, 8);
  if (Result < 0) {
    LogMan::Msg::AFmt("Failed to get status of XID signal");
    return;
  }

  SignalHandler& HostHandler = HostHandlers[SIGNAL_SETXID];
  if (CurrentAction.handler != HostHandler.HostAction.handler) {
    // GLIBC overwrote our XID handler, reinstate our handler
    const int Result = ::syscall(SYS_rt_sigaction, SIGNAL_SETXID, &HostHandler.HostAction, nullptr, 8);
    if (Result < 0) {
      LogMan::Msg::AFmt("Failed to reinstate our XID signal handler {}", strerror(errno));
    }
  }
}

uint64_t SignalDelegator::RegisterGuestSigAltStack(FEX::HLE::ThreadStateObject* Thread, const stack_t* ss, stack_t* old_ss) {
  bool UsingAltStack {};
  uint64_t AltStackBase = reinterpret_cast<uint64_t>(Thread->SignalInfo.GuestAltStack.ss_sp);
  uint64_t AltStackEnd = AltStackBase + Thread->SignalInfo.GuestAltStack.ss_size;
  uint64_t GuestSP = Thread->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];

  if (!(Thread->SignalInfo.GuestAltStack.ss_flags & SS_DISABLE) && GuestSP >= AltStackBase && GuestSP <= AltStackEnd) {
    UsingAltStack = true;
  }

  // If we have an old signal set then give it back
  if (old_ss) {
    *old_ss = Thread->SignalInfo.GuestAltStack;

    if (UsingAltStack) {
      // We are currently operating on the alt stack
      // Let the guest know
      old_ss->ss_flags |= SS_ONSTACK;
    } else {
      old_ss->ss_flags |= SS_DISABLE;
    }
  }

  // Now assign the new action
  if (ss) {
    // If we tried setting the alt stack while we are using it then throw an error
    if (UsingAltStack) {
      return -EPERM;
    }

    // We need to check for invalid flags
    // The only flag that can be passed is SS_AUTODISARM and SS_DISABLE
    if ((ss->ss_flags & ~SS_ONSTACK) & // SS_ONSTACK is ignored
        ~(SS_AUTODISARM | SS_DISABLE)) {
      // A flag remained that isn't one of the supported ones?
      return -EINVAL;
    }

    if (ss->ss_flags & SS_DISABLE) {
      // If SS_DISABLE Is specified then the rest of the details are ignored
      Thread->SignalInfo.GuestAltStack = *ss;
      return 0;
    }

    // stack size needs to be at least X86_MINSIGSTKSZ
    if (ss->ss_size < X86_MINSIGSTKSZ) {
      return -ENOMEM;
    }

    Thread->SignalInfo.GuestAltStack = *ss;
  }

  return 0;
}

static void CheckForPendingSignals(const FEX::HLE::ThreadStateObject* Thread) {
  // Do we have any pending signals that became unmasked?
  uint64_t PendingSignals = ~Thread->SignalInfo.CurrentSignalMask.Val & Thread->SignalInfo.PendingSignals;
  if (PendingSignals != 0) {
    for (int i = 0; i < 64; ++i) {
      if (PendingSignals & (1ULL << i)) {
        FHU::Syscalls::tgkill(Thread->ThreadInfo.PID, Thread->ThreadInfo.TID, i + 1);
        // We might not even return here which is spooky
      }
    }
  }
}

uint64_t SignalDelegator::GuestSigProcMask(FEX::HLE::ThreadStateObject* Thread, int how, const uint64_t* set, uint64_t* oldset) {
  // The order in which we handle signal mask setting is important here
  // old and new can point to the same location in memory.
  // Even if the pointers are to same memory location, we must store the original signal mask
  // coming in to the syscall.
  // 1) Store old mask
  // 2) Set mask to new mask if exists
  // 3) Give old mask back
  uint64_t OldSet {};

  if (set) {
    if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
      return -EINVAL;
    }

    // Read *set from guest memory before masking SIGSEGV so a bad guest pointer or MTRACK fault
    // is handled normally rather than crashing with SIGSEGV blocked.
    constexpr uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    const uint64_t MaskedSet = *set & IgnoredSignalsMask;

    // Unconditionally mask all signals while reading/updating CurrentSignalMask, inspecting
    // DeferredSignalFrames, syncing InterruptFaultPage, and installing HostMask so an async
    // signal cannot race in between and leave HostMask or DeferredSignalFrames inconsistent.
    constexpr uint64_t AllSignals = ~0ULL;
    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &AllSignals, nullptr, 8);

    OldSet = Thread->SignalInfo.CurrentSignalMask.Val;
    uint64_t NewMask = OldSet;
    if (how == SIG_BLOCK) {
      NewMask |= MaskedSet;
    } else if (how == SIG_UNBLOCK) {
      NewMask &= ~MaskedSet;
    } else {
      NewMask = MaskedSet;
    }

    Thread->SignalInfo.CurrentSignalMask.Val = NewMask;
    std::atomic_signal_fence(std::memory_order_seq_cst);

    // Now actually set the host mask, keeping any still-deferred signals' masks applied while hiding
    // that required host signals cannot be masked.
    uint64_t HostMask = MaskToHostSigMask(NewMask | GetDeferredSignalsMask(Thread));

    if (Thread->Thread && Thread->SignalInfo.DeferredSignalFrameCount != 0) {
      mprotect(reinterpret_cast<void*>(&Thread->Thread->InterruptFaultPage), sizeof(Thread->Thread->InterruptFaultPage),
               HasDeliverableDeferredSignal(Thread) ? PROT_NONE : (PROT_READ | PROT_WRITE));
    }

    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &HostMask, nullptr, 8);
  } else {
    OldSet = Thread->SignalInfo.CurrentSignalMask.Val;
  }

  if (oldset) {
    *oldset = OldSet;
  }

  CheckForPendingSignals(Thread);

  return 0;
}

uint64_t SignalDelegator::GuestSigPending(FEX::HLE::ThreadStateObject* Thread, uint64_t* set, size_t sigsetsize) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  uint64_t DeferredSignals {};
  for (size_t i = 0; i < Thread->SignalInfo.DeferredSignalFrameCount; ++i) {
    DeferredSignals |= 1ULL << (Thread->SignalInfo.DeferredSignalFrames[i].Signal - 1);
  }
  *set = (Thread->SignalInfo.PendingSignals | DeferredSignals) & Thread->SignalInfo.CurrentSignalMask.Val;

  sigset_t HostSet {};
  if (sigpending(&HostSet) == 0) {
    uint64_t HostSignals {};
    for (size_t i = 0; i < MAX_SIGNALS; ++i) {
      if (sigismember(&HostSet, i + 1)) {
        HostSignals |= (1ULL << i);
      }
    }

    // Merge the real pending signal mask as well
    *set |= HostSignals;
  }
  return 0;
}

uint64_t SignalDelegator::GuestSigSuspend(FEX::HLE::ThreadStateObject* Thread, uint64_t* set, size_t sigsetsize) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  constexpr uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
  // Read *set from guest memory before masking signals so bad pointers or MTRACK faults
  // still fault cleanly with SIGSEGV unmasked.
  const uint64_t SuspendMask = *set & IgnoredSignalsMask;

  // Mask all signals (including Required) before snapshotting CurrentSignalMask and
  // transitioning PreviousSuspendMask, CurrentSignalMask, and InSigSuspend together, so
  // no async signal can mutate CurrentSignalMask (via uc_sigmask) after the read and no
  // cross-thread Required signal can observe SuspendMask while InSigSuspend is still false.
  constexpr uint64_t AllSignals = ~0ULL;
  const uint64_t BlockAsyncMask = MaskToHostSigMask(~0ULL);
  ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &AllSignals, nullptr, 8);
  std::atomic_signal_fence(std::memory_order_seq_cst);

  const uint64_t SavedPreSuspendMask = Thread->SignalInfo.CurrentSignalMask.Val;
  Thread->SignalInfo.PreviousSuspendMask.Val = SavedPreSuspendMask;
  Thread->SignalInfo.CurrentSignalMask.Val = SuspendMask;
  Thread->SignalInfo.InSigSuspend = true;
  std::atomic_signal_fence(std::memory_order_seq_cst);

  // Deliver any FEX-queued deferred signals unblocked by SuspendMask before sleeping in host
  // rt_sigsuspend (the kernel does not know about FEX's per-thread deferred queue).
  // Triggering InterruptFaultPage while InSigSuspend is active lets HandleGuestSignal dispatch
  // an unblocked deferred frame (saving SavedPreSuspendMask for rt_sigreturn and clearing
  // InSigSuspend), or drain ignored frames and continue to host rt_sigsuspend.
  while (Thread->SignalInfo.InSigSuspend && Thread->Thread && HasDeliverableDeferredSignal(Thread)) {
    mprotect(reinterpret_cast<void*>(&Thread->Thread->InterruptFaultPage), sizeof(Thread->Thread->InterruptFaultPage), PROT_NONE);
    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &BlockAsyncMask, nullptr, 8);
    std::atomic_signal_fence(std::memory_order_seq_cst);
    auto* FaultPage = reinterpret_cast<FEXCore::Core::NonAtomicRefCounter<uint64_t>*>(&Thread->Thread->InterruptFaultPage);
    FaultPage->Store(0);
    std::atomic_signal_fence(std::memory_order_seq_cst);
    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &AllSignals, nullptr, 8);
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }

  uint64_t Result = static_cast<uint64_t>(-EINTR);
  if (Thread->SignalInfo.InSigSuspend) {
    // Move any overflow PendingSignals unblocked by SuspendMask into the kernel pending set
    // while AllSignals stays masked, so host rt_sigsuspend atomically unmasks HostSuspendMask
    // and wakes immediately without a lost-wakeup window for cross-thread Required signals.
    const uint64_t DeliverablePending = ~SuspendMask & Thread->SignalInfo.PendingSignals;
    if (DeliverablePending != 0) {
      Thread->SignalInfo.PendingSignals &= ~DeliverablePending;
      for (size_t i = 0; i < MAX_SIGNALS; ++i) {
        if (DeliverablePending & (1ULL << i)) {
          FHU::Syscalls::tgkill(Thread->ThreadInfo.PID, Thread->ThreadInfo.TID, static_cast<int>(i + 1));
        }
      }
      std::atomic_signal_fence(std::memory_order_seq_cst);
    }

    const uint64_t HostSuspendMask = MaskToHostSigMask(SuspendMask | GetDeferredSignalsMask(Thread));
    const long SyscallRet = ::syscall(SYS_rt_sigsuspend, &HostSuspendMask, 8);
    Result = SyscallRet == -1 ? static_cast<uint64_t>(-errno) : static_cast<uint64_t>(SyscallRet);
  }

  // Re-mask AllSignals in case a guest signal handler ran and rt_sigreturn changed the host
  // signal mask, then restore the pre-suspend logical mask only if no guest signal handler
  // interrupted sigsuspend (which clears InSigSuspend and lets rt_sigreturn install the guest
  // frame's uc_sigmask, including any edits made by the handler).
  ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &AllSignals, nullptr, 8);
  std::atomic_signal_fence(std::memory_order_seq_cst);
  if (Thread->SignalInfo.InSigSuspend) {
    Thread->SignalInfo.InSigSuspend = false;
    Thread->SignalInfo.CurrentSignalMask.Val = SavedPreSuspendMask;
  }
  const uint64_t RestoredHostMask = MaskToHostSigMask(Thread->SignalInfo.CurrentSignalMask.Val | GetDeferredSignalsMask(Thread));
  if (Thread->Thread) {
    mprotect(reinterpret_cast<void*>(&Thread->Thread->InterruptFaultPage), sizeof(Thread->Thread->InterruptFaultPage),
             HasDeliverableDeferredSignal(Thread) ? PROT_NONE : (PROT_READ | PROT_WRITE));
  }
  ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &RestoredHostMask, nullptr, 8);

  CheckForPendingSignals(Thread);

  return Result;
}

uint64_t SignalDelegator::GuestSigTimedWait(uint64_t* set, siginfo_t* info, const struct timespec* timeout, size_t sigsetsize) {
  uint64_t Result = ::syscall(SYS_rt_sigtimedwait, set, info, timeout, sigsetsize);

  return Result == -1 ? -errno : Result;
}

uint64_t SignalDelegator::GuestSignalFD(int fd, const uint64_t* set, size_t sigsetsize, int flags) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  sigset_t HostSet {};
  sigemptyset(&HostSet);

  for (size_t i = 0; i < MAX_SIGNALS; ++i) {
    if (HostHandlers[i + 1].Required.load(std::memory_order_relaxed)) {
      // For now skip our internal signals
      continue;
    }

    if (*set & (1ULL << i)) {
      sigaddset(&HostSet, i + 1);
    }
  }

  // XXX: This is a barebones implementation just to get applications that listen for SIGCHLD to work
  // In the future we need our own listern thread that forwards the result
  // Thread is necessary to prevent deadlocks for a thread that has signaled on the same thread listening to the FD and blocking is enabled
  uint64_t Result = signalfd(fd, &HostSet, flags);

  return Result == -1 ? -errno : Result;
}

fextl::unique_ptr<FEX::HLE::SignalDelegator>
CreateSignalDelegator(FEXCore::Context::Context* CTX, const std::string_view ApplicationName, bool SupportsAVX, bool SupportsSVE256) {
  return fextl::make_unique<FEX::HLE::SignalDelegator>(CTX, ApplicationName, SupportsAVX, SupportsSVE256);
}
} // namespace FEX::HLE
