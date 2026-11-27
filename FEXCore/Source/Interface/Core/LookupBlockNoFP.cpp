// SPDX-License-Identifier: MIT
#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"

#include <FEXCore/Debug/InternalThreadState.h>

namespace FEXCore::Context {

// Compiled with -mgeneral-regs-only on ARM64 so Dispatcher::NoBlock can probe the
// block caches without spilling static FPRs (v16..v31) or serializing FPCR.AFP.
// Force all helper calls inline (flatten) so COMDAT/LTO cannot resolve a template
// helper to a +fp,+neon instantiation from another translation unit.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline, flatten))
#endif
uintptr_t ContextImpl::LookupBlockNoFP(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  if constexpr (BLOCK_DEBUGGING) {
    return 0;
  }

  // If a CodeBuffer generation switch is pending retirement, fall back to CompileBlock
  // so RetireOldCodeBuffers runs at the safe point without locks held.
  if (RetirePending.load(std::memory_order_acquire)) [[unlikely]] {
    return 0;
  }

  if (!CodeInvalidationMutex.TryLockSharedNoFP()) [[unlikely]] {
    return 0;
  }

  auto* Thread = Frame->Thread;
  const uintptr_t HostCode = Thread->LookupCache->TryFindBlockNoFP(Thread, GuestRIP);

  CodeInvalidationMutex.UnlockSharedNoFP();
  return HostCode;
}

} // namespace FEXCore::Context
