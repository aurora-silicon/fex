// SPDX-License-Identifier: MIT
#pragma once

#include <windef.h>
#include <winternl.h>

#include <Common/HostFeatures.h>

namespace FEXCore::Context {
class Context;
}

/**
 * @brief Maps CPUID results to Windows CPU info structures
 */
namespace FEX::Windows {
class CPUFeatures {
public:
  static FEXCore::HostFeatures
  FetchHostFeatures(bool IsWine, FEXCore::HostFeatures::HostTypeEnum HostType, uint32_t ProcessPID, bool (*CheckWineAPFLGCPSR)() = nullptr);

  static bool HandleAPFLGProbeException(const EXCEPTION_RECORD* Exception, ARM64_NT_CONTEXT* NativeContext,
                                        NTSTATUS (*ContinueFn)(ARM64_NT_CONTEXT*, BOOLEAN));
  static bool ProbeWineAPFLGExceptionRoundTrip();

  CPUFeatures(FEXCore::Context::Context& CTX, bool SupportsAPFLG = false);

  /**
   * @brief Enables hardware APFLG on the calling thread when negotiated for the process
   */
  void EnableAPFLGForCurrentThread() const;

  /**
   * @brief If the given PF_* feature is supported
   */
  bool IsFeaturePresent(uint32_t Feature);

  /**
   * @brief Fills in `Info` according to the detected CPU features
   */
  void UpdateInformation(SYSTEM_CPU_INFORMATION* Info);

private:
  SYSTEM_CPU_INFORMATION CpuInfo {};
  bool SupportsAPFLG {};
};
} // namespace FEX::Windows

#ifdef ARCHITECTURE_arm64ec
#define FEX_WINE_APFLG_PROBE_CLOBBERS                                                                                                  \
  "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x15", "x16", "x17", "x30", "v0", "v1", "v2", "v3", "v4", "v5", \
    "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "cc", "memory"
#else
#define FEX_WINE_APFLG_PROBE_CLOBBERS                                                                                                     \
  "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30", "v0", "v1", "v2", "v3",  \
    "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", \
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc", "memory"
#endif

// Probes whether Wine preserves Apple APFLG NZCV bits (26 = PF, 27 = AF) across
// both direct ARM64 context restore (NtContinue / NtContinueNative -> NtSetContextThread)
// and an in-process signal/exception capture + restore round trip (cpsr_user_mask).
// Both ARM64EC (#NtContinueNative) and WOW64 (NtContinue) pass an ARM64_NT_CONTEXT
// directly to Wine's unix NtContinue syscall.
#define FEX_DEFINE_WINE_APFLG_CPSR_PROBE(FnName, ContinueAsmTarget)                                                                            \
  __attribute__((noinline)) static bool FnName##_NtContinueRestore() {                                                                         \
    static constexpr uint32_t APFLGBits = (1U << 26) | (1U << 27);                                                                             \
    ARM64_NT_CONTEXT Ctx {};                                                                                                                   \
    Ctx.ContextFlags = CONTEXT_ARM64_CONTROL;                                                                                                  \
    Ctx.Cpsr = APFLGBits;                                                                                                                      \
    uint64_t OutNZCV = 0;                                                                                                                      \
    uint64_t Resumed = 0;                                                                                                                      \
    register ARM64_NT_CONTEXT* RegCtx asm("x0") = &Ctx;                                                                                        \
    register uint32_t RegAlert asm("x1") = 0;                                                                                                  \
    asm volatile("str x29, %[Fp]\n\t"                                                                                                          \
                 "str x30, %[Lr]\n\t"                                                                                                          \
                 "mov x9, sp\n\t"                                                                                                              \
                 "str x9, %[Sp]\n\t"                                                                                                           \
                 "adr x9, 1f\n\t"                                                                                                              \
                 "str x9, %[Pc]\n\t"                                                                                                           \
                 "msr nzcv, xzr\n\t"                                                                                                           \
                 "bl " ContinueAsmTarget "\n\t"                                                                                                \
                 "mov %x[Resumed], #0\n\t"                                                                                                     \
                 "mov %x[Out], #0\n\t"                                                                                                         \
                 "b 2f\n\t"                                                                                                                    \
                 "1:\n\t"                                                                                                                      \
                 "mrs %x[Out], nzcv\n\t"                                                                                                       \
                 "mov %x[Resumed], #1\n\t"                                                                                                     \
                 "2:\n\t"                                                                                                                      \
                 : [Fp] "=m"(Ctx.Fp), [Lr] "=m"(Ctx.Lr), [Sp] "=m"(Ctx.Sp), [Pc] "=m"(Ctx.Pc), [Out] "=&r"(OutNZCV), [Resumed] "=&r"(Resumed), \
                   "+r"(RegCtx), "+r"(RegAlert)                                                                                                \
                 :                                                                                                                             \
                 : FEX_WINE_APFLG_PROBE_CLOBBERS);                                                                                             \
    return Resumed == 1 && (OutNZCV & APFLGBits) == APFLGBits;                                                                                 \
  }                                                                                                                                            \
  static bool FnName() {                                                                                                                       \
    return FnName##_NtContinueRestore() && FEX::Windows::CPUFeatures::ProbeWineAPFLGExceptionRoundTrip();                                      \
  }
