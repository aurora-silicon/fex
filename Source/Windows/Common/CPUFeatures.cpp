// SPDX-License-Identifier: MIT

#include "Common/CPUInfo.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/fextl/fmt.h>

#include <atomic>
#include <windows.h>

#include "CPUFeatures.h"
#include "FEXUnixLib.h"

namespace {

struct WineAPFLGExceptionProbeState {
  uintptr_t FaultPc {};
  uintptr_t ResumePc {};
  uintptr_t FailPc {};
  uint32_t ExpectedBits {};
  bool Handled {};
  uint32_t CapturedCpsr {};
};

// Use a Win32 TLS slot backed directly by TEB->TlsSlots rather than C++ thread_local:
// FEX's Windows DLLs link with -nostdlib/-nostartfiles and no IMAGE_TLS_DIRECTORY (_tls_used),
// so implicit .tls accesses through TEB->ThreadLocalStoragePointer are uninitialized.
std::atomic<DWORD> ActiveAPFLGProbeTlsSlot {TLS_OUT_OF_INDEXES};

DWORD GetOrAllocAPFLGProbeTlsSlot() {
  DWORD Slot = ActiveAPFLGProbeTlsSlot.load(std::memory_order_acquire);
  if (Slot != TLS_OUT_OF_INDEXES) {
    return Slot;
  }

  const DWORD NewSlot = TlsAlloc();
  if (NewSlot == TLS_OUT_OF_INDEXES) {
    return TLS_OUT_OF_INDEXES;
  }

  DWORD Expected = TLS_OUT_OF_INDEXES;
  if (!ActiveAPFLGProbeTlsSlot.compare_exchange_strong(Expected, NewSlot, std::memory_order_acq_rel, std::memory_order_acquire)) {
    TlsFree(NewSlot);
    return Expected;
  }

  return NewSlot;
}

struct ScopedAPFLGProbeSlot {
  DWORD Slot;
  ~ScopedAPFLGProbeSlot() {
    TlsSetValue(Slot, nullptr);
  }
};

HKEY OpenProcessorKey(uint32_t Idx) {
  HKEY Out;
  auto Path = fextl::fmt::format("Hardware\\Description\\System\\CentralProcessor\\{}", Idx);
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Path.c_str(), 0, KEY_READ, &Out)) {
    return nullptr;
  }
  return Out;
}

uint64_t ReadRegU64(HKEY Key, const char* Name) {
  uint64_t Value = 0;
  DWORD Size = sizeof(Value);
  RegGetValueA(Key, nullptr, Name, 0, nullptr, &Value, &Size);
  return Value;
}

} // namespace

namespace FEX::Windows {
#define GetSysReg(name, reg)                         \
  static uint64_t Get_##name() {                     \
    uint64_t Result {};                              \
    __asm("mrs %[Res], " #reg : [Res] "=r"(Result)); \
    return Result;                                   \
  }
GetSysReg(DCZID_EL0, DCZID_EL0);

class CPUFeaturesFromRegistry final : public FEX::CPUFeatures {
public:
  explicit CPUFeaturesFromRegistry(HKEY Key) {
    ISAR0.SetReg(ReadRegU64(Key, "CP 4030"));
    PFR0.SetReg(ReadRegU64(Key, "CP 4020"));
    PFR1.SetReg(ReadRegU64(Key, "CP 4021"));
    ISAR1.SetReg(ReadRegU64(Key, "CP 4031"));
    MMFR0.SetReg(ReadRegU64(Key, "CP 4038"));
    MMFR2.SetReg(ReadRegU64(Key, "CP 403A"));
    ZFR0.SetReg(ReadRegU64(Key, "CP 4024"));
    MMFR1.SetReg(ReadRegU64(Key, "CP 4039"));
    ISAR2.SetReg(ReadRegU64(Key, "CP 4032"));
    DCZID.SetReg(Get_DCZID_EL0());
    FillFeatureFlags();
  }
};

FEXCore::HostFeatures
CPUFeatures::FetchHostFeatures(bool IsWine, FEXCore::HostFeatures::HostTypeEnum HostType, uint32_t ProcessPID, bool (*CheckWineAPFLGCPSR)()) {
  HKEY Key = OpenProcessorKey(0);
  if (!Key) {
    ERROR_AND_DIE_FMT("Couldn't detect CPU features");
  }

  CPUFeaturesFromRegistry Features(Key);

  uint64_t CTR = ReadRegU64(Key, "CP 5801");
  uint64_t MIDR = ReadRegU64(Key, "CP 4000");

  FEXCore::HostFeatures HostFeatures = {};

  for (uint32_t Idx = 0; Key; Key = OpenProcessorKey(++Idx)) {
    // Truncate to 32-bits, top 32-bits are all reserved in MIDR
    HostFeatures.CPUMIDRs.push_back(static_cast<uint32_t>(ReadRegU64(Key, "CP 4000")));
    RegCloseKey(Key);
  }

  FEX::FetchHostFeatures(Features, HostFeatures, IsWine, CTR, MIDR);

  // Force-disable SVE until wine/windows gain support for SVE context save/restore
  HostFeatures.ProcessFeatures.SupportsSVE128 = false;
  HostFeatures.ProcessFeatures.SupportsSVE256 = false;

  HostFeatures.SupportsCPUIndexInTPIDRRO = !IsWine || FEX::Windows::UnixLib::SupportsTPIDRRO_CPU();

  FEX_CONFIG_OPT(HostFeaturesOpt, HOSTFEATURES);
  const bool DisableAPFLG = (HostFeaturesOpt() & FEXCore::Config::HostFeatures::DISABLEAPFLG) != 0;
  HostFeatures.SupportsAPFLG = false;
  if (IsWine && !DisableAPFLG && HostFeatures.SupportsFlagM && CheckWineAPFLGCPSR && FEX::Windows::UnixLib::TryEnableAPFLG()) {
    if (CheckWineAPFLGCPSR()) {
      HostFeatures.SupportsAPFLG = true;
    } else {
      LogMan::Msg::IFmt("FEX: Wine does not preserve APFLG NZCV bits across context recovery; disabling APFLG");
      if (!FEX::Windows::UnixLib::DisableAPFLG()) {
        ERROR_AND_DIE_FMT("FEX: Failed to disable hardware APFLG after Wine CPSR probe failure");
      }
    }
  }

  HostFeatures.ProcessPID = ProcessPID;

  // AVX is unsupported for WOW64
  HostFeatures.ProcessFeatures.SupportsAVX = HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec;

  HostFeatures.ProcessFeatures.HostType = HostType;
  HostFeatures.ProcessFeatures.Is64BitMode = HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec;
  // arm64ec supports synchronous faults without a double-fault dance.
  HostFeatures.ProcessFeatures.SupportsFaultFreeSynchronousFaults = HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec;

  return HostFeatures;
}

bool CPUFeatures::HandleAPFLGProbeException(const EXCEPTION_RECORD* Exception, ARM64_NT_CONTEXT* NativeContext,
                                            NTSTATUS (*ContinueFn)(ARM64_NT_CONTEXT*, BOOLEAN)) {
  const DWORD Slot = ActiveAPFLGProbeTlsSlot.load(std::memory_order_acquire);
  if (Slot == TLS_OUT_OF_INDEXES || !Exception || !NativeContext || !ContinueFn) {
    return false;
  }

  auto* Probe = static_cast<WineAPFLGExceptionProbeState*>(TlsGetValue(Slot));
  if (!Probe) {
    return false;
  }

  if (Exception->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION || Probe->FaultPc == 0 || Probe->ResumePc == 0 || Probe->FailPc == 0 ||
      NativeContext->Pc != Probe->FaultPc) {
    return false;
  }

  Probe->CapturedCpsr = NativeContext->Cpsr;
  Probe->Handled = true;
  NativeContext->Cpsr |= Probe->ExpectedBits;
  NativeContext->Pc = Probe->ResumePc;

  __asm volatile("msr nzcv, xzr" ::: "cc");
  ContinueFn(NativeContext, FALSE);

  // If ContinueFn returned an error instead of transferring control with the probe bits
  // set in Cpsr, clear the probe bits and redirect to the probe failure label so the
  // probe returns false cleanly rather than letting the synthetic SIGILL escape.
  Probe->Handled = false;
  NativeContext->Cpsr &= ~Probe->ExpectedBits;
  NativeContext->Pc = Probe->FailPc;
  ContinueFn(NativeContext, FALSE);
  ERROR_AND_DIE_FMT("FEX: Failed to resume after Wine APFLG CPSR probe exception");
}

__attribute__((noinline)) bool CPUFeatures::ProbeWineAPFLGExceptionRoundTrip() {
  const DWORD Slot = GetOrAllocAPFLGProbeTlsSlot();
  if (Slot == TLS_OUT_OF_INDEXES || TlsGetValue(Slot) != nullptr) {
    return false;
  }

  static constexpr uint32_t APFLGBits = (1U << 26) | (1U << 27);
  WineAPFLGExceptionProbeState Probe {
    .ExpectedBits = APFLGBits,
  };
  if (!TlsSetValue(Slot, &Probe)) {
    return false;
  }
  ScopedAPFLGProbeSlot Guard {Slot};

  uint64_t OutNZCV = 0;
  uint64_t Resumed = 0;
  asm volatile(
    "adr x9, 1f\n\t"
    "str x9, %[FaultPc]\n\t"
    "adr x9, 2f\n\t"
    "str x9, %[ResumePc]\n\t"
    "adr x9, 4f\n\t"
    "str x9, %[FailPc]\n\t"
    "msr nzcv, %x[Bits]\n\t"
    "1:\n\t"
    "udf #0\n\t"
    "4:\n\t"
    "mov %x[Resumed], #0\n\t"
    "mov %x[Out], #0\n\t"
    "b 3f\n\t"
    "2:\n\t"
    "mrs %x[Out], nzcv\n\t"
    "mov %x[Resumed], #1\n\t"
    "3:\n\t"
    : [FaultPc] "=m"(Probe.FaultPc), [ResumePc] "=m"(Probe.ResumePc), [FailPc] "=m"(Probe.FailPc), [Out] "=&r"(OutNZCV), [Resumed] "=&r"(Resumed)
    : [Bits] "r"(static_cast<uint64_t>(APFLGBits))
    : "x9", "cc", "memory");

  return Probe.Handled && Resumed == 1 && (Probe.CapturedCpsr & APFLGBits) == APFLGBits && (OutNZCV & APFLGBits) == APFLGBits;
}

CPUFeatures::CPUFeatures(FEXCore::Context::Context& CTX, bool SupportsAPFLG)
  : SupportsAPFLG {SupportsAPFLG} {
#ifdef ARCHITECTURE_arm64ec
  // Report as a 64-bit host for ARM64EC.
  CpuInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
  // Report as a 32-bit host for WoW64.
  CpuInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif

  // Baseline FEX feature-set
  CpuInfo.ProcessorFeatureBits = CPU_FEATURE_VME | CPU_FEATURE_TSC | CPU_FEATURE_CMOV | CPU_FEATURE_PGE | CPU_FEATURE_PSE | CPU_FEATURE_MTRR |
                                 CPU_FEATURE_CX8 | CPU_FEATURE_MMX | CPU_FEATURE_X86 | CPU_FEATURE_PAT | CPU_FEATURE_FXSR | CPU_FEATURE_SEP |
                                 CPU_FEATURE_SSE | CPU_FEATURE_3DNOW | CPU_FEATURE_SSE2 | CPU_FEATURE_SSE3 | CPU_FEATURE_CX128 |
                                 CPU_FEATURE_NX | CPU_FEATURE_SSSE3 | CPU_FEATURE_SSE41 | CPU_FEATURE_PAE | CPU_FEATURE_DAZ;

  // Features that require specific host CPU support
  const auto CPUIDResult01 = CTX.RunCPUIDFunction(0x01, 0);
  if (CPUIDResult01.ecx & (1 << 20)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_SSE42;
  }
  if (CPUIDResult01.ecx & (1 << 27)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_XSAVE;
  }
  if (CPUIDResult01.ecx & (1 << 28)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_AVX;
  }

  const auto CPUIDResult07 = CTX.RunCPUIDFunction(0x07, 0);
  if (CPUIDResult07.ebx & (1 << 5)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_AVX2;
  }

  const auto FamilyIdentifier = CPUIDResult01.eax;
  CpuInfo.ProcessorLevel = ((FamilyIdentifier >> 8) & 0xf) + ((FamilyIdentifier >> 20) & 0xff); // Family
  CpuInfo.ProcessorRevision = (FamilyIdentifier & 0xf0000) >> 4;                                // Extended Model
  CpuInfo.ProcessorRevision |= (FamilyIdentifier & 0xf0) << 4;                                  // Model
  CpuInfo.ProcessorRevision |= FamilyIdentifier & 0xf;                                          // Stepping
  // 8-bits in CPUID 01.ebx for up to 256 cores.
  CpuInfo.MaximumProcessors = ((CPUIDResult01.ebx >> 16) & 0xFF) + 1;
}

void CPUFeatures::EnableAPFLGForCurrentThread() const {
  if (SupportsAPFLG && !FEX::Windows::UnixLib::TryEnableAPFLG()) {
    ERROR_AND_DIE_FMT("FEX: Failed to enable hardware APFLG on JIT thread");
  }
}

bool CPUFeatures::IsFeaturePresent(uint32_t Feature) {
  switch (Feature) {
  case PF_FLOATING_POINT_PRECISION_ERRATA: return FALSE;
  case PF_FLOATING_POINT_EMULATED: return FALSE;
  case PF_COMPARE_EXCHANGE_DOUBLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX8);
  case PF_MMX_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_MMX);
  case PF_XMMI_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE);
  case PF_3DNOW_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_3DNOW);
  case PF_RDTSC_INSTRUCTION_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_TSC);
  case PF_PAE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_PAE);
  case PF_XMMI64_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE2);
  case PF_SSE3_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE3);
  case PF_SSSE3_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSSE3);
  case PF_XSAVE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_XSAVE);
  case PF_COMPARE_EXCHANGE128: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX128);
  case PF_SSE_DAZ_MODE_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_DAZ);
  case PF_NX_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_NX);
  case PF_SECOND_LEVEL_ADDRESS_TRANSLATION: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_2NDLEV);
  case PF_VIRT_FIRMWARE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_VIRT);
  case PF_RDWRFSGSBASE_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_RDFS);
  case PF_FASTFAIL_AVAILABLE: return TRUE;
  case PF_SSE4_1_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE41);
  case PF_SSE4_2_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE42);
  case PF_AVX_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX);
  case PF_AVX2_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX2);
  default: return false;
  }
}

void CPUFeatures::UpdateInformation(SYSTEM_CPU_INFORMATION* Info) {
  Info->MaximumProcessors = CpuInfo.MaximumProcessors;
  Info->ProcessorArchitecture = CpuInfo.ProcessorArchitecture;
  Info->ProcessorLevel = CpuInfo.ProcessorLevel;
  Info->ProcessorRevision = CpuInfo.ProcessorRevision;
  Info->ProcessorFeatureBits = CpuInfo.ProcessorFeatureBits;
}
} // namespace FEX::Windows
