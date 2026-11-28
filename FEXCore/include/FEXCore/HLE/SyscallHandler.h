// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <optional>
#include <span>

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/fextl/string.h>

namespace FEXCore::Context {
class Context;
}

namespace FEXCore::Core {
struct InternalThreadState;
struct CpuStateFrame;
} // namespace FEXCore::Core

namespace FEXCore::HLE {
struct ExecutableRangeInfo {
  uint64_t Base;
  uint64_t Size;
  bool Writable;
  // Writes to the range are not trapped, so code decoded from it must validate itself before running.
  bool NeedsInlineSMCChecks {};
};

class SyscallHandler;
class SourcecodeResolver;

class SyscallHandler {
public:
  virtual ~SyscallHandler() = default;

  virtual void HandleSyscall(FEXCore::Core::CpuStateFrame* Frame) = 0;

  /// Sentinel value in the direct-passthrough syscall table indicating x86-64 ioctl,
  /// which requires an inline UFFDIO check before issuing ARM64 ioctl.
  static constexpr int16_t DIRECT_PASSTHROUGH_IOCTL = -2;

  /// Returns a lookup table indexed by x86-64 syscall number mapping to the corresponding
  /// ARM64 Linux kernel syscall number (>= 0), DIRECT_PASSTHROUGH_IOCTL (-2) for inline
  /// non-UFFDIO ioctl passthrough, or -1 to fall back to HandleSyscall.
  /// Returns an empty span when direct passthrough is unsupported (32-bit, non-Linux,
  /// non-ARM64, or DEBUG_STRACE builds).
  virtual std::span<const int16_t> GetDirectPassthroughTable() const {
    return {};
  }

  virtual void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  virtual void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  virtual void MarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) = 0;
  virtual std::optional<ExecutableFileSectionInfo> LookupExecutableFileSection(Core::InternalThreadState* Thread, uint64_t GuestAddr) = 0;

  virtual void PreCompile() {}

  virtual SourcecodeResolver* GetSourcecodeResolver() {
    return nullptr;
  }

  virtual void SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame) {}
};
} // namespace FEXCore::HLE
