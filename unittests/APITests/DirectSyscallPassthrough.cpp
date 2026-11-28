// SPDX-License-Identifier: MIT
#include "Common/HostFeatures.h"
#include "LinuxSyscalls/Arm64/SyscallsEnum.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x64/SyscallsEnum.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <unistd.h>

namespace {
class EmptyLayer final : public FEXCore::Config::Layer {
public:
  EmptyLayer()
    : FEXCore::Config::Layer(FEXCore::Config::LayerType::LAYER_MAIN) { }

  void Load() override { }
};

struct TestEnv {
  fextl::unique_ptr<FEXCore::Context::Context> CTX;
  fextl::unique_ptr<FEX::HLE::SignalDelegator> SignalDelegation;

  explicit TestEnv(bool Is64Bit = true, bool DisableIOUring = false) {
    FEXCore::Config::Shutdown();
    FEXCore::Config::Initialize();
    FEXCore::Config::AddLayer(fextl::make_unique<EmptyLayer>());
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Is64Bit ? "1" : "0");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_DISABLEIOURING, DisableIOUring ? "1" : "0");

    auto HostFeatures = FEX::FetchHostFeatures(Is64Bit);
    HostFeatures.ProcessFeatures.SupportsSVE128 = false;
    HostFeatures.ProcessFeatures.SupportsSVE256 = false;
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
    SignalDelegation = FEX::HLE::CreateSignalDelegator(CTX.get(), {}, HostFeatures.SupportsAVX(), HostFeatures.SupportsSVE256());
  }

  ~TestEnv() {
    SignalDelegation.reset();
    CTX.reset();
    FEXCore::Config::Shutdown();
  }
};

uint64_t DummySyscall(FEXCore::Core::CpuStateFrame*) {
  return 0;
}
} // namespace

TEST_CASE("DirectSyscallPassthroughTable") {
  TestEnv Env(true, false);

  auto BaseHandler = FEX::HLE::x64::CreateHandler(Env.CTX.get(), Env.SignalDelegation.get(), nullptr);
  REQUIRE(BaseHandler != nullptr);

  auto* X64Handler = static_cast<FEX::HLE::x64::x64SyscallHandler*>(BaseHandler.get());
  const auto Table = X64Handler->GetX64DirectPassthroughTable();
  REQUIRE(Table.size() == FEX::HLE::x64::SYSCALL_x64_MAX);
  REQUIRE(Table.size() == 512);
  REQUIRE(Table.size_bytes() == 1024);

#if defined(ARCHITECTURE_arm64) && !defined(DEBUG_STRACE)
  const auto PublicTable = BaseHandler->GetDirectPassthroughTable();
  REQUIRE(PublicTable.data() == Table.data());
  REQUIRE(PublicTable.size() == Table.size());
#else
  REQUIRE(BaseHandler->GetDirectPassthroughTable().empty());
#endif

  // Hot direct-passthrough syscalls must map to exact ARM64 Linux kernel syscall numbers.
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_read] == FEX::HLE::Arm64::SYSCALL_Arm64_read);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_write] == FEX::HLE::Arm64::SYSCALL_Arm64_write);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex] == FEX::HLE::Arm64::SYSCALL_Arm64_futex);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_sched_yield] == FEX::HLE::Arm64::SYSCALL_Arm64_sched_yield);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_recvmsg] == FEX::HLE::Arm64::SYSCALL_Arm64_recvmsg);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_sendmsg] == FEX::HLE::Arm64::SYSCALL_Arm64_sendmsg);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_ppoll] == FEX::HLE::Arm64::SYSCALL_Arm64_ppoll);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_clock_gettime] == FEX::HLE::Arm64::SYSCALL_Arm64_clock_gettime);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_pread_64] == FEX::HLE::Arm64::SYSCALL_Arm64_pread_64);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_pwrite_64] == FEX::HLE::Arm64::SYSCALL_Arm64_pwrite_64);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_enter] == FEX::HLE::Arm64::SYSCALL_Arm64_io_uring_enter);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_register] == FEX::HLE::Arm64::SYSCALL_Arm64_io_uring_register);

  // Runtime kernel-version-gated syscalls inherit host kernel checks automatically.
  if (BaseHandler->IsHostKernelVersionAtLeast(5, 16, 0)) {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_waitv] == FEX::HLE::Arm64::SYSCALL_Arm64_futex_waitv);
  } else {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_waitv] == -1);
  }
  if (BaseHandler->IsHostKernelVersionAtLeast(6, 5, 0)) {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_cachestat] == FEX::HLE::Arm64::SYSCALL_Arm64_cachestat);
  } else {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_cachestat] == -1);
  }
  if (BaseHandler->IsHostKernelVersionAtLeast(6, 6, 0)) {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_fchmodat2] == FEX::HLE::Arm64::SYSCALL_Arm64_fchmodat2);
  } else {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_fchmodat2] == -1);
  }
  if (BaseHandler->IsHostKernelVersionAtLeast(6, 8, 0)) {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_wake] == FEX::HLE::Arm64::SYSCALL_Arm64_futex_wake);
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_wait] == FEX::HLE::Arm64::SYSCALL_Arm64_futex_wait);
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_requeue] == FEX::HLE::Arm64::SYSCALL_Arm64_futex_requeue);
  } else {
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_wake] == -1);
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_wait] == -1);
    CHECK(Table[FEX::HLE::x64::SYSCALL_x64_futex_requeue] == -1);
  }

  // ioctl uses the -2 sentinel for inline UFFDIO filtering before ARM64 ioctl.
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_ioctl] == FEXCore::HLE::SyscallHandler::DIRECT_PASSTHROUGH_IOCTL);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_ioctl] == -2);

  // Signal-sending syscalls are conservatively kept on the slow path (-1).
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_kill] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_tkill] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_tgkill] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_rt_sigqueueinfo] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_rt_tgsigqueueinfo] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_pidfd_send_signal] == -1);

  // Non-passthrough / emulated syscalls MUST stay on the slow path (-1).
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_setpgid] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_setup] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_openat] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_close] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_mmap] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_munmap] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_mprotect] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_brk] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_clone] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_clone3] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_execve] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_exit] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_exit_group] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_rt_sigaction] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_rt_sigprocmask] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_rt_sigreturn] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_seccomp] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_prctl] == -1);

  // x86-64 syscall gap [335, 424) MUST stay -1.
  for (int Nr = 335; Nr < 424; ++Nr) {
    CHECK(Table[Nr] == -1);
  }

  // Validate all entries are in-range and count populated fast-path slots.
  size_t DirectCount = 0;
  size_t IoctlCount = 0;
  for (int16_t Entry : Table) {
    if (Entry >= 0) {
      CHECK(Entry < FEX::HLE::Arm64::SYSCALL_Arm64_MAX);
      ++DirectCount;
    } else if (Entry == FEXCore::HLE::SyscallHandler::DIRECT_PASSTHROUGH_IOCTL) {
      ++IoctlCount;
    } else {
      CHECK(Entry == -1);
    }
  }
  CHECK(IoctlCount == 1);
  CHECK(DirectCount >= 160);

  // Verify RegisterSyscall_64 records explicit passthrough numbers and defaults non-passthroughs to -1.
  constexpr int UnusedPassthroughSlot = 500;
  constexpr int UnusedSlowSlot = 501;
  REQUIRE(Table[UnusedPassthroughSlot] == -1);
  REQUIRE(Table[UnusedSlowSlot] == -1);
  FEX::HLE::x64::RegisterSyscall(BaseHandler.get(), UnusedPassthroughSlot, "dummy_fast", DummySyscall, int16_t {42});
  FEX::HLE::x64::RegisterSyscall(BaseHandler.get(), UnusedSlowSlot, "dummy_slow", DummySyscall);
  CHECK(Table[UnusedPassthroughSlot] == 42);
  CHECK(Table[UnusedSlowSlot] == -1);

  // Verify Dispatcher initialization succeeds with this handler attached.
  Env.CTX->SetSignalDelegator(Env.SignalDelegation.get());
  Env.CTX->SetSyscallHandler(BaseHandler.get());
  REQUIRE(Env.CTX->InitCore());
}

TEST_CASE("DirectSyscallPassthroughTable_DisableIOUring") {
  TestEnv Env(true, true);

  auto BaseHandler = FEX::HLE::x64::CreateHandler(Env.CTX.get(), Env.SignalDelegation.get(), nullptr);
  REQUIRE(BaseHandler != nullptr);

  auto* X64Handler = static_cast<FEX::HLE::x64::x64SyscallHandler*>(BaseHandler.get());
  const auto Table = X64Handler->GetX64DirectPassthroughTable();
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_setup] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_enter] == -1);
  CHECK(Table[FEX::HLE::x64::SYSCALL_x64_io_uring_register] == -1);
}

TEST_CASE("DirectSyscallPassthroughTable_32BitDisabled") {
  TestEnv Env(false, false);

  auto Allocator = FEX::HLE::CreatePassthroughAllocator();
  auto BaseHandler = FEX::HLE::x32::CreateHandler(Env.CTX.get(), Env.SignalDelegation.get(), nullptr, std::move(Allocator));
  REQUIRE(BaseHandler != nullptr);
  CHECK(BaseHandler->GetDirectPassthroughTable().empty());
}
