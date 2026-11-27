// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/Syscalls/Thread.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace SignalDelegator {
struct GuestSigAction;
}

namespace FEX::HLE {
#ifndef UFFD_FEATURE_WP_HUGETLBFS_SHMEM
#define UFFD_FEATURE_WP_HUGETLBFS_SHMEM (1 << 12)
#endif
#ifndef UFFD_FEATURE_WP_UNPOPULATED
#define UFFD_FEATURE_WP_UNPOPULATED (1 << 13)
#endif
#ifndef UFFD_FEATURE_WP_ASYNC
#define UFFD_FEATURE_WP_ASYNC (1 << 15)
#endif

// FEX holds its own locks while it reads guest memory to translate it, across munmap and mremap (VMATracking.Mutex) and
// across fork (CodeInvalidationMutex). A fault that waits for a guest handler thread, or an event that waits until the
// guest reads it, can deadlock against those. So only asynchronous write protection is offered: the kernel resolves those
// faults itself, and the guest collects the written pages with PAGEMAP_SCAN. PAGEFAULT_FLAG_WP and THREAD_ID only change
// fault messages, which that mode never produces.
static constexpr uint64_t UserfaultfdFeatures = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED | UFFD_FEATURE_WP_HUGETLBFS_SHMEM |
                                                UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID;

// The features enabled on a userfaultfd, from the "API:\t<api>:<features>:<ioctls>" line of its fdinfo.
static uint64_t UserfaultfdEnabledFeatures(int fd) {
  char Path[32];
  snprintf(Path, sizeof(Path), "/proc/self/fdinfo/%d", fd);
  const int InfoFD = open(Path, O_RDONLY | O_CLOEXEC);
  if (InfoFD < 0) {
    return 0;
  }
  char Info[512];
  const ssize_t Size = read(InfoFD, Info, sizeof(Info) - 1);
  close(InfoFD);
  Info[Size > 0 ? Size : 0] = 0;
  const char* API = strstr(Info, "API:\t");
  const char* Features = API ? strchr(API, ':') : nullptr;
  Features = Features ? strchr(Features + 1, ':') : nullptr;
  return Features ? strtoull(Features + 1, nullptr, 16) : 0;
}

uint64_t UserfaultfdIoctl(int fd, uint32_t cmd, uint64_t arg) {
  if (cmd == UFFDIO_API) {
    uffdio_api API;
    if (FaultSafeUserMemAccess::CopyFromUser(&API, reinterpret_cast<void*>(arg), sizeof(API)) == EFAULT) {
      return -EFAULT;
    }
    uint64_t Result = 0;
    if (API.features & ~UserfaultfdFeatures) {
      // As the kernel does for a feature it lacks.
      API = {};
      Result = -EINVAL;
    } else if (::ioctl(fd, cmd, &API) == -1) {
      Result = -errno;
    } else {
      API.features &= UserfaultfdFeatures;
    }
    if (FaultSafeUserMemAccess::CopyToUser(reinterpret_cast<void*>(arg), &API, sizeof(API)) == EFAULT) {
      return -EFAULT;
    }
    return Result;
  }

  if (cmd == UFFDIO_REGISTER) {
    // Check and register through one duplicate, another guest thread may dup2() a different userfaultfd onto fd.
    const int Dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (Dup < 0) {
      return -errno;
    }
    // Register the checked copy, another guest thread may change the original.
    uffdio_register Register;
    uint64_t Result = 0;
    if (FaultSafeUserMemAccess::CopyFromUser(&Register, reinterpret_cast<void*>(arg), sizeof(Register)) == EFAULT) {
      Result = -EFAULT;
    } else if (Register.mode != UFFDIO_REGISTER_MODE_WP || !(UserfaultfdEnabledFeatures(Dup) & UFFD_FEATURE_WP_ASYNC)) {
      Result = -EINVAL;
    } else if (::ioctl(Dup, cmd, &Register) == -1) {
      Result = -errno;
    } else if (FaultSafeUserMemAccess::CopyToUser(reinterpret_cast<void*>(arg), &Register, sizeof(Register)) == EFAULT) {
      Result = -EFAULT;
    }
    close(Dup);
    return Result;
  }

  uint64_t Result = ::ioctl(fd, cmd, arg);
  SYSCALL_ERRNO();
}

void RegisterSignals(FEX::HLE::SyscallHandler* Handler) {
  REGISTER_SYSCALL_IMPL(rt_sigprocmask, [](FEXCore::Core::CpuStateFrame* Frame, int how, const uint64_t* set, uint64_t* oldset) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigProcMask(FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame),
                                                                             how, set, oldset);
  });

  REGISTER_SYSCALL_IMPL(rt_sigpending, [](FEXCore::Core::CpuStateFrame* Frame, uint64_t* set, size_t sigsetsize) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigPending(FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame), set,
                                                                            sigsetsize);
  });

  REGISTER_SYSCALL_IMPL(rt_sigsuspend, [](FEXCore::Core::CpuStateFrame* Frame, uint64_t* unewset, size_t sigsetsize) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigSuspend(FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame),
                                                                            unewset, sigsetsize);
  });

  REGISTER_SYSCALL_IMPL(userfaultfd, [](FEXCore::Core::CpuStateFrame* Frame, int flags) -> uint64_t {
    uint64_t Result = ::syscall(SYSCALL_DEF(userfaultfd), flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(signalfd, [](FEXCore::Core::CpuStateFrame* Frame, int fd, const uint64_t* mask, size_t sigsetsize) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSignalFD(fd, mask, sigsetsize, 0);
  });

  REGISTER_SYSCALL_IMPL(signalfd4, [](FEXCore::Core::CpuStateFrame* Frame, int fd, const uint64_t* mask, size_t sigsetsize, int flags) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSignalFD(fd, mask, sigsetsize, flags);
  });
}
} // namespace FEX::HLE
