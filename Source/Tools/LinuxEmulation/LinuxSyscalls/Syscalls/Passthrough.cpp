// SPDX-License-Identifier: MIT
/*
$info$
meta: LinuxSyscalls|syscalls-shared ~ Syscall implementations shared between x86 and x86-64
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Arm64/SyscallsEnum.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <algorithm>
#include <array>
#include <errno.h>
#include <linux/io_uring.h>
#include <linux/userfaultfd.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <unistd.h>

namespace FEX::HLE {
#ifdef ARCHITECTURE_arm64
template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough0(FEXCore::Core::CpuStateFrame* Frame) {
  register uint64_t x0 asm("x0");
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough1(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1) {
  register uint64_t x0 asm("x0") = arg1;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough2(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough3(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough4(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough5(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough6(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register uint64_t x5 asm("x5") = arg6;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough7(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6, uint64_t arg7) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register uint64_t x5 asm("x5") = arg6;
  register uint64_t x6 asm("x6") = arg7;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6)
                 : "memory");
  return x0;
}
#else
template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough0(FEXCore::Core::CpuStateFrame* Frame) {
  uint64_t Result = ::syscall(syscall_num);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough1(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1) {
  uint64_t Result = ::syscall(syscall_num, arg1);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough2(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough3(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough4(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough5(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough6(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough7(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6, uint64_t arg7) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
  SYSCALL_ERRNO();
}
#endif

#ifdef ARCHITECTURE_arm64
// io_uring for x86-64 guests. The queues are guest memory the kernel reads directly, so FEX can't rewrite
// requests. Every opcode's arguments have the same layout on x86-64 and arm64 except the epoll ones (x86's epoll_event
// is a 12-byte packed struct, 16 bytes elsewhere) and URING_CMD (driver-defined payloads FEX can't know). So each ring
// is created disabled, restricted to every other opcode, then enabled: a forbidden request completes with -EACCES
// instead of corrupting data. A guest that registers its own restrictions gets -EBUSY (one restriction set per ring).
static uint64_t IOUringSetupRestricted(FEXCore::Core::CpuStateFrame* Frame, uint32_t entries, io_uring_params* guest_params) {
  io_uring_params params;
  if (FaultSafeUserMemAccess::CopyFromUser(&params, guest_params, sizeof(params)) == EFAULT) {
    return -EFAULT;
  }
  const uint32_t guest_flags = params.flags;
  if (guest_flags & IORING_SETUP_REGISTERED_FD_ONLY) {
    // No file descriptor comes back to restrict the ring through.
    return -EINVAL;
  }
  params.flags |= IORING_SETUP_R_DISABLED;
  const int fd = ::syscall(SYSCALL_DEF(io_uring_setup), entries, &params);
  if (fd < 0) {
    return -errno;
  }

  // The running kernel may know fewer opcodes than these headers: ask it, it refuses restrictions past its last.
  uint32_t sqe_ops = IORING_OP_LAST;
  alignas(io_uring_probe) std::array<uint8_t, sizeof(io_uring_probe) + 256 * sizeof(io_uring_probe_op)> probe {};
  if (::syscall(SYSCALL_DEF(io_uring_register), fd, IORING_REGISTER_PROBE, probe.data(), 256) == 0) {
    sqe_ops = std::min<uint32_t>(sqe_ops, reinterpret_cast<io_uring_probe*>(probe.data())->last_op + 1);
  }

  int result = -1;
  for (uint32_t register_ops = IORING_REGISTER_LAST; register_ops > 0 && result != 0; --register_ops) {
    std::array<io_uring_restriction, 2 * 256 + 1> res {};
    uint32_t n = 0;
    for (uint32_t op = 0; op < register_ops; ++op) {
      res[n].opcode = IORING_RESTRICTION_REGISTER_OP;
      res[n++].register_op = op;
    }
    for (uint32_t op = 0; op < sqe_ops; ++op) {
      if (op == IORING_OP_EPOLL_CTL || op == IORING_OP_EPOLL_WAIT || op == IORING_OP_URING_CMD || op == IORING_OP_URING_CMD128) {
        continue;
      }
      res[n].opcode = IORING_RESTRICTION_SQE_OP;
      res[n++].sqe_op = op;
    }
    res[n].opcode = IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
    res[n++].sqe_flags = 0xff;
    result = ::syscall(SYSCALL_DEF(io_uring_register), fd, IORING_REGISTER_RESTRICTIONS, res.data(), n);
    if (result != 0 && errno != EINVAL) {
      break;
    }
  }
  if (result != 0 || (!(guest_flags & IORING_SETUP_R_DISABLED) &&
                      ::syscall(SYSCALL_DEF(io_uring_register), fd, IORING_REGISTER_ENABLE_RINGS, nullptr, 0) != 0)) {
    const int err = errno;
    close(fd);
    return -err;
  }

  params.flags = guest_flags;
  if (FaultSafeUserMemAccess::CopyToUser(guest_params, &params, sizeof(params)) == EFAULT) {
    close(fd);
    return -EFAULT;
  }
  return fd;
}
#endif

// Conservatively exclude signal-sending syscalls from the NoFP direct-passthrough fast path
// so explicit signal dispatch stays on the C++ slow path.
constexpr int16_t DirectPassthroughNumber(int X64SyscallNumber, int Arm64SyscallNumber) {
  if (Arm64SyscallNumber < 0 || Arm64SyscallNumber >= FEX::HLE::Arm64::SYSCALL_Arm64_MAX) {
    return -1;
  }
  switch (X64SyscallNumber) {
  case FEX::HLE::x64::SYSCALL_x64_kill:
  case FEX::HLE::x64::SYSCALL_x64_tkill:
  case FEX::HLE::x64::SYSCALL_x64_tgkill:
  case FEX::HLE::x64::SYSCALL_x64_rt_sigqueueinfo:
  case FEX::HLE::x64::SYSCALL_x64_rt_tgsigqueueinfo:
  case FEX::HLE::x64::SYSCALL_x64_pidfd_send_signal: return -1;
  default: return static_cast<int16_t>(Arm64SyscallNumber);
  }
}

#define REGISTER_PASSTHROUGH_COMMON(name, nargs)                                                                                       \
  do {                                                                                                                                 \
    static_assert(FEX::HLE::x64::SYSCALL_x64_##name >= 0 && FEX::HLE::x64::SYSCALL_x64_##name < FEX::HLE::x64::SYSCALL_x64_MAX);       \
    static_assert(FEX::HLE::Arm64::SYSCALL_Arm64_##name >= 0 && FEX::HLE::Arm64::SYSCALL_Arm64_##name < FEX::HLE::Arm64::SYSCALL_Arm64_MAX); \
    FEX::HLE::x64::RegisterSyscall(Handler, FEX::HLE::x64::SYSCALL_x64_##name, #name, SyscallPassthrough##nargs<SYSCALL_DEF(name)>,    \
                                   DirectPassthroughNumber(FEX::HLE::x64::SYSCALL_x64_##name, FEX::HLE::Arm64::SYSCALL_Arm64_##name)); \
    FEX::HLE::x32::RegisterSyscall(Handler, FEX::HLE::x32::SYSCALL_x86_##name, #name, SyscallPassthrough##nargs<SYSCALL_DEF(name)>);   \
  } while (false)

#define REGISTER_PASSTHROUGH_X64(name, nargs)                                                                                          \
  do {                                                                                                                                 \
    static_assert(x64::SYSCALL_x64_##name >= 0 && x64::SYSCALL_x64_##name < x64::SYSCALL_x64_MAX);                                     \
    static_assert(FEX::HLE::Arm64::SYSCALL_Arm64_##name >= 0 && FEX::HLE::Arm64::SYSCALL_Arm64_##name < FEX::HLE::Arm64::SYSCALL_Arm64_MAX); \
    FEX::HLE::x64::RegisterSyscall(Handler, x64::SYSCALL_x64_##name, #name, SyscallPassthrough##nargs<SYSCALL_DEF(name)>,              \
                                   DirectPassthroughNumber(x64::SYSCALL_x64_##name, FEX::HLE::Arm64::SYSCALL_Arm64_##name));           \
  } while (false)

static void RegisterCommon(FEX::HLE::SyscallHandler* Handler) {
  REGISTER_PASSTHROUGH_COMMON(read, 3);
  REGISTER_PASSTHROUGH_COMMON(write, 3);
  REGISTER_PASSTHROUGH_COMMON(lseek, 3);
  REGISTER_PASSTHROUGH_COMMON(sched_yield, 0);
  REGISTER_PASSTHROUGH_COMMON(msync, 3);
  REGISTER_PASSTHROUGH_COMMON(mincore, 3);
  REGISTER_PASSTHROUGH_COMMON(shmget, 3);
  REGISTER_PASSTHROUGH_COMMON(shmctl, 3);
  REGISTER_PASSTHROUGH_COMMON(getpid, 0);
  REGISTER_PASSTHROUGH_COMMON(socket, 3);
  REGISTER_PASSTHROUGH_COMMON(connect, 3);
  REGISTER_PASSTHROUGH_COMMON(sendto, 6);
  REGISTER_PASSTHROUGH_COMMON(recvfrom, 6);
  REGISTER_PASSTHROUGH_COMMON(shutdown, 2);
  REGISTER_PASSTHROUGH_COMMON(bind, 3);
  REGISTER_PASSTHROUGH_COMMON(listen, 2);
  REGISTER_PASSTHROUGH_COMMON(getsockname, 3);
  REGISTER_PASSTHROUGH_COMMON(getpeername, 3);
  REGISTER_PASSTHROUGH_COMMON(socketpair, 4);
  // Conservatively keep signal-sending syscall on the C++ slow path.
  REGISTER_SYSCALL_IMPL(kill, SyscallPassthrough2<SYSCALL_DEF(kill)>);
  REGISTER_PASSTHROUGH_COMMON(semget, 3);
  REGISTER_PASSTHROUGH_COMMON(msgget, 2);
  REGISTER_PASSTHROUGH_COMMON(msgsnd, 4);
  REGISTER_PASSTHROUGH_COMMON(msgrcv, 5);
  REGISTER_PASSTHROUGH_COMMON(msgctl, 3);
  REGISTER_PASSTHROUGH_COMMON(flock, 2);
  REGISTER_PASSTHROUGH_COMMON(fsync, 1);
  REGISTER_PASSTHROUGH_COMMON(fdatasync, 1);
  REGISTER_PASSTHROUGH_COMMON(truncate, 2);
  REGISTER_PASSTHROUGH_COMMON(getcwd, 2);
  REGISTER_PASSTHROUGH_COMMON(chdir, 1);
  REGISTER_PASSTHROUGH_COMMON(fchdir, 1);
  REGISTER_PASSTHROUGH_COMMON(fchmod, 2);
  REGISTER_PASSTHROUGH_COMMON(fchown, 3);
  REGISTER_PASSTHROUGH_COMMON(umask, 1);
  REGISTER_PASSTHROUGH_COMMON(getuid, 0);
  REGISTER_PASSTHROUGH_COMMON(syslog, 3);
  REGISTER_PASSTHROUGH_COMMON(getgid, 0);
  REGISTER_PASSTHROUGH_COMMON(setuid, 1);
  REGISTER_PASSTHROUGH_COMMON(setgid, 1);
  REGISTER_PASSTHROUGH_COMMON(geteuid, 0);
  REGISTER_PASSTHROUGH_COMMON(getegid, 0);
  // posix_spawn(POSIX_SPAWN_SETSID | POSIX_SPAWN_SETPGROUP) does setsid()
  // then setpgid(0, 0). The kernel returns EPERM because the process is
  // already a session leader, even when the requested group is already in
  // effect. glibc then _exit(127) and the parent can hang on a pipe whose
  // write end is still open in the parent.
  REGISTER_SYSCALL_IMPL(setpgid, [](FEXCore::Core::CpuStateFrame* Frame, uint64_t pid, uint64_t pgid) -> uint64_t {
    uint64_t Result = ::syscall(SYSCALL_DEF(setpgid), pid, pgid);
    if (Result == -1ULL && errno == EPERM) {
      const pid_t self = ::getpid();
      const pid_t target = (pid == 0) ? self : static_cast<pid_t>(pid);
      const pid_t want = (pgid == 0) ? target : static_cast<pid_t>(pgid);
      if (target == self && ::getpgrp() == want && ::getsid(0) == self) {
        return 0;
      }
      return -EPERM;
    }
    SYSCALL_ERRNO();
  });
  REGISTER_PASSTHROUGH_COMMON(getppid, 0);
  REGISTER_PASSTHROUGH_COMMON(setsid, 0);
  REGISTER_PASSTHROUGH_COMMON(setreuid, 2);
  REGISTER_PASSTHROUGH_COMMON(setregid, 2);
  REGISTER_PASSTHROUGH_COMMON(getgroups, 2);
  REGISTER_PASSTHROUGH_COMMON(setgroups, 2);
  REGISTER_PASSTHROUGH_COMMON(setresuid, 3);
  REGISTER_PASSTHROUGH_COMMON(getresuid, 3);
  REGISTER_PASSTHROUGH_COMMON(setresgid, 3);
  REGISTER_PASSTHROUGH_COMMON(getresgid, 3);
  REGISTER_PASSTHROUGH_COMMON(getpgid, 1);
  REGISTER_PASSTHROUGH_COMMON(setfsuid, 1);
  REGISTER_PASSTHROUGH_COMMON(setfsgid, 1);
  REGISTER_PASSTHROUGH_COMMON(getsid, 1);
  REGISTER_PASSTHROUGH_COMMON(capget, 2);
  REGISTER_PASSTHROUGH_COMMON(capset, 2);
  REGISTER_PASSTHROUGH_COMMON(getpriority, 2);
  REGISTER_PASSTHROUGH_COMMON(setpriority, 3);
  REGISTER_PASSTHROUGH_COMMON(sched_setparam, 2);
  REGISTER_PASSTHROUGH_COMMON(sched_getparam, 2);
  REGISTER_PASSTHROUGH_COMMON(sched_setscheduler, 3);
  REGISTER_PASSTHROUGH_COMMON(sched_getscheduler, 1);
  REGISTER_PASSTHROUGH_COMMON(sched_get_priority_max, 1);
  REGISTER_PASSTHROUGH_COMMON(sched_get_priority_min, 1);
  REGISTER_PASSTHROUGH_COMMON(mlock, 2);
  REGISTER_PASSTHROUGH_COMMON(munlock, 2);
  REGISTER_PASSTHROUGH_COMMON(pivot_root, 2);
  REGISTER_PASSTHROUGH_COMMON(chroot, 1);
  REGISTER_PASSTHROUGH_COMMON(sync, 0);
  REGISTER_PASSTHROUGH_COMMON(acct, 1);
  REGISTER_PASSTHROUGH_COMMON(mount, 5);
  REGISTER_PASSTHROUGH_COMMON(umount2, 2);
  REGISTER_PASSTHROUGH_COMMON(swapon, 2);
  REGISTER_PASSTHROUGH_COMMON(swapoff, 1);
  REGISTER_PASSTHROUGH_COMMON(gettid, 0);
  REGISTER_PASSTHROUGH_COMMON(fsetxattr, 5);
  REGISTER_PASSTHROUGH_COMMON(fgetxattr, 4);
  REGISTER_PASSTHROUGH_COMMON(flistxattr, 3);
  REGISTER_PASSTHROUGH_COMMON(fremovexattr, 2);
  // Conservatively keep signal-sending syscall on the C++ slow path.
  REGISTER_SYSCALL_IMPL(tkill, SyscallPassthrough2<SYSCALL_DEF(tkill)>);
  REGISTER_PASSTHROUGH_COMMON(sched_setaffinity, 3);
  REGISTER_PASSTHROUGH_COMMON(sched_getaffinity, 3);
  REGISTER_PASSTHROUGH_COMMON(io_setup, 2);
  REGISTER_PASSTHROUGH_COMMON(io_destroy, 1);
  REGISTER_PASSTHROUGH_COMMON(io_submit, 3);
  REGISTER_PASSTHROUGH_COMMON(io_cancel, 3);
  REGISTER_PASSTHROUGH_COMMON(remap_file_pages, 5);
  REGISTER_PASSTHROUGH_COMMON(timer_getoverrun, 1);
  REGISTER_PASSTHROUGH_COMMON(timer_delete, 1);
  // Conservatively keep signal-sending syscall on the C++ slow path.
  REGISTER_SYSCALL_IMPL(tgkill, SyscallPassthrough3<SYSCALL_DEF(tgkill)>);
  REGISTER_PASSTHROUGH_COMMON(mbind, 6);
  REGISTER_PASSTHROUGH_COMMON(set_mempolicy, 3);
  REGISTER_PASSTHROUGH_COMMON(get_mempolicy, 5);
  REGISTER_PASSTHROUGH_COMMON(mq_unlink, 1);
  REGISTER_PASSTHROUGH_COMMON(add_key, 5);
  REGISTER_PASSTHROUGH_COMMON(request_key, 4);
  REGISTER_PASSTHROUGH_COMMON(keyctl, 5);
  REGISTER_PASSTHROUGH_COMMON(ioprio_set, 2);
  REGISTER_PASSTHROUGH_COMMON(ioprio_get, 3);
  REGISTER_PASSTHROUGH_COMMON(inotify_add_watch, 3);
  REGISTER_PASSTHROUGH_COMMON(inotify_rm_watch, 2);
  REGISTER_PASSTHROUGH_COMMON(migrate_pages, 4);
  REGISTER_PASSTHROUGH_COMMON(mkdirat, 3);
  REGISTER_PASSTHROUGH_COMMON(mknodat, 4);
  REGISTER_PASSTHROUGH_COMMON(fchownat, 5);
  REGISTER_PASSTHROUGH_COMMON(unlinkat, 3);
  REGISTER_PASSTHROUGH_COMMON(renameat, 4);
  REGISTER_PASSTHROUGH_COMMON(linkat, 5);
  REGISTER_PASSTHROUGH_COMMON(symlinkat, 3);
  REGISTER_PASSTHROUGH_COMMON(fchmodat, 3);
  REGISTER_PASSTHROUGH_COMMON(unshare, 1);
  REGISTER_PASSTHROUGH_COMMON(splice, 6);
  REGISTER_PASSTHROUGH_COMMON(tee, 4);
  REGISTER_PASSTHROUGH_COMMON(move_pages, 6);
  REGISTER_PASSTHROUGH_COMMON(timerfd_create, 2);
  REGISTER_PASSTHROUGH_COMMON(accept4, 4);
  REGISTER_PASSTHROUGH_COMMON(eventfd2, 2);
  REGISTER_PASSTHROUGH_COMMON(epoll_create1, 1);
  REGISTER_PASSTHROUGH_COMMON(inotify_init1, 1);
  REGISTER_PASSTHROUGH_COMMON(fanotify_init, 2);
  REGISTER_PASSTHROUGH_COMMON(fanotify_mark, 5);
  REGISTER_PASSTHROUGH_COMMON(prlimit_64, 4);
  REGISTER_PASSTHROUGH_COMMON(name_to_handle_at, 5);
  REGISTER_PASSTHROUGH_COMMON(open_by_handle_at, 3);
  REGISTER_PASSTHROUGH_COMMON(syncfs, 1);
  REGISTER_PASSTHROUGH_COMMON(setns, 2);
  REGISTER_PASSTHROUGH_COMMON(getcpu, 3);
  REGISTER_PASSTHROUGH_COMMON(kcmp, 5);
  REGISTER_PASSTHROUGH_COMMON(sched_setattr, 3);
  REGISTER_PASSTHROUGH_COMMON(sched_getattr, 4);
  REGISTER_PASSTHROUGH_COMMON(renameat2, 5);
  REGISTER_PASSTHROUGH_COMMON(getrandom, 3);
  REGISTER_PASSTHROUGH_COMMON(memfd_create, 2);
  REGISTER_PASSTHROUGH_COMMON(membarrier, 2);
  REGISTER_PASSTHROUGH_COMMON(mlock2, 3);
  REGISTER_PASSTHROUGH_COMMON(copy_file_range, 6);
  REGISTER_PASSTHROUGH_COMMON(pkey_mprotect, 4);
  REGISTER_PASSTHROUGH_COMMON(pkey_alloc, 2);
  REGISTER_PASSTHROUGH_COMMON(pkey_free, 1);
  REGISTER_PASSTHROUGH_COMMON(open_tree, 3);
  REGISTER_PASSTHROUGH_COMMON(move_mount, 5);
  REGISTER_PASSTHROUGH_COMMON(fsopen, 3);
  REGISTER_PASSTHROUGH_COMMON(fsconfig, 5);
  REGISTER_PASSTHROUGH_COMMON(fsmount, 3);
  REGISTER_PASSTHROUGH_COMMON(fspick, 3);
  REGISTER_PASSTHROUGH_COMMON(pidfd_open, 2);
  REGISTER_PASSTHROUGH_COMMON(pidfd_getfd, 3);
  REGISTER_PASSTHROUGH_COMMON(mount_setattr, 5);
  REGISTER_PASSTHROUGH_COMMON(quotactl_fd, 4);
  REGISTER_PASSTHROUGH_COMMON(landlock_create_ruleset, 3);
  REGISTER_PASSTHROUGH_COMMON(landlock_add_rule, 4);
  REGISTER_PASSTHROUGH_COMMON(landlock_restrict_self, 2);
  REGISTER_PASSTHROUGH_COMMON(memfd_secret, 1);
  REGISTER_PASSTHROUGH_COMMON(process_mrelease, 2);
  if (Handler->IsHostKernelVersionAtLeast(5, 16, 0)) {
    REGISTER_PASSTHROUGH_COMMON(futex_waitv, 5);
  } else {
    REGISTER_SYSCALL_IMPL(futex_waitv, UnimplementedSyscallSafe);
  }
  if (Handler->IsHostKernelVersionAtLeast(5, 17, 0)) {
    REGISTER_PASSTHROUGH_COMMON(set_mempolicy_home_node, 4);
  } else {
    REGISTER_SYSCALL_IMPL(set_mempolicy_home_node, UnimplementedSyscallSafe);
  }

  if (Handler->IsHostKernelVersionAtLeast(6, 8, 0)) {
    REGISTER_PASSTHROUGH_COMMON(futex_wake, 4);
    REGISTER_PASSTHROUGH_COMMON(futex_wait, 6);
    REGISTER_PASSTHROUGH_COMMON(futex_requeue, 4);
    REGISTER_PASSTHROUGH_COMMON(statmount, 4);
    REGISTER_PASSTHROUGH_COMMON(listmount, 4);
    REGISTER_PASSTHROUGH_COMMON(lsm_get_self_attr, 4);
    REGISTER_PASSTHROUGH_COMMON(lsm_set_self_attr, 4);
    REGISTER_PASSTHROUGH_COMMON(lsm_list_modules, 3);
  } else {
    REGISTER_SYSCALL_IMPL(futex_wake, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(futex_wait, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(futex_requeue, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(statmount, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(listmount, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_get_self_attr, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_set_self_attr, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_list_modules, UnimplementedSyscallSafe);
  }
  if (Handler->IsHostKernelVersionAtLeast(6, 10, 0)) {
    REGISTER_PASSTHROUGH_COMMON(mseal, 3);
  } else {
    REGISTER_SYSCALL_IMPL(mseal, UnimplementedSyscallSafe);
  }
}

namespace x64 {
  void RegisterPassthrough(FEX::HLE::SyscallHandler* Handler) {
    RegisterCommon(Handler);
    if (FEXCore::Config::Get_DISABLEIOURING()()) {
      REGISTER_SYSCALL_IMPL_X64(io_uring_setup, UnimplementedSyscallSafe);
      REGISTER_SYSCALL_IMPL_X64(io_uring_enter, UnimplementedSyscallSafe);
      REGISTER_SYSCALL_IMPL_X64(io_uring_register, UnimplementedSyscallSafe);
    } else {
#ifdef ARCHITECTURE_arm64
      REGISTER_SYSCALL_IMPL_X64(io_uring_setup, IOUringSetupRestricted);
#else
      REGISTER_SYSCALL_IMPL_X64(io_uring_setup, SyscallPassthrough2<SYSCALL_DEF(io_uring_setup)>);
#endif
      REGISTER_PASSTHROUGH_X64(io_uring_enter, 6);
      REGISTER_PASSTHROUGH_X64(io_uring_register, 4);
    }
    REGISTER_PASSTHROUGH_X64(ftruncate, 2);
    FEX::HLE::x64::RegisterSyscall(
      Handler, x64::SYSCALL_x64_ioctl, "ioctl",
      [](FEXCore::Core::CpuStateFrame* Frame, int fd, uint64_t request, uint64_t args) -> uint64_t {
        if (_IOC_TYPE(request) == UFFDIO) [[unlikely]] {
          return FEX::HLE::UserfaultfdIoctl(fd, request, args);
        }
        return SyscallPassthrough3<SYSCALL_DEF(ioctl)>(Frame, fd, request, args);
      },
      FEXCore::HLE::SyscallHandler::DIRECT_PASSTHROUGH_IOCTL);
    REGISTER_PASSTHROUGH_X64(pread_64, 4);
    REGISTER_PASSTHROUGH_X64(pwrite_64, 4);
    REGISTER_PASSTHROUGH_X64(readv, 3);
    REGISTER_PASSTHROUGH_X64(writev, 3);
    REGISTER_PASSTHROUGH_X64(dup, 1);
    REGISTER_PASSTHROUGH_X64(nanosleep, 2);
    REGISTER_PASSTHROUGH_X64(getitimer, 2);
    REGISTER_PASSTHROUGH_X64(setitimer, 3);
    REGISTER_PASSTHROUGH_X64(sendfile, 4);
    REGISTER_PASSTHROUGH_X64(accept, 3);
    REGISTER_PASSTHROUGH_X64(sendmsg, 3);
    REGISTER_PASSTHROUGH_X64(recvmsg, 3);
    REGISTER_PASSTHROUGH_X64(setsockopt, 5);
    REGISTER_PASSTHROUGH_X64(getsockopt, 5);
    REGISTER_PASSTHROUGH_X64(wait4, 4);
    REGISTER_PASSTHROUGH_X64(semop, 3);
    REGISTER_PASSTHROUGH_X64(getrlimit, 2);
    REGISTER_PASSTHROUGH_X64(getrusage, 2);
    REGISTER_PASSTHROUGH_X64(sysinfo, 1);
    REGISTER_PASSTHROUGH_X64(times, 1);
    // Conservatively keep signal-sending syscall on the C++ slow path.
    REGISTER_SYSCALL_IMPL_X64(rt_sigqueueinfo, SyscallPassthrough3<SYSCALL_DEF(rt_sigqueueinfo)>);
    REGISTER_PASSTHROUGH_X64(fstatfs, 2);
    REGISTER_PASSTHROUGH_X64(sched_rr_get_interval, 2);
    REGISTER_PASSTHROUGH_X64(mlockall, 1);
    REGISTER_PASSTHROUGH_X64(munlockall, 0);
    REGISTER_PASSTHROUGH_X64(adjtimex, 1);
    REGISTER_PASSTHROUGH_X64(setrlimit, 2);
    REGISTER_PASSTHROUGH_X64(settimeofday, 2);
    REGISTER_PASSTHROUGH_X64(readahead, 3);
    REGISTER_PASSTHROUGH_X64(futex, 6);
    REGISTER_PASSTHROUGH_X64(io_getevents, 5);
    REGISTER_PASSTHROUGH_X64(semtimedop, 4);
    REGISTER_PASSTHROUGH_X64(timer_create, 3);
    REGISTER_PASSTHROUGH_X64(timer_settime, 4);
    REGISTER_PASSTHROUGH_X64(timer_gettime, 2);
    REGISTER_PASSTHROUGH_X64(clock_settime, 2);
    REGISTER_PASSTHROUGH_X64(clock_gettime, 2);
    REGISTER_PASSTHROUGH_X64(clock_getres, 2);
    REGISTER_PASSTHROUGH_X64(clock_nanosleep, 4);
    REGISTER_PASSTHROUGH_X64(mq_open, 4);
    REGISTER_PASSTHROUGH_X64(mq_timedsend, 5);
    REGISTER_PASSTHROUGH_X64(mq_timedreceive, 5);
    REGISTER_PASSTHROUGH_X64(mq_notify, 2);
    REGISTER_PASSTHROUGH_X64(mq_getsetattr, 3);
    REGISTER_PASSTHROUGH_X64(waitid, 5);
    REGISTER_PASSTHROUGH_X64(pselect6, 6);
    REGISTER_PASSTHROUGH_X64(ppoll, 5);
    REGISTER_PASSTHROUGH_X64(set_robust_list, 2);
    REGISTER_PASSTHROUGH_X64(get_robust_list, 3);
    REGISTER_PASSTHROUGH_X64(sync_file_range, 4);
    REGISTER_PASSTHROUGH_X64(vmsplice, 4);
    REGISTER_PASSTHROUGH_X64(utimensat, 4);
    REGISTER_PASSTHROUGH_X64(fallocate, 4);
    REGISTER_PASSTHROUGH_X64(timerfd_settime, 4);
    REGISTER_PASSTHROUGH_X64(timerfd_gettime, 2);
    REGISTER_PASSTHROUGH_X64(preadv, 5);
    REGISTER_PASSTHROUGH_X64(pwritev, 5);
    // Conservatively keep signal-sending syscall on the C++ slow path.
    REGISTER_SYSCALL_IMPL_X64(rt_tgsigqueueinfo, SyscallPassthrough4<SYSCALL_DEF(rt_tgsigqueueinfo)>);
    REGISTER_PASSTHROUGH_X64(recvmmsg, 5);
    REGISTER_PASSTHROUGH_X64(clock_adjtime, 2);
    REGISTER_PASSTHROUGH_X64(sendmmsg, 4);
    REGISTER_PASSTHROUGH_X64(process_vm_readv, 6);
    REGISTER_PASSTHROUGH_X64(process_vm_writev, 6);
    REGISTER_PASSTHROUGH_X64(preadv2, 6);
    REGISTER_PASSTHROUGH_X64(pwritev2, 6);
    REGISTER_PASSTHROUGH_X64(io_pgetevents, 6);
    // Conservatively keep signal-sending syscall on the C++ slow path.
    REGISTER_SYSCALL_IMPL_X64(pidfd_send_signal, SyscallPassthrough4<SYSCALL_DEF(pidfd_send_signal)>);
    REGISTER_PASSTHROUGH_X64(process_madvise, 5);
    REGISTER_PASSTHROUGH_X64(fadvise64, 4);
    if (Handler->IsHostKernelVersionAtLeast(6, 5, 0)) {
      REGISTER_PASSTHROUGH_X64(cachestat, 4);
    } else {
      REGISTER_SYSCALL_IMPL_X64(cachestat, UnimplementedSyscallSafe);
    }
    if (Handler->IsHostKernelVersionAtLeast(6, 6, 0)) {
      REGISTER_PASSTHROUGH_X64(fchmodat2, 4);
    } else {
      REGISTER_SYSCALL_IMPL_X64(fchmodat2, UnimplementedSyscallSafe);
    }
  }
} // namespace x64

#undef REGISTER_PASSTHROUGH_COMMON
#undef REGISTER_PASSTHROUGH_X64

namespace x32 {
  void RegisterPassthrough(FEX::HLE::SyscallHandler* Handler) {
    RegisterCommon(Handler);
    // 32-bit guests: iovec, msghdr and pointer-sized fields in the requests differ from arm64's.
    REGISTER_SYSCALL_IMPL_X32(io_uring_setup, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL_X32(io_uring_enter, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL_X32(io_uring_register, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL_X32(getuid32, SyscallPassthrough0<SYSCALL_DEF(getuid)>);
    REGISTER_SYSCALL_IMPL_X32(getgid32, SyscallPassthrough0<SYSCALL_DEF(getgid)>);
    REGISTER_SYSCALL_IMPL_X32(geteuid32, SyscallPassthrough0<SYSCALL_DEF(geteuid)>);
    REGISTER_SYSCALL_IMPL_X32(getegid32, SyscallPassthrough0<SYSCALL_DEF(getegid)>);
    REGISTER_SYSCALL_IMPL_X32(setreuid32, SyscallPassthrough2<SYSCALL_DEF(setreuid)>);
    REGISTER_SYSCALL_IMPL_X32(setregid32, SyscallPassthrough2<SYSCALL_DEF(setregid)>);
    REGISTER_SYSCALL_IMPL_X32(getgroups32, SyscallPassthrough2<SYSCALL_DEF(getgroups)>);
    REGISTER_SYSCALL_IMPL_X32(setgroups32, SyscallPassthrough2<SYSCALL_DEF(setgroups)>);
    REGISTER_SYSCALL_IMPL_X32(fchown32, SyscallPassthrough3<SYSCALL_DEF(fchown)>);
    REGISTER_SYSCALL_IMPL_X32(setresuid32, SyscallPassthrough3<SYSCALL_DEF(setresuid)>);
    REGISTER_SYSCALL_IMPL_X32(getresuid32, SyscallPassthrough3<SYSCALL_DEF(getresuid)>);
    REGISTER_SYSCALL_IMPL_X32(setresgid32, SyscallPassthrough3<SYSCALL_DEF(setresgid)>);
    REGISTER_SYSCALL_IMPL_X32(getresgid32, SyscallPassthrough3<SYSCALL_DEF(getresgid)>);
    REGISTER_SYSCALL_IMPL_X32(setuid32, SyscallPassthrough1<SYSCALL_DEF(setuid)>);
    REGISTER_SYSCALL_IMPL_X32(setgid32, SyscallPassthrough1<SYSCALL_DEF(setgid)>);
    REGISTER_SYSCALL_IMPL_X32(setfsuid32, SyscallPassthrough1<SYSCALL_DEF(setfsuid)>);
    REGISTER_SYSCALL_IMPL_X32(setfsgid32, SyscallPassthrough1<SYSCALL_DEF(setfsgid)>);
    REGISTER_SYSCALL_IMPL_X32(sendfile64, SyscallPassthrough4<SYSCALL_DEF(sendfile)>);
    REGISTER_SYSCALL_IMPL_X32(clock_gettime64, SyscallPassthrough2<SYSCALL_DEF(clock_gettime)>);
    REGISTER_SYSCALL_IMPL_X32(clock_settime64, SyscallPassthrough2<SYSCALL_DEF(clock_settime)>);
    REGISTER_SYSCALL_IMPL_X32(clock_adjtime64, SyscallPassthrough2<SYSCALL_DEF(clock_adjtime)>);
    REGISTER_SYSCALL_IMPL_X32(clock_getres_time64, SyscallPassthrough2<SYSCALL_DEF(clock_getres)>);
    REGISTER_SYSCALL_IMPL_X32(clock_nanosleep_time64, SyscallPassthrough4<SYSCALL_DEF(clock_nanosleep)>);
    REGISTER_SYSCALL_IMPL_X32(timer_gettime64, SyscallPassthrough2<SYSCALL_DEF(timer_gettime)>);
    REGISTER_SYSCALL_IMPL_X32(timer_settime64, SyscallPassthrough4<SYSCALL_DEF(timer_settime)>);
    REGISTER_SYSCALL_IMPL_X32(timerfd_gettime64, SyscallPassthrough2<SYSCALL_DEF(timerfd_gettime)>);
    REGISTER_SYSCALL_IMPL_X32(timerfd_settime64, SyscallPassthrough4<SYSCALL_DEF(timerfd_settime)>);
    REGISTER_SYSCALL_IMPL_X32(utimensat_time64, SyscallPassthrough4<SYSCALL_DEF(utimensat)>);
    REGISTER_SYSCALL_IMPL_X32(ppoll_time64, SyscallPassthrough5<SYSCALL_DEF(ppoll)>);
    REGISTER_SYSCALL_IMPL_X32(io_pgetevents_time64, SyscallPassthrough6<SYSCALL_DEF(io_pgetevents)>);
    REGISTER_SYSCALL_IMPL_X32(mq_timedsend_time64, SyscallPassthrough5<SYSCALL_DEF(mq_timedsend)>);
    REGISTER_SYSCALL_IMPL_X32(mq_timedreceive_time64, SyscallPassthrough5<SYSCALL_DEF(mq_timedreceive)>);
    REGISTER_SYSCALL_IMPL_X32(semtimedop_time64, SyscallPassthrough4<SYSCALL_DEF(semtimedop)>);
    REGISTER_SYSCALL_IMPL_X32(futex_time64, SyscallPassthrough6<SYSCALL_DEF(futex)>);
    REGISTER_SYSCALL_IMPL_X32(sched_rr_get_interval_time64, SyscallPassthrough2<SYSCALL_DEF(sched_rr_get_interval)>);
  }
} // namespace x32
} // namespace FEX::HLE
