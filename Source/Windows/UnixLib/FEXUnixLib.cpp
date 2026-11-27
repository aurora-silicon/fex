// SPDX-License-Identifier: MIT
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#ifdef __aarch64__
#include <sys/auxv.h>
#endif
#include <sys/prctl.h>
#include <unistd.h>

#include "FEXUnixLib.h"

// Equivalent to C++23's std::to_underlying.
template<typename Enum>
[[nodiscard]]
constexpr std::underlying_type_t<Enum> ToUnderlying(Enum e) noexcept {
  return static_cast<std::underlying_type_t<Enum>>(e);
}

using NTSTATUS = int32_t;
using unixlib_entry_t = NTSTATUS (*)(void*);

constexpr NTSTATUS STATUS_SUCCESS = 0;
constexpr NTSTATUS STATUS_NOT_SUPPORTED = 0xC00000BB;
constexpr NTSTATUS STATUS_INTERNAL_ERROR = 0xC00000E5;

#ifndef PR_GET_MEM_MODEL
#define PR_GET_MEM_MODEL 0x6d4d444c
#endif
#ifndef PR_SET_MEM_MODEL
#define PR_SET_MEM_MODEL 0x4d4d444c
#endif
#ifndef PR_SET_MEM_MODEL_DEFAULT
#define PR_SET_MEM_MODEL_DEFAULT 0
#endif
#ifndef PR_SET_MEM_MODEL_TSO
#define PR_SET_MEM_MODEL_TSO 1
#endif
#ifndef PR_ARM64_SET_UNALIGN_ATOMIC
#define PR_ARM64_SET_UNALIGN_ATOMIC 0x46455849
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#ifndef PR_GET_TPIDRRO_CPU
#define PR_GET_TPIDRRO_CPU 0x7F1DBB0
#endif

#ifndef AT_HWCAP3
#define AT_HWCAP3 29
#endif
#ifndef HWCAP3_APPLE_APFLG
#define HWCAP3_APPLE_APFLG (1UL << 63)
#endif
#ifndef PR_AURORA_SET_X86_FLAGS
#define PR_AURORA_SET_X86_FLAGS 0x41555006
#endif

static NTSTATUS FEXUnixLib_SetHardwareTSOControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetHardwareTSOControlArgs*>(_Args);
  if (Args->Enable) {
    int ret = prctl(PR_GET_MEM_MODEL, 0, 0, 0, 0);
    if (ret == PR_SET_MEM_MODEL_DEFAULT) {
      return prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO, 0, 0, 0) ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
    }
    return ret == PR_SET_MEM_MODEL_TSO ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
  }

  prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_DEFAULT, 0, 0, 0);
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_SetKernelUnalignedAtomicControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetKernelUnalignedAtomicControl*>(_Args);
  return prctl(PR_ARM64_SET_UNALIGN_ATOMIC, Args->Flags, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_MadviseHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_Madvise*>(_Args);
  return madvise(const_cast<void*>(Args->Addr), Args->Size, Args->Advise) == 0 ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_SetVMANameHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetVMAName*>(_Args);
  return prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<unsigned long>(Args->Addr), Args->Size, Args->Name) == 0 ?
           STATUS_SUCCESS :
           STATUS_INTERNAL_ERROR;
}

constexpr static int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
static inline void* InitializeSHM(uint32_t MapSize, uint32_t MaxSize) {
  void* Base {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  int fd = shm_open(Name.c_str(), O_CREAT | O_TRUNC | O_RDWR, USER_PERMS);

  if (fd == -1) {
    return nullptr;
  }

  if (ftruncate(fd, MapSize) == -1) {
    goto err;
  }

  // Reserve a region of MAX_STATS_SIZE so we can grow the allocation buffer.
  // Number of thread slots when ThreadStatsHeader == 64bytes and ThreadStats == 40bytes:
  // 1 page: 99 slots
  // 1 MB: 26211 slots
  // 128 MB: 3355440 slots
  Base = mmap(nullptr, MaxSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (Base == MAP_FAILED) {
    Base = nullptr;
    goto err;
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(Base), MaxSize, "FEXMem_Misc");

  // Allocate a small working shared space for now, grow as necessary.
  {
    auto SharedBase = mmap(Base, MapSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      ::munmap(Base, MaxSize);
      Base = nullptr;
      goto err;
    }
  }

err:
  close(fd);

  return Base;
}

static inline bool AllocateMoreSlots(void* SHMBase, uint32_t NewSize) {
  bool Result {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";

  // When allocating more slots, open the fd without O_TRUNC | O_CREAT.
  int fd = shm_open(Name.c_str(), O_RDWR, USER_PERMS);
  if (fd == -1) {
    return false;
  }

  if (ftruncate(fd, NewSize) == -1) {
    goto err;
  }

  {
    auto SharedBase = mmap(SHMBase, NewSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      goto err;
    }
  }

  Result = true;

err:
  close(fd);
  return Result;
}

static NTSTATUS FEXUnixLib_GetSHMStatsVMAHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_GetSHMStatsVMA*>(_Args);
  if (Args->SHMBase == nullptr) {
    Args->SHMBase = InitializeSHM(Args->MapSize, Args->MaxSize);
    return Args->SHMBase ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
  }

  return AllocateMoreSlots(Args->SHMBase, Args->MapSize) ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_DeleteSHMStatsFileHandler(void* _Args) {
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  shm_unlink(Name.c_str());
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_MapFileHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_MapFile*>(_Args);
  // could find a way to dedupe with DiskCacheFilemapper in FEXInterpreter but it's barely any code
  // fd was already duped by Wine handle translation
  Args->Result = mmap(nullptr, Args->MapSize, PROT_READ, MAP_SHARED | MAP_NORESERVE, Args->FD, 0);
  close(Args->FD);
  if (Args->Result == (void*)-1) {
    Args->Result = nullptr;
    return STATUS_INTERNAL_ERROR;
  }
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_GetPIDHandler(void* _Args) {
  uint32_t Magic {};
  std::memcpy(&Magic, _Args, sizeof(Magic));
  if (Magic == FEX_UNIXLIB_QUERY_MAGIC) {
    auto Query = reinterpret_cast<FEXUnixLib_GetPIDQuery*>(_Args);
    Query->Result = ::getpid();
    Query->MaxFunction = ToUnderlying(FEXUnixLibFunctions::MAX);
    return STATUS_SUCCESS;
  }

  auto Args = reinterpret_cast<FEXUnixLib_GetPID*>(_Args);
  Args->Result = ::getpid();
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_CheckSupportsTPIDRRO_CPUHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_CheckSupportsTPIDRRO_CPU*>(_Args);
  Args->Result = prctl(PR_GET_TPIDRRO_CPU, 0, 0, 0, 0);
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_EnableAPFLGHandler(void*) {
#ifdef __aarch64__
  if (!(getauxval(AT_HWCAP3) & HWCAP3_APPLE_APFLG)) {
    return STATUS_NOT_SUPPORTED;
  }
  return prctl(PR_AURORA_SET_X86_FLAGS, 1, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
#else
  return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS FEXUnixLib_SetAPFLGControlHandler(void* _Args) {
#ifdef __aarch64__
  if (!_Args) {
    return STATUS_NOT_SUPPORTED;
  }
  auto Args = reinterpret_cast<const FEXUnixLib_SetAPFLGControlArgs*>(_Args);
  if (Args->Enable) {
    if (!(getauxval(AT_HWCAP3) & HWCAP3_APPLE_APFLG)) {
      return STATUS_NOT_SUPPORTED;
    }
    return prctl(PR_AURORA_SET_X86_FLAGS, 1, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
  }

  return prctl(PR_AURORA_SET_X86_FLAGS, 0, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
#else
  (void)_Args;
  return STATUS_NOT_SUPPORTED;
#endif
}

extern "C" const unixlib_entry_t __wine_unix_call_funcs[] = {
  FEXUnixLib_SetHardwareTSOControlHandler,
  FEXUnixLib_SetKernelUnalignedAtomicControlHandler,
  FEXUnixLib_MadviseHandler,
  FEXUnixLib_SetVMANameHandler,
  FEXUnixLib_GetSHMStatsVMAHandler,
  FEXUnixLib_DeleteSHMStatsFileHandler,
  FEXUnixLib_MapFileHandler,
  FEXUnixLib_GetPIDHandler,
  FEXUnixLib_CheckSupportsTPIDRRO_CPUHandler,
  FEXUnixLib_EnableAPFLGHandler,
  FEXUnixLib_SetAPFLGControlHandler,
};

static_assert(sizeof(__wine_unix_call_funcs) / sizeof(__wine_unix_call_funcs[0]) == ToUnderlying(FEXUnixLibFunctions::MAX));
