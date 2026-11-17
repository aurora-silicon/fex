// x86 CPUs without protection keys, which is what FEX reports, have no execute-only memory: Linux makes PROT_EXEC readable there.
// FEX reads guest code to translate it, so it has to map PROT_EXEC readable on the host too. Arm64 with EPAN would map it
// execute-only and the frontend would fault on its own read.
//
// On cores without EPAN, PROT_EXEC is readable on the host anyway, so this only fails there.

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

// mov eax, 42; ret
static const uint8_t Code[] = {0xb8, 42, 0, 0, 0, 0xc3};

static int Run(void* Ptr) {
  return reinterpret_cast<int (*)()>(Ptr)();
}

TEST_CASE("Exec-only: mprotect to PROT_EXEC") {
  const size_t PageSize = sysconf(_SC_PAGESIZE);
  void* Ptr = mmap(nullptr, PageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(Ptr != MAP_FAILED);
  memcpy(Ptr, Code, sizeof(Code));
  REQUIRE(mprotect(Ptr, PageSize, PROT_EXEC) == 0);

  CHECK(Run(Ptr) == 42);
  munmap(Ptr, PageSize);
}

TEST_CASE("Exec-only: mmap with PROT_EXEC") {
  const size_t PageSize = sysconf(_SC_PAGESIZE);
  int FD = memfd_create("exec_only", 0);
  REQUIRE(FD != -1);
  REQUIRE(ftruncate(FD, PageSize) == 0);
  REQUIRE(pwrite(FD, Code, sizeof(Code), 0) == sizeof(Code));
  void* Ptr = mmap(nullptr, PageSize, PROT_EXEC, MAP_PRIVATE, FD, 0);
  close(FD);
  REQUIRE(Ptr != MAP_FAILED);

  CHECK(Run(Ptr) == 42);
  munmap(Ptr, PageSize);
}
