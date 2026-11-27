/*
  tests one thread rewriting code that another thread keeps running, as the SDM's cross-modifying code protocol allows:
  the writer stores the new code and then publishes its generation, the runner reads the generation, serializes and runs the
  code. The code must return at least the generation the runner saw. The JIT must not keep a translation that it decoded
  from the old code while the store was landing.
*/

#include <atomic>
#include <cpuid.h>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

typedef int UnalignedInt __attribute__((aligned(1)));

// Returns the first generation whose code the runner missed, or 0.
static int RewriteWhileRunning(char* code, char* rw) {
  memcpy(rw, "\xB8\x00\x00\x00\x00\xC3", 6); // mov eax, 0; ret
  std::atomic<int> generation {0};
  std::atomic<int> missed {0};
  std::atomic<bool> stop {false};

  std::thread runner([&] {
    while (!stop) {
      const int seen = generation.load(std::memory_order_acquire);
      unsigned a, b, c, d;
      __cpuid(0, a, b, c, d); // serialize
      if (((int (*)())code)() < seen && !missed) {
        missed = seen;
      }
    }
  });

  for (int i = 1; i <= 1000 && !missed; i++) {
    *reinterpret_cast<volatile UnalignedInt*>(rw + 1) = i; // the immediate, in one 32-bit store
    generation.store(i, std::memory_order_release);
    usleep(100);
  }
  stop = true;
  runner.join();
  return missed;
}

TEST_CASE("SMC: private_rwx") {
  auto code = (char*)mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(code != MAP_FAILED);
  CHECK(RewriteWhileRunning(code, code) == 0);
  munmap(code, 4096);
}

// Runs from one view of a memfd and writes through an RW view of it. The code view is placed both below and above the RW view,
// because the old per-view invalidation walked the views in address order and depended on it.
static void CodeAndRWViews(int code_prot) {
  int fd = memfd_create("smc-mt-3", 0);
  REQUIRE(fd >= 0);
  REQUIRE(ftruncate(fd, 4096) == 0);

  for (const bool code_below : {true, false}) {
    auto area = (char*)mmap(0, 8192, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(area != MAP_FAILED);
    auto code = (char*)mmap(area + (code_below ? 0 : 4096), 4096, code_prot, MAP_SHARED | MAP_FIXED, fd, 0);
    auto rw = (char*)mmap(area + (code_below ? 4096 : 0), 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    REQUIRE(code != MAP_FAILED);
    REQUIRE(rw != MAP_FAILED);
    INFO("code view below RW view: " << code_below);
    CHECK(RewriteWhileRunning(code, rw) == 0);
    munmap(area, 8192);
  }
  close(fd);
}

TEST_CASE("SMC: memfd_rx_and_rw_views") {
  CodeAndRWViews(PROT_READ | PROT_EXEC);
}

// The code view is writable too: unprotecting the writable views before invalidating the others would not be enough
TEST_CASE("SMC: memfd_rwx_and_rw_views") {
  CodeAndRWViews(PROT_READ | PROT_WRITE | PROT_EXEC);
}
