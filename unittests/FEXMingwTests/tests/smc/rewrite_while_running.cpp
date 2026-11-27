/*
  tests one thread rewriting code that another thread keeps running, as the SDM's cross-modifying code protocol allows:
  the writer stores the new code and then publishes its generation, the runner reads the generation, serializes and runs the
  code. The code must return at least the generation the runner saw.
*/

#include <atomic>
#include <cpuid.h>
#include <cstring>
#include <thread>
#include <windows.h>

#include <catch2/catch_test_macros.hpp>

typedef int UnalignedInt __attribute__((aligned(1)));

TEST_CASE("SMC: rewrite_while_running") {
  auto code = static_cast<char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  REQUIRE(code);
  memcpy(code, "\xB8\x00\x00\x00\x00\xC3", 6); // mov eax, 0; ret
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
    *reinterpret_cast<volatile UnalignedInt*>(code + 1) = i; // the immediate, in one 32-bit store
    generation.store(i, std::memory_order_release);
    Sleep(0);
  }
  stop = true;
  runner.join();
  CHECK(missed == 0);
  VirtualFree(code, 0, MEM_RELEASE);
}
