/*
  tests a block that jumps over a no-access page while the disk cache stores it: the guest code the cache keeps may only be
  read where the block decoded it, not across the page in between.
*/

#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("DiskCache: jump over a no-access page") {
  const size_t Page = sysconf(_SC_PAGESIZE);
  auto Code = static_cast<uint8_t*>(mmap(nullptr, Page * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  REQUIRE(Code != MAP_FAILED);

  // The last instruction of the first page jumps to the third page.
  uint8_t* Entry = Code + Page - 5;
  const int32_t Rel = static_cast<int32_t>((Code + 2 * Page) - (Entry + 5));
  Entry[0] = 0xE9; // jmp rel32
  memcpy(Entry + 1, &Rel, sizeof(Rel));
  memcpy(Code + 2 * Page, "\xB8\x2A\x00\x00\x00\xC3", 6); // mov eax, 42; ret

  REQUIRE(mprotect(Code, Page * 3, PROT_READ | PROT_EXEC) == 0);
  REQUIRE(mprotect(Code + Page, Page, PROT_NONE) == 0);

  CHECK(reinterpret_cast<int (*)()>(Entry)() == 42);
  munmap(Code, Page * 3);
}
