#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

struct LegacyDirent {
  unsigned long Ino;
  unsigned long Offset;
  unsigned short RecordLength;
  char Name[1];
};

TEST_CASE("getdents - overlapping conversion and ABI record packing") {
  struct Fixture {
    char Directory[32] = "/tmp/getdents-tests.XXXXXX";
    int FD = -1;
    std::vector<std::string> Names;
    ~Fixture() {
      if (FD != -1) {
        for (const auto& Name : Names) {
          unlinkat(FD, Name.c_str(), 0);
        }
        close(FD);
      }
      rmdir(Directory);
    }
  } Fixture;

  REQUIRE(mkdtemp(Fixture.Directory) != nullptr);
  Fixture.FD = open(Fixture.Directory, O_RDONLY | O_DIRECTORY);
  REQUIRE(Fixture.FD != -1);
  std::set<std::string> Expected {".", ".."};
  for (const size_t Length : {1, 2, 5, 6, 7, 8, 9, 13, 14, 15, 16, 29, 30, 31, 32, 253, 254, 255}) {
    std::string Name(Length, 'x');
    int FD = openat(Fixture.FD, Name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    REQUIRE(FD != -1);
    Fixture.Names.push_back(Name);
    REQUIRE(close(FD) == 0);
    Expected.insert(Name);
  }

  for (const size_t Count : {512, 4096}) {
    REQUIRE(lseek(Fixture.FD, 0, SEEK_SET) == 0);
    std::set<std::string> Seen;
    unsigned Calls = 0;
    while (true) {
      alignas(8) std::array<unsigned char, 4096 + 64> Buffer;
      Buffer.fill(0xa5);
      const auto Bytes = syscall(SYS_getdents, Fixture.FD, Buffer.data(), Count);
      REQUIRE(Bytes >= 0);
      REQUIRE(static_cast<size_t>(Bytes) <= Count);
      CHECK(std::all_of(Buffer.begin() + Count, Buffer.end(), [](unsigned char Value) { return Value == 0xa5; }));
      REQUIRE(++Calls < 128);
      if (Bytes == 0) {
        break;
      }
      size_t Offset = 0;
      while (Offset < static_cast<size_t>(Bytes)) {
        REQUIRE(static_cast<size_t>(Bytes) - Offset > offsetof(LegacyDirent, Name));
        const auto* Entry = reinterpret_cast<const LegacyDirent*>(Buffer.data() + Offset);
        const size_t Size = Entry->RecordLength;
        REQUIRE(Size >= offsetof(LegacyDirent, Name) + 2);
        REQUIRE(Size <= static_cast<size_t>(Bytes) - Offset);
        REQUIRE(Size % sizeof(unsigned long) == 0);
        const size_t NameCapacity = Size - offsetof(LegacyDirent, Name) - 1;
        const auto* End = static_cast<const char*>(memchr(Entry->Name, 0, NameCapacity));
        REQUIRE(End != nullptr);
        const std::string Name(Entry->Name, End);
        REQUIRE(Expected.count(Name) == 1);
        CHECK(Seen.insert(Name).second);
        const size_t Required = offsetof(LegacyDirent, Name) + Name.size() + 2;
        CHECK(Size == (Required + sizeof(unsigned long) - 1) / sizeof(unsigned long) * sizeof(unsigned long));
        const unsigned char Type = Buffer[Offset + Size - 1];
        CHECK((Type == DT_UNKNOWN || Type == (Name == "." || Name == ".." ? DT_DIR : DT_REG)));
        Offset += Size;
      }
    }
    CHECK(Seen == Expected);
  }
}
