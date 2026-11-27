// FEX offers userfaultfd only with asynchronous write protection, the mode the kernel resolves without a handler thread.

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int OpenUserfaultfd() {
  return syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
}

// Returns the features offered, or -1 if the host has no userfaultfd for this process.
static int64_t ProbeFeatures() {
  const int fd = OpenUserfaultfd();
  if (fd < 0) {
    return -1;
  }
  uffdio_api API {.api = UFFD_API, .features = 0};
  const int Result = ioctl(fd, UFFDIO_API, &API);
  close(fd);
  return Result == 0 ? static_cast<int64_t>(API.features) : -1;
}

TEST_CASE("userfaultfd: modes that wait for a handler are refused") {
  const auto Features = ProbeFeatures();
  if (Features < 0) {
    SKIP("no userfaultfd");
  }
  CHECK((Features & (UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_EVENT_REMOVE | UFFD_FEATURE_EVENT_UNMAP |
                     UFFD_FEATURE_SIGBUS | UFFD_FEATURE_MINOR_SHMEM)) == 0);

  int fd = OpenUserfaultfd();
  REQUIRE(fd >= 0);
  uffdio_api API {.api = UFFD_API, .features = UFFD_FEATURE_EVENT_UNMAP};
  CHECK(ioctl(fd, UFFDIO_API, &API) == -1);
  CHECK(errno == EINVAL);
  close(fd);

  // Without asynchronous write protection, write-protect faults would wait for a handler too.
  fd = OpenUserfaultfd();
  REQUIRE(fd >= 0);
  API = {.api = UFFD_API, .features = 0};
  REQUIRE(ioctl(fd, UFFDIO_API, &API) == 0);
  const size_t PageSize = sysconf(_SC_PAGESIZE);
  void* Ptr = mmap(nullptr, PageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(Ptr != MAP_FAILED);
  for (const uint64_t Mode : {UFFDIO_REGISTER_MODE_MISSING, UFFDIO_REGISTER_MODE_WP, UFFDIO_REGISTER_MODE_MINOR}) {
    uffdio_register Register {.range = {.start = reinterpret_cast<uintptr_t>(Ptr), .len = PageSize}, .mode = Mode};
    CHECK(ioctl(fd, UFFDIO_REGISTER, &Register) == -1);
    CHECK(errno == EINVAL);
  }
  munmap(Ptr, PageSize);
  close(fd);
}

TEST_CASE("userfaultfd: a bad fd gets EBADF") {
  const int fd = OpenUserfaultfd();
  if (fd < 0) {
    SKIP("no userfaultfd");
  }
  close(fd);
  uffdio_api API {.api = UFFD_API, .features = 0};
  CHECK(ioctl(fd, UFFDIO_API, &API) == -1);
  CHECK(errno == EBADF);
  uffdio_register Register {.range = {.start = 0, .len = 0}, .mode = UFFDIO_REGISTER_MODE_WP};
  CHECK(ioctl(fd, UFFDIO_REGISTER, &Register) == -1);
  CHECK(errno == EBADF);
}

TEST_CASE("userfaultfd: asynchronous write protection with PAGEMAP_SCAN") {
#if defined(UFFD_FEATURE_WP_ASYNC) && defined(PAGEMAP_SCAN)
  const auto Features = ProbeFeatures();
  if (Features < 0 || !(Features & UFFD_FEATURE_WP_ASYNC)) {
    SKIP("no asynchronous write protection");
  }
  const int fd = OpenUserfaultfd();
  REQUIRE(fd >= 0);
  // These only change fault messages, which asynchronous write protection never produces.
  CHECK((Features & UFFD_FEATURE_PAGEFAULT_FLAG_WP) != 0);
  CHECK((Features & UFFD_FEATURE_THREAD_ID) != 0);
  uffdio_api API {.api = UFFD_API, .features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID};
  REQUIRE(ioctl(fd, UFFDIO_API, &API) == 0);

  const size_t PageSize = sysconf(_SC_PAGESIZE);
  auto* Pages = static_cast<uint8_t*>(mmap(nullptr, 4 * PageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  REQUIRE(Pages != MAP_FAILED);
  const auto Start = reinterpret_cast<uintptr_t>(Pages);
  for (size_t i = 0; i < 4; i++) {
    Pages[i * PageSize] = 1;
  }
  uffdio_register Register {.range = {.start = Start, .len = 4 * PageSize}, .mode = UFFDIO_REGISTER_MODE_WP};
  REQUIRE(ioctl(fd, UFFDIO_REGISTER, &Register) == 0);
  uffdio_writeprotect Protect {.range = {.start = Start, .len = 4 * PageSize}, .mode = UFFDIO_WRITEPROTECT_MODE_WP};
  REQUIRE(ioctl(fd, UFFDIO_WRITEPROTECT, &Protect) == 0);

  const int Pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
  REQUIRE(Pagemap >= 0);
  // Reports the written pages and write-protects them again.
  const auto Scan = [&](page_region* Regions, uint64_t Count) {
    pm_scan_arg Arg {.size = sizeof(Arg),
                     .flags = PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC,
                     .start = Start,
                     .end = Start + 4 * PageSize,
                     .vec = reinterpret_cast<uintptr_t>(Regions),
                     .vec_len = Count,
                     .category_mask = PAGE_IS_WRITTEN,
                     .return_mask = PAGE_IS_WRITTEN};
    return ioctl(Pagemap, PAGEMAP_SCAN, &Arg);
  };

  page_region Regions[4] {};
  CHECK(Scan(Regions, 4) == 0);

  // Faults on write-protected pages resolve in the kernel, no thread waits.
  Pages[1 * PageSize] = 2;
  Pages[2 * PageSize] = 3;
  REQUIRE(Scan(Regions, 4) == 1);
  CHECK(Regions[0].start == Start + PageSize);
  CHECK(Regions[0].end == Start + 3 * PageSize);
  CHECK(Regions[0].categories == PAGE_IS_WRITTEN);
  CHECK(Scan(Regions, 4) == 0);

  Pages[3 * PageSize] = 4;
  REQUIRE(Scan(Regions, 4) == 1);
  CHECK(Regions[0].start == Start + 3 * PageSize);
  CHECK(Pages[1 * PageSize] == 2);

  close(Pagemap);
  munmap(Pages, 4 * PageSize);
  close(fd);
#else
  SKIP("headers without UFFD_FEATURE_WP_ASYNC or PAGEMAP_SCAN");
#endif
}
