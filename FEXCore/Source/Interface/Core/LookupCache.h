// SPDX-License-Identifier: MIT
#pragma once
#include "Interface/Context/Context.h"
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/SpinWaitLock.h>
#include <FEXCore/Utils/WritePriorityMutex.h>

#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory_resource.h>
#include <FEXCore/fextl/robin_map.h>
#include <FEXCore/fextl/robin_set.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/memory_resource.h>

#include <chrono>
#include <cstdint>
#include <span>
#include <stddef.h>
#include <utility>
#include <mutex>

namespace FEXCore {
struct LookupCacheBaseLockToken {
protected:
  // Protected constructor - only derived classes can construct
  LookupCacheBaseLockToken() = default;
};

struct LookupCacheWriteLockToken : public LookupCacheBaseLockToken {
private:
  // Only constructible by GuestToHostMap
  friend struct GuestToHostMap;
  LookupCacheWriteLockToken(FEXCore::Utils::WritePriorityMutex::Mutex& Mutex)
    : Lock {Mutex} {}
  std::lock_guard<FEXCore::Utils::WritePriorityMutex::Mutex> Lock;
};

struct LookupCacheReadLockToken : public LookupCacheBaseLockToken {
private:
  // Only constructible by GuestToHostMap
  friend struct GuestToHostMap;
  LookupCacheReadLockToken(FEXCore::Utils::WritePriorityMutex::Mutex& Mutex)
    : Lock {Mutex} {}
  std::shared_lock<FEXCore::Utils::WritePriorityMutex::Mutex> Lock;
};

struct GuestToHostMap {
  FEXCore::Utils::WritePriorityMutex::Mutex Lock {};

  [[nodiscard]]
  LookupCacheWriteLockToken AcquireWriteLock() {
    return LookupCacheWriteLockToken {Lock};
  }

  [[nodiscard]]
  LookupCacheReadLockToken AcquireReadLock() {
    return LookupCacheReadLockToken {Lock};
  }

  struct BlockLinkTag {
    uint64_t GuestDestination;
    FEXCore::Context::ExitFunctionLinkData* HostLink;

    bool operator<(const BlockLinkTag& other) const {
      if (GuestDestination < other.GuestDestination) {
        return true;
      } else if (GuestDestination == other.GuestDestination) {
        return HostLink < other.HostLink;
      } else {
        return false;
      }
    }
  };

  // Use a monotonic buffer resource to allocate both the std::pmr::map and its members.
  // This allows us to quickly clear the block link map by clearing the monotonic allocator.
  // If we had allocated the block link map without the MBR, then clearing the map would require slowly
  // walking each block member and destructing objects.
  //
  // This makes `BlockLinks` look like a raw pointer that could memory leak, but since it is backed by the MBR, it won't.
  fextl::pmr::named_monotonic_page_buffer_resource BlockLinks_mbr;
  using BlockLinksMapType = std::pmr::map<BlockLinkTag, FEXCore::Context::BlockDelinkerFunc>;
  fextl::unique_ptr<std::pmr::polymorphic_allocator<std::byte>> BlockLinks_pma;
  BlockLinksMapType* BlockLinks;

  struct BlockEntry {
    uint64_t HostCode;
    fextl::vector<uint64_t> CodePages;
  };

  fextl::robin_map<uint64_t, BlockEntry> BlockList;

  fextl::map<uint64_t, fextl::vector<uint64_t>> CodePages;

  GuestToHostMap();

  // Adds to Guest -> Host code mapping
  const BlockEntry& AddBlockMapping(uint64_t Address, std::span<const uint64_t> CodePages, void* HostCode, const LookupCacheWriteLockToken&) {
    // This may replace an existing mapping
    // NOTE: Generally no previous entry should exist, however there is one exception:
    //       If the backend updates the active thread's CodeBuffer, the new associated LookupCache
    //       may already contain the block address. Since is comparatively rare, we'll just leak
    //       one of the two blocks in this case.
    return BlockList
      .insert_or_assign(Address, BlockEntry {(uintptr_t)HostCode, fextl::vector<uint64_t>(CodePages.begin(), CodePages.end())})
      .first->second;
  }

  bool HasCodePage(uint64_t Address, const LookupCacheReadLockToken&) const {
    auto It = CodePages.find(Address >> 12);
    return It != CodePages.end() && !It->second.empty();
  }

  const BlockEntry* FindBlock(uint64_t Address, const LookupCacheReadLockToken&) {
    auto HostCode = BlockList.find(Address);
    if (HostCode == BlockList.end()) {
      return nullptr;
    }
    return &HostCode->second;
  }

  bool Erase(uint64_t Address, const LookupCacheWriteLockToken&) {
    // Sever any links to this block
    auto lower = BlockLinks->lower_bound({Address, nullptr});
    auto upper = BlockLinks->upper_bound({Address, reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(UINTPTR_MAX)});
    for (auto it = lower; it != upper; it = BlockLinks->erase(it)) {
      it->second(it->first.HostLink);
    }

    // Remove from BlockList
    return BlockList.erase(Address) != 0;
  }

  bool InvalidateRange(uint64_t Start, uint64_t Length) {
    auto lk = AcquireWriteLock();

    auto lower = CodePages.lower_bound(Start >> 12);
    auto upper = CodePages.upper_bound((Start + Length - 1) >> 12);
    const bool HadEntries = lower != upper;

    for (auto it = lower; it != upper; it++) {
      for (const auto& Entry : it->second) {
        Erase(Entry, lk);
      }
    }
    CodePages.erase(lower, upper);
    return HadEntries;
  }

  void AddBlockLink(uint64_t GuestDestination, FEXCore::Context::ExitFunctionLinkData* HostLink,
                    const FEXCore::Context::BlockDelinkerFunc& delinker, const LookupCacheWriteLockToken&) {
    BlockLinks->insert({{GuestDestination, HostLink}, delinker});
  }

  bool AddBlockExecutableRange(const std::ranges::input_range auto& Addresses, uint64_t Start, uint64_t Length, const LookupCacheWriteLockToken&) {
    bool rv = false;

    for (auto CurrentPage = Start >> 12, EndPage = (Start + Length - 1) >> 12; CurrentPage <= EndPage; CurrentPage++) {
      auto& CodePage = CodePages[CurrentPage];
      rv |= CodePage.empty();
      CodePage.insert(CodePage.end(), Addresses.begin(), Addresses.end());
    }

    return rv;
  }

  void ClearCache(const LookupCacheWriteLockToken&);

  // Drops every block mapping, code-page record and block link of this (superseded) generation.
  // Every recorded link is severed first so that no block of this generation can reach another one
  // without going through the dispatcher. Requires the CodeInvalidationMutex to be held exclusively.
  void Retire(const LookupCacheWriteLockToken&);
};

class LookupCache {
public:
  struct LookupCacheEntry {
    uintptr_t HostCode;
    uintptr_t GuestCode;
  };

  static constexpr uint32_t L1_HASH_SHIFT = 4;

  // Mix bits [k+3:4] into [k-1:0] so 16-byte-aligned x86-64 function entrypoints
  // utilize all L1 slots instead of only every 16th slot, while remaining collision-free
  // within any naturally aligned 2^k-byte window and mask-independent for DynamicL1Cache.
  static constexpr uint64_t HashL1Index(uint64_t Address) {
    return Address ^ (Address >> L1_HASH_SHIFT);
  }

  LookupCache(FEXCore::Context::ContextImpl* CTX);
  ~LookupCache();

  // Swaps out the underlying GuestToHostMap and clears all associated caches.
  // This interface requires the previous CodeBuffer to be provided despite not using it. This ensures the shared write lock is still valid.
  void ChangeGuestToHostMapping([[maybe_unused]] CPU::CodeBuffer& Prev, GuestToHostMap& NewMap, const LookupCacheWriteLockToken& lk) {
    ClearThreadLocalCaches(lk);
    Shared = &NewMap;
  }

  uintptr_t FindBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
    // Try L1, no lock needed
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[HashL1Index(Address) & L1PointerMask];
    if (L1Entry.GuestCode == Address) {
      return L1Entry.HostCode;
    }

    // L2 and L3 need to be locked
    uintptr_t HostPtr {};
    {
      std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
        Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheReadLockTime : nullptr);
      auto lk = Shared->AcquireReadLock();
      LockTime.reset();

      if (!DisableL2Cache()) {
        // Try L2
        const auto PageIndex = (Address & (VirtualMemSize - 1)) >> 12;
        const auto PageOffset = Address & (0x0FFF);

        const auto Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
        auto LocalPagePointer = Pointers[PageIndex];

        // Do we a page pointer for this address?
        if (LocalPagePointer) {
          // Find there pointer for the address in the blocks
          auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);

          if (BlockPointers[PageOffset].GuestCode == Address) {
            L1Entry.GuestCode = Address;
            L1Entry.HostCode = BlockPointers[PageOffset].HostCode;
            HostPtr = L1Entry.HostCode;
          }
        }
      }

      if (!HostPtr) {
        // Try L3
        auto Entry = Shared->FindBlock(Address, lk);
        if (Entry) {
          CacheBlockMapping(Address, *Entry, false, lk);
          HostPtr = Entry->HostCode;
        }
      }
    }

    if (HostPtr && DynamicL1Cache()) {
      UpdateDynamicL1Stats(Thread, Address, HostPtr);
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedCacheMissCount, 1);

    return HostPtr;
  }

  void UpdateDynamicL1Stats(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddress, uint64_t HostCode) {
    // If host pointer was found in L2 or L3, then add it to the counter.
    // Keeping track not L1 misses, but specifically L2/L3 hits.
    ++L2L3CacheHits;

    // Only check the clock every SAMPLE_CHECK_STRIDE hits to keep L2/L3 lookups cheap.
    if ((L2L3CacheHits & (SAMPLE_CHECK_STRIDE - 1)) != 0) {
      return;
    }

    double AveragePerSecond {};
#ifdef ARCHITECTURE_arm64
    const uint64_t Freq = FEXCore::Utils::SpinWaitLock::CycleCounterFrequency;
    if (Freq == 0) [[unlikely]] {
      return;
    }

    const uint64_t CurrentTicks = ReadSampleCounter();
    const uint64_t ElapsedTicks = CurrentTicks - LastPeriodTicks;
    const uint64_t SamplePeriodTicks = Freq * SamplePeriodSeconds;
    if (ElapsedTicks < SamplePeriodTicks) {
      return;
    }

    // Scale in double to avoid 64-bit integer overflow in L2L3CacheHits * Freq.
    // ElapsedTicks >= SamplePeriodTicks >= Freq > 0 guarantees a positive divisor.
    AveragePerSecond = (static_cast<double>(L2L3CacheHits) * static_cast<double>(Freq)) / static_cast<double>(ElapsedTicks);
    LastPeriodTicks = CurrentTicks;
#else
    const auto CurrentTime = std::chrono::steady_clock::now();
    const auto Period = CurrentTime - LastPeriod;
    if (Period < SamplePeriod) {
      return;
    }

    const auto ElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(Period).count();
    AveragePerSecond = static_cast<double>(L2L3CacheHits) / static_cast<double>(ElapsedMs) * 1000.0;
    LastPeriod = CurrentTime;
#endif

    // If larger than the sample period then check if we need to increase L1 cache size.
    if (AveragePerSecond >= DynamicL1CacheIncreaseCountHeuristic()) {
      if (CurrentL1Entries < MAX_L1_ENTRIES) {
        // Entries whose address has the new mask bit set would be unreachable by InvalidateCache
        FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(L1Pointer), CurrentL1Entries * sizeof(LookupCacheEntry), false);

        CurrentL1Entries <<= 1;
        L1PointerMask = CurrentL1Entries - 1;

        // Update the thread's L1 pointer mask to increase how much cache it uses.
        // Since we're in C-code, this is safe to update here.
        Thread->CurrentFrame->State.L1Mask = GetScaledL1PointerMask();

        // If L1 was just grown and cleared, re-insert our cached entry.
        AddL1Entry(GuestAddress, HostCode);
      }
    } else if (AveragePerSecond < DynamicL1CacheDecreaseCountHeuristic()) {
      if (CurrentL1Entries > MIN_L1_ENTRIES) {
        CurrentL1Entries >>= 1;
        L1PointerMask = CurrentL1Entries - 1;

        // Madvise the entries that we are dropping. Gives the memory back to the OS.
        LookupCacheEntry* FirstZeroL1Entry = &reinterpret_cast<LookupCacheEntry*>(L1Pointer)[CurrentL1Entries];
        size_t ZeroMemorySize = (MAX_L1_ENTRIES - CurrentL1Entries) * sizeof(LookupCacheEntry);
        FEXCore::Allocator::VirtualDontNeed(FirstZeroL1Entry, ZeroMemorySize, false);

        // Update the thread's L1 pointer mask to decrease how much cache it uses.
        // Since we're in C-code, this is safe to update here.
        Thread->CurrentFrame->State.L1Mask = GetScaledL1PointerMask();
      }
    }

    L2L3CacheHits = 0;
  }

  GuestToHostMap* Shared = nullptr;

  // Whether a block was compiled from the guest page containing Address
  bool HasCodePage(uint64_t Address) {
    auto lk = Shared->AcquireReadLock();
    return Shared->HasCodePage(Address, lk);
  }

  // Appends a list of Block {Address} to CodePages [Start, Start + Length)
  // Returns true if new pages are marked as containing code
  bool AddBlockExecutableRange(FEXCore::Core::InternalThreadState* Thread, auto& Addresses, uint64_t Start, uint64_t Length) {
    std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
      Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheWriteLockTime : nullptr);
    auto lk = Shared->AcquireWriteLock();
    LockTime.reset();

    return Shared->AddBlockExecutableRange(Addresses, Start, Length, lk);
  }

  // Adds to Guest -> Host code mapping
  void AddBlockMapping(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, std::span<const uint64_t> CodePages, void* HostCode) {
    std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
      Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheWriteLockTime : nullptr);
    auto lk = Shared->AcquireWriteLock();
    LockTime.reset();

    const auto& Entry = Shared->AddBlockMapping(Address, CodePages, HostCode, lk);

    // There is no need to update L1 or L2, they will get updated on first lookup
    // However, adding to L1 here increases performance
    CacheBlockMapping(Address, Entry, true, lk);
  }

  // Invalidates L1/L2 for a given guest block
  void InvalidateCache(uint64_t Address, const LookupCacheWriteLockToken& lk) {
    // Do L1
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[HashL1Index(Address) & L1PointerMask];
    if (L1Entry.GuestCode == Address) {
      L1Entry.GuestCode = 0;
      // Leave L1Entry.HostCode as is, so that concurrent lookups won't read a null pointer
      // This is a soft guarantee for cross thread invalidation, as atomics are not used
      // and it hasn't been thoroughly tested
    }

    if (!DisableL2Cache()) {
      // Do full map
      Address = Address & (VirtualMemSize - 1);
      uint64_t PageOffset = Address & (0x0FFF);
      Address >>= 12;

      uintptr_t* Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
      uint64_t LocalPagePointer = Pointers[Address];
      if (!LocalPagePointer) {
        // Page for this code didn't even exist, nothing to do
        return;
      }

      // Page exists, just set the offset to zero
      auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);
      BlockPointers[PageOffset].GuestCode = 0;
      BlockPointers[PageOffset].HostCode = 0;
    }
  }

  // Invalidates all L1/L2 entries for all guest block that intersect the given range
  bool InvalidateCacheRange(uint64_t Start, uint64_t Length) {
    auto lk = Shared->AcquireWriteLock();

    auto lower = CachedCodePages.lower_bound(Start >> 12);
    auto upper = CachedCodePages.upper_bound((Start + Length - 1) >> 12);

    for (auto it = lower; it != upper; it++) {
      for (const auto& Entry : it->second) {
        InvalidateCache(Entry, lk);
      }
    }
    bool ret = upper != lower;
    CachedCodePages.erase(lower, upper);
    return ret;
  }

  void AddBlockLink(uint64_t GuestDestination, FEXCore::Context::ExitFunctionLinkData* HostLink,
                    const FEXCore::Context::BlockDelinkerFunc& delinker, const LookupCacheWriteLockToken& lk) {
    Shared->AddBlockLink(GuestDestination, HostLink, delinker, lk);
  }

  // Invalidates every L1/L2 entry this thread has ever fetched, entry by entry.
  // Safe to call from another thread (cross-thread invalidation rules of ::InvalidateCache apply):
  // the owning thread may be executing JIT code concurrently and only ever observes a cleared guest
  // address, never a dangling host pointer. Requires the CodeInvalidationMutex to be held exclusively.
  void InvalidateAllCachedCode() {
    auto lk = Shared->AcquireWriteLock();
    for (auto& [Page, Entries] : CachedCodePages) {
      for (const auto& Entry : Entries) {
        InvalidateCache(Entry, lk);
      }
    }
    CachedCodePages.clear();
  }

  void ClearCache(const LookupCacheWriteLockToken&);
  void ClearL2Cache(const LookupCacheBaseLockToken&);
  void ClearThreadLocalCaches(const LookupCacheWriteLockToken&);

  uintptr_t GetL1Pointer() const {
    return L1Pointer;
  }
  uintptr_t GetScaledL1PointerMask() const {
    return L1PointerMask << FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry));
  }
  uintptr_t GetPagePointer() const {
    return PagePointer;
  }
  uintptr_t GetVirtualMemorySize() const {
    return VirtualMemSize;
  }

  // This needs to be taken before reads or writes to L2, L3, CodePages,
  // and before writes to L1. Concurrent access from a thread that this LookupCache doesn't belong to
  // may only happen during cross thread invalidation (::Erase).
  // All other operations must be done from the owning thread.
  // Some care is taken so that L1 lookups can be done without locks, and even tearing is unlikely to lead to a crash.
  // This approach has not been fully vetted yet.
  // Also note that L1 lookups might be inlined in the JIT Dispatcher and/or block ends.
  auto AcquireWriteLock() {
    return Shared->AcquireWriteLock();
  }

private:
  void AddL1Entry(uint64_t GuestAddress, uint64_t HostCode) {
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[HashL1Index(GuestAddress) & L1PointerMask];
    L1Entry.GuestCode = GuestAddress;
    L1Entry.HostCode = HostCode;
  }

  void CacheBlockMapping(uint64_t Address, const GuestToHostMap::BlockEntry& Entry, bool L1Only, const LookupCacheBaseLockToken& lk) {
    for (const auto& CodePage : Entry.CodePages) {
      CachedCodePages[CodePage >> 12].insert(Address);
    }

    // Do L1
    AddL1Entry(Address, Entry.HostCode);

    if (!DisableL2Cache() && !L1Only) {
      // Do ful map
      auto FullAddress = Address;
      Address = Address & (VirtualMemSize - 1);

      uint64_t PageOffset = Address & (0x0FFF);
      Address >>= 12;

      uintptr_t* Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
      uint64_t LocalPagePointer = Pointers[Address];
      if (!LocalPagePointer) {
        // We don't have a page pointer for this address
        // Allocate one now if we can
        uintptr_t NewPageBacking = AllocateBackingForPage();
        if (!NewPageBacking) {
          // Couldn't allocate, clear L2 and retry
          ClearL2Cache(lk);
          CacheBlockMapping(FullAddress, Entry, false, lk);
          return;
        }
        Pointers[Address] = NewPageBacking;
        LocalPagePointer = NewPageBacking;
      }

      // Add the new pointer to the page block
      auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);

      // This silently replaces existing mappings
      BlockPointers[PageOffset].GuestCode = FullAddress;
      BlockPointers[PageOffset].HostCode = Entry.HostCode;
    }
  }

  uintptr_t AllocateBackingForPage() {
    uintptr_t NewBase = AllocateOffset;
    uintptr_t NewEnd = AllocateOffset + SIZE_PER_PAGE;

    if (NewEnd >= CODE_SIZE) {
      // We ran out of block backing space. Need to clear the block cache and tell the JIT cores to clear their caches as well
      // Tell whatever is calling this that it needs to do it.
      return 0;
    }

    AllocateOffset = NewEnd;
    return PageMemory + NewBase;
  }

  // Maps from a page index to all blocks in the page that have at some point been fetched into L1/L2
  fextl::map<uint64_t, fextl::robin_set<uint64_t>> CachedCodePages;

  uintptr_t PagePointer;
  uintptr_t PageMemory;
  uintptr_t L1Pointer;
  uintptr_t L1PointerMask;

  size_t TotalCacheSize;

  // Start with 8k entries in L1 to give 128KB of L1 cache to each thread.
  // Max out at 1 million entries to give each thread 16MB of L1 cache maximum.
  constexpr static size_t MIN_L1_ENTRIES = 8 * 1024;        // Must be a power of 2
  constexpr static size_t MAX_L1_ENTRIES = 1 * 1024 * 1024; // Must be a power of 2

  constexpr static size_t CODE_SIZE = 128 * 1024 * 1024;
  constexpr static size_t SIZE_PER_PAGE = FEXCore::Utils::FEX_PAGE_SIZE * sizeof(LookupCacheEntry);
  constexpr static size_t MAX_L1_SIZE = MAX_L1_ENTRIES * sizeof(LookupCacheEntry);

  size_t AllocateOffset {};

  FEXCore::Context::ContextImpl* ctx;
  uint64_t VirtualMemSize {};

  size_t CurrentL1Entries = MIN_L1_ENTRIES;
  uint64_t L2L3CacheHits {};
  constexpr static uint64_t SAMPLE_CHECK_STRIDE = 32; // Must be a power of 2
  static_assert((SAMPLE_CHECK_STRIDE & (SAMPLE_CHECK_STRIDE - 1)) == 0, "SAMPLE_CHECK_STRIDE must be a power of 2");
#ifdef ARCHITECTURE_arm64
  static inline uint64_t ReadSampleCounter() {
    uint64_t Result {};
    // An unsynchronized CNTVCT_EL0 read avoids an ISB pipeline flush; a few cycles of
    // reordering jitter is negligible over a 1-second sampling window.
    __asm volatile("mrs %[Res], CNTVCT_EL0;" : [Res] "=r"(Result));
    return Result;
  }

  uint64_t LastPeriodTicks {};
  constexpr static uint64_t SamplePeriodSeconds {1};
#else
  std::chrono::steady_clock::time_point LastPeriod {};
  constexpr static std::chrono::seconds SamplePeriod {1};
#endif
  FEX_CONFIG_OPT(DynamicL1CacheIncreaseCountHeuristic, DYNAMICL1CACHEINCREASECOUNTHEURISTIC);
  FEX_CONFIG_OPT(DynamicL1CacheDecreaseCountHeuristic, DYNAMICL1CACHEDECREASECOUNTHEURISTIC);

  FEX_CONFIG_OPT(DynamicL1Cache, DYNAMICL1CACHE);
  FEX_CONFIG_OPT(DisableL2Cache, DISABLEL2CACHE);
};
} // namespace FEXCore
