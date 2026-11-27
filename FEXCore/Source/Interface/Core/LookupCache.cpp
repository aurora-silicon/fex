// SPDX-License-Identifier: MIT
/*
$info$
tags: glue|block-database
desc: Stores information about blocks, and provides C++ implementations to lookup the blocks
$end_info$
*/

#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"

namespace FEXCore {
GuestToHostMap::GuestToHostMap()
  : BlockLinks_mbr {"FEXMem_BlockLinks"} {
  BlockLinks_pma = fextl::make_unique<std::pmr::polymorphic_allocator<std::byte>>(&BlockLinks_mbr);
  // Setup our PMR map.
  BlockLinks = BlockLinks_pma->new_object<BlockLinksMapType>();
}

LookupCache::LookupCache(FEXCore::Context::ContextImpl* CTX)
  : ctx {CTX} {

  TotalCacheSize = ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE + MAX_L1_SIZE;

  // Block cache ends up looking like this
  // PageMemoryMap[VirtualMemoryRegion >> 12]
  //       |
  //       v
  // PageMemory[Memory & (VIRTUAL_PAGE_SIZE - 1)]
  //       |
  //       v
  // Pointer to Code
  //
  // Allocate a region of memory that we can use to back our block pointers
  // We need one pointer per page of virtual memory
  // At 64GB of virtual memory this will allocate 128MB of virtual memory space
  PagePointer = reinterpret_cast<uintptr_t>(FEXCore::Allocator::VirtualAlloc(TotalCacheSize, false, false));
  LOGMAN_THROW_A_FMT(PagePointer != -1ULL, "Failed to allocate PagePointer");

  // Disable THP on the Lookup cache.
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<const void*>(PagePointer), TotalCacheSize, FEXCore::Allocator::THPControl::Disable);

  FEXCore::Allocator::VirtualName("FEXMem_Lookup", reinterpret_cast<void*>(PagePointer),
                                  ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE);
  CTX->SyscallHandler->MarkOvercommitRange(PagePointer, TotalCacheSize);

  // Allocate our memory backing our pages
  // We need 32KB per guest page (One pointer per byte)
  // XXX: We can drop down to 16KB if we store 4byte offsets from the code base
  // We currently limit to 128MB of real memory for caching for the total cache size.
  // Can end up being inefficient if we compile a small number of blocks per page
  PageMemory = PagePointer + ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8;

  // L1 Cache
  L1Pointer = PageMemory + CODE_SIZE;
  FEXCore::Allocator::VirtualName("FEXMem_Lookup_L1", reinterpret_cast<void*>(L1Pointer), MAX_L1_SIZE);

  VirtualMemSize = ctx->Config.VirtualMemSize;

  if (DynamicL1Cache()) {
    // Start at minimum size when dynamic.
    L1PointerMask = MIN_L1_SETS - 1;
  } else {
    // Start at maximum instead.
    L1PointerMask = MAX_L1_SETS - 1;
  }

#ifdef ARCHITECTURE_arm64
  LastPeriodTicks = ReadSampleCounter();
#else
  LastPeriod = std::chrono::steady_clock::now();
#endif
}

LookupCache::~LookupCache() {
  FEXCore::Allocator::VirtualFree(reinterpret_cast<void*>(PagePointer), TotalCacheSize);
  ctx->SyscallHandler->UnmarkOvercommitRange(PagePointer, TotalCacheSize);

  // No need to free BlockLinks map.
  // These will get freed when their memory allocators are deallocated.
}

void LookupCache::ClearL2Cache(const FEXCore::LookupCacheBaseLockToken& lk) {
  // Clear out the page memory
  // PagePointer and PageMemory are sequential with each other. Clear both at once.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer),
                                      ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE, false);
  AllocateOffset = 0;
}

void LookupCache::UpdateDynamicL1Stats(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddress, uint64_t HostCode) {
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
      L1PointerMask = (CurrentL1Entries / L1_WAYS) - 1;

      // Update the thread's L1 pointer mask to increase how much cache it uses.
      // Since we're in C-code, this is safe to update here.
      Thread->CurrentFrame->State.L1Mask = GetScaledL1PointerMask();

      // If L1 was just grown and cleared, re-insert our cached entry.
      AddL1Entry(GuestAddress, HostCode);
    }
  } else if (AveragePerSecond < DynamicL1CacheDecreaseCountHeuristic()) {
    if (CurrentL1Entries > MIN_L1_ENTRIES) {
      CurrentL1Entries >>= 1;
      L1PointerMask = (CurrentL1Entries / L1_WAYS) - 1;

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

void LookupCache::ClearThreadLocalCaches(const LookupCacheWriteLockToken&) {
  // TODO: Preserve code cache entries?
  // Clear L1 and L2 by clearing the full cache.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer), TotalCacheSize, false);

  // TODO: Rename this member to avoid confusion with code caching
  CachedCodePages.clear();
}

void LookupCache::ClearCache(const LookupCacheWriteLockToken& lk) {
  // Clear L1 and L2 by clearing the full cache.
  ClearThreadLocalCaches(lk);
  Shared->ClearCache(lk);
}

void GuestToHostMap::ClearCache(const LookupCacheWriteLockToken&) {
  // Allocate a new pointer from the BlockLinks pma again.
  BlockLinks = BlockLinks_pma->new_object<BlockLinksMapType>();
  // All code is gone, clear the block list
  BlockList.clear();
}

void GuestToHostMap::Retire(const LookupCacheWriteLockToken&) {
  // Sever every recorded link so that each block exit of this generation returns to the dispatcher.
  // This is the same patching that ::Erase performs on SMC invalidation, applied to all links at once.
  for (auto& [Tag, Delinker] : *BlockLinks) {
    Delinker(Tag.HostLink);
  }

  // The map and all of its nodes live in the monotonic arena. Nothing references them anymore,
  // so the arena can be handed back to the OS right away instead of waiting for the final owner.
  BlockLinks_mbr.release();
  BlockLinks = BlockLinks_pma->new_object<BlockLinksMapType>();

  // No block of this generation may be found through L3 anymore.
  BlockList.clear();
  CodePages.clear();
}

} // namespace FEXCore
