// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/ThreadPoolAllocator.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <cstdlib>
#include <utility>

namespace {
class TestPooledAllocator final : public FEXCore::Utils::IntrusivePooledAllocator {
public:
  ~TestPooledAllocator() {
    FreeAllBuffers();
  }
  void* Alloc(size_t Size) override {
    return std::aligned_alloc(4096, (Size + 4095) & ~size_t(4095));
  }
  void Free(void* Ptr, size_t) override {
    std::free(Ptr);
  }
};

struct RAHarness {
  TestPooledAllocator Allocator;
  FEXCore::IR::IREmitter Emit;
  FEXCore::IR::IROp_IRHeader* Header {};
  FEXCore::IR::Ref FirstBlock {};

  RAHarness()
    : Emit(Allocator, true) {
    Emit.ReownOrClaimBuffer();
    auto HeaderPair = Emit._IRHeader(Emit.Invalid(), 0x1000, 0, 1, 0, 0);
    Header = HeaderPair.first;
    FirstBlock = Emit.CreateCodeNode(true, 0);
    HeaderPair.first->Blocks = Emit.WrapNode(FirstBlock);
    Emit.SetCurrentCodeBlock(FirstBlock);
  }

  ~RAHarness() {
    Emit.DelayedDisownBuffer();
  }

  FEXCore::IR::Ref AppendBlock() {
    auto Block = Emit.CreateNewCodeBlockAtEnd();
    Emit.SetCurrentCodeBlock(Block);
    return Block;
  }

  // Emit `LiveCount` values in the given class+size that exceed the available
  // physical registers, then consume them in FIFO order so earlier values spill
  // and later get filled and killed.
  void EmitPressureWave(FEXCore::IR::RegClass Class, FEXCore::IR::OpSize Size, size_t LiveCount, uint32_t BaseOffset = 0x2000) {
    fextl::vector<FEXCore::IR::Ref> Vals;
    Vals.reserve(LiveCount);
    for (size_t i = 0; i < LiveCount; ++i) {
      Vals.push_back(Emit._LoadContext(Size, Class, BaseOffset + static_cast<uint32_t>(i * 32)));
    }
    for (size_t i = 0; i < LiveCount; ++i) {
      Emit._StoreContext(Size, Class, Vals[i], BaseOffset + static_cast<uint32_t>(i * 32));
    }
  }

  void RunRA(uint32_t GPRs = 2, uint32_t FPRs = 2) {
    auto Pass = FEXCore::IR::CreateRegisterAllocationPass(nullptr);
    auto* RAPass = static_cast<FEXCore::IR::RegisterAllocationPass*>(Pass.get());
    RAPass->AddRegisters(FEXCore::IR::RegClass::GPR, GPRs);
    RAPass->AddRegisters(FEXCore::IR::RegClass::GPRFixed, 16);
    RAPass->AddRegisters(FEXCore::IR::RegClass::FPR, FPRs);
    RAPass->AddRegisters(FEXCore::IR::RegClass::FPRFixed, 16);
    RAPass->SetNumPairRegs(0);
    RAPass->Run(&Emit);
  }
};
} // namespace

TEST_CASE("RegisterAllocationPass - Small frames avoid spill slot reuse") {
  RAHarness H;
  // 2 GPR regs available, 5 live values -> 3 spills in block 0.
  H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i64Bit, 5);
  H.AppendBlock();
  // 3 more spills in block 1 -> total 6 < MinSpillSlotsBeforeReuse (8).
  H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i64Bit, 5);

  H.RunRA(2, 2);

  auto IR = H.Emit.ViewIR();
  REQUIRE(IR.GetHeader()->SpillSlots == 6);
}

TEST_CASE("RegisterAllocationPass - Spill slots are partitioned by RegClass and OpSize") {
  RAHarness H;
  // Exceed MinSpillSlotsBeforeReuse (8) and exercise mixed classes and widths
  // across multiple blocks.
  for (int b = 0; b < 4; ++b) {
    if (b > 0) {
      H.AppendBlock();
    }
    H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i32Bit, 4);
    H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i64Bit, 4);
    H.EmitPressureWave(FEXCore::IR::RegClass::FPR, FEXCore::IR::OpSize::i64Bit, 4);
    H.EmitPressureWave(FEXCore::IR::RegClass::FPR, FEXCore::IR::OpSize::i128Bit, 4);
  }

  H.RunRA(2, 2);

  auto IR = H.Emit.ViewIR();
  // 4 blocks * 4 types * 2 spills = 32 spills total; pooling keeps frame bounded.
  REQUIRE(IR.GetHeader()->SpillSlots < 32);
  REQUIRE(IR.GetHeader()->SpillSlots >= 8);

  fextl::map<uint32_t, std::pair<FEXCore::IR::RegClass, FEXCore::IR::OpSize>> SlotType;
  size_t SpillCount = 0;
  size_t FillCount = 0;

  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (IROp->Op == FEXCore::IR::OP_SPILLREGISTER) {
        const auto* Op = IROp->C<FEXCore::IR::IROp_SpillRegister>();
        const auto Key = std::make_pair(Op->Class, IROp->Size);
        auto [It, Inserted] = SlotType.emplace(Op->Slot, Key);
        REQUIRE((Inserted || It->second == Key));
        ++SpillCount;
      } else if (IROp->Op == FEXCore::IR::OP_FILLREGISTER) {
        const auto* Op = IROp->C<FEXCore::IR::IROp_FillRegister>();
        const auto Key = std::make_pair(Op->Class, IROp->Size);
        auto It = SlotType.find(Op->Slot);
        REQUIRE(It != SlotType.end());
        REQUIRE(It->second == Key);
        ++FillCount;
      }
    }
  }

  REQUIRE(SpillCount == 32);
  REQUIRE(FillCount == 32);
}

TEST_CASE("RegisterAllocationPass - FIFO reuse caps large multiblock frames without live collisions") {
  RAHarness H;
  // 20 blocks each spilling 3 GPR i64Bit values = 60 spills total.
  for (int b = 0; b < 20; ++b) {
    if (b > 0) {
      H.AppendBlock();
    }
    H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i64Bit, 5);
  }

  H.RunRA(2, 2);

  auto IR = H.Emit.ViewIR();
  // Threshold is 8 slots; once 8 slots exist and >= 2 are queued, spills cycle
  // through slots 0..7 in strict FIFO order without allocating more.
  REQUIRE(IR.GetHeader()->SpillSlots == 8);

  fextl::vector<uint32_t> SpillOrder;
  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (IROp->Op == FEXCore::IR::OP_SPILLREGISTER) {
        SpillOrder.push_back(IROp->C<FEXCore::IR::IROp_SpillRegister>()->Slot);
      }
    }
  }

  REQUIRE(SpillOrder.size() == 60);
  for (size_t i = 0; i < SpillOrder.size(); ++i) {
    REQUIRE(SpillOrder[i] == (i % 8));
  }
}

TEST_CASE("RegisterAllocationPass - Dead defs, >64 threshold, and repeated runs stay isolated") {
  RAHarness H;
  // Block 0: 65 FPR i64Bit values where 63 are dead defs (never filled/killed
  // in Block 0), exercising end-of-block release of Slots 0..62.
  fextl::vector<FEXCore::IR::Ref> DeadVals;
  for (int i = 0; i < 65; ++i) {
    DeadVals.push_back(H.Emit._LoadContext(FEXCore::IR::OpSize::i64Bit, FEXCore::IR::RegClass::FPR, 0x2000 + i * 32));
  }
  H.Emit._StoreContext(FEXCore::IR::OpSize::i64Bit, FEXCore::IR::RegClass::FPR, DeadVals[63], 0x3000);
  H.Emit._StoreContext(FEXCore::IR::OpSize::i64Bit, FEXCore::IR::RegClass::FPR, DeadVals[64], 0x3020);

  // Block 1: 1 GPR i32Bit spill allocates Slot 63 (TotalSlots reaches 64),
  // then kills it so FreeSpillSlots[GPR, i32Bit] holds exactly 1 free slot.
  auto Block1 = H.AppendBlock();
  H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i32Bit, 3);

  // Block 2: 1 GPR i32Bit spill at TotalSlots == 64 with only 1 compatible free
  // slot must reuse Slot 63 (would allocate Slot 64 under the >= 2 rule alone).
  auto Block2 = H.AppendBlock();
  H.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i32Bit, 3);

  // Block 3: subsequent FPR i64Bit spills reuse the dead-def slots released at
  // the end of Block 0 without growing the frame.
  H.AppendBlock();
  H.EmitPressureWave(FEXCore::IR::RegClass::FPR, FEXCore::IR::OpSize::i64Bit, 10);

  auto Pass = FEXCore::IR::CreateRegisterAllocationPass(nullptr);
  auto* RAPass = static_cast<FEXCore::IR::RegisterAllocationPass*>(Pass.get());
  RAPass->AddRegisters(FEXCore::IR::RegClass::GPR, 2);
  RAPass->AddRegisters(FEXCore::IR::RegClass::GPRFixed, 16);
  RAPass->AddRegisters(FEXCore::IR::RegClass::FPR, 2);
  RAPass->AddRegisters(FEXCore::IR::RegClass::FPRFixed, 16);
  RAPass->SetNumPairRegs(0);
  RAPass->Run(&H.Emit);

  auto IR = H.Emit.ViewIR();
  REQUIRE(IR.GetHeader()->SpillSlots == 64);

  auto FindSingleSpillSlot = [&](FEXCore::IR::Ref BlockNode) {
    fextl::vector<uint32_t> Slots;
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (IROp->Op == FEXCore::IR::OP_SPILLREGISTER) {
        Slots.push_back(IROp->C<FEXCore::IR::IROp_SpillRegister>()->Slot);
      }
    }
    REQUIRE(Slots.size() == 1);
    return Slots[0];
  };
  REQUIRE(FindSingleSpillSlot(Block1) == 63);
  REQUIRE(FindSingleSpillSlot(Block2) == 63);

  // Reuse the exact same pass instance on a fresh IR to ensure no state leaks across Run().
  RAHarness H2;
  H2.EmitPressureWave(FEXCore::IR::RegClass::GPR, FEXCore::IR::OpSize::i64Bit, 5);
  RAPass->Run(&H2.Emit);
  REQUIRE(H2.Emit.ViewIR().GetHeader()->SpillSlots == 3);
}
