// Multiblock translation units that end at, or are entered at, code another unit also covers.
// The results are the same whatever the units look like; these cases make the JIT take those paths.
#include <catch2/catch_test_macros.hpp>

extern "C" int farft_func(int take_cold);
extern "C" int stop_target(int x);
extern "C" int stop_caller(int x, int sel);

__asm__(R"(
.text

// A conditional branch to a cold block placed beyond the multiblock range (16 KiB) that jumps back to the instruction after the
// branch. The fall-through reads PF, which the cold block sets differently from the hot path.
.globl farft_func
farft_func:
  xor eax, eax
  mov ecx, 1
  test edi, edi
  jnz farft_cold
farft_back:
  setp al
  shl eax, 8
  add eax, ecx
  ret
.skip 20480, 0xcc
farft_cold:
  mov ecx, 2
  mov edx, 1
  test edx, edx
  jmp farft_back

// A branch, in range, to code that is already translated on its own.
.globl stop_caller
stop_caller:
  test esi, esi
  jz stop_target
  lea eax, [rdi + 5]
  ret
.globl stop_target
stop_target:
  lea eax, [rdi + 100]
  ret

)");

TEST_CASE("Multiblock: cold path jumping back after a far branch") {
  // Hot path first, so the unit with the fall-through exists before the cold block jumps back to it.
  // Hot: test of 0 sets PF; cold: test of 1 clears it.
  CHECK(farft_func(0) == 0x101);
  CHECK(farft_func(1) == 0x002);
  CHECK(farft_func(0) == 0x101);
  CHECK(farft_func(1) == 0x002);
}

TEST_CASE("Multiblock: branch to code that is already translated") {
  // Translate the target on its own first, then a unit that branches to it.
  CHECK(stop_target(1) == 101);
  CHECK(stop_caller(7, 0) == 107);
  CHECK(stop_caller(7, 1) == 12);
  CHECK(stop_caller(-3, 0) == 97);
}
