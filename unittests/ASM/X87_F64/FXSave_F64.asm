%ifdef CONFIG
{
  "RegData": {
    "R8": "0x8d5",
    "R9": "0x881",
    "R10": "0",
    "XMM0": ["0", "0x8000"],
    "XMM1": ["0", "0x8000"],
    "XMM2": ["0", "0"],
    "XMM3": ["0x8000000000000000", "0x3fff"],
    "XMM4": ["0", "0x8000"],
    "XMM5": ["0xc000000000000000", "0xbfff"],
    "XMM6": ["0x8000000000000000", "0x3bcd"],
    "XMM7": ["0x8000000000000000", "0x7fff"],
    "XMM8": ["0", "0"],
    "XMM9": ["0x1122334455667788", "0x99aabbccddeeff00"],
    "XMM10": ["0", "0"]
  },
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif

; Verify FXSAVE/FXRSTOR under X87ReducedPrecision:
; 1. All-+0.0 fast path overwrites buffer, preserves EFLAGS, and saves SSE state.
; 2. -0.0 slot preserves {0, 0x8000} and EFLAGS on slow path and across FXRSTOR.
; 3. Freed non-zero slot (FTW == 0, ST(7) == 1.0) does not take all-zero fast path.
; 4. F32/F64 -> ExtF80 conversion for -0.0, normal, min subnormal, and +Inf.

mov rsp, 0xe0000f00
mov rbp, 0xe0000000
mov r12, 0xe0000200
mov r13, 0xe0000400

; --- Case 1: all-+0.0 fast path + EFLAGS + SSE save ---
fxrstor64 [rel .zero_fxstate]
movups xmm15, [rel .sse_sentinel]
movups xmm14, [rel .x87_mask]

mov rax, 0xaaaaaaaaaaaaaaaa
mov rcx, 16
lea rdi, [rbp + 32]
.fill1:
mov [rdi], rax
add rdi, 8
dec rcx
jnz .fill1

push 0x8d7
popfq
fxsave64 [rbp]
pushfq
pop r8
and r8, 0x8d5

pxor xmm8, xmm8
%assign i 0
%rep 8
movups xmm11, [rbp + 32 + i * 16]
pand xmm11, xmm14
por xmm8, xmm11
%assign i i+1
%endrep
movups [r13 + 0], xmm8

; Check SSE register saved after SaveX87State block split
movups xmm9, [rbp + 160 + 15 * 16]
movups [r13 + 16], xmm9

; --- Case 2: -0.0 preservation + EFLAGS on slow path + FXRSTOR round-trip ---
fxrstor64 [rel .zero_fxstate]
movups xmm14, [rel .x87_mask]
fldz
fchs

mov rax, 0x5555555555555555
mov rcx, 16
lea rdi, [rbp + 32]
.fill2:
mov [rdi], rax
add rdi, 8
dec rcx
jnz .fill2

push 0x883
popfq
fxsave64 [rbp]
pushfq
pop r9
and r9, 0x8d5

movups xmm0, [rbp + 32]
pand xmm0, xmm14
movups [r13 + 32], xmm0

pxor xmm10, xmm10
%assign i 1
%rep 7
movups xmm11, [rbp + 32 + i * 16]
pand xmm11, xmm14
por xmm10, xmm11
%assign i i+1
%endrep
movups [r13 + 48], xmm10

; Dirty reserved bytes [10..15] of ST(1) (+0.0) and round-trip through FXRSTOR
mov word [rbp + 32 + 16 + 10], 0xdead
mov dword [rbp + 32 + 16 + 12], 0xcafebeef
fxrstor64 [rel .zero_fxstate]
fxrstor64 [rbp]
fxsave64 [r12]

movups xmm14, [rel .x87_mask]
movups xmm1, [r12 + 32]
pand xmm1, xmm14
movups [r13 + 64], xmm1
movups xmm2, [r12 + 48]
pand xmm2, xmm14
movups [r13 + 80], xmm2

; --- Case 3: freed non-zero slot (FTW == 0, mm[7] == 1.0) ---
fxrstor64 [rel .seed_freed_st7]
movups xmm14, [rel .x87_mask]

mov rax, 0xaaaaaaaaaaaaaaaa
mov rcx, 16
lea rdi, [rbp + 32]
.fill3:
mov [rdi], rax
add rdi, 8
dec rcx
jnz .fill3

fxsave64 [rbp]
movzx r10, byte [rbp + 4]
movups xmm3, [rbp + 32 + 7 * 16]
pand xmm3, xmm14
movups [r13 + 96], xmm3

; --- Case 4: F32/F64 -> ExtF80 edge values ---
fxrstor64 [rel .zero_fxstate]
movups xmm14, [rel .x87_mask]
fld qword [rel .d_pinf]
fld qword [rel .d_min_denorm]
fld dword [rel .f_neg1p5]
fld dword [rel .f_nzero]
fxsave64 [rbp]

movups xmm4, [rbp + 32 + 0 * 16]
pand xmm4, xmm14
movups xmm5, [rbp + 32 + 1 * 16]
pand xmm5, xmm14
movups xmm6, [rbp + 32 + 2 * 16]
pand xmm6, xmm14
movups xmm7, [rbp + 32 + 3 * 16]
pand xmm7, xmm14

; Reload saved Case 1-3 vectors unaffected by subsequent fxrstor64 calls
movups xmm8, [r13 + 0]
movups xmm9, [r13 + 16]
movups xmm0, [r13 + 32]
movups xmm10, [r13 + 48]
movups xmm1, [r13 + 64]
movups xmm2, [r13 + 80]
movups xmm3, [r13 + 96]

hlt

align 16
.x87_mask:
dq 0xffff_ffff_ffff_ffff, 0xffff
.sse_sentinel:
dq 0x1122334455667788, 0x99aabbccddeeff00
.d_pinf:
dq 0x7ff0000000000000
.d_min_denorm:
dq 0x0000000000000001
.f_neg1p5:
dd 0xbfc00000
.f_nzero:
dd 0x80000000

align 64
.zero_fxstate:
dw 0x037f        ; FCW
dw 0             ; FSW
db 0             ; FTW (all empty)
db 0
dw 0             ; FOP
dq 0             ; FIP
dq 0             ; FDP
dd 0x1f80        ; MXCSR
dd 0             ; MXCSR_MASK
times 480 db 0   ; ST0..ST7 + XMM0..XMM15 + reserved = 0

align 64
.seed_freed_st7:
dw 0x037f        ; FCW
dw 0             ; FSW (TOP == 0)
db 0             ; FTW == 0 (all empty)
db 0
dw 0             ; FOP
dq 0             ; FIP
dq 0             ; FDP
dd 0x1f80        ; MXCSR
dd 0             ; MXCSR_MASK
times 7*16 db 0  ; ST0..ST6 = +0.0
dq 0x8000000000000000 ; ST7 significand (1.0)
dw 0x3fff             ; ST7 sign_exp (1.0)
times 6 db 0          ; ST7 reserved
times 352 db 0        ; XMM0..XMM15 + reserved = 0
