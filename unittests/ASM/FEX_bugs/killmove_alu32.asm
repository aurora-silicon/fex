%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0",
    "RBX": "0x45",
    "RBP": "0xfffffffe",
    "RDX": "0x881",
    "RSI": "0xa0a0a0a0",
    "RDI": "0x84",
    "R8":  "0x25a5a5a5",
    "R9":  "0x3000000",
    "R10": "0x16969695",
    "R11": "0x2d2d2d2d"
  }
}
%endif

; Verify 32-bit KillMove() post-RA move merging across expanded ALU opcodes
; (OP_ADD, OP_ADDWITHFLAGS, OP_SUBWITHFLAGS, OP_ANDWITHFLAGS, OP_MUL,
; OP_ADDSHIFT, OP_ROR) with dirty upper 32 bits in all source and destination
; registers prior to each 32-bit mov + 32-bit ALU pair.

mov rsp, 0xe0001000

mov r12, 0xdeadbeef80000001
mov r13, 0xcafebabe7fffffff
mov r14, 0xfeedfacef0f0f0f0
mov r15, 0x12345678a5a5a5a5

; OP_ADD / OP_ADDWITHFLAGS: 0x80000001 + 0x7fffffff = 0, CF=1, PF=1, ZF=1
mov rax, -1
mov eax, r12d
add eax, r13d
pushfq
pop rbx
and rbx, 0x8c5

; OP_SUB / OP_SUBWITHFLAGS: 0x7fffffff - 0x80000001 = 0xfffffffe, CF=1, SF=1, OF=1
mov rbp, -1
mov ebp, r13d
sub ebp, r12d
pushfq
pop rdx
and rdx, 0x8c5

; OP_AND / OP_ANDWITHFLAGS: 0xf0f0f0f0 & 0xa5a5a5a5 = 0xa0a0a0a0, PF=1, SF=1
mov rsi, -1
mov esi, r14d
and esi, r15d
pushfq
pop rdi
and rdi, 0x8c5

; OP_MUL: (uint32_t)(0x80000001 * 0xa5a5a5a5) = 0x25a5a5a5
mov r8, -1
mov r8d, r12d
imul r8d, r15d

; OP_ROR (imm): ror32(0x80000001, 7) = 0x03000000
mov r9, -1
mov r9d, r12d
ror r9d, 7

; OP_ADDSHIFT (scaled 32-bit lea): (uint32_t)(0x80000001 + (0xa5a5a5a5 << 2)) = 0x16969695
mov r10, -1
mov r10d, r12d
lea r10d, [r10 + r15*4]

; OP_ROR (cl with dirty upper bits): ror32(0xa5a5a5a5, 0x2d & 31 = 13) = 0x2d2d2d2d
mov rcx, 0xdeadbeef0000002d
mov r11, -1
mov r11d, r15d
ror r11d, cl

hlt
