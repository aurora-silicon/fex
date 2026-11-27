%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x14",
    "RBX": "0x85",
    "RCX": "0x0",
    "RDX": "0x0",
    "R8": "0x440895",
    "R9": "0x10014",
    "R10": "0x810",
    "R11": "0x20014",
    "R12": "0x44",
    "R13": "0x814",
    "R14": "0x10044",
    "R15": "0x10004"
  }
}
%endif

; Verify REPE/REPNE CMPS across all four operand sizes (8/16/32/64-bit),
; DF=0 and DF=1, RCX=0 flag preservation, early mismatch, and last-element
; mismatch (RCX==0 on exit), checking full arithmetic flags (0x8d5: CF/PF/AF/ZF/SF/OF).

mov rsp, 0xe0000800
mov rbp, 0xe0000000

; 1) RCX=0 must preserve flags (including PF/AF).
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
xor rcx, rcx
mov rax, 0x895
push rax
popfq
cld
repe cmpsb
pushfq
pop r8
and r8, 0x8d5
; Also verify RCX=0 with DF=1 and repne cmpsq preserves flags (0x044).
xor rcx, rcx
mov rax, 0x044
push rax
popfq
std
repne cmpsq
pushfq
pop rdx
and rdx, 0x8d5
cld
shl rdx, 16
or r8, rdx

; 2) REPE CMPSB DF=0: mismatch at byte 2 (0x10 - 0x01 = 0x0f -> AF=1, PF=1, CF=0, ZF=0, SF=0, OF=0)
mov dword [rbp + 0x100], 0x44102211
mov dword [rbp + 0x200], 0x44012211
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
mov rcx, 4
cld
repe cmpsb
pushfq
pop r9
and r9, 0x8d5
shl rcx, 16
or r9, rcx

; 3) REPE CMPSB DF=1: mismatch on last element (byte 0: 0x80 - 0x7f = 0x01 -> OF=1, AF=1, PF=0, CF=0, ZF=0, SF=0, RCX=0)
mov dword [rbp + 0x100], 0x33221180
mov dword [rbp + 0x200], 0x3322117f
lea rsi, [rbp + 0x103]
lea rdi, [rbp + 0x203]
mov rcx, 4
std
repe cmpsb
pushfq
pop r10
and r10, 0x8d5
cld
shl rcx, 16
or r10, rcx

; 4) REPE CMPSW DF=0: mismatch at word 1 (0x0010 - 0x0001 = 0x000f -> AF=1, PF=1), RCX=2
mov dword [rbp + 0x100], 0x00101234
mov dword [rbp + 0x104], 0x56789abc
mov dword [rbp + 0x200], 0x00011234
mov dword [rbp + 0x204], 0x56789abc
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
mov rcx, 4
cld
repe cmpsw
pushfq
pop r11
and r11, 0x8d5
shl rcx, 16
or r11, rcx

; 5) REPE CMPSW DF=1: all equal -> ZF=1, PF=1, RCX=0
mov dword [rbp + 0x100], 0xdeadbeef
mov dword [rbp + 0x104], 0xcafebabe
mov dword [rbp + 0x200], 0xdeadbeef
mov dword [rbp + 0x204], 0xcafebabe
lea rsi, [rbp + 0x106]
lea rdi, [rbp + 0x206]
mov rcx, 4
std
repe cmpsw
pushfq
pop r12
and r12, 0x8d5
cld
shl rcx, 16
or r12, rcx

; 6) REPE CMPSD DF=0: mismatch on last element (0x80000000 - 0x00000001 -> OF=1, AF=1, PF=0, SF=0, CF=0, ZF=0), RCX=0
mov dword [rbp + 0x100], 0x11111111
mov dword [rbp + 0x104], 0x22222222
mov dword [rbp + 0x108], 0x80000000
mov dword [rbp + 0x200], 0x11111111
mov dword [rbp + 0x204], 0x22222222
mov dword [rbp + 0x208], 0x00000001
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
mov rcx, 3
cld
repe cmpsd
pushfq
pop r13
and r13, 0x8d5
shl rcx, 16
or r13, rcx

; 7) REPNE CMPSD DF=1: match at index 1 -> ZF=1, PF=1, RCX=1
mov dword [rbp + 0x100], 0xaaaaaaaa
mov dword [rbp + 0x104], 0x55555555
mov dword [rbp + 0x108], 0x12345678
mov dword [rbp + 0x200], 0xbbbbbbbb
mov dword [rbp + 0x204], 0x55555555
mov dword [rbp + 0x208], 0x87654321
lea rsi, [rbp + 0x108]
lea rdi, [rbp + 0x208]
mov rcx, 3
std
repne cmpsd
pushfq
pop r14
and r14, 0x8d5
cld
shl rcx, 16
or r14, rcx

; 8) REPE CMPSQ DF=0: mismatch at qword 1 (0x0000000100000000 vs 0x0000000000000000 -> low 32 bits equal, high bit differs!)
mov rax, 0x0123456789abcdef
mov [rbp + 0x100], rax
mov [rbp + 0x200], rax
mov rax, 0x0000000100000000
mov [rbp + 0x108], rax
mov rax, 0x0000000000000000
mov [rbp + 0x208], rax
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
mov rcx, 3
cld
repe cmpsq
pushfq
pop r15
and r15, 0x8d5
shl rcx, 16
or r15, rcx

; 9) REPE CMPSQ DF=1: mismatch on last qword (0x0000000000000005 - 0x0000000000000010 -> CF=1, SF=1, AF=0, PF=0, OF=0), RCX=0
mov rax, 0x0000000000000005
mov [rbp + 0x100], rax
mov rax, 0x0000000000000010
mov [rbp + 0x200], rax
mov rax, 0xfedcba9876543210
mov [rbp + 0x108], rax
mov [rbp + 0x208], rax
lea rsi, [rbp + 0x108]
lea rdi, [rbp + 0x208]
mov rcx, 2
std
repe cmpsq
pushfq
pop rbx
and rbx, 0x8d5
cld
shl rcx, 16
or rbx, rcx

; 10) REPNE CMPSQ DF=0: all unequal -> RCX=0, flags of last compare (0x10 - 0x01 = 0x0f -> AF=1, PF=1)
mov rax, 0x1111111111111111
mov [rbp + 0x100], rax
mov rax, 0x2222222222222222
mov [rbp + 0x200], rax
mov rax, 0x0000000000000010
mov [rbp + 0x108], rax
mov rax, 0x0000000000000001
mov [rbp + 0x208], rax
lea rsi, [rbp + 0x100]
lea rdi, [rbp + 0x200]
mov rcx, 2
cld
repne cmpsq
pushfq
pop rax
and rax, 0x8d5
shl rcx, 16
or rax, rcx

xor rdx, rdx
hlt
