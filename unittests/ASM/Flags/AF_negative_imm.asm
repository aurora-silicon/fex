%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1300",
    "RBX": "0x0300",
    "RCX": "0x0700",
    "RDI": "0x49",
    "RDX": "0x87",
    "RSI": "0x07"
  }
}
%endif

; AF must come from the x86 operands even when FEX rewrites an add/sub of a
; negative immediate into the opposite operation with a positive immediate
; (hosts that compute AF in NZCV, such as Apple APFLG, see the rewritten
; operand). LAHF: bit0 CF, bit1 always 1, bit2 PF, bit4 AF, bit6 ZF, bit7 SF.

; 0x68 + 0xff..e1 = 0x49, CF=1, PF=0, AF=bit4(0x68^0xe1^0x49)=0.
; The rewritten sub of 31 would give AF=bit4(0x68^0x1f^0x49)=1.
mov rdi, 0x68
add rdi, -31
mov rax, 0
lahf
mov rbx, rax

; 0x68 - 0xffffffe1 = 0x87, CF=1 (borrow), PF=1, AF=bit4(0x68^0xe1^0x87)=0.
; The rewritten add of 31 would give AF=bit4(0x68^0x1f^0x87)=1.
mov edx, 0x68
sub edx, -31
mov rax, 0
lahf
mov rcx, rax

; 0x08 + 0xff..ff = 0x07, CF=1, PF=0, AF=bit4(0x08^0xff^0x07)=1.
; The rewritten sub of 1 would give AF=bit4(0x08^0x01^0x07)=0.
mov rsi, 0x08
add rsi, -1
mov rax, 0
lahf

hlt
