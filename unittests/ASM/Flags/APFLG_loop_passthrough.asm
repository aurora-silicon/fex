%ifdef CONFIG
{
  "RegData": {
    "RBX": "0x815",
    "RDX": "0xfffffffffffffffd",
    "RDI": "0xd0",
    "RSI": "0x30",
    "R10": "0x3",
    "R14": "0x815",
    "R15": "0xfffffffffffffffd",
    "R12": "0x815",
    "R13": "0xfffffffffffffffd",
    "R11": "0x815",
    "R9": "0xfffffffffffffffd"
  }
}
%endif

; ADCX/ADOX keep PF/AF, so loops of them carry PF/AF around their back-edge
; and out of their LOOP/JRCXZ exits. The values must survive both.
; Arithmetic flags: CF 0x1, PF 0x4, AF 0x10, ZF 0x40, SF 0x80, OF 0x800.

mov rsp, 0xe0000010

; PF=1 AF=1 from POPF, JRCXZ exit, flags read after the loop.
mov rax, 0x16
push rax
popfq
mov rcx, -4
mov rdx, 0
mov r8, -1
.loop1:
adcx rdx, r8
adox rdx, r8
lea rcx, [rcx + 1]
jrcxz .done1
jmp .loop1
.done1:
pushfq
pop rbx
and rbx, 0x8d5

; PF=0 AF=1 ZF=1 SF=1 CF=1 from POPF, LOOP exit.
mov rax, 0xd3
push rax
popfq
mov rcx, 3
mov rsi, 5
mov r9, 7
.loop2:
adox rsi, r9
adcx rsi, r9
loop .loop2
pushfq
pop rdi
and rdi, 0x8d5

; PF read inside the loop, PF=1 AF=0 from POPF.
mov rax, 0x6
push rax
popfq
mov rcx, -3
mov r10, 0
mov r11, 1
mov r12, 2
.loop3:
adcx r11, r12
setp al
movzx eax, al
lea r10, [r10 + rax]
lea rcx, [rcx + 1]
jrcxz .done3
jmp .loop3
.done3:

; PF=1 AF=1 computed by a compare (0x10 - 1 = 0x0f), JRCXZ exit.
mov eax, 0x10
cmp eax, 1
mov rcx, -4
mov r15, 0
mov r8, -1
.loop4:
adcx r15, r8
adox r15, r8
lea rcx, [rcx + 1]
jrcxz .done4
jmp .loop4
.done4:
pushfq
pop r14
and r14, 0x8d5

; Same, with PF/AF from an 8-bit compare (0x10 - 1), which computes them
; apart from NZCV.
mov eax, 0x10
cmp al, 1
mov rcx, -4
mov r13, 0
mov r8, -1
.loop5:
adcx r13, r8
adox r13, r8
lea rcx, [rcx + 1]
jrcxz .done5
jmp .loop5
.done5:
pushfq
pop r12
and r12, 0x8d5

; Same, leaving the compiled unit through an indirect jump after the loop.
mov eax, 0x10
cmp al, 1
mov rcx, -4
mov r9, 0
mov r8, -1
.loop6:
adcx r9, r8
adox r9, r8
lea rcx, [rcx + 1]
jrcxz .done6
jmp .loop6
.done6:
lea rax, [rel .after6]
jmp rax
.after6:
pushfq
pop r11
and r11, 0x8d5

hlt
