%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1111111111111111",
    "RBX": "0x2222222222222222",
    "RCX": "0xe0000088",
    "RDX": "0x3333",
    "RSI": "0xe0000092"
  }
}
%endif

; POP to memory computes an RSP-based address after incrementing RSP.
mov rsp, 0xe0000080

mov rax, 0x1111111111111111
mov rbx, 0x2222222222222222
mov [rsp], rax
mov qword [rsp + 8], 0
mov qword [rsp + 16], 0
mov qword [rsp + 24], 0

; Loads from 0xe0000080 and stores to 0xe0000088.
pop qword [rsp]
mov rcx, rsp
mov rax, [rsp]

; Loads from 0xe0000088 and stores to 0xe0000098.
mov [rsp], rbx
mov rbx, 0
pop qword [rsp + 8]
mov rbx, [rsp + 8]

; Loads the word at 0xe0000090 and stores it to 0xe0000092.
mov qword [rsp], 0x3333
pop word [rsp]
movzx edx, word [rsp]
mov rsi, rsp

hlt
