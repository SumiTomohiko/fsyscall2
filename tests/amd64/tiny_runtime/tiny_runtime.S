%include "sys.inc"
%include "../lib/print_num.S"
%include "../lib/strlen.S"

extern main

global _exit
_exit:
	mov rax, sys.exit
	mov rdi, rdi
	syscall
	; NOTREACHED

global fcntl
fcntl:
	mov rax, sys.fcntl
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global open
open:
	mov rax, sys.open
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global read
read:
	mov rax, sys.read
	syscall
	jne .exit
	mov rax, -1
.exit:
	ret

global write
write:
	mov rax, sys.write
	mov rdi, rdi
	mov rsi, rsi
	mov rdx, rdx
	syscall
	jc .error
	mov rax, 0
	ret
.error:
	mov rax, -1
	ret

global select
select:
	mov rax, sys.select
	mov rdi, rdi
	mov rsi, rsi
	mov rdx, rdx
	mov r10, rcx
	mov r8, r8
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global getpid
getpid:
	mov rax, sys.getpid
	syscall
	ret

global geteuid
geteuid:
	mov rax, sys.geteuid
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global getegid
getegid:
	mov rax, sys.getegid
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global getgid
getgid:
	mov rax, sys.getgid
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global getuid
getuid:
	mov rax, sys.getuid
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global dup
dup:
	mov rax, sys.dup
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret

global _start
_start:
	mov rbp, rsp
	sub rsp, 3 * 8
%define	argc qword [rbp - 1 * 8]
%define	argv qword [rbp - 2 * 8]
%define	status qword [rbp - 3 * 8]
	mov r8, qword [rdi]
	mov argc, r8
	add rdi, 8
	mov argv, rdi

	mov rdi, argc
	mov rsi, argv
	call main
	;mov status, rax

	mov rdi, rax
	mov rax, sys.exit
	;call _exit
	syscall
	; NOTREACHED

; vim: filetype=nasm
