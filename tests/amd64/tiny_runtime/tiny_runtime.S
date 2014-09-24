%include "sys.inc"
%include "../lib/print_num.S"
%include "../lib/strlen.S"
%include "../lib/strcpy.S"

; defsyscall name num
%macro defsyscall 2
global %1
%1:
	mov rax, %2
	syscall
	jnc .exit
	mov rax, -1
.exit:
	ret
%endmacro

extern main

global _exit
_exit:
	mov rax, sys.exit
	mov rdi, rdi
	syscall
	; NOTREACHED

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

defsyscall getdirentries, sys.getdirentries
defsyscall fstatfs, sys.fstatfs
defsyscall fcntl, sys.fcntl
defsyscall open, sys.open
defsyscall read, sys.read
defsyscall geteuid, sys.geteuid
defsyscall getegid, sys.getegid
defsyscall getgid, sys.getgid
defsyscall getuid, sys.getuid
defsyscall dup, sys.dup
defsyscall close, sys.close
defsyscall socket, sys.socket
defsyscall connect, sys.connect
defsyscall poll, sys.poll
defsyscall fork, sys.fork
defsyscall gettimeofday, sys.gettimeofday
defsyscall getresuid, sys.getresuid
defsyscall getpeername, sys.getpeername

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
