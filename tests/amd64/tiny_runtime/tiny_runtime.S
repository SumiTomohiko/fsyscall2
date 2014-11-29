%include "sys.inc"
%include "../lib/print_num.S"
%include "../lib/strlen.S"
%include "../lib/strcpy.S"

section .data

error: dq 0

section .text

global __error
__error:
	mov rax, error
	ret

; defsyscall name num
%macro defsyscall 1
global %1
%1:
	mov rax, sys.%1
	mov r10, rcx
	syscall
	jnc .exit
	mov [error], rax
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
	mov [error], rax
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
	mov [error], rax
	mov rax, -1
.exit:
	ret

global getpid
getpid:
	mov rax, sys.getpid
	syscall
	ret

defsyscall	getdirentries
defsyscall 	fstatfs
defsyscall 	fcntl
defsyscall	open
defsyscall	read
defsyscall	geteuid
defsyscall	getegid
defsyscall	getgid
defsyscall	getuid
defsyscall	dup
defsyscall	close
defsyscall	socket
defsyscall	connect
defsyscall	poll
defsyscall	fork
defsyscall	gettimeofday
defsyscall	getresuid
defsyscall	getpeername
defsyscall	getsockname
defsyscall	bind
defsyscall	wait4
defsyscall	execve
defsyscall	listen
defsyscall	accept
defsyscall	sigaction
defsyscall	sigprocmask
defsyscall	kill
defsyscall	sigwait

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
