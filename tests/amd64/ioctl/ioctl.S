%include "lib.inc"
%include "sys.inc"

; Calls ioctl(2). This program makes sure if ioctl is in system call entry. This
; program does not tell if ioctl works correctly.

global _start
_start:
%define	status	r8
	mov status, 0

	; ioctl
	mov rax, sys.ioctl
	mov rdi, 0
	mov rsi, 0
	mov rdx, 0
	syscall
	jnc .exit
	cmp rax, 78	; ENOSYS
	jne .exit
	mov status, 1

.exit:
	; exit
	mov rdi, status
	call exit

; vim: filetype=nasm
