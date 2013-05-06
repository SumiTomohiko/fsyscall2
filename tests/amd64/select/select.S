%include "lib.inc"
%include "sys.inc"

; This program does select(2) for the file descriptor 2 (stdout) to write
; without timeout.

global _start
_start:
%define	i		r9
%define	writefds	r10
%define	sizeof.fd_set	128
%define	status		qword [rsp]
	sub rsp, sizeof.fd_set
	mov writefds, rsp
	sub rsp, 8
	mov status, 1

	mov i, 0
.begin:
	cmp i, sizeof.fd_set
	je .end
	mov byte [writefds + i], 0
	inc i
	jmp .begin
.end:

	mov qword [writefds], 2	; FD_SET(1, writefds)

	; select
	mov rax, sys.select
	mov rdi, 2		; nfds
	mov rsi, 0		; readfds
	mov rdx, writefds	; writefds
	mov rcx, 0		; exceptfds
	mov r8, 0		; timeout
	syscall
	jc .exit
	cmp rax, 1
	jne .exit
	mov status, 0

.exit:
	; exit
	mov rdi, status
	call exit

; vim: filetype=nasm
