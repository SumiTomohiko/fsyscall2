%include "../amd64.inc"

; Usage: access path flags
; flags is hexadecimal.

global _start
_start:
	mov	rbp, rsp
	sub	rsp, 2 * 8
%define	path	qword [rbp - 8]
%define	mode	qword [rbp - 2 * 8]
	mov	rax, qword [rdi + 2 * 8]
	mov	path, rax

	mov	rdi, qword [rdi + 3 * 8]
	mov	rsi, 16
	call	atoi
	mov	mode, rax

	; access
	mov	rax, sys.access
	mov	rdi, path
	mov	rsi, mode
	syscall

	mov	rdi, rax
	call	exit

# vim: filetype=nasm
