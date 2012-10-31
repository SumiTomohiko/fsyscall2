%include "prog.inc"

global _start
_start:
	mov	rbp, rsp

	; issetugid
	mov	rax, sys.issetugid
	syscall

	mov	rdi, rax
	call	exit

; vim: filetype=nasm
