%include "../amd64.inc"

; Usage: write fd string

global _start
_start:
	push	rdi
	mov	rbp, rsp

	mov	rdi, [rbp]
	mov	rdi, [rdi + 2 * 8]
	mov	rsi, 10
	call	atoi
	mov	r10, rax

	mov	rdi, [rbp]
	mov	rdi, [rdi + 3 * 8]
	mov	r8, rdi
	call	strlen
	mov	r9, rax

	; write
	mov	rax, sys.write
	mov	rdi, r10
	mov	rsi, r8
	mov	rdx, r9
	syscall
	jc	.error

	; exit
	mov	rdi, rax
	call	exit

.error:
	mov	rdi, -1
	call	exit

# vim: filetype=nasm
