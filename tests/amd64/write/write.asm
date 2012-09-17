
; Usage: write fd string

strlen:
	enter	0, 0

	mov	rax, 0
	mov	rbx, rdi
.begin:
	cmp	byte [rbx], 0
	je	.end
	inc	rax
	inc	rbx
	jmp	.begin

.end:
	leave
	ret

atoi:
	enter	0, 0

	mov	rax, 10
	mov	r8, 0
	mov	rbx, rdi
.begin:
	mov	cl, [rbx]
	cmp	cl, 0
	je	.end
	sub	cl, '0'
	movzx	r9, cl
	mul	r8
	add	r8, r9

	inc	rbx
	jmp	.begin

.end:
	mov	rax, r8
	leave
	ret

global _start
_start:
	push	rdi
	mov	rbp, rsp

	mov	rdi, [rbp]
	mov	rdi, [rdi + 2 * 8]
	call	atoi
	mov	r10, rax

	mov	rdi, [rbp]
	mov	rdi, [rdi + 3 * 8]
	mov	r8, rdi
	call	strlen
	mov	r9, rax

	; write
	mov	rax, 4
	mov	rdi, r10
	mov	rsi, r8
	mov	rdx, r9
	syscall
	mov	r8, rax

	; exit
	mov	rax, 1
	mov	rdi, r8
	syscall
