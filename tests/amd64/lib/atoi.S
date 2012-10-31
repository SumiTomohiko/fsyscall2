%include "sys.inc"

; usage: rdi=string, rsi=base
global atoi
atoi:
	enter	0, 0
	save_registers

	mov	r8, 0
	mov	rbx, rdi
.begin:
	mov	cl, [rbx]
	cmp	cl, 0
	je	.end
	sub	cl, '0'
	movzx	r9, cl
	mov	rax, rsi
	mul	r8
	mov	r8, rax
	add	r8, r9

	inc	rbx
	jmp	.begin

.end:
	mov	rax, r8
	restore_registers
	leave
	ret

# vim: filetype=nasm
