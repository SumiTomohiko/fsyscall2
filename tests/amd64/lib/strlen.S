%include "sys.inc"

; usage: rdi=string
global strlen
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

# vim: filetype=nasm
