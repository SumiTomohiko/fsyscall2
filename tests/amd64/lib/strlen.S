%include "sys.inc"

; usage: rdi=string
global strlen
strlen:
	enter	0, 0
	save_registers

	mov	rax, 0
	mov	rbx, rdi
.begin:
	cmp	byte [rbx], 0
	je	.end
	inc	rax
	inc	rbx
	jmp	.begin

.end:
	restore_registers
	leave
	ret

# vim: filetype=nasm
