%include "macro.inc"
%include "sys.inc"

; usage: rdi=string
global strlen
strlen:
	prologue	0

	mov	rax, 0
	mov	rbx, rdi
.begin:
	cmp	byte [rbx], 0
	je	.end
	inc	rax
	inc	rbx
	jmp	.begin

.end:
	epilogue

; vim: filetype=nasm
