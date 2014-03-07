%include "macro.inc"
%include "sys.inc"

; usage: rdi=dst, rsi=src
global strcpy
strcpy:
	prologue	0
	mov	rax, rdi

.begin:
	mov	bl, byte [rsi]
	mov	byte [rdi], bl
	cmp	bl, 0
	je	.end
	inc	rsi
	inc	rdi
	jmp	.begin

.end:
	epilogue

; vim: filetype=nasm
