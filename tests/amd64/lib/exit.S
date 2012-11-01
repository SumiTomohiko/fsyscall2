%include "macro.inc"
%include "sys.inc"

; usage: rdi=status
global exit
exit:
	prologue	0

	mov	rax, sys.exit
	syscall
	; NOTREACHED

	epilogue

# vim: filetype=nasm
