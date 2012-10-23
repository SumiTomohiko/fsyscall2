%include "../sys.inc"

; usage: rdi=status
global exit
exit:
	enter	0, 0

	mov	rax, sys.exit
	syscall
	; NOTREACHED

	leave
	ret

# vim: filetype=nasm
