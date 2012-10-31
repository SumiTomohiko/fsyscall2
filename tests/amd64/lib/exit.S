%include "sys.inc"

; usage: rdi=status
global exit
exit:
	enter	0, 0
	save_registers

	mov	rax, sys.exit
	syscall
	; NOTREACHED

	restore_registers
	leave
	ret

# vim: filetype=nasm
