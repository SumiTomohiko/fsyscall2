%include "../test.inc"

; Usage: exit x x x ...
; exit exits with status number that is same as number of command line
; arguments. If you $(exit), exit status is zero. If you $(exit foo bar), exit
; status is two. Pay attention to that each argument's value has no mean for
; this program. For example, if you $(exit 42), exit will exit with status of
; one. This behavior is unexpected for you, if you expect the status of 42.

global _start
_start:
	mov	rdi, [rdi]
	dec	rdi
	call	exit

# vim: filetype=nasm
