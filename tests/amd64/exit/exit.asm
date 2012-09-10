%include "../amd64.inc"

; Usage: exit x x x ...
; exit exits with status number that is same as number of command line
; arguments. If you $(exit), exit status is zero. If you $(exit foo bar), exit
; status is two. Pay attention to that each argument's value has no mean for
; this program. For example, if you $(exit 42), exit will exit with status of 1.
; This behavior is unexpected for you, if you expect the status of 42.

;hex:	db "0123456789abcdef"

global _start
_start:
	mov	[rsp - 8], rsp
.loop:
	cmp	qword [rsp - 8], 0
	je	.end

	mov	rax, [rsp - 8]
	mov	[rsp - 16], rax
	and	qword [rsp - 16], 0x0f
	add	qword [rsp - 16], hex

	mov	rax, 4
	mov	rdi, 1
	mov	rsi, [rsp - 16]
	mov	rdx, 1
	syscall

	shr	qword [rsp - 8], 4
	jmp	.loop

.end:
	mov	rax, 1
	syscall
