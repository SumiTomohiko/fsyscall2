%include "sys.inc"

; usage: rdi=string, rsi=string
; If two strings are same, streq will return zero. Otherwise, non-zero.
global streq
streq:
	enter	0, 0
	save_registers
%define	p	rdi
%define	q	rsi

; retval = 1;
; while (*p == *q) {
;     if (*p == '\0') {
;         retval = 0;
;         break;
;     }
;     p++;
;     q++;
; }
; return (retval);
	mov	rax, 1
.begin:
	mov	al, byte [p]
	cmp	al, byte [q]
	jne	.end
	cmp	al, 0
	jne	.inc
	mov	rax, 0
	jmp	.end
.inc:
	inc	p
	inc	q
	jmp	.begin
.end:

%undef	q
%undef	p
	restore_registers
	leave
	ret

# vim: filetype=nasm
