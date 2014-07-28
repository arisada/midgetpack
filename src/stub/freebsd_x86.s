# Copyright 2014 Aris Adamantiadis <aris@badcode.be>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

.globl mmap
.globl write
.globl read
.globl open
.globl close
.globl exit
.globl munmap
.globl getpid
.globl get_os
.globl ioctl

.text
mmap:
	push %ebp
	mov %esp, %ebp
	#we need to push 6 arguments and a zero
	push %ebx #save ebx
	push $0
	mov 28(%ebp), %ebx
	push %ebx

	mov 24(%ebp), %ebx
	push %ebx

	mov 20(%ebp), %ebx
	push %ebx

	mov 16(%ebp), %ebx
	push %ebx

	mov 12(%ebp), %ebx
	push %ebx

	mov 8(%ebp), %ebx
	push %ebx

	push $0 # dummy saved eip	
	mov $477, %eax # sys_mmap
	int $0x80
	add $32, %esp
	pop %ebx
	leave
	ret

syscall:
	# eax preloaded in caller
	int $0x80
	ret

munmap:
	mov $73, %eax # sys_unmap
	jmp syscall

write:
	mov $4, %eax # sys_write
	jmp syscall

read:
	mov $3, %eax # sys_read
	jmp syscall

open:
	mov $5, %eax # sys_open
	jmp syscall

close:
	mov $6, %eax # sys_close
	jmp syscall

exit:
	mov $1, %eax # sys_exit
	jmp syscall

getpid:
	mov $20, %eax #sys_getpid
	jmp syscall

get_os:
	mov $2, %eax
	ret
ioctl:
	mov $54, %eax
	jmp syscall
