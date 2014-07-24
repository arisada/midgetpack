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

.text
mmap:
	push %ebp
	mov %esp, %ebp
	sub $0x4, %esp # save space for return value
	pusha
	push %ebp #ebp will be overwritten
	mov 0x8(%ebp), %ebx
	mov 0xc(%ebp), %ecx
	mov 0x10(%ebp), %edx
	mov 0x14(%ebp), %esi
	mov 0x18(%ebp), %edi
	mov 0x1c(%ebp), %ebp
	shr $0xc, %ebp # mmap2 uses *4096
	mov $0xc0, %eax # sys_mmap2
	int $0x80
	pop %ebp
	mov %eax, -0x4(%ebp)
	popa
	mov -0x4(%ebp), %eax
	leave
	ret

syscall3:
	push %ebp
	mov %esp, %ebp
	push %ebx
	push %ecx
	push %edx
	mov 0x8(%ebp), %ebx
	mov 0xc(%ebp), %ecx
	mov 0x10(%ebp), %edx
	# eax preloaded in caller
	int $0x80
	pop %edx
	pop %ecx
	pop %ebx
	leave
	ret

syscall1:
	push %ebx
	mov 0x8(%esp), %ebx
	# eax is preloaded in caller
	int $0x80
	pop %ebx
	ret

syscall2:
	push %ebx
	push %ecx
	mov 0xc(%esp), %ebx
	mov 0x10(%esp), %ecx
	# eax is preloaded in caller
	int $0x80
	pop %ecx
	pop %ebx
	ret

munmap:
	mov $91, %eax # sys_unmap
	jmp syscall2

write:
	mov $4, %eax # sys_write
	jmp syscall3

read:
	mov $3, %eax # sys_read
	jmp syscall3

open:
	mov $5, %eax # sys_open
	jmp syscall3

close:
	mov $6, %eax # sys_close
	jmp syscall1

exit:
	mov $1, %eax # sys_exit
	jmp syscall1

getpid:
	mov $20, %eax #sys_getpid
	int $0x80
	ret

get_os:
	mov $1, %eax
	ret
