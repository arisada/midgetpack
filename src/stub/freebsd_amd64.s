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
.globl ioctl
.globl get_os

.text
# syscalls conventions
# User:
# %rdi, %rsi, %rdx, %rcx, %r8 and %r9
# kernel
# %rdi, %rsi, %rdx, %r10, %r8 and %r9.

mmap:
	push %r10
	mov %rcx, %r10
	#shr $0xc, %rbp # mmap2 uses *4096
	mov $477, %rax # sys_mmap
	syscall
	pop %r10
	ret

syscall1:
syscall2:
syscall3:
	syscall
	ret

munmap:
	mov $73, %rax # sys_unmap
	jmp syscall2

write:
	mov $4, %rax # sys_write
	jmp syscall3

read:
	mov $3, %rax # sys_read
	jmp syscall3

open:
	mov $5, %rax # sys_open
	jmp syscall3

close:
	mov $6, %rax # sys_close
	jmp syscall1

exit:
	mov $1, %rax # sys_exit
	jmp syscall1

getpid:
	mov $20, %rax #sys_getpid
	syscall
	ret

ioctl:
	mov $54, %rax
	jmp syscall3

get_os:
	mov $2, %rax
	ret

