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
	push {r4,r5,r7}
	mov r7, #192
	ldr r4, [sp, #12]
	ldr r5, [sp, #16]
	lsr r5, r5, #12
	svc 0x0
	pop {r7,r5,r4}
	bx lr

munmap:
	push {r7}
	mov r7, #91
	svc 0x0
	pop {r7}
	bx lr

write:
	push {r7}
	mov r7, #4
	svc 0x0
	pop {r7}
	bx lr

read:
	push {r7}
	mov r7, #3
	svc 0x0
	pop {r7}
	bx lr

open:
	push {r7}
	mov r7, #5
	svc 0x0
	pop {r7}
	bx lr

close:
	push {r7}
	mov r7, #6
	svc 0x0
	pop {r7}
	bx lr

exit:
	push {r7}
	mov r7, #1
	svc 0x0
	pop {r7}
	bx lr

getpid:
	push {r7}
	mov r7, #20
	svc 0x0
	pop {r7}
	bx lr

ioctl:
	push {r7}
	mov r7, #54
	svc 0x0
	pop {r7}
	bx lr

get_os:
	mov r0, #1
	bx lr
