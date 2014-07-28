/*
 * Copyright 2014 Aris Adamantiadis <aris@badcode.be>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _STUB_H_
#define _STUB_H_

/* definitions specific to the stub */
#include <stdint.h>
#include <sys/mman.h>
#include "shared.h"
#include "elf.h"
#include "config.h"

void *memcpy(void *dest, void *src, size_t len);
off_t strlen(char *s);
void* memset(void *p, int val, size_t len);
int memcmp(const void *s1, const void *s2, size_t n);
char *strchr(const char *s, int c);

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
int read(int fd, void *dest, size_t len);
int getpid(void);
int close(int fd);
int write(int fd, const void *data, size_t len);
void gettsc(uint32_t tsc[2]);
void *get_oep(char **base);
enum os_e get_os();

#ifndef ARCH_X86
#ifndef ARCH_AMD64
#ifndef ARCH_ARM
/* X86 as a fallback */
#warning "No architecture defined !"
#define ARCH_X86
#endif
#endif
#endif

#if defined(ARCH_X86) || defined(ARCH_ARM)
typedef Elf32_auxv_t Elf_auxv_t;

typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Addr Elf_Addr;
typedef struct stub_data_32 stub_data;

#endif
#ifdef ARCH_AMD64
typedef Elf64_auxv_t Elf_auxv_t;

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Addr Elf_Addr;
typedef struct stub_data_64 stub_data;
#endif

#endif

/* Linux */
#define TCGETS 0x5401
#define TCSETS 0x5402
/* FreeBSD */
#define TIOCGETA 0x402c7413
#define TIOCSETA 0x802c7414
typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#define NCCS 19
struct termios {
        tcflag_t c_iflag;               /* input mode flags */
        tcflag_t c_oflag;               /* output mode flags */
        tcflag_t c_cflag;               /* control mode flags */
        tcflag_t c_lflag;               /* local mode flags */
        cc_t c_line;                    /* line discipline */
        cc_t c_cc[NCCS];                /* control characters */
	    speed_t     c_ispeed;   /* input speed */
    	speed_t     c_ospeed;   /* output speed */
};

#define LINUX_ECHO 0x08
#define FREEBSD_ECHO 0x08
int ioctl(int fd, int code, void *param);
