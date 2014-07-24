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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "midgetpack.h"
#include "elf.h"

struct elf_file_s *elf_file_open(const char *filename){
  int fd = -1;
  struct elf_file_s *file = NULL;
  struct stat statbuf;
  size_t r;
  off_t total=0;
  int pad;
  unsigned char buffer[4096];

  fd = open(filename, O_RDONLY);
  if (fd < 0){
    perror("Opening file");
    goto err;
  }
  file = malloc(sizeof(struct elf_file_s));
  if(file == NULL)
    goto err;
  memset(file, 0, sizeof(*file));

  if (fstat(fd, &statbuf) < 0){
    perror("fstat");
    goto err;
  }
  file->size = statbuf.st_size;
  /* leave enough space for padding */
  pad = (16 - file->size%16)% 16;
  /* blocks must be 16 bytes padded */
  file->size += pad;

  file->data = malloc(file->size);
  if (file->data == NULL){
    fprintf(stderr, "Could not allocate memory\n");
    goto err;
  }
  while (total < statbuf.st_size){
    size_t s = (size_t)(statbuf.st_size - total) >  sizeof(buffer) ? sizeof(buffer) : (size_t)(statbuf.st_size - total);
    r = read(fd, buffer, s);
    if (r <= 0){
      perror("reading file");
      goto err;
    }
    memcpy(file->data + total, buffer, r);
    total += r;
  }
  memset(file->data + statbuf.st_size, 0, pad);
  return file;

err:
  if(file != NULL){
    if(file->data != NULL){
      free(file->data);
      file->data = NULL;
    }
    free(file);
    file = NULL;
  }
  if (fd >= 0)
    close(fd);
  return NULL;
}

void elf_file_free(struct elf_file_s *file){
  if(file != NULL) {
    if(file->data != NULL){
      free(file->data);
      file->data = NULL;
    }
    free(file);
  }
}

enum architecture_e elf_get_arch(struct elf_file_s *file){
  Elf32_Ehdr *header32 = (Elf32_Ehdr *)file->data;
  Elf64_Ehdr *header64 = (Elf64_Ehdr *)file->data;
  if (file->size < sizeof(*header32))
    return ARCH_INVALID;
  if (memcmp(header32->e_ident, ELFMAG, 4) != 0)
    return ARCH_INVALID;
  switch(header32->e_ident[EI_CLASS]) {
    case ELFCLASS32:
      if (header32->e_machine == EM_386){
        file->arch = ARCH_x86;
        return ARCH_x86;
      }
      if (header32->e_machine == EM_ARM){
    	  file->arch = ARCH_ARM;
    	  return ARCH_ARM;
      }
      return ARCH_UNSUPPORTED;
    case ELFCLASS64:
      if(file->size < sizeof(*header64)){
        return ARCH_INVALID;
      }
      if(header64->e_machine == EM_X86_64){
        file->arch = ARCH_AMD64;
        return ARCH_AMD64;
      }
      return ARCH_UNSUPPORTED;
  }
  return ARCH_INVALID;
}

enum os_e elf_get_os(struct elf_file_s *file){
  Elf32_Ehdr *header32 = (Elf32_Ehdr *)file->data;
  if (file->size < sizeof(*header32))
    return OS_INVALID;
  if (memcmp(header32->e_ident, ELFMAG, 4) != 0)
    return OS_INVALID;
  switch(header32->e_ident[EI_OSABI]) {
    case ELFOSABI_FREEBSD:
      return OS_FREEBSD;
    case ELFOSABI_LINUX:
    case ELFOSABI_SYSV:
      return OS_LINUX;
    default:
      return OS_UNSUPPORTED;
  }
  return OS_INVALID;
}

/** @brief overwrite the OS definition in the ELF header
 * of the stub, so it runs in the required OS.
 */
void elf_set_os(uint8_t *stub, enum os_e os){
	/* ELF32 and ELF64 use common fields for ABI */
	Elf32_Ehdr *header = (Elf32_Ehdr *)stub;
	switch(os){
	case OS_LINUX:
		header->e_ident[EI_OSABI] = ELFOSABI_SYSV;
		break;
	case OS_FREEBSD:
		header->e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
		break;
	default:
		printf("Invalid OS %d\n", os);
	}
}

#define ELF_ADD_PHEADER(BITS) \
	void elf_add_pheader_ ## BITS (unsigned char *stub, uint ## BITS ## _t vaddr, \
			uint ## BITS ## _t offset, size_t len){ \
		Elf ## BITS ## _Ehdr *header = (Elf ## BITS ## _Ehdr *)stub; \
		Elf ## BITS ## _Phdr *pheader = (Elf ## BITS ## _Phdr *)(stub + header->e_phoff + \
				header->e_phnum * header->e_phentsize); \
		printf("Adding new pheader with vaddr base %" PRIu64 ", offset %" PRIu64 " of filesz %" PRIu32 "\n",\
			(int64_t)vaddr, (int64_t)offset, (uint32_t)len);\
		pheader->p_type = PT_LOAD;\
		pheader->p_offset = offset;\
		pheader->p_vaddr = vaddr + offset;\
		pheader->p_paddr = vaddr + offset;\
		pheader->p_filesz = len;\
		pheader->p_memsz = len;\
		pheader->p_flags = PF_R | PF_W | PF_X;\
		pheader->p_align = 0x1000;\
		header->e_phnum++;\
}

ELF_ADD_PHEADER(32)
ELF_ADD_PHEADER(64)


