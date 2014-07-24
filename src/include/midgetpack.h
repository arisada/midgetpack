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

#include <sys/types.h>
#include <stdint.h>
#include "config.h"
#include "shared.h"

#define BASE_ADDR 0xda79000
enum architecture_e {
  ARCH_x86 = 1,
  ARCH_AMD64,
  ARCH_ARM,
  ARCH_UNSUPPORTED,
  ARCH_INVALID
};

#define KEY_FILE_MAGIC_0 ((uint8_t)'M')
#define KEY_FILE_MAGIC_1 ((uint8_t)'P')
#define KEY_FILE_MAGIC_2 ((uint8_t)'\x7f')
#define KEY_FILE_MAGIC_3 ((uint8_t)'\x9f')

/* key file structure */
struct key_file {
	uint8_t magic[4];
	char filename[32];
	uint8_t master_key[AES128_KEY_LEN];
	uint8_t authentication_key[AES128_KEY_LEN];
};

/* elf.c */
struct elf_file_s {
  unsigned char *data;
  size_t size;
  enum architecture_e arch;
};

struct elf_file_s *elf_file_open(const char *filename);
void elf_file_free(struct elf_file_s *file);
enum architecture_e elf_get_arch(struct elf_file_s *file);
enum os_e elf_get_os(struct elf_file_s *file);
void elf_set_os(uint8_t *stub, enum os_e os);
void elf_add_pheader_32(unsigned char *stub, uint32_t vaddr, uint32_t offset, size_t len);
void elf_add_pheader_64(unsigned char *stub, uint64_t vaddr, uint64_t offset, size_t len);

/* embedded data */
unsigned char* get_x86_stub(size_t *size);

/* crypto.c */

char *ask_password(void);
void encrypt_payload(void *payload, size_t len, uint8_t encryptkey[AES128_KEY_LEN],
		uint8_t IV[AES128_KEY_LEN]);

int generate_password_parameters(uint8_t encryption_salt[8], uint8_t password_salt[8]);
int generate_curve25519_parameters(uint8_t encryption_salt[8],
		uint8_t master_key[AES128_KEY_LEN],
		uint8_t authentication_key[AES128_KEY_LEN]);
